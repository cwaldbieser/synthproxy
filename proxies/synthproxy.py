#! /usr/bin/env python

from __future__ import print_function

import collections
import copy
from ConfigParser import SafeConfigParser
import json
import os.path
import sys
from urlparse import urlparse
import httpclient
from proxies.lru import LRUTimedCache, LRUClusterProtocolFactory, \
                        LRUClusterClient, make_cluster_func
from ldaptor import config
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import proxybase, ldaperrors
import treq
from twisted.application import service
from twisted.internet import reactor, defer, ssl, protocol
from twisted.internet.endpoints import serverFromString
from twisted.python import log


class SynthProxy(proxybase.ProxyBase):
    """
    Proxy synthesizes search result attributes from database.
    """
    dbcache_lifetime = 300
    bind_dn = None

    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Override to modify request and/or controls forwarded on to the proxied server.
        Must return a tuple of request, controls or a deferred that fires the same.
        Return `None` or a deferred that fires `None` to bypass forwarding the 
        request to the proxied server.  In this case, any response can be sent to the
        client via `reply(response)`.
        """
        searchCache = self.factory.searchCache
        responses = None
        responses = searchCache.get((self.bind_dn, repr(request)))
        if responses is not None:
            if self.debug:
                log.msg("[DEBUG] LDAP responses were cached for request {0}".format(repr(request)))
            for response in responses:
                reply(response)
            reply(pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode))
            return None
        elif self.debug:
            log.msg("[DEBUG] Results must be retrieved from proxied server.")
        return defer.succeed((request, controls))

    def handleProxiedResponse(self, response, request, controls):
        """
        Append memberships/members to search results if those attributes
        were requested.
        """
        searchResponses = self.searchResponses
        d = defer.succeed(response)
        if isinstance(response, pureldap.LDAPBindResponse) and response.resultCode == 0:
            self.bind_dn = request.dn 
        elif isinstance(response, pureldap.LDAPSearchResultEntry):
            responses = searchResponses.setdefault(id(request), [])
            responses.append(response)
            attributes = frozenset(request.attributes)
            all_attributes = len(attributes) == 0
            if all_attributes or 'memberOf' in attributes or 'member' in attributes:
                dn = response.objectName.lower() 
                d = self._getAuxilliaryAttributes(dn, response)
                d.addCallback(self._receivedAuxilliaryAttributes, response, request, controls, attributes)
        elif isinstance(response, pureldap.LDAPSearchResultDone):
            searchCache = self.factory.searchCache
            key = id(request)
            searchCache.store((self.bind_dn, repr(request)), searchResponses.get(key))
            if key in searchResponses:
                del searchResponses[key]
        return d

    def _getAuxilliaryAttributes(self, dn, response):
        """
        Returns a deferred that will fire with a modified response
        that will include any additional attributes.
        """
        cache = self.factory.dbcache
        entry = cache.get(dn)
        if entry is None:
            d0 = self.http_client.get(
                self.membership_view_url, 
                auth=(self.db_user, self.db_passwd), 
                params=dict(key=json.dumps(dn)))
            d0.addCallback(treq.json_content)
            d0.addCallback(self._scheduleExpireCache, dn)
            pending = []
            d = defer.Deferred()
            pending.append(d)
            cache[dn] = ('pending', pending)
            d0.addCallback(self._processPending, pending, dn)
            d0.addErrback(self._receivedErrorFromDB, pending, dn)
        else:
            kind, cached = entry
            if kind == 'pending':
                d = defer.Deferred()
                cached.append(d)
            elif kind == 'result':
                if self.debug:
                    log.msg("[DEBUG] Aux. attributes are already in the cache.")
                d = defer.succeed(cached)
        return d

    def _processPending(self, result, pending, dn, failed=False):
        """
        Cache the aux. attribute lookup.
        Process pending aux. attribute lookups.
        Fire each waiting deferred.
        """
        debug = self.debug
        if not failed:
            if debug:
                log.msg("[DEBUG] Caching aux attributes ...")
            self.factory.dbcache[dn] = ('result', result)
        for d in pending:
            if debug:
                if not failed:
                    log.msg("[DEBUG] Pending aux. attributes fetched from cache.")
                else:
                    log.msg("[DEBUG] Failed to fetch aux attributes for pending request.")
            
            d.callback(result)

    def _scheduleExpireCache(self, result, dn):
        """
        Schedule the expiration of the cached aux. attribs.
        """
        self.reactor.callLater(self.dbcache_lifetime, self._expireCache, dn)
        return result

    def _expireCache(self, dn):
        if self.debug:
            log.msg("[DEBUG] Expiring cached DN -> {0}".format(dn))
        del self.factory.dbcache[dn]

    def _receivedErrorFromDB(self, err, pending, dn):
        """
        An error ocurred while trying to lookup the aux attributes.
        Log the error and reply with the standard attributes.
        """
        log.msg("[ERROR] Could not retrieve external attributes for '{0}.".format(dn))
        log.msg(str(err))
        d = defer.succeed(None)
        d.addCallback(self._processPending, pending, dn, failed=True)
        return d
    
    def _receivedAuxilliaryAttributes(self, doc, response, request, controls, requested_attributes):
        """
        Aux. attributes for a DN have been received from the DB.
        Check if the requestor has access.  If so, add the attributes to the
        result.
        Otherwise, return the original result.
        """
        if doc is not None:
            attribs = response.attributes
            all_attribs = len(requested_attributes) == 0
            attrib_map = dict((k,v) for k, v in response.attributes)
            rows = doc["rows"]
            changed = False
            for item in rows:
                pair = item["value"]
                attrib = pair[0]
                if all_attribs or attrib in requested_attributes:
                    value = pair[1]
                    values = attrib_map.setdefault(attrib, [])
                    values.append(value)
                    changed = True
            if changed:
                temp = attrib_map.items()
                attribs[:] = temp
        return response

def load_config(filename="synthproxy.cfg", instance_config=None):
    """
    Load the proxy configuration.
    """
    scp = SafeConfigParser()
    system = os.path.join("/etc", filename)
    user = os.path.join(os.path.expanduser("~/"), ".{0}".format(filename))
    local = os.path.join(".", filename) 
    config_files = [system, user, local]
    if instance_config is not None:
        config_files.append(instance_config)
    files_read = scp.read(config_files)
    assert len(files_read) > 0, "No config file found."
    return scp

def validate_config(config):
    """
    Validate the configuration.
    """
    required = {
        'CouchDB': frozenset(['url', 'user', 'passwd']),
        'LDAP': frozenset(['proxied_url',]),
        } 
    def isValidClusterOption(opt):
        if opt == "endpoint":
            return True
        if opt.startswith("peer"):
            return True
        return False
    optional = {
        'Application': lambda x: x in frozenset([
            'debug', 'endpoint', 'search_cache_lifetime', 'search_cache_size']),
        'LDAP': lambda x: x in frozenset(['proxy_cert', 'use_starttls']),
        'Cluster': isValidClusterOption
        }
    valid = True
    for section, options in required.iteritems():
        if not config.has_section(section):
            valid = False
            log.msg("[ERROR] Missing required section '{0}'.".format(section))
        for option in options:
            if not config.has_option(section, option):
                valid = False
                log.msg("[ERROR] Missing required option '{0}:{1}'.".format(section, option))
    nullset = frozenset([])
    falsetest = lambda x: False
    for section in config.sections():
        is_required = section in required 
        is_optional = section in optional
        if not (is_required or is_optional):
            log.msg("[WARNING] Section '{0}' is not recognized.".format(section))
            continue
        required_options = required.get(section, nullset)
        optional_test = optional.get(section, falsetest)
        for option in config.options(section):
            is_required = option in required_options
            is_optional = optional_test(option)
            if not (is_required or is_optional):
                log.msg("[WARNING] Option '{0}:{1}' is not recognized.".format(section, option))
                continue
    if not valid:
        sys.exit(1)

def parse_url(url):
    """
    Return (scheme, host, port).
    """
    p = urlparse(url)
    parts = p.netloc.split(":", 1)
    host = parts[0]
    if len(parts) > 1:
        port = int(parts[1])
    else:
        port = 389
    return (p.scheme, host, port)

class SynthProxyService(service.Service):
    def __init__(self, instance_config=None, endpoint=None):
        self._port = None
        self._cluster_port = None
        self.instance_config = instance_config
        self.endpoint = endpoint

    def startService(self):
        #log.startLogging(sys.stderr)
        scp = load_config(instance_config=self.instance_config)
        validate_config(scp)
        endpoint = self.endpoint
        if endpoint is None:
            if scp.has_option("Application", "endpoint"):
                endpoint = scp.get("Application", "endpoint")
            else:
                endpoint = "tcp:10389"
        db_url = scp.get("CouchDB", "url")
        db_user = scp.get("CouchDB", "user")
        db_passwd = scp.get("CouchDB", "passwd") 
        proxied_scheme, proxied_host, proxied_port = parse_url(
            scp.get("LDAP", "proxied_url"))
        factory = protocol.ServerFactory()
        if scp.has_option("LDAP", "proxy_cert"):
            proxy_cert = scp.get("LDAP", "proxy_cert")
            with open("ssl/proxy.pem", "r") as f:
                certData = f.read()
            cert = ssl.PrivateCertificate.loadPEM(certData)
            factory.options = cert.options()
        proxied = (proxied_host, proxied_port)
        if proxied_scheme == 'ldaps':
            log.msg("[ERROR] `ldaps` scheme is not supported.")
            sys.exit(0)
        use_tls = scp.getboolean('LDAP', 'use_starttls')
        cfg = config.LDAPConfig(serviceLocationOverrides={'': proxied, })
        debug_app = scp.getboolean('Application', 'debug')
        if scp.has_option('Application', 'search_cache_lifetime'):
            searchCacheLifetime = scp.getint('Application', 'search_cache_lifetime')
        else:
            searchCacheLifetime = 600
        if scp.has_option('Application', 'search_cache_size'):
            searchCacheSize = scp.getint('Application', 'search_cache_size')
        else:
            searchCacheSize = 2000
        use_cluster = False
        if scp.has_section("Cluster"):
            cluster_endpoint = None
            cluster_peers = []
            if not scp.has_option("Cluster", "endpoint"):
                log.msg("[ERROR] Section 'Cluster' does not define an 'endpoint' option.")
                sys.exit(1)
            cluster_endpoint = scp.get("Cluster", "endpoint")
            options = scp.options("Cluster")
            has_peer = False
            for option in options:
                if option.startswith("peer"):
                    has_peer = True
                    cluster_peers.append(scp.get("Cluster", option))
            if not has_peer:
                log.msg("[ERROR] Section 'Cluster' does not have any 'peerxxx' options.")
                sys.exit(1)
            use_cluster = True
            clusterClient = LRUClusterClient(cluster_peers)
        def make_protocol():
            proto = SynthProxy(cfg, use_tls=use_tls)
            proto.debug = debug_app
            proto.bind_dn = None
            proto.membership_view_url = db_url
            proto.db_user = db_user
            proto.db_passwd = db_passwd
            proto.http_client = httpclient
            proto.searchResponses = {}
            return proto
        factory.protocol = make_protocol
        factory.dbcache = {}
        kwds = {}
        if use_cluster:
            kwds['cluster_func'] = make_cluster_func('search', clusterClient)
        factory.searchCache = LRUTimedCache(lifetime=searchCacheLifetime, capacity=searchCacheSize, **kwds)
        kwds = {}
        ep = serverFromString(reactor, endpoint)
        d = ep.listen(factory)
        d.addCallback(self.set_listening_port)
        if use_cluster:
            ep = serverFromString(reactor, cluster_endpoint)
            cache_map = {
                'search': factory.searchCache,}
            cluster_proto_factory = LRUClusterProtocolFactory(cache_map)
            d = ep.listen(cluster_proto_factory)
            d.addCallback(self.set_cluster_port)
            d.addErrback(log.err)

    def set_listening_port(self, port):
        self._port = port

    def set_cluster_port(self, port):
        self._cluster_port = port
        
    def stopService(self):
        """
        Stop the service.
        """
        if self._cluster_port is not None:
            self._cluster_port.stopListening()
        if self._port is not None:
            return self._port.stopListening()
