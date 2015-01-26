
from __future__ import print_function

import copy
from ConfigParser import SafeConfigParser
import hashlib
import json
import os.path
import sys
from urlparse import urlparse
from bindproxyws import make_ws
from proxies.lru import LRUTimedCache, LRUClusterProtocolFactory, \
                        LRUClusterClient, make_cluster_func
import proxies.patch
from ldaptor import config
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import proxybase, ldaperrors
from twisted.internet import reactor, defer, ssl, protocol
from twisted.internet.endpoints import serverFromString
from twisted.python import log
from twisted.application import service


class BindProxy(proxybase.ProxyBase):
    """
    LDAP Proxy notices failed BIND attempts that use the same failed
    password and responds with a failure immediately instead of passing
    the credentials on to the proxied service.
    """
    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Override to modify request and/or controls forwarded on to the proxied server.
        Must return a tuple of request, controls or a deferred that fires the same.
        Return `None` or a deferred that fires `None` to bypass forwarding the 
        request to the proxied server.  In this case, any response can be sent to the
        client via `reply(response)`.
        """
        if isinstance(request, pureldap.LDAPBindRequest): 
            dn = request.dn
            auth_digest = hashlib.md5(request.auth).hexdigest()
            bind_info = self._getLastBind(dn)
            if bind_info is not None:
                digest, resultCode = bind_info
                if self.debug:
                    log.msg(("[DEBUG] curr digest == '{0}', "
                             "last cached digest == '{1}'").format(auth_digest, digest))
                if digest == auth_digest:
                    log.msg("[INFO] Same invalid credentials presented for DN '{0}'."
                            "  Not forwarding to proxied service.".format(dn))
                    response = pureldap.LDAPBindResponse(resultCode=resultCode)
                    reply(response)
                    return defer.succeed(None)
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

    def _getLastBind(self, dn):
        """
        Get the last BIND password digest and result code for a DN.
        """
        lastBindCache = self.factory.lastBindCache
        return lastBindCache.get(dn)

    def _setLastBind(self, dn, passwd_digest, resultCode):
        """
        Record the last failed password digest and result code for 
        a DN and schedule an eviction from the cache.
        """
        lastBindCache = self.factory.lastBindCache
        lastBindCache.store(dn, (passwd_digest, resultCode))

    def handleProxiedResponse(self, response, request, controls):
        """
        Append memberships/members to search results if those attributes
        were requested.
        """
        if isinstance(response, pureldap.LDAPBindResponse) and response.resultCode != 0L:
            digest = hashlib.md5(request.auth).hexdigest()
            self._setLastBind(
                request.dn, digest, response.resultCode)
            if self.debug:
                log.msg("[DEBUG] Caching BIND digest '{0}'.".format(digest))
        searchResponses = self.searchResponses
        d = defer.succeed(response)
        if isinstance(response, pureldap.LDAPBindResponse) and response.resultCode == 0:
            self.bind_dn = request.dn 
        elif isinstance(response, pureldap.LDAPSearchResultEntry):
            responses = searchResponses.setdefault(id(request), [])
            responses.append(response)
        elif isinstance(response, pureldap.LDAPSearchResultDone):
            searchCache = self.factory.searchCache
            key = id(request)
            searchCache.store((self.bind_dn, repr(request)), searchResponses.get(key))
            if key in searchResponses:
                del searchResponses[key]
        return d

def load_config(filename="bindproxy.cfg", instance_config=None):
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
            'debug',
            'debug_cache', 
            'endpoint', 
            'bind_cache_lifetime', 
            'bind_cache_size',
            'search_cache_lifetime',
            'search_cache_size']),
        'LDAP': lambda x: x in frozenset(['proxy_cert', 'use_starttls']),
        'Cluster': isValidClusterOption,
        'WebService': lambda x: x in frozenset(['endpoint'])
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
    for section in config.sections():
        is_required = section in required 
        is_optional = section in optional
        if not (is_required or is_optional):
            log.msg("[WARNING] Section '{0}' is not recognized.".format(section))
            continue
        required_options = required.get(section, nullset)
        optional_test = optional.get(section, nullset)
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

class BindProxyService(service.Service):
    def __init__(self, instance_config=None, endpoint=None, portal=None):
        self._ports = {}
        self.instance_config = instance_config
        self.endpoint = endpoint
        self.portal = portal

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
        if scp.has_option('Application', 'debug'):
            debug_app = scp.getboolean('Application', 'debug')
        else:
            debug_app = False
        if scp.has_option('Application', 'debug_cache'):
            debug_cache = scp.getboolean('Application', 'debug_cache')
        else:
            debug_cache = False
        if scp.has_option('Application', 'search_cache_lifetime'):
            searchCacheLifetime = scp.getint('Application', 'search_cache_lifetime')
        else:
            searchCacheLifetime = 600
        if scp.has_option('Application', 'search_cache_size'):
            searchCacheSize = scp.getint('Application', 'search_cache_size')
        else:
            searchCacheSize = 2000
        if scp.has_option('Application', 'bind_cache_lifetime'):
            bindCacheLifetime = scp.getint('Application', 'bind_cache_lifetime')
        else:
            bindCacheLifetime = 600
        if scp.has_option('Application', 'bind_cache_size'):
            bindCacheSize = scp.getint('Application', 'bind_cache_size')
        else:
            bindCacheSize = 2000
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
            clusterClient.debug = debug_cache
        def make_protocol():
            proto = BindProxy(cfg, use_tls=use_tls)
            proto.debug = debug_app
            proto.bind_dn = None
            proto.searchResponses = {}
            return proto
        factory.protocol = make_protocol
        kwds = {}
        if use_cluster:
            kwds['cluster_func'] = make_cluster_func('bind', clusterClient, debug=debug_cache)
        factory.lastBindCache = LRUTimedCache(lifetime=bindCacheLifetime, capacity=bindCacheSize, **kwds)
        kwds = {}
        if use_cluster:
            kwds['cluster_func'] = make_cluster_func('search', clusterClient, debug=debug_cache)
        factory.searchCache = LRUTimedCache(lifetime=searchCacheLifetime, capacity=searchCacheSize, **kwds)
        ep = serverFromString(reactor, endpoint)
        d = ep.listen(factory)
        d.addCallback(self.set_listening_port, port_type='ldap')
        if use_cluster:
            ep = serverFromString(reactor, cluster_endpoint)
            cache_map = {
                'bind': factory.lastBindCache,
                'search': factory.searchCache,}
            cluster_proto_factory = LRUClusterProtocolFactory(cache_map)
            cluster_proto_factory.protocol.debug = debug_cache
            d = ep.listen(cluster_proto_factory)
            d.addCallback(self.set_listening_port, port_type='cluster')
            d.addErrback(log.err)
        if scp.has_section("WebService") and scp.has_option("WebService", "endpoint"):
            endpoint = scp.get("WebService", "endpoint")
            ws_site = make_ws(bindCache=factory.lastBindCache, portal=self.portal)
            ws_site.displayTracebacks = debug_cache
            ep = serverFromString(reactor, endpoint)
            d = ep.listen(ws_site)
            d.addCallback(self.set_listening_port, port_type='ws')

    def set_listening_port(self, port, port_type):
        self._ports[port_type] = port

    def stopService(self):
        """
        Stop the service.
        """
        rval = True
        for port_type, port in self._ports.iteritems():
            rval = (rval and port.stopListening())
        return rval

