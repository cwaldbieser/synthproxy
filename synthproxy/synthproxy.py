#! /usr/bin/env python

from __future__ import print_function

import collections
import copy
from ConfigParser import SafeConfigParser
import json
import os.path
import sys
from urlparse import urlparse

import http
from ldaptor import config
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import proxybase, ldaperrors
import treq
from twisted.internet import reactor, defer, ssl, protocol
from twisted.internet.endpoints import serverFromString
from twisted.python import log

class SearchCache(object):
    """
    """
    def __init__(self, capacity=1000, reactor_=reactor, lifetime=240):
        """
        """
        self.cache = collections.OrderedDict()
        self.capacity = capacity
        self.evictors = {}
        self.reactor = reactor_
        self.lifetime = lifetime

    def get(self, bind_dn, request):
        key = (bind_dn, repr(request))
        responses = self.cache.get(key, None) 
        return responses

    def store(self, bind_dn, request, responses):
        cache = self.cache   
        key = (bind_dn, repr(request))
        try:
            cache.pop(key)
        except KeyError:
            pass
        cache[key] = responses
        evictors = self.evictors
        evictor = evictors.get(key, None)
        if evictor is not None:
            evictor.cancel()
        evictor = self.reactor.callLater(self.lifetime, self._evict, key)
        evictors[key] = evictor
        if len(cache) > self.capacity:
            evicted_key = cache.popitem(last=False)
            evictor = evictors[evicted_key]
            evictor.cancel()
            del evictors[evicted_key]

    def _evict(self, key):
        del self.evictors[key]
        del self.cache[key]

    def __str__(self):
        return str(self.cache)

class SynthProxy(proxybase.ProxyBase):
    """
    Proxy synthesizes search result attributes from database.
    """
    dbcache_lifetime = 60
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
        responses = searchCache.get(self.bind_dn, request)
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
            searchCache.store(self.bind_dn, request, searchResponses.get(key))
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
            d0.addErrback(self._receivedErrorFromDB, response)
            d0.addCallback(self._scheduleExpireCache, dn)
            pending = []
            d = defer.Deferred()
            pending.append(d)
            cache[dn] = ('pending', pending)
            d0.addCallback(self._processPending, pending, dn)
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

    def _processPending(self, result, pending, dn):
        """
        Cache the aux. attribute lookup.
        Process pending aux. attribute lookups.
        Fire each waiting deferred.
        """
        self.factory.dbcache[dn] = ('result', result)
        debug = self.debug
        for d in pending:
            if debug:
                log.msg("[DEBUG] Pending aux. attributes fetched from cache.")
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

    def _receivedErrorFromDB(self, err, response):
        """
        An error ocurred while trying to lookup the aux attributes.
        Log the error and reply with the standard attributes.
        """
        log.msg("[ERROR] Could not retrieve external attributes.")
        log.msg(str(err))
        log.msg("Returning the raw response provided by the proxied server => {0}".format(repr(response)))
        return response
    
    def _receivedAuxilliaryAttributes(self, doc, response, request, controls, requested_attributes):
        """
        Aux. attributes for a DN have been received from the DB.
        Check if the requestor has access.  If so, add the attributes to the
        result.
        Otherwise, return the original result.
        """
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

def load_config(filename="synthproxy.cfg"):
    """
    Load the proxy configuration.
    """
    scp = SafeConfigParser()
    system = os.path.join("/etc", filename)
    user = os.path.join(os.path.expanduser("~/"), ".{0}".format(filename))
    local = os.path.join(".", filename) 
    files_read = scp.read([system, user, local])
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
    optional = {
        'Application': frozenset(['debug', 'port']),
        'LDAP': frozenset(['proxy_cert', 'use_starttls']),
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
        optional_options = optional.get(section, nullset)
        for option in config.options(section):
            is_required = option in required_options
            is_optional = option in optional_options
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

def main():
    """
    LDAP Proxy; synthesizes group membership from external database.
    """
    log.startLogging(sys.stderr)
    scp = load_config()
    validate_config(scp)
    if scp.has_option("Application", "port"):
        port = scp.getint("Application", "port")
    else:
        port = 10389
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
    def make_protocol():
        proto = SynthProxy(cfg, use_tls=use_tls)
        proto.debug = debug_app
        proto.bind_dn = None
        proto.membership_view_url = db_url
        proto.db_user = db_user
        proto.db_passwd = db_passwd
        proto.http_client = http
        proto.searchResponses = {}
        return proto
    factory.protocol = make_protocol
    factory.dbcache = {}
    factory.searchCache = SearchCache()
    endpoint = serverFromString(reactor, "tcp:port={0}".format(port))
    #endpoint = serverFromString(reactor, "ssl:port=10389:certKey=ssl/proxy.crt.pem:privateKey=ssl/proxy.key.pem")
    endpoint.listen(factory)
    reactor.run()

if __name__ == '__main__':
    main()

