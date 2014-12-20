#! /usr/bin/env python

from __future__ import print_function

import collections
import copy
from ConfigParser import SafeConfigParser
import json
import os.path
import sys
from urlparse import urlparse

from ldaptor import config
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import proxybase, ldaperrors
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

class BindProxy(proxybase.ProxyBase):
    """
    LDAP Proxy notices failed BIND attempts that use the same failed
    password and responds with a failure immediately instead of passing
    the credentials on to the proxied service.
    """
    badPasswdLifetime = 600

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
            badpasswd = self._getLastFailedPasswd(dn)
            if badpasswd is not None:
                if badpasswd == request.auth:
                    log.msg("[INFO] Same bad credentials presented for DN '{0}'."
                            "  Not forwarding to proxied service.".format( request.dn))
                    response = pureldap.LDAPBindResponse(resultCode=49)
                    reply(response)
                    self._setLastFailedPasswd(dn, badpasswd)
                    return defer.succeed(None)
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

    def _getLastFailedPasswd(self, dn):
        """
        Get the last failed password for a DN.
        """
        last_fails = self.factory.last_fails
        t = last_fails.get(dn, None)
        if t is None:
            return None
        else:
            badpasswd, __ = t
            return badpasswd 

    def _setLastFailedPasswd(self, dn, badpasswd):
        """
        Record the last failed password for a DN and schedule an eviction from the cache.
        """
        last_fails = self.factory.last_fails
        if dn in last_fails:
            __, evictor = last_fails[dn]
            evictor.cancel()
        evictor = self.reactor.callLater(self.badPasswdLifetime, self._evictBadPasswd, dn)
        last_fails[dn] = (badpasswd, evictor)

    def _evictBadPasswd(self, dn):
        """
        Evict a failed password from the cache.
        """
        last_fails = self.factory.last_fails
        del last_fails[dn]
        if self.debug:
            log.msg("[DEBUG] Evicted failed password for DN '{0}'.".format(dn))

    def handleProxiedResponse(self, response, request, controls):
        """
        Append memberships/members to search results if those attributes
        were requested.
        """
        if isinstance(response, pureldap.LDAPBindResponse) and response.resultCode == 49:
            self._setLastFailedPasswd(request.dn, request.auth)
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
            searchCache.store(self.bind_dn, request, searchResponses.get(key))
            del searchResponses[key]
        return d

def load_config(filename="bindproxy.cfg"):
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
        'LDAP': frozenset(['proxied_url',]),
        } 
    optional = {
        'Application': frozenset(['debug', 'endpoint']),
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
    LDAP Proxy
    """
    log.startLogging(sys.stderr)
    scp = load_config()
    validate_config(scp)
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
    debug_app = scp.getboolean('Application', 'debug')
    def make_protocol():
        proto = BindProxy(cfg, use_tls=use_tls)
        proto.debug = debug_app
        proto.bind_dn = None
        proto.searchResponses = {}
        return proto
    factory.protocol = make_protocol
    factory.last_fails = {}
    factory.searchCache = SearchCache()
    endpoint = serverFromString(reactor, endpoint)
    endpoint.listen(factory)
    reactor.run()

if __name__ == '__main__':
    main()

