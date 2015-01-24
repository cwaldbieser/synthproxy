
from __future__ import print_function
import base64
import exceptions
import hashlib
import json
from klein import Klein
from twisted.cred import error
from twisted.cred.credentials import IUsernamePassword, UsernamePassword
from twisted.cred.portal import IRealm
from twisted.internet import defer
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python import log
from  twisted.web.http import BAD_REQUEST, UNAUTHORIZED
from twisted.web.server import Site
import werkzeug.exceptions
from zope.interface import Interface, Attribute, implements

def noop():
    pass

def decode_basic_auth(request):
    """
    Decodes basic auth info and returns (user, passwd) or None.
    """
    auth = request.getHeader("Authorization")
    if auth is None:
        return None
    if not auth.startswith("Basic "):
        return None
    encoded = auth[len("Basic "):]
    decoded = base64.decodestring(encoded)
    parts = decoded.split(":", 1)
    if len(parts) != 2:
        return None
    return tuple(parts)


class IBindProxyWSUser(Interface):
    username = Attribute('String username')


class BindProxyWSUser(object):
    implements(IBindProxyWSUser)
    username = None


class BindProxyWSRealm(object):
    implements(IRealm)

    def requestAvatar(avatarId, mind, *interfaces):
        if not IBindProxyWSUser in interfaces:
            log.msg(interfaces)
            log.msg(IBindProxyWSUser in interfaces)
            return defer.fail(NotImplementedError("This realm only implements IBindProxyWSUser."))
        else:
            avatar = BindProxyWSUser()
            avatar.username = avatarId
            return defer.succeed((IBindProxyWSUser, avatar, noop))


class BindProxyWebService(object):
    app = Klein()

    def __init__(self, bindCache, portal):
        self.bindCache = bindCache
        self.portal = portal

    @app.route('/cache/<string:dn>', methods=['DELETE'])
    @inlineCallbacks
    def cache_DELETE(self, request, dn):
        request.setHeader("Content-Type", "application/json")
        result = decode_basic_auth(request)
        if result is None:
            request.setResponseCode(UNAUTHORIZED)
            request.setHeader("WWW-Authenticate", 'Basic realm="BindProxyWS"')
            returnValue("""{"result": "not authorized"}""")
        try:
            iface, avatar, logout = yield self.portal.login(UsernamePassword(*result), None, IBindProxyWSUser)
        except (error.UnauthorizedLogin, exceptions.NotImplementedError) as ex:
            log.msg("[ERROR] Unauthorized login attempt to web service.\n{0}".format(str(ex)))
            request.setResponseCode(UNAUTHORIZED)
            returnValue("""{"result": "not authorized"}""")
        except Exception as ex:
            log.msg("[ERROR] {0}".format(str(ex)))
            request.setResponseCode(500)
            returnValue('''{"result": "error"}''')
        self.bindCache.store(dn, None)
        returnValue('''{"result": "ok"}''')

    @app.handle_errors(werkzeug.exceptions.NotFound)
    def error_handler(self, request, failure):
        log.msg("[ERROR] 404 => {0}".format(request.path))
        request.setResponseCode(404)
        return '''{"result": "not found"}'''
             
def make_ws(bindCache, portal):
    """
    Create and return the web service site.
    """
    ws = BindProxyWebService(bindCache, portal)
    root = ws.app.resource()
    site = Site(root)
    return site
