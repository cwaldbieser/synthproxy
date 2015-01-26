
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
        client_ip = request.getClientIP()
        result = decode_basic_auth(request)
        if result is None:
            request.setResponseCode(UNAUTHORIZED)
            request.setHeader("WWW-Authenticate", 'Basic realm="BindProxyWS"')
            returnValue("""{"result": "not authorized"}""")
        user, passwd = result
        try:
            iface, avatar, logout = yield self.portal.login(UsernamePassword(*result), None, IBindProxyWSUser)
        except (error.UnauthorizedLogin, exceptions.NotImplementedError) as ex:
            log.msg((
                    "[ERROR] client_ip={client_ip}, login={login}: "
                    "Unauthorized login attempt to web service.\n{err}").format(
                client_ip=client_ip, login=user, err=str(ex)))
            request.setResponseCode(UNAUTHORIZED)
            returnValue("""{"result": "not authorized"}""")
        except Exception as ex:
            log.msg("[ERROR] {0}".format(str(ex)))
            request.setResponseCode(500)
            returnValue('''{"result": "error"}''')
        self.bindCache.store(dn, None)
        log.msg((
                "[INFO] client_ip={client_ip}, login={login}: "
                "Successfully removed cached entry for {dn}").format(
                    client_ip=client_ip, login=user, dn=dn))
        returnValue('''{"result": "ok"}''')

    @app.handle_errors(werkzeug.exceptions.NotFound)
    def error_handler_404(self, request, failure):
        log.msg("[ERROR] http_status=404, client_ip={client_ip}: {err}".format(
            client_ip=request.getClientIP(), err=str(failure)))
        request.setResponseCode(404)
        return '''{"result": "not found"}'''

    @app.handle_errors
    def error_handler_500(self, request, failure):
        request.setResponseCode(500)
        log.msg("[ERROR] http_status=500, client_ip={client_ip}: {err}".format(
            client_ip=request.getClientIP(), err=str(failure)))
        return '''{"result": "error"}'''
        
             
def make_ws(bindCache, portal):
    """
    Create and return the web service site.
    """
    ws = BindProxyWebService(bindCache, portal)
    root = ws.app.resource()
    site = Site(root)
    return site
