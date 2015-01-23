
# Standard library
import sys
# Application modules
from proxies.bindproxy import BindProxyService
from proxies.bindproxyws import IBindProxyWSUser, BindProxyWSRealm
# External modules
from twisted.application import internet
from twisted.application.service import IServiceMaker
from twisted.cred import credentials, portal, strcred
from twisted.internet import defer
from twisted.plugin import getPlugins, IPlugin
from twisted.python import usage
from zope.interface import implements

def noop():
    pass


class Options(usage.Options, strcred.AuthOptionMixin):
    supportedInterfaces = (credentials.IUsernamePassword,)

    optFlags = [
            ["xyzzy", "x", "Magic flag"],
        ]

    optParameters = [
                        ["endpoint", "e", None, "The endpoint listen on (default 'tcp:10389')."],
                        ["instance-config", "c", None, "Instance configuration overrides settings from other configs."],
                    ]

    def __init__(self):
        usage.Options.__init__(self)

class MyServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "bindproxy"
    description = "LDAP BIND proxy."
    options = Options

    def makeService(self, options):
        """
        Construct a server from a factory defined in myproject.
        """
        endpoint_str = options['endpoint']
        instance_config = options['instance-config']
        realm = BindProxyWSRealm()
        checkers = options.get("credCheckers", None)
        if checkers is not None:
            prtl = portal.Portal(realm, checkers)
        else:
            prtl = None
        # Create the service.
        return BindProxyService(endpoint=endpoint_str, instance_config=instance_config, portal=prtl)


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = MyServiceMaker()
