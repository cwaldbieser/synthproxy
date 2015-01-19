
# Standard library
import sys

# Application modules
from proxies.tcp_dispatcher import BalancerService

# External modules
from twisted.application import internet
from twisted.application.service import IServiceMaker
from twisted.plugin import getPlugins, IPlugin
from twisted.python import usage
from zope.interface import implements

class Options(usage.Options):
    optParameters = [
                        ["endpoint", "e", "tcp:10389", "The endpoint listen on (default 'tcp:10389')."],
                        ["hostport", "H", None, "Host and port separated by a colon.  "
                                                "May be specified multiple times."],
                    ]

    def __init__(self):
        usage.Options.__init__(self)
        self["hostport"] = []

    def opt_hostport(self, value):
        self["hostport"].append(value)

    def postOptions(self):
        if len(self["hostport"]) < 1:
            raise usage.UsageError("Must specify at least one `hostport`.")

class MyServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "balancer"
    description = "TCP Round-Robin Balancer"
    options = Options

    def makeService(self, options):
        """
        Construct a server from a factory defined in myproject.
        """
        endpoint_str = options['endpoint']
        temp = options['hostport']
        hostports = []
        for x in temp:
            parts = x.split(":", 1)
            hostports.append((parts[0], int(parts[1])))
        # Create the service.
        return BalancerService(endpoint_str, hostports)


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = MyServiceMaker()
