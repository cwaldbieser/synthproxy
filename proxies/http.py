
# Standard library
from __future__ import print_function
# Application modules
from ca_trust import CustomPolicyForHTTPS
# External modules
from OpenSSL import crypto
from treq.client import HTTPClient
from twisted.internet.ssl import ClientContextFactory
from twisted.web.client import (
    Agent, BrowserLikePolicyForHTTPS)


class NonVerifyingContextFactory(ClientContextFactory):
    """
    Context factory does *not* verify SSL cert.
    """
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)

def normalizeDict_(d):
    if d is None:
        d = {}
    else:
        d = dict(d)
    return d

def createNonVerifyingHTTPClient(reactor, agent_kwds=None, **kwds):
    agent_kwds = normalizeDict_(agent_kwds)
    agent_kwds['contextFactory'] = NonVerifyingContextFactory()
    return HTTPClient(Agent(reactor, **agent_kwds), **kwds)

def createVerifyingHTTPClient(reactor, extra_ca_certs=None, agent_kwds=None, **kwds):
    """
    extra_ca_certs: Should be a list of PEM formatted certificates that are trust anchors.
    """
    agent_kwds = normalizeDict_(agent_kwds)
    if extra_ca_certs is not None:
        trust_anchors = []
        for ca_cert in extra_ca_certs:
            with open(ca_cert, "rb") as f:
                data = f.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
            del data
            trust_anchors.append(cert)
        policy = CustomPolicyForHTTPS(extra_ca_certs)
    else:
        policy = BrowserLikePolicyForHTTPS()
    agent_kwds['contextFactory'] = policy
    return HTTPClient(Agent(reactor, **agent_kwds), **kwds)
