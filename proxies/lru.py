
from __future__ import print_function
import collections
from cPickle import dumps, loads
from twisted.internet import reactor
from twisted.internet.endpoints import clientFromString, connectProtocol
from twisted.internet.protocol import Factory, Protocol, connectionDone
from twisted.protocols.basic import NetstringReceiver
from twisted.python import log

class LRUClusterProtocol(NetstringReceiver):
    def stringReceived(self, string):
        label, key, value = loads(string)
        cache_map = self.factory.cache_map
        cache = cache_map.get(label, None)
        if cache:
            if not cache.peek(key, value):
                cache.store(key, value, from_remote=True)

class LRUClusterProtocolFactory(Factory):
    protocol = LRUClusterProtocol

    def __init__(self, cache_map):
        self.cache_map = cache_map

class LRUClusterClientProtocol(NetstringReceiver):
    connectionLostCallback = None
    peer = None

    def __init__(self, failOK=False):
        self.failOK = failOK

    def sendMessage(self, label, key, value):
        msg = dumps((label, key, value))
        self.sendString(msg)
    
    def connectionLost(self, reason):
        self.connectionLostCallback(self.peer, reason, failOK=self.failOK)

class LRUClusterClient(object):
    retry_delay = 10

    def __init__(self, peers, reactor_=reactor):
        self.reactor = reactor_
        self.connections = {}
        self.reactor.callLater(self.retry_delay, self.startConnecting)
        self.peers = peers

    def startConnecting(self):
        peers = self.peers
        for peer in peers:
            self.connectToPeer(peer)

    def connectedToPeer(self, proto, peer):
        proto.connectionLostCallback = self.connectionLost
        proto.peer = peer
        self.connections[peer] = proto
        log.msg("[INFO] Successfully connected to peer: {0}.".format(peer))

    def connectionLost(self, peer, err, failOK=False):
        if not failOK and type(err.value) != type(connectionDone.value):
            log.msg("[WARNING] Connection to peer {0} was lost.\n{1}".format(peer, err))
            msg = "[INFO] Reconnecting to peer {0}".format(peer)
        else:
            log.msg("[INFO] Peer {0} has disconnected.".format(peer))
            msg = None
            failOK = True
        self.reactor.callLater(
            self.retry_delay, self.connectToPeer, peer, msg, failOK=failOK)

    def failedToConnectToPeer(self, err, peer, failOK=False):
        if not failOK:
            log.msg("[ERROR] Was unable to connect to peer {0}:\n{1}".format(peer, err))
        self.reactor.callLater(
            self.retry_delay, self.connectToPeer, peer, "[INFO] Reconnecting to peer {0}".format(peer), failOK=failOK)

    def connectToPeer(self, peer, msg=None, failOK=False):
        if msg is not None:
            log.msg(msg)
        d = connectProtocol(clientFromString(self.reactor, peer), LRUClusterClientProtocol(failOK=failOK)) 
        d.addCallback(self.connectedToPeer, peer)
        d.addErrback(self.failedToConnectToPeer, peer, failOK=failOK)

    def sendMessage(self, label, key, value):
        connections = self.connections
        for peer, proto in connections.iteritems():
            proto.sendMessage(label, key, value)

def make_cluster_func(label, peer_manager):
    def cluster_func(key, value):
        peer_manager.sendMessage(label, key, value)
    return cluster_func

class LRUTimedCache(object):
    """
    Least recently used cache.
    Entries are evicted if they are not referenced within a configurable
    span of time.
    """
    def __init__(self, capacity=2000, reactor_=reactor, lifetime=600, reset_on_access=False, cluster_func=None):
        self.cache = collections.OrderedDict()
        self.capacity = capacity
        self.evictors = {}
        self.reactor = reactor_
        self.lifetime = lifetime
        self.reset_on_access = reset_on_access
        self.cluster_func = cluster_func

    def peek(self, key, value):
        """
        Return True if the key-value pair exists in
        the cache.
        """
        if self.cache.get(key, None) == value:
            return True
        return False

    def get(self, key):
        cache = self.cache
        evictors = self.evictors
        try:
            value = cache.pop(key) 
        except KeyError:
            value = None
        if value is not None:
            cache[key] = value 
        if self.reset_on_access:
            evictor = evictors.get(key, None)
            if evictor is not None:
                evictor.cancel()
            evictor = self.reactor.callLater(self.lifetime, self._evict, key)
            evictors[key] = evictor
        return value

    def store(self, key, value, from_remote=False):
        cache = self.cache   
        try:
            cache.pop(key)
        except KeyError:
            pass
        cache[key] = value
        cluster_func = self.cluster_func
        evictors = self.evictors
        evictor = evictors.get(key, None)
        if evictor is not None:
            evictor.cancel()
        evictor = self.reactor.callLater(self.lifetime, self._evict, key)
        evictors[key] = evictor
        if len(cache) > self.capacity:
            evicted_key = cache.popitem(last=False)
            evictor = evictors.get(evicted_key, None)
            if evictor is not None:
                evictor.cancel()
                del evictors[evicted_key]
        if cluster_func is not None and not from_remote:
            cluster_func(key, value)

    def _evict(self, key):
        del self.evictors[key]
        cache = self.cache
        if key in cache:
            del cache[key]

    def __str__(self):
        return str(self.cache)
