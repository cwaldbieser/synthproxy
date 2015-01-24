##################
LDAP Proxy Servers
##################

--------
Clusters
--------

Because Twisted is single threaded, it may be desirable to run multiple
bindproxy daemons on a multi-core/multi-processor host if it is determined
that the service is CPU bound during high load (i.e. if the CPU becomes
a bottleneck).  It is possible this may occur because LDAP requests and
responses are encoded/decoded using pure Python.

To take advantage of multiple cores/processors in a CPU-bound scenario,
multiple bindproxy services may be run and place behind a TCP load
balancer.  The services can be configured to communicate their cache
states amongst each other.

To run a cluster of proxy daemons, create one config file for each node.
This config file will inherit from the usual places (system, user, local
configs).  It should specify the endpoint for the LRU cluster service and
the endpoint for each peer.  For example (:file:`bindproxy-0.cfg`)::

    [Application]
    endpoint = tcp:10390

    [Cluster]
    endpoint = unix:address=/tmp/bindproxy/bp0.sock
    peer0 = unix:path=/tmp/bindproxy/bp1.sock

If your config files follow this naming convention, you can use the shell script
:program:`bpcluster.sh` to run :program:`twistd bindproxy` with the appropriate 
arguments for each node.  The :program:`synthcluster.sh` works identically for
the `synthproxy` subcommand.  When a node starts up, it will try to connect to its 
peers.  It will retry at intervals until the peer connections have been 
established.

When a node caches a result, it communicates the cached results to its peers.

The `twistd balancer` command may be used to create a simple TCP load balancer
in front of the cluster.

---------
BindProxy
---------

Records failed BIND attempts.  If the same invalid credentials are presented,
a failure response is returned, and the proxied LDAP service is *not* consulted.

The use case is to prevent account lockouts due to the *same* bad credentials
being repeatedly presented (e.g. by a misconfigured mail client).

The bindproxy has an optional web service that can be used to clear cached BIND
results for a DN.  The `[WebService]` section, `endpoint` option controls where
this service listens.  Authentication can be configured via the command line
by passing an :option:`--auth` option to :program:`twistd` or 
:program:`bpcluster.sh` or :program:`synthcluster.sh`.  The only valid web service
URL is:

  DELETE http://$HOST[:$PORT]/cache/$DN

Issuing a DELETE HTTP request to this URL removes the cached entry for the DN.
In a cluster, the removal is communicated to peers.

=====
Usage
=====

To run in the foreground::

    $ twistd -n bindproxy

To run as a daemon::

    $ twisted bindproxy

Additional options can be found by adding the :option:`--help` option.

----------
SynthProxy
----------

When search results are returned from the proxied LDAP service, an external CouchDB
database is consulted.  If a DN corresponding to a search result is found, the 
`memberOf` attributes from that external lookup are added to the result before it is
returned to the client.  This allows group memberships for an account to be maintained
in a separate database.

=====
Usage
=====

To run in the foreground::

    $ twistd -n synthproxy

To run as a daemon::

    $ twisted synthproxy

Additional options can be found by adding the :option:`--help` option.

