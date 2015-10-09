##################
LDAP Proxy Servers
##################

* *bindproxy*: An LDAP proxy server that records the last **failed** BIND
  for a DN.  If the same invalid credential is provided, a failure response
  is returned to the client without consulting the proxied server.  This
  helps prevent accounts from getting locked out by a password policy when
  a misconfigured client (e.g. smart phone email client) rapidly presents
  the **same** wong credentials multiple times.
* *synthproxy*: An LDAP proxy server that examines search result DNs returned
  from the proxied server and merges attributes from an external CouchDB
  database into the result.  This allows multi-valued attributes like
  `memberOf` to be manipulated independently.

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
the endpoint for each peer.  For example (`bindproxy-0.cfg`)::

    [Application]
    endpoint = tcp:10390

    [Cluster]
    endpoint = unix:address=/tmp/bindproxy/bp0.sock
    peer0 = unix:path=/tmp/bindproxy/bp1.sock

If your config files follow this naming convention, you can use the shell script
:program:`bpcluster.sh` to run `twistd bindproxy` with the appropriate 
arguments for each node.  The `synthcluster.sh` works identically for
the `synthproxy` subcommand.  When a node starts up, it will try to connect to its 
peers.  It will retry at intervals until the peer connections have been 
established.

When a node caches a result, it communicates the cached results to its peers.

The `twistd balancer` command may be used to create a simple TCP load balancer
in front of the cluster.

---
TLS
---

The LDAP proxies can be configured to communicate with the proxied host(s) 
using TLS.  Set the `LDAP` -> `use_starttls` option to 1.

The Proxy itself can be conigured to respond to a request to initiate a StartTLS 
session with clients.  The `LDAP` -> `proxy_cert` option must be set to the path
of a file containing a PEM formatted certificate or certificate chain followed by
a corresponding PEM formatted private key.  If this option is present and the
client issues a StartTLS request, the proxy server will respond and establish
a TLS session.  If this option is not present, the proxy server will respond with
an error code indicating that StartTLS is not available.

----------------------
Multiple Proxied Hosts
----------------------
Multiple LDAP hosts can be proxied.  Provide a unique option under the `LDAP`
section for each service.  The option must start with 'proxied_url'.  E.g.
'proxied_url_1 = ldap://first.example.org:389' and 
'proxied_url_2 = ldap://second.example.org:389'.  The host will be queried in 
a round-robin fashion.

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
by passing an `--auth` option to `twistd` or 
`bpcluster.sh` or `synthcluster.sh`.  The only valid web service
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

Additional options can be found by adding the `--help` option.

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

Additional options can be found by adding the `--help` option.

=============
CouchDB Setup
=============

Your CouchDB database must be set up with a design document and a view that 
will emit a value which is a 2 element list-- the attribute name and an
attribute value.  Multi-values attributes may should emit multiple rows.

An example view is as follows:
.. code-block:: javascript

    {
       "attribs": {
           "map": "function(doc) {\n  var dn = doc[\"dn\"];\n  var attrib = doc[\"attrib\"];\n  var value = doc[\"value\"];\n  emit(dn, [attrib, value]);\n}"
       }
    }

An example document might look like this:
.. code-block:: javascript

    {
        "_id": "2788d56289351b834ae127701e002e09", 
        "_rev": "3-5e5212a443d68ee10b989b515fe6abed", 
        "attrib": "memberOf", 
        "dn": "uid=esteban,ou=people,dc=example,dc=fr", 
        "order": 0, 
        "value": "cn=warriors,ou=groups,dc=example,dc=fr"
    }

