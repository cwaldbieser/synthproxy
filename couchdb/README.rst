#############
CouchDB Setup
#############

Installation and configuration of the CouchDB database server is detailed at:

  http://docs.couchdb.org/en/stable/

To use CouchDB with synthproxy, you need to create the design document stored
in :file:`ddoc.json`.  The design document has a single view, `attrib_view`
that maps DNs to attribute-value pairs.  It also performs reverse mapping
for groupOfNames.

Documents in the CouchDB database are assumed to look like::

    {
        "_id": "059300d482675550cf71a064330035bb",
        "dn": "cn=pumpkin,ou=people,dc=example,dc=org",
        "attrib": "memberOf",
        "order": 0,
        "value": "cn=xyzzy,ou=groups,dc=example,dc=org"
    }

For multi-valued attributes, multiple documents should exist with the same `dn` 
and `attrib`.  The `order` attribute is optional.  If it is present, 
multi-valued attributes will be sorted by this field.  The `member` attributes
for computed `groupOfNames` are sorted by the values of the attributes.

