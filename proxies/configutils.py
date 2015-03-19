
import collections
import copy
from ldaptor.config import MissingBaseDNError
from ldaptor.interfaces import ILDAPConfig
from ldaptor.protocols.ldap import distinguishedname
from zope.interface import implements

class ServiceOverrideMultiLocations(collections.MutableMapping):
    """
    A special mapping of keys to lists of (host, port) tuples that
    cycles through (host, port) locations on each access.
    """

    def __init__(self, *args, **kwargs):
        self.store = dict(*args, **kwargs)

    def __getitem__(self, key):
        lst = self.store[key]
        nextItem = lst.pop(0)
        lst.append(nextItem)
        return nextItem

    def __setitem__(self, key, value):
        lst = self.store.setdefault(key, [])
        lst.append(value)

    def __delitem__(self, key):
        del self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    def has_key(self, key):
        return self.store.has_key(key)

class MultiLocationLDAPConfig(object):

    implements(ILDAPConfig)
    
    def __init__(self, baseDN=None, serviceLocationOverrides=None):
        if baseDN is not None:
            baseDN = distinguishedname.DistinguishedName(baseDN)
        else:
            baseDN = ''    
        self.baseDN = baseDN
        slo = {}
        if serviceLocationOverrides is not None:
            for k,v in serviceLocationOverrides.items():
                dn = distinguishedname.DistinguishedName(k)
                slo[dn] = v
        self.serviceLocationOverrides = ServiceOverrideMultiLocations(slo)

    def getBaseDN(self):
        """
        Get the LDAP base DN, as a DistinguishedName.

        Raises ldaptor.config.MissingBaseDNError
        if configuration does not specify a base DN.
        """
        return self.baseDN

    def getServiceLocationOverrides(self):
        """
        Get the LDAP service location overrides, as a mapping of
        DistinguishedName to (host, port) tuples.
        """
        return self.serviceLocationOverrides

    def copy(self,
             baseDN=None,
             serviceLocationOverrides=None):
        """
        Make a copy of this configuration, overriding certain aspects
        of it.
        """
        return MultiLocationLDAPConfig(
            baseDN=self.baseDN,
            serviceLocationOverrides=copy.deepcopy(self.serviceLocationOverrides))

    def getIdentityBaseDN(self):
        pass

    def getIdentitySearch(self, name):
        pass

