#! /usr/bin/env python

from __future__ import print_function
from twisted.internet import reactor, defer
from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector
from ldaptor.protocols.ldap.ldaperrors import LDAPInvalidCredentials
from twisted.internet.task import LoopingCall

def report(stats):
    """
    """
    print("Total Attempts: {attempted}".format(**stats))
    print("Total Successful: {successful}".format(**stats))
    print("Attempts second: {att_per_s}".format(**stats))
    print("Successful this second: {suc_per_s}".format(**stats))
    stats['att_per_s'] = 0
    stats['suc_per_s'] = 0
    print("")

@defer.inlineCallbacks
def example(stats):
    test_starttls = True
    test_bind = True
    test_search = False
    unbind = True
    with open("dn_list.txt", "r") as f:
        dns = [line.strip() for line in f]
        
    serverip = '127.0.0.1'
    basedn = 'o=lafayette'
    bindpw = 'secret'
    for n, binddn in enumerate(dns):
        c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        overrides = {basedn: (serverip, 10389)}
        client = yield c.connect(basedn, overrides=overrides)
        stats['attempted'] += 1
        stats['att_per_s'] += 1
        if test_starttls:
            client = yield client.startTLS()
        if test_bind:
            try:
                yield client.bind(binddn, bindpw)
            except LDAPInvalidCredentials:
                pass
        if test_search:
            o = ldapsyntax.LDAPEntry(client, basedn)
            results = yield o.search(filterText="(uid=xyzzy)", attributes=['uid'])
        if unbind:
            client.unbind()
        stats['successful'] += 1
        stats['suc_per_s'] += 1

if __name__ == '__main__':
    stats = {
        'attempted': 0, 
        'successful': 0,
        'att_per_s': 0,
        'suc_per_s': 0}
    df = example(stats)
    df.addErrback(lambda err: err.printTraceback())
    def stopit(_):
        if reactor.running:
            reactor.stop()
    df.addCallback(stopit)
    lc = LoopingCall(report, stats=stats)
    lc.start(1)
    reactor.run()
