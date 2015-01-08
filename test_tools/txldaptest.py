#! /usr/bin/env python

from __future__ import print_function
import argparse
from twisted.internet import reactor, defer, task
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
def example(dn_file, stats, basedn, test_starttls, test_bind, test_search, unbind):
    with open(dn_file, "r") as f:
        dns = [line.strip() for line in f]
    serverip = '127.0.0.1'
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

def runTest(reactor_, args):
    stats = {
        'attempted': 0, 
        'successful': 0,
        'att_per_s': 0,
        'suc_per_s': 0}
    starttls = not args.no_starttls
    bind = not args.no_bind
    search = args.search
    unbind = not args.no_unbind
    df = example(args.dn_file, stats, args.base_dn, starttls, bind, search, unbind)
    df.addErrback(lambda err: err.printTraceback())
    def stopit(_):
        if reactor_.running:
            reactor_.stop()
    df.addCallback(stopit)
    lc = LoopingCall(report, stats=stats)
    lc.start(1)
    return df

def main(args):
    task.react(runTest, [args])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="LDAP test client.")
    parser.add_argument(
        'dn_file',
        action='store',
        help='Read DNs to query from file, one per line.')
    parser.add_argument(
        'base_dn',
        action='store',
        help="The base DN from which to search.")
    parser.add_argument(
        '-B',
        '--no-bind',
        action='store_true',
        help="Don't test BINDs.")
    parser.add_argument(
        '-T',
        '--no-starttls',
        action='store_true',
        help="Don't test startTLS.")
    parser.add_argument(
        '-s',
        '--search',
        action='store_true',
        help="Test searches.")
    parser.add_argument(
        '-U',
        '--no-unbind',
        action='store_true',
        help="Don't unbind after requests are completed-- let the connection hang.")
    args = parser.parse_args()
    main(args)

