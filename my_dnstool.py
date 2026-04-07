#!/usr/bin/env python
####################
#
# Copyright (c) 2019 Dirk-jan Mollema (@_dirkjan)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Tool to interact with ADIDNS over LDAP
#
# Minimal transport change: swap ldap3 session/bind usage for Impacket's
# LDAPConnection so SASL/GSS-SPNEGO signing/sealing works on DCs that require it.
#
####################
import sys
import argparse
import getpass
import re
import os
import socket
from urllib.parse import urlparse
from struct import unpack

from impacket.structure import Structure
from impacket.krb5.ccache import CCache
import ldap3
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from impacket.ldap import ldap, ldaptypes, ldapasn1
import dns.resolver
import datetime

##Testing out constants and if we can safely remove the ldap3 import
MODIFY_ADD = 0
MODIFY_DELETE = 1
MODIFY_REPLACE = 2

def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))


def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))


def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))


class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )


# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.

class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """
    structure = (
        ('cchNameLength', 'B-dnsName'),
        ('dnsName', ':')
    )


class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """
    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':')
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for _ in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind + 1])[0]
            labels.append(self['RawName'][ind + 1:ind + 1 + nextlen].decode('utf-8'))
            ind += nextlen + 1
        labels.append('')
        return '.'.join(labels)


class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    [MS-DNSP] section 2.2.2.2.3
    """
    structure = (
        ('wLength', '>H'),
        ('wRecordCount', '>H'),
        ('dwFlags', '>L'),
        ('dwChildCount', '>L'),
        ('dnsNodeName', ':')
    )


class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """
    structure = (
        ('nameNode', ':', DNS_COUNT_NAME),
    )


class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    [MS-DNSP] section 2.2.2.2.4.3
    """
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME)
    )


class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL
    [MS-DNSP] section 2.2.2.2.4.4
    """
    structure = (
        ('bData', ':'),
    )


class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE
    [MS-DNSP] section 2.2.2.2.4.8
    """
    structure = (
        ('wPreference', '>H'),
        ('nameExchange', ':', DNS_COUNT_NAME)
    )


class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    """
    structure = (
        ('ipv6Address', '16s'),
    )


class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME)
    )


class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )

    def toDatetime(self):
        microseconds = self['entombedTime'] / 10.
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=microseconds)


RECORD_TYPE_MAPPING = {
    0: 'ZERO',
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    33: 'SRV',
    65281: 'WINS'
}


def _entry_values(entry, attr, raw=False):
    values = []
    for attribute in entry['attributes']:
        if str(attribute['type']) != attr:
            continue
        for value in attribute['vals']:
            if raw:
                if hasattr(value, 'asOctets'):
                    values.append(value.asOctets())
                else:
                    values.append(bytes(value))
            else:
                if hasattr(value, 'asOctets'):
                    data = value.asOctets()
                    try:
                        values.append(data.decode('utf-8'))
                    except Exception:
                        values.append(data)
                else:
                    values.append(str(value))
    return values


def _entry_value(entry, attr, default=None, raw=False):
    values = _entry_values(entry, attr, raw=raw)
    if values:
        return values[0]
    return default


def _entry_dn(entry):
    return str(entry['objectName'])


def _entry_bool(entry, attr, default=False):
    value = _entry_value(entry, attr, None)
    if value is None:
        return default
    return str(value).lower() in ('true', '1')


def _rootdse_attr(connection, attr):
    results = connection.search(
        searchBase='',
        scope=ldapasn1.Scope('baseObject'),
        searchFilter='(objectClass=*)',
        attributes=[attr],
    )
    for entry in results:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            value = _entry_value(entry, attr)
            if value is not None:
                return value
    raise RuntimeError('Could not read %s from RootDSE' % attr)


def get_dns_zones(connection, root, attr="dc"):
    results = connection.search(
        searchBase=root,
        scope=ldapasn1.Scope('singleLevel'),
        searchFilter='(objectClass=dnsZone)',
        attributes=[attr],
    )
    zones = []
    for entry in results:
        if not isinstance(entry, ldapasn1.SearchResultEntry):
            continue
        zones.extend(_entry_values(entry, attr))
    return zones


def get_next_serial(dnsserver, dc, zone, tcp):
    dnsresolver = dns.resolver.Resolver()
    if dnsserver:
        server = dnsserver
    else:
        server = dc

    try:
        socket.inet_aton(server)
        dnsresolver.nameservers = [server]
    except socket.error:
        pass

    res = dnsresolver.resolve(zone, 'SOA', tcp=tcp)
    for answer in res:
        return answer.serial + 1


def ldap2domain(ldapdn):
    return re.sub(',DC=', '.', ldapdn[ldapdn.find('DC='):], flags=re.I)[3:]


def print_record(record, ts=False):
    try:
        rtype = RECORD_TYPE_MAPPING[record['Type']]
    except KeyError:
        rtype = 'Unsupported'
    if ts:
        print('Record is tombStoned (inactive)')
    print_o('Record entry:')
    print(' - Type: %d (%s) (Serial: %d)' % (record['Type'], rtype, record['Serial']))
    if record['Type'] == 0:
        tstime = DNS_RPC_RECORD_TS(record['Data'])
        print(' - Tombstoned at: %s' % tstime.toDatetime())
    if record['Type'] == 1:
        address = DNS_RPC_RECORD_A(record['Data'])
        print(' - Address: %s' % address.formatCanonical())
    if record['Type'] == 2 or record['Type'] == 5:
        address = DNS_RPC_RECORD_NODE_NAME(record['Data'])
        print(' - Address: %s' % address['nameNode'].toFqdn())
    if record['Type'] == 33:
        record_data = DNS_RPC_RECORD_SRV(record['Data'])
        print(' - Priority: %d' % record_data['wPriority'])
        print(' - Weight: %d' % record_data['wWeight'])
        print(' - Port: %d' % record_data['wPort'])
        print(' - Name: %s' % record_data['nameTarget'].toFqdn())
    if record['Type'] == 6:
        record_data = DNS_RPC_RECORD_SOA(record['Data'])
        print(' - Serial: %d' % record_data['dwSerialNo'])
        print(' - Refresh: %d' % record_data['dwRefresh'])
        print(' - Retry: %d' % record_data['dwRetry'])
        print(' - Expire: %d' % record_data['dwExpire'])
        print(' - Minimum TTL: %d' % record_data['dwMinimumTtl'])
        print(' - Primary server: %s' % record_data['namePrimaryServer'].toFqdn())
        print(' - Zone admin email: %s' % record_data['zoneAdminEmail'].toFqdn())


def new_record(rtype, serial, ttl=180):
    nr = DNS_RECORD()
    nr['Type'] = rtype
    nr['Serial'] = serial
    nr['TtlSeconds'] = ttl
    nr['Rank'] = 240
    return nr


def ldap_operation(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
        print_o('LDAP operation completed successfully')
        return True
    except Exception as e:
        print_f('LDAP operation failed. Message returned from server: %s' % e)
        return False





def parse_target(host_arg, force_ssl, port):
    if host_arg.lower().startswith(('ldap://', 'ldaps://')):
        parsed = urlparse(host_arg)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        final_port = parsed.port or (636 if scheme == 'ldaps' else 389)
    else:
        scheme = 'ldaps' if force_ssl else 'ldap'
        host = host_arg
        final_port = port

    if host is None:
        raise ValueError('Invalid host/LDAP URL specified')

    url = '%s://%s:%d' % (scheme, host, final_port)
    return scheme, host, final_port, url


def main():

    parser = argparse.ArgumentParser(description='Query/modify DNS records for Active Directory integrated DNS via LDAP')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    parser.add_argument("host", type=str, metavar='HOSTNAME', help="Hostname/ip or ldap://host:port connection string to connect to")
    parser.add_argument("-u", "--user", type=str, metavar='USERNAME', help="DOMAIN\\username for authentication.")
    parser.add_argument("-p", "--password", type=str, metavar='PASSWORD', help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("--forest", action='store_true', help="Search the ForestDnsZones instead of DomainDnsZones")
    parser.add_argument("--legacy", action='store_true', help="Search the System partition (legacy DNS storage)")
    parser.add_argument("--zone", help="Zone to search in (if different than the current domain)")
    parser.add_argument("--print-zones", action='store_true', help="Only query all zones on the DNS server, no other modifications are made")
    parser.add_argument("--print-zones-dn", action='store_true', help="Query and print the Distinguished Names of all zones on the DNS server")
    parser.add_argument("--tcp", action='store_true', help="use DNS over TCP")
    parser.add_argument('-k', '--kerberos', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    parser.add_argument('-port', default=389, metavar="port", type=int, help='LDAP port, default value is 389')
    parser.add_argument('-force-ssl', action='store_true', default=False, help='Force SSL when connecting to LDAP server')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-dns-ip', action="store", metavar="ip address", help='IP Address of a DNS Server')
    parser.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    recordopts = parser.add_argument_group("Record options")
    recordopts.add_argument("-r", "--record", type=str, metavar='TARGETRECORD', help="Record to target (FQDN)")
    recordopts.add_argument("-a",
                        "--action",
                        choices=['add', 'modify', 'query', 'remove', 'resurrect', 'ldapdelete'],
                        default='query',
                        help="Action to perform. Options: add (add a new record), modify ("
                             "modify an existing record), query (show existing), remove (mark record "
                             "for cleanup from DNS cache), delete (delete from LDAP). Default: query"
                        )
    recordopts.add_argument("-t", "--type", choices=['A'], default='A', help="Record type to add (Currently only A records supported)")
    recordopts.add_argument("-d", "--data", metavar='RECORDDATA', help="Record data (IP address)")
    recordopts.add_argument("--allow-multiple", action='store_true', help="Allow multiple A records for the same name")
    recordopts.add_argument("--ttl", type=int, default=180, help="TTL for record (default: 180)")

    args = parser.parse_args()

    if not args.user or '\\' not in args.user:
        print_f('Username must include a domain, use: DOMAIN\\username')
        sys.exit(1)

    try:
        _scheme, target_host, target_port, ldap_url = parse_target(args.host, args.force_ssl, args.port)
    except Exception as e:
        print_f(str(e))
        sys.exit(1)

    domain, user = args.user.split('\\', 1)

    if args.password is None and not (args.kerberos and 'KRB5CCNAME' in os.environ):
        args.password = getpass.getpass()

    try:
        lmhash, nthash = args.password.split(':')
        assert len(nthash) == 32
        password = ''
    except Exception:
        lmhash = ''
        nthash = ''
        password = args.password if args.password else ''

    kdcHost = args.dc_ip if args.dc_ip else domain

    print_m('Connecting to host...')
    print_m('Binding to host')
    try:
        c = ldap.LDAPConnection(ldap_url, '', args.dc_ip)
        if args.kerberos:
            c.kerberosLogin(user, password, domain, lmhash, nthash, args.aesKey, kdcHost=kdcHost)
        else:
            c.login(user, password, domain, lmhash, nthash, authenticationChoice='sasl')
    except Exception as e:
        print_f('Could not bind with specified credentials')
        print_f(str(e))
        sys.exit(1)

    print_o('Bind OK')

    try:
        domainroot = _rootdse_attr(c, 'defaultNamingContext')
        forestroot = _rootdse_attr(c, 'rootDomainNamingContext')
        schemaroot = _rootdse_attr(c, 'schemaNamingContext')
    except Exception as e:
        print_f('Failed to query RootDSE: %s' % e)
        sys.exit(1)

    if args.forest:
        dnsroot = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % forestroot
    else:
        if args.legacy:
            dnsroot = 'CN=MicrosoftDNS,CN=System,%s' % domainroot
        else:
            dnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % domainroot

    if args.print_zones or args.print_zones_dn:
        attr = 'distinguishedName' if args.print_zones_dn else 'dc'
        zones = get_dns_zones(c, dnsroot, attr)
        if len(zones) > 0:
            print_m('Found %d domain DNS zones:' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        forestdns = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % forestroot
        zones = get_dns_zones(c, forestdns, attr)
        if len(zones) > 0:
            print_m('Found %d forest DNS zones:' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        return

    target = args.record
    if args.zone:
        zone = args.zone
    else:
        zone = ldap2domain(domainroot)

    if not target:
        print_f('You need to specify a target record')
        return

    if target.lower().endswith(zone.lower()):
        target = target[:-(len(zone) + 1)]

    searchtarget = 'DC=%s,%s' % (zone, dnsroot)
    try:
        results = c.search(
            searchBase=searchtarget,
            searchFilter='(&(objectClass=dnsNode)(name=%s))' % ldap3.utils.conv.escape_filter_chars(target),
            attributes=['dnsRecord', 'dNSTombstoned', 'name']
        )
    except Exception as e:
        print_f('LDAP search failed: %s' % e)
        return

    targetentry = None
    for entry in results:
        if not isinstance(entry, ldapasn1.SearchResultEntry):
            continue
        targetentry = entry
        break
    
    # It seems that adding the -dns-ip at times is neccesary since the script cant seem to find the "dns server" otherwise.
    # Instead its easier for us to Use -dns-ip if the executor provided, otherwise fallback to -dc-ip, 
    # otherwise fallback to the host/IP used for LDAP.
    dns_target_to_use = args.dns_ip if args.dns_ip else (args.dc_ip if args.dc_ip else target_host)

    if args.action in ['add', 'modify', 'remove'] and not args.data:
        print_f('This operation requires you to specify record data with --data')
        return

    if args.action in ['modify', 'remove', 'ldapdelete', 'resurrect', 'query'] and not targetentry:
        print_f('Target record not found!')
        return

    if args.action == 'query':
        print_o('Found record %s' % _entry_value(targetentry, 'name'))
        for record in _entry_values(targetentry, 'dnsRecord', raw=True):
            dr = DNS_RECORD(record)
            print(_entry_dn(targetentry))
            print_record(dr, _entry_bool(targetentry, 'dNSTombstoned'))

    elif args.action == 'add':
        addtype = 1
        if targetentry:
            if not args.allow_multiple:
                for record in _entry_values(targetentry, 'dnsRecord', raw=True):
                    dr = DNS_RECORD(record)
                    if dr['Type'] == 1:
                        address = DNS_RPC_RECORD_A(dr['Data'])
                        print_f('Record already exists and points to %s. Use --action modify to overwrite or --allow-multiple to override this' % address.formatCanonical())
                        return False

            record = new_record(addtype, get_next_serial(dns_target_to_use, target_host, zone, args.tcp), args.ttl)
            record['Data'] = DNS_RPC_RECORD_A()
            record['Data'].fromCanonical(args.data)
            print_m('Adding extra record')
            ldap_operation(c.modify, _entry_dn(targetentry), {'dnsRecord': [(MODIFY_ADD, record.getData())]})
        else:
            node_data = {
                'objectCategory': 'CN=Dns-Node,%s' % schemaroot,
                'dNSTombstoned': 'FALSE',
                'name': target,
            }
            record = new_record(addtype, get_next_serial(dns_target_to_use, target_host, zone, args.tcp), args.ttl)
            record['Data'] = DNS_RPC_RECORD_A()
            record['Data'].fromCanonical(args.data)
            record_dn = 'DC=%s,%s' % (target, searchtarget)
            node_data['dnsRecord'] = [record.getData()]
            print_m('Adding new record')
            ldap_operation(c.add, record_dn, ['top', 'dnsNode'], node_data)

    elif args.action == 'modify':
        addtype = 1
        targetrecord = None
        records = []
        for record in _entry_values(targetentry, 'dnsRecord', raw=True):
            dr = DNS_RECORD(record)
            if dr['Type'] == 1:
                targetrecord = dr
            else:
                records.append(record)

        if not targetrecord:
            print_f('No A record exists yet. Use --action add to add it')
            return

        targetrecord['Serial'] = get_next_serial(dns_target_to_use, target_host, zone, args.tcp)
        targetrecord['TtlSeconds'] = args.ttl
        targetrecord['Data'] = DNS_RPC_RECORD_A()
        targetrecord['Data'].fromCanonical(args.data)
        records.append(targetrecord.getData())
        print_m('Modifying record')
        ldap_operation(c.modify, _entry_dn(targetentry), {'dnsRecord': [(MODIFY_REPLACE, records)]})

    elif args.action == 'remove':
        addtype = 0
        raw_records = _entry_values(targetentry, 'dnsRecord', raw=True)
        if len(raw_records) > 1:
            print_m('Target has multiple records, removing the one specified')
            targetrecord = None
            for record in raw_records:
                dr = DNS_RECORD(record)
                if dr['Type'] == 1:
                    tr = DNS_RPC_RECORD_A(dr['Data'])
                    if tr.formatCanonical() == args.data:
                        targetrecord = record
            if not targetrecord:
                print_f('Could not find a record with the specified data')
                return
            ldap_operation(c.modify, _entry_dn(targetentry), {'dnsRecord': [(MODIFY_DELETE, targetrecord)]})
        else:
            print_m('Target has only one record, tombstoning it')
            diff = datetime.datetime.today() - datetime.datetime(1601, 1, 1)
            tstime = int(diff.total_seconds() * 10000)
            record = new_record(addtype, get_next_serial(dns_target_to_use, target_host, zone, args.tcp), args.ttl)
            record['Data'] = DNS_RPC_RECORD_TS()
            record['Data']['entombedTime'] = tstime
            ldap_operation(
                c.modify,
                _entry_dn(targetentry),
                {
                    'dnsRecord': [(MODIFY_REPLACE, [record.getData()])],
                    'dNSTombstoned': [(MODIFY_REPLACE, 'TRUE')],
                }
            )

    elif args.action == 'ldapdelete':
        print_m('Deleting record over LDAP')
        ldap_operation(c.delete, _entry_dn(targetentry))

    elif args.action == 'resurrect':
        addtype = 0
        if len(_entry_values(targetentry, 'dnsRecord', raw=True)) > 1:
            print_m('Target has multiple records, I dont know how to handle this.')
            return
        else:
            print_m('Target has only one record, resurrecting it')
            diff = datetime.datetime.today() - datetime.datetime(1601, 1, 1)
            tstime = int(diff.total_seconds() * 10000)
            record = new_record(addtype, get_next_serial(dns_target_to_use, target_host, zone, args.tcp), args.ttl)
            record['Data'] = DNS_RPC_RECORD_TS()
            record['Data']['entombedTime'] = tstime
            if ldap_operation(
                c.modify,
                _entry_dn(targetentry),
                {
                    'dnsRecord': [(MODIFY_REPLACE, [record.getData()])],
                    'dNSTombstoned': [(MODIFY_REPLACE, 'FALSE')],
                }
            ):
                print_o('Record resurrected. You will need to (re)add the record with the IP address.')


if __name__ == '__main__':
    main()
