#!/usr/bin/env python
####################
#
# Copyright (c) 2023 Dirk-jan Mollema (@_dirkjan)
# Modified to use impacket.ldap for GSSAPI signing support when using NTLM/password auth.
#
####################
import sys
import argparse
import os
import getpass

from impacket.ldap import ldap, ldapasn1

def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))

def main():
    parser = argparse.ArgumentParser(description='Add an SPN to a user/computer account')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    parser.add_argument("host", metavar='HOSTNAME', help="Hostname/ip to connect to")
    parser.add_argument("-u", "--user", metavar='USERNAME', help="DOMAIN\\username for authentication")
    parser.add_argument("-p", "--password", metavar='PASSWORD', help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("-t", "--target", metavar='TARGET', help="Computername or username to target (FQDN or COMPUTER$ name, if unspecified user with -u is target)")
    parser.add_argument("-T", "--target-type", metavar='TARGETTYPE', choices=('samname','hostname','auto'), default='auto', help="Target type (samname or hostname) If unspecified, will assume it's a hostname if there is a . in the name and a SAM name otherwise.")
    parser.add_argument("-s", "--spn", metavar='SPN', help="servicePrincipalName to add (for example: http/host.domain.local or cifs/host.domain.local)")
    parser.add_argument("-r", "--remove", action='store_true', help="Remove the SPN instead of add it")
    parser.add_argument("-c", "--clear", action='store_true', help="Clear, i.e. remove all SPNs")
    parser.add_argument("-q", "--query", action='store_true', help="Show the current target SPNs instead of modifying anything")
    parser.add_argument("-a", "--additional", action='store_true', help="Add the SPN via the msDS-AdditionalDnsHostName attribute")
    parser.add_argument('-k', '--kerberos', action="store_true", help='Use Kerberos authentication.')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller.')
    parser.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
   
    args = parser.parse_args()

    if not args.query and not args.clear:
        if not args.spn:
            parser.error("-s/--spn is required when not querying (-q/--query) or clearing (--clear)")

    if not args.user or not '\\' in args.user:
        print_f('Username must include a domain, use: DOMAIN\\username')
        sys.exit(1)
        
    domain, user = args.user.split('\\', 1)

    if args.password is None and not (args.kerberos and 'KRB5CCNAME' in os.environ):
        args.password = getpass.getpass()

    try:
        lmhash, nthash = args.password.split(':')
        assert len(nthash) == 32
        password = ''
    except:
        lmhash = ''
        nthash = ''
        password = args.password if args.password else ''

    kdcHost = args.dc_ip if args.dc_ip else domain

    print_m('Connecting to host...')
    try:
        ldap_url = f"ldap://{args.host}"
        c = ldap.LDAPConnection(ldap_url, baseDN='')
        
        print_m('Binding to host')
        if args.kerberos:
            c.kerberosLogin(user, password, domain, lmhash, nthash, args.aesKey, kdcHost=kdcHost)
        else:
            c.login(user, password, domain, lmhash, nthash)
            
        print_o('Bind OK')
    except ldap.LDAPSessionError as e:
        print_f('Could not bind with specified credentials')
        print_f(str(e))
        sys.exit(1)

    if args.target:
        targetuser = args.target
    else:
        targetuser = user

    if ('.' in targetuser and args.target_type != 'samname') or args.target_type == 'hostname':
        if args.target_type == 'auto':
            print_m('Assuming target is a hostname. If this is incorrect use --target-type samname')
        search = '(dnsHostName=%s)' % targetuser
    else:
        search = '(sAMAccountName=%s)' % targetuser

    try:
        # Construct DN directly from the domain name
        baseDN = ','.join(['DC=' + x for x in domain.split('.')])
        
        # Perform the actual user/computer search using the constructed baseDN
        resp = c.search(searchBase=baseDN, 
                        searchFilter=search, 
                        attributes=['sAMAccountName', 'servicePrincipalName', 'dnsHostName', 'msds-additionaldnshostname'])
        
        targetobject = None
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry):
                targetobject = item
                break
                
        if not targetobject:
            print_f('Target not found!')
            return
            
        print_o('Found modification target')
    except Exception as e:
        print_f('Search failed: %s' % str(e))
        return

    dn = str(targetobject['objectName'])

    def print_target_attributes(entry):
        print(f"DN: {dn}")
        for attr in entry['attributes']:
            attr_type = str(attr['type'])
            attr_vals = [str(val) for val in attr['vals']]
            print(f"  {attr_type}: {attr_vals}")

    if args.query:
        print_target_attributes(targetobject)
        return

    if args.remove:
        operation = 1 # MODIFY_DELETE
    elif args.clear:
        operation = 2 # MODIFY_REPLACE
    else:
        operation = 0 # MODIFY_ADD

    if not args.additional:
        attr_name = 'servicePrincipalName'
        values = [args.spn] if not args.clear else []
    else:
        attr_name = 'msDS-AdditionalDnsHostName'
        try:
            host = args.spn.split('/')[1]
        except IndexError:
            host = args.spn
        values = [host] if not args.clear else []

    if args.clear:
        print_o('Printing object before clearing')
        print_target_attrs(targetobject)

    modifyRequest = ldapasn1.ModifyRequest()
    modifyRequest['object'] = dn
    
    mod = ldapasn1.Modification()
    mod['operation'] = operation
    mod['modification'] = ldapasn1.AttributeTypeAndValues()
    mod['modification']['type'] = attr_name
    
    if len(values) > 0:
        for i, val in enumerate(values):
            mod['modification']['vals'].setComponentByPosition(i, val.encode('utf-8'))
            
    modifyRequest['modification'] = None
    modifyRequest['modification'].setComponentByPosition(0, mod)

    try:
        c.sendReceive(modifyRequest)
        print_o('SPN Modified successfully')
    except ldap.LDAPSessionError as e:
        error_code = e.errorCode
        error_msg = str(e)
        if error_code == 50:
            print_f('Could not modify object, the server reports insufficient rights: %s' % error_msg)
        elif error_code == 19:
            print_f('Could not modify object, the server reports a constrained violation')
            if args.additional:
                print_f('You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs ending on the domain FQDN)')
            else:
                print_f('You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs matching the hostname)')
                print_f('To add any SPN in the current domain, use --additional to add the SPN via the msDS-AdditionalDnsHostName attribute')
        else:
            print_f('The server returned an error: [%s] %s' % (error_code, error_msg))

if __name__ == '__main__':
    main()
