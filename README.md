# ldap-signing-patches

These are just patched versions scripts that fail to be able to work with LDAP when signing is in place with NTLM/password auth. when LDAPS (port 636) is unavailable and the DC enforces `strongAuthRequired` on plain LDAP (port 389), many tools ended up breaking. 

gmsadump.py was a complete rewrite of the original gMSADump.py tool, by myself and @chin-tech. The re-write includes support for supporting LDAP signing over NTLM/Password auth by implemetning SASL, supporting specifying a GMSA object as opposed to extracting them all, supports using wildcards or specifying the gmsa name.

## Original Credits:

| Tool | Original Author | What It Does |
|---|---|---|
| `gmsadump.py` (gMSADumper) | micahvandeusen | Dumps gMSA managed passwords as NT hash + Kerberos keys |
| `dnstool.py` | dirkjanm (krbrelayx) | Reads and modifies AD-integrated DNS records via LDAP |
| `badsuccessor.py` | Fortra / Impacket | Abuses the badsucessor vulnrability released by Akamai |

## Root Cause

All three tools depend on **ldap3** for their LDAP transport layer. ldap3 implements NTLM authentication as a straightforward bind — it completes the three-way NTLM handshake (NEGOTIATE → CHALLENGE → AUTHENTICATE) but does not negotiate **SASL GSS-API Privacy** (Sign + Seal) as part of that handshake.

This matters because Windows DCs gate certain sensitive attribute reads behind channel confidentiality. With gMSADumper for example, When a client requests `msDS-ManagedPassword` or attempts writes over a connection the DC considers unencrypted, the DC responds with `strongAuthRequired` (LDAP error `00002028`) or silently omits the attribute from the result set entirely. The DC accepts two forms of confidentiality:

- **LDAPS** — TLS on port 636, or STARTTLS on port 389
- **NTLM with Sign + Seal** — NTLM session security where both parties derive a session key from the NTLM exchange and use it to encrypt all subsequent LDAP PDUs at the application layer

ldap3 supports neither out of the box. Its `authentication=NTLM` mode does a plain bind only. There is no `session_security` parameter or equivalent in the publicly available ldap3 API, despite what some documentation implies.

The contrast is visible in Wireshark. A tool using ldap3 shows a bare `NTLMSSP_NEGOTIATE` frame followed by `bindResponse: strongAuthRequired`. A tool using impacket's LDAP implementation shows `NTLMSSP_NEGOTIATEsasl` followed by `SASL GSS-API Privacy: payload` frames — the entire LDAP session is opaque on the wire after the handshake, identical to what bloodyAD produces.
As an example, running dnstool.py, we get the following ouput:
```bash
[-] Connecting to host...
[-] Binding to host
[!] Could not bind with specified credentials
[!] {'result': 49, 'description': 'invalidCredentials', 'dn': '', 'message': '8009030C: LdapErr: DSID-0C090924, comment: AcceptSecurityContext error, data 52e, v65f4\x00', 'referrals': None, 'saslCreds': None, 'type': 'bindResponse'}
```

## The Fix

Each tool was patched to replace its ldap3 connection with **impacket's `LDAPConnection`**, which negotiates NTLM Sign + Seal automatically during `login()` regardless of whether LDAPS is present.

The minimal change in each case was:

**Before (ldap3):**
```python
from ldap3 import Connection, Server, NTLM, ALL

server = Server(target, get_info=ALL)
conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM)
conn.open()
conn.bind()
conn.search(base_dn, search_filter, attributes=[...])
for entry in conn.entries:
    process(entry)
```

**After (impacket):**
```python
from impacket.ldap import ldap, ldapasn1

conn = ldap.LDAPConnection(f'ldap://{target}', base_dn, dc_ip)
conn.login(username, password, domain, lmhash, nthash)
conn.search(base_dn, searchFilter=search_filter, attributes=[...], perRecordCallback=process_entry)
```

`login()` internally sets the NTLM Negotiate flags `NTLMSSP_NEGOTIATE_SEAL` and `NTLMSSP_NEGOTIATE_SIGN`, which the DC honours as a confidential channel. All while theres mo LDAPS, STARTTLS, or additional configuration on the DCs side required.

One gotcha worth noting: impacket's `search()` method takes `scope` as its second **positional** argument. Passing the search filter string as the second positional argument causes pyasn1 to attempt coercing the filter string into an integer enum and throw a `PyAsn1Error`. The filter must always be passed as the `searchFilter=` keyword argument.


## Why ldap3 Is Still Widely Used
The Sign + Seal issue appears to be pretty commong. Projects like rusthound-ce, bloodhound-ce-python and others I have noticed also are not able to negoatiate when a DC asks for LDAP signing. I iamgine alot of dev enviroments dont have this issue until you hit a DC that enforces `strongAuthRequired` when it wants to.
