#!/usr/bin/env python3
"""DCOMatMEbro — DCOM privilege escalation scanner via WMI"""

import argparse
import json
import logging
import re
import sys
import time
from datetime import datetime

from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import (
    CLSID_WbemLevel1Login,
    IID_IWbemLevel1Login,
    IWbemLevel1Login,
)
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples.utils import parse_target

logger = logging.getLogger('DCOMatMEbro')

HKLM = 0x80000002
HKU  = 0x80000003

FINDING_CRITICAL = 'CRITICAL'
FINDING_HIGH     = 'HIGH'
FINDING_MEDIUM   = 'MEDIUM'
FINDING_LOW      = 'LOW'
FINDING_INFO     = 'INFO'

COLORS = {
    FINDING_CRITICAL: '\033[91m',
    FINDING_HIGH:     '\033[91m',
    FINDING_MEDIUM:   '\033[93m',
    FINDING_LOW:      '\033[94m',
    FINDING_INFO:     '\033[90m',
}
RESET = '\033[0m'
BOLD = '\033[1m'

ANSI_RE = re.compile(r'\033\[[0-9;]*m')


class WMIConnection:
    """Manages DCOM connection and WMI service interface."""

    def __init__(self, address, username, password, domain,
                 lmhash='', nthash='', do_kerberos=False, kdc_host=None):
        self.address = address
        self.dcom = DCOMConnection(
            address, username, password, domain, lmhash, nthash,
            oxidResolver=True, doKerberos=do_kerberos, kdcHost=kdc_host)

        iI = self.dcom.CoCreateInstanceEx(
            CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
        iLogin = IWbemLevel1Login(iI)
        self.wmi = iLogin.NTLMLogin('//./root/cimv2', NULL, NULL)
        iLogin.RemRelease()

        self._reg = None

    def disconnect(self):
        self.dcom.disconnect()

    @property
    def reg(self):
        if self._reg is None:
            self._reg, _ = self.wmi.GetObject('StdRegProv')
        return self._reg

    def reg_get_string(self, hive, path, name):
        try:
            resp = self.reg.GetStringValue(hive, path, name)
            val = resp.getProperties()
            rc = val['ReturnValue']['value']
            if rc != 0:
                return None
            s = val['sValue']['value']
            return s if s else None
        except Exception as e:
            logger.debug(f'reg_get_string({path}\\{name}): {e}')
            return None

    def reg_get_expanded_string(self, hive, path, name):
        try:
            resp = self.reg.GetExpandedStringValue(hive, path, name)
            val = resp.getProperties()
            if val['ReturnValue']['value'] != 0:
                return None
            s = val['sValue']['value']
            return s if s else None
        except Exception as e:
            logger.debug(f'reg_get_expanded_string({path}\\{name}): {e}')
            return None

    def reg_get_dword(self, hive, path, name):
        try:
            resp = self.reg.GetDWORDValue(hive, path, name)
            val = resp.getProperties()
            if val['ReturnValue']['value'] != 0:
                return None
            return val['uValue']['value']
        except Exception as e:
            logger.debug(f'reg_get_dword({path}\\{name}): {e}')
            return None

    def reg_enum_keys(self, hive, path):
        try:
            resp = self.reg.EnumKey(hive, path)
            val = resp.getProperties()
            if val['ReturnValue']['value'] != 0:
                return []
            names = val['sNames']['value']
            return list(names) if names else []
        except Exception as e:
            logger.debug(f'reg_enum_keys({path}): {e}')
            return []

    def wql(self, query):
        rows = []
        try:
            enum = self.wmi.ExecQuery(query)
            while True:
                try:
                    obj = enum.Next(0xffffffff, 1)[0]
                    props = obj.getProperties()
                    row = {}
                    for k, v in props.items():
                        row[k] = v['value']
                    rows.append(row)
                except Exception:
                    break
        except Exception as e:
            logger.debug(f'WQL error: {e}')
        return rows


class Finding:
    def __init__(self, severity, title, detail='', data=None):
        self.severity = severity
        self.title = title
        self.detail = detail
        self.data = data or {}

    def __str__(self):
        color = COLORS.get(self.severity, '')
        s = f'  {color}[{self.severity}]{RESET} {BOLD}{self.title}{RESET}'
        if self.detail:
            for line in self.detail.strip().split('\n'):
                s += f'\n         {line}'
        return s


class PrivescScanner:
    def __init__(self, conn, our_user=''):
        self.conn = conn
        self.our_user = our_user.lower()
        self.findings = []

    def add(self, severity, title, detail='', **data):
        f = Finding(severity, title, detail, data)
        self.findings.append(f)
        return f

    SLOW_CHECKS = {'proc-owners'}

    ALL_CHECKS = [
        ('autologon',    'AutoLogon Credentials'),
        ('wdigest',      'WDigest Plaintext Creds'),
        ('lsa',          'LSA Protection'),
        ('spooler',      'Print Spooler'),
        ('webclient',    'WebClient Service'),
        ('domain',       'Domain Info'),
        ('smb-signing',  'SMB Signing Config'),
        ('ldap-signing', 'LDAP Signing Config'),
        ('user-profiles','User SID Profiles'),
        ('sessions',     'Active Logon Sessions'),
        ('proc-owners',  'Process Owners (per-PID)'),
    ]

    CHECK_FUNCS = {
        'autologon': 'check_autologon', 'wdigest': 'check_wdigest',
        'lsa': 'check_lsa_protection', 'spooler': 'check_spooler',
        'webclient': 'check_webclient', 'domain': 'check_domain_info',
        'smb-signing': 'check_smb_signing', 'ldap-signing': 'check_ldap_signing',
        'user-profiles': 'check_user_profiles', 'sessions': 'check_active_sessions',
        'proc-owners': 'check_process_owners',
    }

    @classmethod
    def list_checks(cls):
        for slug, name in cls.ALL_CHECKS:
            tag = '  (slow)' if slug in cls.SLOW_CHECKS else ''
            print(f'  {slug:<16} {name}{tag}')

    def run_all(self, only=None, exclude=None, fast=False):
        skip = set()
        if fast:
            skip |= self.SLOW_CHECKS
        if exclude:
            skip |= {s.strip() for s in exclude.split(',')}

        if only:
            requested = [s.strip() for s in only.split(',')]
            checks = []
            for slug in requested:
                if slug not in self.CHECK_FUNCS:
                    print(f'[!] Unknown check: {slug}', file=sys.stderr)
                    continue
                name = dict(self.ALL_CHECKS).get(slug, slug)
                checks.append((slug, name, getattr(self, self.CHECK_FUNCS[slug])))
        else:
            checks = [(slug, name, getattr(self, self.CHECK_FUNCS[slug]))
                       for slug, name in self.ALL_CHECKS
                       if slug not in skip]

        if skip and not only:
            print(f'[*] Skipping: {", ".join(sorted(skip))}', file=sys.stderr)

        total = len(checks)
        for i, (slug, name, func) in enumerate(checks, 1):
            sys.stderr.write(f'\r  [{i}/{total}] {name:<45}')
            sys.stderr.flush()
            try:
                func()
            except Exception as e:
                logger.debug(f'Check {name} failed: {e}')
        sys.stderr.write('\r' + ' ' * 60 + '\r')
        sys.stderr.flush()

    def check_autologon(self):
        path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        user = self.conn.reg_get_string(HKLM, path, 'DefaultUserName')
        pw = self.conn.reg_get_string(HKLM, path, 'DefaultPassword')
        domain = self.conn.reg_get_string(HKLM, path, 'DefaultDomainName')
        auto = self.conn.reg_get_string(HKLM, path, 'AutoAdminLogon')

        if pw:
            uname = user or '(not set — check domain users)'
            self.add(FINDING_CRITICAL, 'AutoLogon credentials in registry',
                     f'Domain:   {domain or "."}\n'
                     f'Username: {uname}\n'
                     f'Password: {pw}\n'
                     f'AutoAdminLogon: {auto or "(not set)"}')
        elif user:
            self.add(FINDING_LOW, 'AutoLogon username set (no password)',
                     f'User: {domain or "."}\\{user}')

        alt_pw = self.conn.reg_get_string(HKLM, path, 'DefaultPasswordAlt')
        if alt_pw:
            self.add(FINDING_CRITICAL, 'AutoLogon alt credentials in registry',
                     f'DefaultPasswordAlt: {alt_pw}')

    def check_wdigest(self):
        val = self.conn.reg_get_dword(
            HKLM, r'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
            'UseLogonCredential')
        if val is not None and val == 1:
            self.add(FINDING_HIGH, 'WDigest plaintext credential caching ENABLED',
                     'Cleartext passwords stored in LSASS memory for all logons')
        else:
            self.add(FINDING_INFO, 'WDigest plaintext caching disabled (default)')

    def check_lsa_protection(self):
        val = self.conn.reg_get_dword(
            HKLM, r'SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL')
        if val is not None and val >= 1:
            self.add(FINDING_INFO, f'LSA Protection (RunAsPPL) enabled (value={val})')
        else:
            self.add(FINDING_MEDIUM, 'LSA Protection (RunAsPPL) NOT enabled',
                     'LSASS not running as Protected Process Light — '
                     'credential dumping tools can read memory directly')

    def check_spooler(self):
        svcs = self.conn.wql(
            "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'Spooler'")
        if svcs:
            svc = svcs[0]
            state = svc.get('State', 'Unknown')
            mode = svc.get('StartMode', 'Unknown')
        else:
            start = self.conn.reg_get_dword(
                HKLM, r'SYSTEM\CurrentControlSet\Services\Spooler', 'Start')
            if start is not None:
                mode = {2: 'Automatic', 3: 'Manual', 4: 'Disabled'}.get(start, str(start))
                state = 'Running (assumed)' if start <= 2 else 'Stopped (assumed)'
            else:
                self.add(FINDING_INFO, 'Print Spooler service not found')
                return
        if 'Running' in state:
            self.add(FINDING_MEDIUM, 'Print Spooler is RUNNING',
                     f'State: {state} | StartMode: {mode}\n'
                     'Enables PrinterBug/SpoolSample coercion.\n'
                     'If unconstrained delegation host exists, can capture DC TGT.')
        else:
            self.add(FINDING_INFO, f'Print Spooler: {state} ({mode})')

    def check_webclient(self):
        svcs = self.conn.wql(
            "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'WebClient'")
        if svcs:
            svc = svcs[0]
            state = svc.get('State', 'Unknown')
            mode = svc.get('StartMode', 'Unknown')
        else:
            start = self.conn.reg_get_dword(
                HKLM, r'SYSTEM\CurrentControlSet\Services\WebClient', 'Start')
            if start is not None:
                mode = {2: 'Automatic', 3: 'Manual', 4: 'Disabled'}.get(start, str(start))
                state = 'Running (assumed)' if start <= 2 else 'Stopped'
            else:
                self.add(FINDING_LOW, 'WebClient service not installed',
                         'Cannot do WebDAV NTLM coercion for HTTP→LDAP relay.\n'
                         'Desktop Experience feature not present on this server.')
                return
        if state == 'Running' or 'Running' in state:
            self.add(FINDING_HIGH, 'WebClient service is RUNNING',
                     f'State: {state} | StartMode: {mode}\n'
                     'Enables WebDAV NTLM coercion — HTTP auth (no signing)\n'
                     'Can relay HTTP→LDAP for RBCD/shadow creds')
        elif mode != 'Disabled':
            self.add(FINDING_MEDIUM, f'WebClient service available ({state}, {mode})',
                     'Not running but could be started (trigger via searchConnector-ms)')
        else:
            self.add(FINDING_INFO, f'WebClient: {state} ({mode})')

    def check_domain_info(self):
        cs = self.conn.wql("SELECT Domain, DomainRole, PartOfDomain FROM Win32_ComputerSystem")
        if cs:
            info = cs[0]
            roles = {0: 'Standalone Workstation', 1: 'Member Workstation',
                     2: 'Standalone Server', 3: 'Member Server',
                     4: 'Backup DC', 5: 'Primary DC'}
            role = roles.get(info.get('DomainRole', -1), 'Unknown')
            self.add(FINDING_INFO, f'Domain: {info.get("Domain")} | Role: {role}')

    def check_smb_signing(self):
        val = self.conn.reg_get_dword(
            HKLM, r'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
            'RequireSecuritySignature')
        if val is not None and val == 0:
            self.add(FINDING_HIGH, 'SMB signing NOT required on server',
                     'SMB relay attacks possible against this host')
        elif val == 1:
            self.add(FINDING_INFO, 'SMB signing required (relay-resistant)')
        else:
            self.add(FINDING_INFO, 'SMB signing: registry key not set (check effective policy)')

    def check_ldap_signing(self):
        val = self.conn.reg_get_dword(
            HKLM, r'SYSTEM\CurrentControlSet\Services\NTDS\Parameters',
            'LDAPServerIntegrity')
        levels = {0: 'None', 1: 'Negotiated signing', 2: 'Required'}
        if val is not None:
            desc = levels.get(val, str(val))
            if val < 2:
                self.add(FINDING_HIGH, f'LDAP signing: {desc} (level {val})',
                         'LDAP relay attacks may be possible if NTLM auth comes via HTTP')
            else:
                self.add(FINDING_INFO, f'LDAP signing: {desc}')
        else:
            self.add(FINDING_INFO, 'LDAP signing not configured (default: Negotiated)')

        cb = self.conn.reg_get_dword(
            HKLM, r'SYSTEM\CurrentControlSet\Services\NTDS\Parameters',
            'LdapEnforceChannelBinding')
        if cb is not None:
            self.add(FINDING_INFO, f'LDAP channel binding: {cb} (0=off, 1=when-supported, 2=always)')
        else:
            self.add(FINDING_INFO, 'LDAP channel binding: not set (default: 0)')

    @staticmethod
    def _filetime_to_str(high, low):
        if high is None or low is None:
            return None
        ft = (high << 32) | (low & 0xFFFFFFFF)
        if ft == 0:
            return None
        try:
            unix_ts = (ft - 116444736000000000) / 10000000
            from datetime import timezone
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (OSError, ValueError, OverflowError):
            return None

    def check_user_profiles(self):
        path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        sids = self.conn.reg_enum_keys(HKLM, path)
        profiles = []
        loaded_profiles = []
        for sid in sids:
            if not sid.startswith('S-1-5-21-'):
                continue
            subkey = f'{path}\\{sid}'
            img_path = self.conn.reg_get_expanded_string(HKLM, subkey, 'ProfileImagePath')
            username = (img_path or '?').rsplit('\\', 1)[-1]

            load_hi = self.conn.reg_get_dword(HKLM, subkey, 'ProfileLoadTimeHigh')
            load_lo = self.conn.reg_get_dword(HKLM, subkey, 'ProfileLoadTimeLow')
            unload_hi = self.conn.reg_get_dword(HKLM, subkey, 'LocalProfileUnloadTimeHigh')
            unload_lo = self.conn.reg_get_dword(HKLM, subkey, 'LocalProfileUnloadTimeLow')

            load_time = self._filetime_to_str(load_hi, load_lo)
            unload_time = self._filetime_to_str(unload_hi, unload_lo)

            line = f'{sid} → {img_path or "?"}'
            if load_time:
                line += f'\n           Loaded: {load_time} (profile ACTIVE — creds likely in LSASS)'
                loaded_profiles.append(username)
            if unload_time:
                line += f'\n           Last logoff: {unload_time}'
            if not load_time and not unload_time:
                line += f'\n           (no login timestamps in registry)'
            profiles.append(line)

        if profiles:
            self.add(FINDING_INFO, f'User profiles ({len(profiles)}):',
                     '\n'.join(profiles))
        if loaded_profiles:
            self.add(FINDING_MEDIUM,
                     f'Active profile hives ({len(loaded_profiles)} users)',
                     'These profiles have non-zero ProfileLoadTime — the user\'s\n'
                     'registry hive is mounted and creds are likely in LSASS:\n' +
                     '\n'.join(f'  {u}' for u in loaded_profiles))

    def check_active_sessions(self):
        LOGON_TYPES = {
            0: 'System', 2: 'Interactive', 3: 'Network', 4: 'Batch',
            5: 'Service', 7: 'Unlock', 8: 'NetworkCleartext',
            9: 'NewCredentials', 10: 'RemoteInteractive',
            11: 'CachedInteractive', 12: 'CachedRemoteInteractive'}
        INTERACTIVE_TYPES = {2, 10, 11, 12}

        sess_map = {}
        all_sessions = self.conn.wql(
            'SELECT LogonId, LogonType, StartTime FROM Win32_LogonSession')
        for s in all_sessions:
            lid = str(s.get('LogonId', ''))
            lt = s.get('LogonType', -1)
            sess_map[lid] = {
                'type': lt,
                'type_name': LOGON_TYPES.get(lt, f'Type{lt}'),
                'start': s.get('StartTime', '')}

        logons = self.conn.wql('SELECT * FROM Win32_LoggedOnUser')
        user_sessions = {}
        for l in logons:
            ant = str(l.get('Antecedent', ''))
            dep = str(l.get('Dependent', ''))
            m_user = re.search(r'Domain="([^"]+)".*Name="([^"]+)"', ant)
            m_sess = re.search(r'LogonId="([^"]+)"', dep)
            if m_user and m_sess:
                user = f'{m_user.group(1)}\\{m_user.group(2)}'
                lid = m_sess.group(1)
                info = sess_map.get(lid, {})
                if user not in user_sessions:
                    user_sessions[user] = []
                user_sessions[user].append(info)

        console = self.conn.wql('SELECT UserName FROM Win32_ComputerSystem')
        console_user = console[0].get('UserName') if console else None

        if not user_sessions:
            self.add(FINDING_INFO, 'No logon sessions enumerated')
            return

        lines = []
        interactive_users = []
        for user, sessions in sorted(user_sessions.items()):
            type_counts = {}
            has_interactive = False
            earliest_start = None
            for s in sessions:
                tn = s.get('type_name', '?')
                type_counts[tn] = type_counts.get(tn, 0) + 1
                if s.get('type') in INTERACTIVE_TYPES:
                    has_interactive = True
                st = s.get('start', '')
                if st and (earliest_start is None or st < earliest_start):
                    earliest_start = st
            summary = ', '.join(f'{v}x {k}' for k, v in type_counts.items())
            tag = ''
            if console_user and user.lower() == str(console_user).lower():
                tag = ' ** CONSOLE **'
                has_interactive = True
            if has_interactive:
                tag += ' [INTERACTIVE]'
                interactive_users.append(user)
            time_note = ''
            if earliest_start and not str(earliest_start).startswith('1601'):
                try:
                    ts = str(earliest_start).split('.')[0]
                    time_note = f' (since {ts})'
                except Exception:
                    pass
            lines.append(f'{user}: {len(sessions)} sessions ({summary}){tag}{time_note}')

        hku_sids = self.conn.reg_enum_keys(HKU, '')
        hku_users = []
        profile_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        wmi_users_lower = {u.lower() for u in user_sessions}

        svc_by_user = {}
        svc_root = r'SYSTEM\CurrentControlSet\Services'
        all_svcs = self.conn.reg_enum_keys(HKLM, svc_root)
        system_accounts = {'localsystem', 'nt authority\\localservice',
                           'nt authority\\networkservice', 'nt authority\\system',
                           'localservice', 'networkservice', 'local service',
                           'network service'}
        for svc_name in all_svcs:
            obj = self.conn.reg_get_string(HKLM, f'{svc_root}\\{svc_name}', 'ObjectName')
            if not obj or obj.lower() in system_accounts:
                continue
            acct_short = obj.rsplit('\\', 1)[-1].lower()
            svc_by_user.setdefault(acct_short, []).append(svc_name)

        for sid in hku_sids:
            if not sid.startswith('S-1-5-21-') or sid.endswith('_Classes'):
                continue
            img = self.conn.reg_get_expanded_string(
                HKLM, f'{profile_path}\\{sid}', 'ProfileImagePath')
            if img:
                uname = img.rsplit('\\', 1)[-1]
                found_in_wmi = any(uname.lower() in u for u in wmi_users_lower)
                if not found_in_wmi:
                    subkey = f'{profile_path}\\{sid}'
                    unload_hi = self.conn.reg_get_dword(HKLM, subkey, 'LocalProfileUnloadTimeHigh')
                    unload_lo = self.conn.reg_get_dword(HKLM, subkey, 'LocalProfileUnloadTimeLow')
                    load_hi = self.conn.reg_get_dword(HKLM, subkey, 'ProfileLoadTimeHigh')
                    load_lo = self.conn.reg_get_dword(HKLM, subkey, 'ProfileLoadTimeLow')
                    load_t = self._filetime_to_str(load_hi, load_lo)
                    unload_t = self._filetime_to_str(unload_hi, unload_lo)

                    svcs = svc_by_user.get(uname.lower(), [])
                    svc_info = f' — services: {", ".join(svcs)}' if svcs else ''
                    reason = 'SERVICE' if svcs else 'CACHED'

                    time_info = ''
                    if load_t:
                        time_info = f', loaded {load_t}'
                    elif unload_t:
                        time_info = f', last logoff {unload_t}'

                    detail = f'{uname} (SID: {sid}{time_info}) [{reason}]{svc_info}'
                    hku_users.append(detail)
                    line_str = f'{uname}: HKU hive loaded [{reason}]{svc_info}'
                    if time_info:
                        line_str += f' ({time_info.strip(", ")})'
                    lines.append(line_str)

        if interactive_users:
            self.add(FINDING_HIGH,
                     f'Interactive sessions detected ({len(interactive_users)} users)',
                     'Users with interactive/RDP/console sessions:\n' +
                     '\n'.join(f'  {u}' for u in interactive_users) + '\n\n'
                     'If any are privileged (DA/EA), DCOM objects with RunAs\n'
                     '"Interactive User" execute as them. Combined with DCOM\n'
                     'activation perms, this may allow code exec as that user.\n\n'
                     'All sessions:\n' + '\n'.join(lines))
        elif console_user:
            self.add(FINDING_HIGH, f'Console session: {console_user}',
                     'All sessions:\n' + '\n'.join(lines))
        else:
            self.add(FINDING_INFO, f'Logged-on users ({len(user_sessions)}):',
                     'No interactive/console sessions detected.\n' +
                     '\n'.join(lines))

        if hku_users:
            self.add(FINDING_MEDIUM,
                     f'Loaded HKU hives for {len(hku_users)} additional users',
                     'These users have registry hives loaded (active/cached session)\n'
                     'but did NOT appear in Win32_LogonSession:\n' +
                     '\n'.join(f'  {u}' for u in hku_users) + '\n\n'
                     'A loaded hive means the user has or recently had an active\n'
                     'session. Their credentials may be in LSASS memory.')

    def check_process_owners(self):
        procs = self.conn.wql(
            'SELECT ProcessId, Name, SessionId FROM Win32_Process')
        if not procs:
            return

        owner_map = {}
        for proc in procs:
            pid = proc.get('ProcessId', 0)
            name = proc.get('Name', '?')
            sid = proc.get('SessionId', 0)
            try:
                pobj, _ = self.conn.wmi.GetObject(f"Win32_Process.Handle='{pid}'")
                resp = pobj.GetOwner()
                rp = resp.getProperties()
                domain = rp.get('Domain', {}).get('value', '')
                user = rp.get('User', {}).get('value', '')
                if domain and user:
                    key = f'{domain}\\{user}'
                    if key not in owner_map:
                        owner_map[key] = {'procs': [], 'sessions': set()}
                    owner_map[key]['procs'].append(name)
                    owner_map[key]['sessions'].add(sid)
            except Exception:
                continue

        if not owner_map:
            return

        boring = {'nt authority\\system', 'nt authority\\local service',
                  'nt authority\\network service', 'window manager\\dwm-1',
                  'font driver host\\umfd-0', 'font driver host\\umfd-1'}
        interesting = {}
        for owner, info in owner_map.items():
            low = owner.lower()
            if low in boring:
                continue
            if self.our_user and self.our_user in low:
                continue
            interesting[owner] = info

        if interesting:
            lines = []
            for owner, info in sorted(interesting.items()):
                sessions = sorted(info['sessions'])
                top_procs = list(set(info['procs']))[:8]
                lines.append(
                    f'{owner} (sessions: {sessions}, '
                    f'{len(info["procs"])} procs: {", ".join(top_procs)})')
            n = len(interesting)
            sev = FINDING_HIGH if any(s > 0 for i in interesting.values()
                                       for s in i['sessions']) else FINDING_MEDIUM
            self.add(sev,
                     f'Other users with running processes ({n})',
                     'Non-system/non-attacker user contexts found:\n' +
                     '\n'.join(lines) + '\n\n'
                     'Processes in session >0 indicate interactive logon.\n'
                     'High-value accounts here are targets for token theft,\n'
                     'session hijack, or DCOM "Interactive User" abuse.')


def format_findings(address, findings, os_line='', hf_count=0):
    lines = []
    lines.append(f'\n{BOLD}{"="*60}{RESET}')
    lines.append(f'{BOLD}  DCOM Scan — {address}{RESET}')
    if os_line:
        lines.append(f'  {os_line} | {hf_count} hotfixes')
    lines.append(f'{BOLD}{"="*60}{RESET}\n')

    crits = [f for f in findings if f.severity == FINDING_CRITICAL]
    highs = [f for f in findings if f.severity == FINDING_HIGH]
    meds = [f for f in findings if f.severity == FINDING_MEDIUM]
    lows = [f for f in findings if f.severity == FINDING_LOW]
    infos = [f for f in findings if f.severity == FINDING_INFO]

    if crits:
        lines.append(f'{COLORS[FINDING_CRITICAL]}{BOLD}  CRITICAL FINDINGS{RESET}')
        for f in crits:
            lines.append(str(f))
        lines.append('')
    if highs:
        lines.append(f'{COLORS[FINDING_HIGH]}{BOLD}  HIGH FINDINGS{RESET}')
        for f in highs:
            lines.append(str(f))
        lines.append('')
    if meds:
        lines.append(f'{COLORS[FINDING_MEDIUM]}{BOLD}  MEDIUM FINDINGS{RESET}')
        for f in meds:
            lines.append(str(f))
        lines.append('')
    if lows:
        lines.append(f'{COLORS[FINDING_LOW]}{BOLD}  LOW FINDINGS{RESET}')
        for f in lows:
            lines.append(str(f))
        lines.append('')
    if infos:
        lines.append(f'{BOLD}  INFO{RESET}')
        for f in infos:
            lines.append(str(f))
        lines.append('')

    summary = (f'  Findings: '
               f'{COLORS[FINDING_CRITICAL]}{len(crits)} critical{RESET}, '
               f'{COLORS[FINDING_HIGH]}{len(highs)} high{RESET}, '
               f'{COLORS[FINDING_MEDIUM]}{len(meds)} medium{RESET}, '
               f'{len(lows)} low, {len(infos)} info')
    lines.append(f'{BOLD}{"="*60}{RESET}')
    lines.append(summary)
    lines.append(f'{BOLD}{"="*60}{RESET}')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='DCOM privilege escalation scanner via WMI')
    parser.add_argument('target', nargs='?', help='[[domain/]username[:password]@]<target>')
    parser.add_argument('-hashes', metavar='LMHASH:NTHASH')
    parser.add_argument('-no-pass', action='store_true')
    parser.add_argument('-k', action='store_true', help='Kerberos auth')
    parser.add_argument('-dc-ip', metavar='IP')
    parser.add_argument('-json', action='store_true', help='Output JSON')
    parser.add_argument('-checks', metavar='LIST',
                        help='Comma-separated check slugs to run (default: all)')
    parser.add_argument('-exclude', metavar='LIST',
                        help='Comma-separated check slugs to skip')
    parser.add_argument('-fast', action='store_true',
                        help='Skip slow checks (proc-owners)')
    parser.add_argument('-list-checks', action='store_true',
                        help='List available check names and exit')
    parser.add_argument('-targets-file', metavar='FILE',
                        help='File with one target IP/hostname per line')
    parser.add_argument('-min-severity', metavar='LEVEL',
                        choices=['critical', 'high', 'medium', 'low', 'info'],
                        help='Hide findings below this severity')
    parser.add_argument('-o', metavar='FILE', default='dcomatmebro-output.txt',
                        help='Output file (default: dcomatmebro-output.txt)')
    parser.add_argument('-debug', action='store_true')

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format='%(levelname)s: %(message)s')

    print(f'\n{BOLD}DCOMatMEbro.py{RESET} — DCOM Privilege Escalation Scanner\n',
          file=sys.stderr)

    if args.list_checks:
        PrivescScanner.list_checks()
        sys.exit(0)

    if not args.target:
        parser.error('target is required')

    if args.targets_file:
        with open(args.targets_file) as fh:
            targets = [line.strip() for line in fh if line.strip() and not line.startswith('#')]
        if not targets:
            parser.error('targets file is empty')
        domain, username, password, orig_addr = parse_target(args.target)
        if orig_addr not in targets:
            domain, username, password, _ = parse_target(f'{args.target}@{targets[0]}')
    else:
        domain, username, password, address = parse_target(args.target)
        targets = [address]
    if domain is None:
        domain = ''
    lmhash = nthash = ''
    if args.hashes:
        lmhash, nthash = args.hashes.split(':')
    if password == '' and username != '' and not args.hashes and not args.no_pass:
        from getpass import getpass
        password = getpass('Password:')

    out_file = args.o
    file_output = []
    all_results = {}
    total_targets = len(targets)

    for tidx, target_host in enumerate(targets, 1):
        if total_targets > 1:
            print(f'\n{"#"*60}', file=sys.stderr)
            print(f'# [{tidx}/{total_targets}] {target_host}', file=sys.stderr)
            print(f'{"#"*60}', file=sys.stderr)

        print(f'[*] Target:   {target_host}', file=sys.stderr)
        print(f'[*] User:     {domain}\\{username}', file=sys.stderr)
        print(f'[*] Connecting via DCOM/WMI...', file=sys.stderr)

        conn = None
        try:
            conn = WMIConnection(target_host, username, password, domain,
                                 lmhash, nthash,
                                 do_kerberos=args.k, kdc_host=args.dc_ip)
        except Exception as e:
            print(f'[-] DCOM connection failed: {e}', file=sys.stderr)
            all_results[target_host] = {'error': str(e)}
            continue

        print(f'[+] Connected', file=sys.stderr)

        os_line = ''
        hf_count = 0
        try:
            os_info = conn.wql(
                "SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem")
            if os_info:
                oi = os_info[0]
                caption = (oi.get('Caption') or '?').strip()
                build = oi.get('BuildNumber', '?')
                ver = oi.get('Version', '?')
                os_line = f'{caption} (Build {build})'
                print(f'[*] OS:       {caption} | Version {ver} | Build {build}',
                      file=sys.stderr)

            hotfixes = conn.wql("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering")
            if not hotfixes:
                pkgs = conn.reg_enum_keys(HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages')
                kb_set = set()
                import re
                kb_re = re.compile(r'Package_(?:\d+_)?for_(KB\d+)')
                for p in pkgs:
                    m = kb_re.match(p)
                    if m:
                        kb_set.add(m.group(1))
                if kb_set:
                    hotfixes = [{'HotFixID': kb, 'InstalledOn': ''} for kb in sorted(kb_set)]
            hf_count = len(hotfixes) if hotfixes else 0
            if hotfixes:
                dated = [h for h in hotfixes if h.get('InstalledOn')]
                if dated:
                    dated.sort(key=lambda x: x['InstalledOn'], reverse=True)
                    last = dated[0]
                    print(f'[*] Hotfixes: {hf_count} (latest: {last.get("HotFixID", "?")} '
                          f'on {last.get("InstalledOn", "?")})', file=sys.stderr)
                else:
                    print(f'[*] Hotfixes: {hf_count} (via registry)', file=sys.stderr)
            else:
                print(f'[*] Hotfixes: none detected', file=sys.stderr)
        except Exception as e:
            logger.debug(f'OS info query failed: {e}')

        print(f'[*] Running checks...\n', file=sys.stderr)

        try:
            scanner = PrivescScanner(conn, our_user=username)
            scanner.run_all(only=args.checks, exclude=args.exclude, fast=args.fast)

            findings = scanner.findings
            if args.min_severity:
                sev_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
                threshold = sev_rank.get(args.min_severity.upper(), 4)
                findings = [f for f in findings if sev_rank.get(f.severity, 4) <= threshold]
            all_results[target_host] = findings

            if not args.json:
                output = format_findings(target_host, findings, os_line, hf_count)
                print(output)
                file_output.append(ANSI_RE.sub('', output))

        except KeyboardInterrupt:
            print('\n[!] Interrupted', file=sys.stderr)
            break
        except Exception as e:
            if args.debug:
                import traceback
                traceback.print_exc()
            print(f'[-] Scanner error: {e}', file=sys.stderr)
            all_results[target_host] = {'error': str(e)}
        finally:
            if conn:
                conn.disconnect()

    if args.json:
        out = {}
        for host, result in all_results.items():
            if isinstance(result, dict) and 'error' in result:
                out[host] = result
            else:
                out[host] = [{'severity': f.severity, 'title': f.title,
                              'detail': f.detail, 'data': f.data} for f in result]
        json_str = json.dumps(out, indent=2)
        print(json_str)
        file_output.append(json_str)

    if total_targets > 1 and not args.json:
        summary_lines = []
        summary_lines.append(f'\n{BOLD}{"="*60}{RESET}')
        summary_lines.append(f'{BOLD}  SUMMARY — {total_targets} targets{RESET}')
        summary_lines.append(f'{BOLD}{"="*60}{RESET}')
        for host, result in all_results.items():
            if isinstance(result, dict) and 'error' in result:
                summary_lines.append(
                    f'  {host}: {COLORS[FINDING_CRITICAL]}FAILED{RESET} — {result["error"][:60]}')
            else:
                c = sum(1 for f in result if f.severity == FINDING_CRITICAL)
                h = sum(1 for f in result if f.severity == FINDING_HIGH)
                m = sum(1 for f in result if f.severity == FINDING_MEDIUM)
                summary_lines.append(
                    f'  {host}: '
                    f'{COLORS[FINDING_CRITICAL]}{c}C{RESET} '
                    f'{COLORS[FINDING_HIGH]}{h}H{RESET} '
                    f'{COLORS[FINDING_MEDIUM]}{m}M{RESET} '
                    f'({len(result)} total)')
        summary_lines.append(f'{BOLD}{"="*60}{RESET}')
        summary_text = '\n'.join(summary_lines)
        print(summary_text)
        file_output.append(ANSI_RE.sub('', summary_text))

    if file_output and out_file:
        with open(out_file, 'w') as fh:
            fh.write('\n'.join(file_output) + '\n')
        print(f'\n[*] Output saved to {out_file}', file=sys.stderr)


if __name__ == '__main__':
    main()
