# DCOMatMEbro

DCOM privilege escalation scanner and research tools for the BloodHound "ExecuteDCOM" attack path.

**Status:** Incomplete research project.

## Tools

### DCOMatMEbro.py
WMI-over-DCOM scanner. Enumerates security misconfigurations accessible from a non-admin DCOM user via StdRegProv and WMI queries.

**Checks:** autologon, wdigest, lsa, spooler, webclient, domain, smb-signing, ldap-signing, user-profiles, sessions, proc-owners

```
python3 DCOMatMEbro.py ecorp.local/dcomuser:'DCOMPwn2026!'@192.168.15.40
python3 DCOMatMEbro.py ecorp.local/dcomuser:'DCOMPwn2026!'@192.168.15.40 -checks autologon,sessions -fast
python3 DCOMatMEbro.py ecorp.local/dcomuser:'DCOMPwn2026!'@192.168.15.40 -min-severity medium -o results.txt
python3 DCOMatMEbro.py -targets-file targets.txt ecorp.local/dcomuser:'DCOMPwn2026!'
```

### dcom_exec.py
Session-less DCOM code execution via WMI Win32_Process.Create with HTTP callback for output retrieval.

```
python3 dcom_exec.py ecorp.local/dcomuser:'DCOMPwn2026!'@192.168.15.40 'whoami /all'
```

## Requirements
- Python 3
- impacket

## Research
See [research.md](research.md) for full findings from black-box testing of the WMI/DCOM attack surface.
