# DCOM/WMI Zero-Day Research
## ecorp.local Lab — ExecuteDCOM Attack Path Analysis
**Date:** 2026-09-16
**Target:** ECORP-DC (192.168.15.40) — Windows Server 2019 Datacenter Build 17763.737 (unpatched)
**User:** ecorp\dcomuser (non-admin, Distributed COM Users group only)
**Objective:** Find novel/undocumented DCOM primitives or zero-day vulnerabilities

**Status:** Incomplete — black-box testing exhausted, binary analysis phase not started.

---

## Summary

All remote black-box testing of the WMI-over-DCOM attack surface from a non-admin DCOM user found no exploitable zero-day vulnerability. Windows WMI/DCOM security model is robust against non-admin users on Server Core — all write operations are properly denied at either the WMI dispatch layer or the underlying Windows API layer.

Findings:
1. Three security quality issues (CIM_DataFile info leak, session state corruption, method dispatch inconsistency)
2. Specific areas in the WMI kernel driver and DCOM protocol likely to yield results with binary analysis

---

## Attack Surface

### DCOM Activation (Server Core)
Only WMI (`CLSID {8BC3F05E-D86B-11D0-A075-00C04FB68820}`) is remotely activatable. All other COM objects (MMC20.Application, ShellWindows, ShellBrowserWindow, WScript.Shell) return `REGDB_E_CLASSNOTREG`.

### WMI Namespace Access
| Namespace | Access |
|-----------|--------|
| root/cimv2 | ALLOWED |
| root/RSOP | ALLOWED (limited) |
| root/subscription | DENIED |
| root/default | DENIED |
| root/standardcimv2 | DENIED |
| root/cimv2/Security | DENIED |
| root/directory/LDAP | DENIED |
| root/MicrosoftDNS | DENIED |
| All others tested | DENIED |

---

## WMI Method Security Boundary Testing

### Methods That Execute (provider reached, OS denies)
| Method | Result |
|--------|--------|
| Win32_Process.Create | rc=0 (success — primary exec primitive) |
| Win32_Product.Install (local) | rc=1601 (installer service inaccessible) |
| Win32_Product.Install (UNC) | rc=1601 |
| Win32_ScheduledJob.Create | rc=8 (AT service disabled) |
| Win32_Process.SetPriority | rc=5 (access denied) |

### Methods Blocked at WMI Layer
| Method | Error |
|--------|-------|
| Win32_Service.StopService | PROVIDER_FAILURE |
| Win32_Service.ChangeStartMode | INVALID_PARAMETER |
| Win32_ShadowCopy.Create | INITIALIZATION_FAILURE |
| __SystemSecurity.GetSD/SetSD | ACCESS_DENIED |

### All Write Operations Denied
| Operation | Error |
|-----------|-------|
| PutClass | ACCESS_DENIED |
| PutInstance | ACCESS_DENIED |
| Registry writes (HKLM) | rc=5 |
| Registry writes (other users' HKU) | rc=5 |

---

## Security Quality Issues

### 1. CIM_DataFile.Writeable Reports SYSTEM Perspective (Info Leak)
`CIM_DataFile.Writeable` returns True for files writable by the WMI provider host (SYSTEM), not the impersonated caller. 294 MOF files in `C:\Windows\System32\wbem\` reported as writable; actual ACL is TrustedInstaller-protected.

Useful for DLL hijack research — reveals which files SYSTEM processes can write.

### 2. WMI Session State Corruption After Failed Write
PutInstance or DeleteInstance on a system class (`__Win32Provider`, `__EventFilter`) permanently corrupts the WMI session. All subsequent operations return ACCESS_DENIED until reconnection. Per-connection only, no persistent server damage.

### 3. WMI Method Dispatch Inconsistency
Some methods pass through WMI security to the provider (which denies at OS level), while structurally similar methods are blocked at the WMI layer. Suggests non-uniform method-level ACL configuration.

---

## Namespace Path Manipulation

### Null-Byte Truncation (CWE-158)
Embedded `\x00` in namespace paths causes server-side truncation. `root/cimv2\x00/subscription` connects to root/cimv2. The truncation occurs in wmiprvse.exe.

Not an ACL bypass — both access check and resolution use the truncated path. Impact limited to security monitoring evasion (tools logging full path see different namespace than what WMI connects to).

PoC: `wmi_nullbyte_poc.py`

### Path Traversal
All `../` traversal attempts return INVALID_NAMESPACE. No namespace escape possible.

---

## SYSTEM Auth Coercion — Not Exploitable

| Vector | Result |
|--------|--------|
| CIM_DataFile UNC query | 0 rows, no outbound connection |
| Win32_Product.Install (UNC) | rc=1601, no network fetch |
| Win32_Product.Install (HTTP) | rc=1601, no HTTP request |
| Win32_Process.Create + UNC dir | Process created but runs as dcomuser, not SYSTEM |
| Outbound SMB from DC | Blocked by Windows Firewall |

WMI provider never makes outbound connections for attacker-supplied paths. Process creation runs in caller context.

---

## CIM_DataFile Method Impersonation — Verified Secure

| Method | Target | Result |
|--------|--------|--------|
| CIM_DataFile.Delete | hosts file | rc=2 (properly impersonated) |
| CIM_DataFile.TakeOwnerShip | SAM/SYSTEM/SECURITY hives | rc=2 (properly impersonated) |
| CIM_DataFile.Copy | accessible files | rc=0, file owned by dcomuser |
| CIM_DataFile.Copy | restricted files | rc=2 (properly impersonated) |

Methods properly impersonate. Only the `Writeable` property reports from SYSTEM's perspective.

---

## dcomuser Capabilities Summary

| Capability | Status |
|------------|--------|
| Win32_Process.Create | Works (as dcomuser) |
| StdRegProv read (HKLM) | Full read access |
| StdRegProv write (HKLM) | rc=5 denied |
| CIM_DataFile.Writeable | Info leak (reports SYSTEM perspective) |
| CIM_DataFile methods (Delete/TakeOwnerShip/Copy) | Properly impersonated (denied) |
| Win32_Service queries | ACCESS_DENIED (fallback via registry) |
| Event subscriptions | No access to root/subscription |
| WMI class/instance creation | ACCESS_DENIED |
| SYSTEM auth coercion | Provider never connects outbound |
| COM activation (non-WMI) | CLASSNOTREG on Server Core |

---

## Remaining Research Vectors (Binary Analysis Required)

Black-box testing from DCOM-only access is exhausted. Remaining paths require IDA/Ghidra/WinDbg:

1. **WMI Kernel IOCTL Handlers** — integer arithmetic bugs in ntoskrnl.exe WMI dispatch (0x228000-0x228FFF range). Adjacent functions to known vuln patterns.
2. **DCOM Protocol Parsing** — heap handling in rpcss.exe marshaling/unmarshaling (OXID resolution, IRemUnknown2 object reference management).
3. **WMI Provider DLL Internals** — code paths in cimwin32.dll/fastprox.dll that might skip impersonation under specific error conditions.

---

## Conclusion

ExecuteDCOM ceiling for non-admin on Server Core: code execution as yourself + registry read. No SYSTEM escalation via black-box WMI. Further progress requires binary analysis tooling.
