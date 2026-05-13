# Mapping To MITRE ATT&CK

This mapping connects CafeSec Lab checklist controls and detection rules to MITRE ATT&CK techniques. It is a defensive index, not a claim that every technique has been observed in a specific venue.

## Checklist Mapping

| ATT&CK Technique | Venue Risk | Relevant Controls |
| --- | --- | --- |
| T1005 Data from Local System | Billing exports, local logs, and configuration files may be collected from compromised hosts. | BS-06, BS-10, NI-10, IR-13 |
| T1021 Remote Services | RDP, SMB, WinRM, SSH, and vendor remote tools can support lateral movement. | WH-49, WH-50, NI-11, NI-43, IR-20 |
| T1021.002 SMB/Windows Admin Shares | SMB exposure from clients to servers can enable lateral movement and file access. | NI-11, NI-18 |
| T1027 Obfuscated Files or Information | Packed or obfuscated tools can appear on customer-facing PCs. | WH-17, WH-18, WH-19, detection YARA packer traits |
| T1041 Exfiltration Over C2 Channel | Billing data, logs, or exports may leave through unusual outbound paths. | NI-21, NI-27, IR-13 |
| T1046 Network Service Discovery | Flat networks allow scanning of billing, cashier, CCTV, and management services. | NI-02, NI-05, NI-14, PS-26 |
| T1052 Exfiltration Over Physical Medium | USB drives and removed disks can carry sensitive data. | PS-08, PS-15, IR-17 |
| T1055 Process Injection | Unauthorized tools may tamper with local processes or security controls. | WH-28, BS-23, YARA memory scanner, YARA injector traits |
| T1059 Command and Scripting Interpreter | PowerShell, cmd, and scripts can be used for tampering or maintenance. | WH-23 through WH-28, IR-10 |
| T1070.001 Clear Windows Event Logs | Log clearing weakens investigations and accountability. | WH-44, WH-46, BS-36, IR-11 |
| T1071.004 DNS | DNS may be used for command-and-control, bypass, or investigation evidence. | NI-22, NI-23, NI-28, IR-13 |
| T1078 Valid Accounts | Shared staff, vendor, local admin, and service accounts increase compromise impact. | WH-02, WH-05, BS-05, IR-19 |
| T1090 Proxy | Proxy and anonymizer use can hide outbound activity. | NI-25, NI-27 |
| T1091 Replication Through Removable Media | Customer and staff USB devices can introduce unwanted software. | WH-29, PS-10, PS-15, IR-17 |
| T1105 Ingress Tool Transfer | Downloads and outbound access can introduce tooling. | WH-19, NI-21, NI-26 |
| T1112 Modify Registry | Registry changes can affect startup, security, proxy, DNS, and billing configuration. | WH-13, BS-25, Sigma registry rule |
| T1133 External Remote Services | Vendor and remote administration access can become an entry path. | WH-50, BS-34, NI-43, IR-20 |
| T1195 Supply Chain Compromise | Vendor updates and installers can affect many systems. | BS-31, BS-32, BS-33 |
| T1200 Hardware Additions | Physical access can introduce hardware implants, adapters, or rogue devices. | PS-10 through PS-15, IR-17, IR-29 |
| T1204 User Execution | Customers or staff may execute unapproved files. | WH-17, WH-18, WH-19, YARA rules |
| T1486 Data Encrypted for Impact | Ransomware can stop billing operations and recovery. | BS-12, IR-21, IR-27 |
| T1490 Inhibit System Recovery | Backups and restore paths can be disabled or corrupted. | BS-12, IR-22, PS-36 |
| T1542 Pre-OS Boot | Boot media and firmware changes can bypass OS controls. | PS-16 through PS-24 |
| T1543.003 Windows Service | Unauthorized services and service changes affect persistence and control. | WH-15, BS-20, Sigma service rule |
| T1547 Boot or Logon Autostart Execution | Startup entries can restore unwanted tools. | WH-13, Sigma registry rule |
| T1552 Unsecured Credentials | Saved passwords and exposed secrets increase account compromise. | WH-08, BS-10, IR-33 |
| T1557 Adversary-in-the-Middle | DNS, rogue DHCP, and flat networks can enable interception. | NI-22, NI-29 |
| T1562.001 Disable or Modify Tools | Billing, restoration, logging, and protection services may be disabled. | WH-10, WH-36, BS-20, Sigma service and process rules |
| T1565 Data Manipulation | Billing database or application state may be altered. | BS-02, BS-11, IR-28 |
| T1574 Hijack Execution Flow | Writable directories and DLL search paths can affect billing binaries. | WH-22, BS-19 |

## Detection Rule Mapping

| Rule | Primary Techniques | Notes |
| --- | --- | --- |
| `yara/generic_memory_scanner.yar` | T1055, T1005, T1105, T1204 | Triage-only signal for memory-scanning traits. |
| `yara/unsigned_injector_patterns.yar` | T1055, T1105, T1027, T1204 | Prioritize matches from customer-writable paths and unsigned binaries. |
| `yara/suspicious_packer_traits.yar` | T1027, T1036, T1105, T1204 | High false-positive potential for protected commercial software. |
| `sigma/billing_process_termination.yml` | T1562.001, T1059 | Correlate with service events and billing agent health logs. |
| `sigma/critical_service_disabled.yml` | T1562.001, T1543.003 | Tune service names for local billing, restoration, logging, and backup components. |
| `sigma/anomalous_registry_modification.yml` | T1112, T1547, T1562.001 | Requires registry auditing and local path tuning. |

## References

- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- CafeSec Lab checklist: `../checklist/`
- CafeSec Lab detection rules: `../detection/`
