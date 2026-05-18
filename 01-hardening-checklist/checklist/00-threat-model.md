# Threat Model Foundation

This document defines the baseline threat model for CafeSec Lab's hardening checklist. All later checklist files inherit these assumptions unless they explicitly state otherwise.

The target environment is an internet cafe, gaming venue, esports hotel, or managed shared-PC site. The model is global in scope, while the first public examples use Dubai/UAE operator assumptions. A typical deployment includes Windows client PCs, a billing server, cashier or reception workstations, restoration or "rollback" software, network equipment, guest Wi-Fi, administrative remote access, and business records used for revenue reconciliation.

This document uses MITRE ATT&CK for technique naming, STRIDE for threat categories, and a simple risk matrix inspired by NIST risk-management practice. ATT&CK mappings are a defensive taxonomy, not a claim that every listed technique has been observed in a specific venue.

## Operating Assumptions

- Client PCs are physically accessible to customers for long sessions.
- Most daily administration is performed by non-security staff.
- The venue has limited budget for enterprise EDR, SIEM, or dedicated SOC staffing.
- Billing availability is business-critical because downtime directly affects revenue.
- Billing integrity is business-critical because manipulation can cause revenue loss, disputes, or fraud.
- Some software may be legacy, vendor-managed, or difficult to patch quickly.
- Restoration systems may reset client state but do not automatically protect servers, cashier hosts, network devices, or cloud consoles.
- Remote maintenance by vendors or contractors may exist.
- Local legal and compliance obligations must be reviewed by qualified counsel in the relevant jurisdiction, including Dubai/UAE counsel where UAE examples are used.

## Assets

| Asset | Trust Zone | Security Properties | Failure Impact | Evidence to Preserve |
| --- | --- | --- | --- | --- |
| Billing database | Server zone | Integrity, availability, confidentiality | Revenue manipulation, customer disputes, business interruption | Database audit logs, backups, transaction exports, server event logs |
| Billing server application | Server zone | Integrity, availability, authenticity | Service outage, false session state, unauthorized privilege changes | Binary hashes, service configuration, process logs, update logs |
| Billing client agent | Client zone | Integrity, availability, tamper resistance | Session bypass, local policy disablement, false client state | File hashes, service status, process tree, local event logs |
| Cashier workstation | Admin zone | Confidentiality, integrity, non-repudiation | Account takeover, manual balance changes, refund abuse | Login logs, application audit trail, screen recordings where lawful |
| Administrator accounts | Identity zone | Least privilege, accountability, revocability | Full environment compromise | Account inventory, MFA logs, password vault logs, change records |
| Client golden image | Build zone | Integrity, provenance, reproducibility | Persistent compromise across many PCs | Image hash, build notes, package list, signing records |
| Restoration or rollback control plane | Client/build zone | Integrity, availability, controlled exceptions | Malware persistence, failed patching, false recovery assumptions | Policy exports, version records, exception list, restore logs |
| Network switches and routers | Network zone | Segmentation, configuration integrity, logging | Lateral movement, interception, outage | Config backups, firmware versions, admin logs, port maps |
| Guest Wi-Fi | Guest zone | Isolation, abuse containment | Pivoting, legal complaints, malware distribution | WLAN controller logs, DHCP leases, DNS logs |
| Remote administration channel | Remote access zone | Strong authentication, logging, least privilege | External compromise, vendor account abuse | VPN logs, remote tool logs, session recordings where lawful |
| Payment and accounting exports | Business zone | Integrity, confidentiality, retention | Financial loss, privacy incident | Export hashes, accounting records, access logs |
| Security logs | Evidence zone | Completeness, time accuracy, retention | Investigation failure, weak accountability | Event logs, Sysmon logs, firewall logs, NTP records |
| Backups | Recovery zone | Availability, integrity, offline protection | Unable to recover from ransomware or destructive change | Backup job logs, restore-test records, media inventory |

## Trust Zones

| Zone | Description | Baseline Trust Level |
| --- | --- | --- |
| Client zone | Customer-facing PCs used for gaming, browsing, and local applications. | Untrusted. Physical access is assumed. |
| Admin zone | Cashier, reception, manager, and owner workstations. | Semi-trusted. High impact if compromised. |
| Server zone | Billing server, database, license server, and management services. | High trust. Strictly minimized access. |
| Build zone | Golden images, software packages, deployment shares, restoration administration. | High trust. Strong change control required. |
| Network zone | Switches, routers, firewalls, WLAN controllers, DNS, DHCP, and time services. | High trust. Configuration integrity required. |
| Guest zone | Guest Wi-Fi, personal devices, unmanaged phones, visitor laptops. | Untrusted. No access to billing or admin systems. |
| Remote access zone | VPN, vendor support tools, remote desktop gateways, cloud consoles. | Conditional trust. Strong identity and logging required. |
| Evidence zone | Centralized logs, backups, audit exports, incident evidence. | High trust. Write-once or tamper-resistant where possible. |

## Threat Actors

| Actor | Motivation | Initial Access | STRIDE Categories | Representative ATT&CK Techniques | Defensive Priority |
| --- | --- | --- | --- | --- | --- |
| Opportunistic customer | Free time, cheating, curiosity, bragging rights | Physical access to a client PC | Tampering, elevation of privilege, denial of service | T1055 Process Injection, T1562.001 Disable or Modify Tools, T1112 Modify Registry, T1091 Replication Through Removable Media | Lock down client privileges, application control, USB policy, restoration validation |
| Repeat customer with tools | Billing bypass, cheating, resale of methods | Client PC plus removable media or downloaded tools | Tampering, information disclosure, elevation of privilege | T1105 Ingress Tool Transfer, T1027 Obfuscated Files or Information, T1036 Masquerading, T1574 Hijack Execution Flow | Egress filtering, binary integrity checks, process monitoring, least privilege |
| Insider staff member | Refund abuse, free sessions, retaliation, data access | Cashier or manager workstation | Spoofing, repudiation, tampering, information disclosure | T1078 Valid Accounts, T1552 Unsecured Credentials, T1136 Create Account, T1070.001 Clear Windows Event Logs | Role separation, audit trails, MFA, immutable logs |
| Vendor or contractor account compromise | Remote compromise, supply-chain pivot, persistence | Remote support tool, VPN, shared admin credentials | Spoofing, tampering, elevation of privilege | T1133 External Remote Services, T1021 Remote Services, T1110 Brute Force, T1195 Supply Chain Compromise | Named accounts, MFA, session logging, vendor access windows |
| Commercial cheat or bypass seller | Monetization, reputation, scale | Downloaded tools, social channels, client endpoint | Tampering, elevation of privilege, denial of service | T1055 Process Injection, T1218 System Binary Proxy Execution, T1562 Impair Defenses, T1105 Ingress Tool Transfer | App control, DNS filtering, EDR/Sysmon telemetry, integrity monitoring |
| Criminal extortion actor | Ransomware, data theft, fraud | Phishing, exposed services, reused credentials | Information disclosure, denial of service, tampering | T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery, T1005 Data from Local System, T1041 Exfiltration Over C2 Channel | Offline backups, segmentation, least privilege, incident response runbooks |
| Software update compromise | Distribution of malicious or vulnerable code | Vendor update channel, package repository, shared installer | Tampering, spoofing, elevation of privilege | T1195 Supply Chain Compromise, T1553.002 Code Signing, T1574 Hijack Execution Flow | Signed updates, staged deployment, hash verification, rollback plan |
| Network-adjacent attacker | Interception, lateral movement, DNS abuse | Guest Wi-Fi, exposed switch ports, weak segmentation | Spoofing, information disclosure, tampering | T1557 Adversary-in-the-Middle, T1046 Network Service Discovery, T1021 Remote Services | VLANs, ACLs, DNS security, port security, firewall logging |

## Primary Attack Surfaces

### Customer-Facing Client PCs

Client PCs are the highest-exposure systems because customers have keyboard, mouse, USB, and sometimes local storage access. A restoration product reduces long-term persistence risk, but it does not make the live session trustworthy.

Common defensive concerns:

- local administrator rights or weak kiosk restrictions;
- unsigned executables running from downloads, temp directories, USB media, or game folders;
- process injection against billing agents or anti-cheat adjacent processes;
- service stop attempts against billing, restoration, logging, or endpoint protection components;
- registry changes that affect startup, policy, proxy, DNS, or application execution;
- time tampering that weakens logs and billing reconciliation.

Relevant ATT&CK techniques include T1055 Process Injection, T1562.001 Disable or Modify Tools, T1112 Modify Registry, T1547 Boot or Logon Autostart Execution, and T1091 Replication Through Removable Media.

### Billing Server and Database

The billing server is the central integrity anchor. If the server trusts client-reported state too much, local client compromise can become revenue manipulation. If the database is reachable from broad network segments, a workstation compromise can become a business-critical incident.

Common defensive concerns:

- shared database credentials across applications or staff;
- database ports reachable from client or guest networks;
- unaudited manual balance edits;
- weak update or plugin paths;
- absence of immutable transaction logs;
- backups that are online, writable, or never restore-tested.

Relevant ATT&CK techniques include T1078 Valid Accounts, T1005 Data from Local System, T1565 Data Manipulation, T1021 Remote Services, and T1486 Data Encrypted for Impact.

### Cashier and Manager Workstations

Cashier systems are both administrative endpoints and business terminals. They often bridge customer service, payment handling, and system management. This makes them a high-value target even when they are not technically powerful servers.

Common defensive concerns:

- shared cashier accounts;
- saved passwords in browsers, remote tools, or plain-text notes;
- uncontrolled remote desktop or vendor support tools;
- weak separation between cashier, manager, and owner privileges;
- lack of review for refunds, manual time grants, and account adjustments.

Relevant ATT&CK techniques include T1078 Valid Accounts, T1552 Unsecured Credentials, T1136 Create Account, T1070.001 Clear Windows Event Logs, and T1059 Command and Scripting Interpreter.

### Remote Administration and Vendor Support

Remote maintenance is useful but dangerous when it is always-on, shared, or poorly logged. The core question is not whether remote access exists, but whether access is named, temporary, strongly authenticated, and reviewable.

Common defensive concerns:

- unattended remote access agents with shared passwords;
- vendor accounts that are never disabled;
- direct RDP exposure;
- missing MFA;
- lack of session logging;
- support tools that bypass network segmentation.

Relevant ATT&CK techniques include T1133 External Remote Services, T1021 Remote Services, T1110 Brute Force, and T1195 Supply Chain Compromise.

### Network and Guest Wi-Fi

Many venue networks grow organically. Gaming PCs, cashier stations, printers, Wi-Fi, CCTV, and billing servers may end up on the same broadcast domain. This makes containment difficult.

Common defensive concerns:

- no VLAN boundary between client PCs and servers;
- guest Wi-Fi able to reach internal services;
- unrestricted outbound traffic from clients;
- unmanaged DNS that can be hijacked or changed locally;
- switch management interfaces reachable from client ports.

Relevant ATT&CK techniques include T1046 Network Service Discovery, T1021 Remote Services, T1557 Adversary-in-the-Middle, and T1105 Ingress Tool Transfer.

### Golden Images, Restoration Systems, and Updates

Restoration systems are often treated as a security boundary. They should instead be treated as recovery and consistency tools. If the golden image, restoration exceptions, or update packages are compromised, the venue can redeploy the compromise at scale.

Common defensive concerns:

- unsigned or unverified image changes;
- broad write access to deployment shares;
- untracked restoration exceptions;
- update packages fetched over weak channels;
- inability to prove which image version is deployed.

Relevant ATT&CK techniques include T1195 Supply Chain Compromise, T1553.002 Code Signing, T1574 Hijack Execution Flow, T1565 Data Manipulation, and T1490 Inhibit System Recovery.

## STRIDE Summary

| STRIDE Category | Venue Example | Control Objective |
| --- | --- | --- |
| Spoofing | A shared cashier account is used to make unauthorized adjustments. | Named accounts, MFA, role separation, session review. |
| Tampering | A client-side billing agent binary or service configuration is modified. | File integrity monitoring, ACLs, application control, service recovery policy. |
| Repudiation | Staff deny making a refund or clearing logs. | Centralized logs, time sync, immutable exports, manager review. |
| Information disclosure | Database exports or saved credentials leak from an admin workstation. | Least privilege, encryption, secret storage, workstation hardening. |
| Denial of service | Billing services are stopped during peak hours. | Service monitoring, recovery actions, segmentation, tested backups. |
| Elevation of privilege | A customer gains local admin rights on a client PC. | Standard users, UAC policy, WDAC/AppLocker, USB and boot controls. |

## Risk Matrix

Likelihood and impact are scored from 1 to 5.

| Score | Likelihood | Impact |
| --- | --- | --- |
| 1 | Rare in the current venue model | Negligible operational effect |
| 2 | Unlikely but plausible | Limited host or user impact |
| 3 | Expected occasionally | Multi-host or short business interruption |
| 4 | Likely without controls | Revenue, evidence, or service impact |
| 5 | Frequently attempted or easy to scale | Severe revenue loss, prolonged outage, legal exposure, or public trust damage |

Risk level is calculated as `likelihood x impact`.

| Score Range | Level | Response |
| --- | --- | --- |
| 1-4 | Low | Track and address during normal maintenance. |
| 5-9 | Medium | Add controls in the next hardening cycle. |
| 10-16 | High | Prioritize with documented owner and validation date. |
| 17-25 | Critical | Treat as urgent; reduce exposure before normal operations continue. |

## Baseline Risk Register

| Threat Event | Likelihood | Impact | Risk | Primary Controls | Verification Evidence |
| --- | ---: | ---: | ---: | --- | --- |
| Customer disables or tampers with client billing agent | 4 | 4 | 16 High | Standard user sessions, WDAC/AppLocker, service ACLs, integrity monitor | Service status logs, file hash deltas, application-control events |
| Customer runs unsigned tool from USB or downloads | 4 | 3 | 12 High | USB policy, DNS filtering, download controls, application control | Device-control logs, DNS logs, blocked execution events |
| Billing database reachable from client VLAN | 3 | 5 | 15 High | VLAN isolation, firewall allowlist, database account restrictions | Firewall rules, connection logs, network scan from client VLAN |
| Shared cashier credentials used for unauthorized adjustment | 3 | 5 | 15 High | Named accounts, MFA, role-based access, audit review | Account list, adjustment logs, identity provider logs |
| Remote support account abused outside maintenance window | 3 | 5 | 15 High | MFA, time-bound access, named vendor accounts, session logging | VPN logs, remote tool logs, access approvals |
| Golden image modified without review | 2 | 5 | 10 High | Image signing, build notes, restricted deployment share, restore tests | Image hash, change ticket, restore validation |
| Logs cleared after local compromise | 3 | 4 | 12 High | Centralized logging, restricted admin rights, alert on event ID 1102 | SIEM events, Windows security logs, NTP evidence |
| Ransomware encrypts billing server or backups | 2 | 5 | 10 High | Offline backups, EDR, segmentation, least privilege, restore testing | Backup logs, restore test records, security alerts |
| Guest Wi-Fi can reach management interfaces | 3 | 4 | 12 High | WLAN isolation, ACLs, management VLAN, port security | Network diagram, firewall logs, scan evidence |
| DNS hijack redirects update or support traffic | 2 | 4 | 8 Medium | Trusted DNS, locked network settings, DNS logging, TLS validation | DNS logs, endpoint policy, certificate validation records |
| Time drift undermines audit evidence | 3 | 3 | 9 Medium | NTP hierarchy, domain time policy, alert on drift | NTP logs, Windows time service events |
| Backup restore fails during incident | 3 | 5 | 15 High | Scheduled restore tests, offline copy, backup integrity checks | Restore test reports, backup verification logs |

## Control Objectives

The following objectives drive all later checklist files.

### 1. Treat Client PCs as Untrusted

Customer-facing PCs must not be trusted to report billing state without server-side validation. Client controls should slow abuse, generate evidence, and limit blast radius. They should not be the only revenue protection mechanism.

Minimum evidence:

- client users are not local administrators;
- billing agent files and services have restricted ACLs;
- application control policy exists for high-risk paths;
- client-to-server traffic is allowlisted;
- integrity deviations are logged centrally.

### 2. Keep Billing Authority on the Server

The billing server and database should be the source of truth. Client signals should be authenticated, validated, and reconciled against server-side state.

Minimum evidence:

- database is unreachable from client and guest networks;
- service accounts are distinct and least-privileged;
- manual financial adjustments are logged with named users;
- backups are encrypted or access-controlled and restore-tested.

### 3. Separate Business Roles

Cashier, manager, owner, vendor, and administrator privileges should be separate. Shared accounts make fraud and incident response harder.

Minimum evidence:

- named accounts exist for privileged users;
- vendor access is temporary or explicitly reviewed;
- high-risk actions require manager or owner review;
- logs identify the actor, host, time, and action.

### 4. Segment the Network

Client PCs, billing servers, admin workstations, guest Wi-Fi, CCTV, and management interfaces should not share one flat network.

Minimum evidence:

- VLAN or equivalent segmentation exists;
- firewall rules are deny-by-default between zones;
- guest Wi-Fi cannot reach internal RFC1918 ranges except approved services;
- switch, router, and firewall management interfaces are not reachable from client ports.

### 5. Preserve Evidence Before Reimaging

Restoration tools are useful for recovery but can destroy evidence. Incident response must define when to preserve logs, memory, disk images, or application exports before resetting a host.

Minimum evidence:

- staff have an incident checklist;
- log retention is centralized or exported;
- system time is synchronized;
- evidence handling procedures avoid altering original data where possible.

### 6. Validate Recovery, Not Just Backup

Backups only matter when they restore correctly. Venue operators should test realistic recovery paths for billing, database, configuration, and image systems.

Minimum evidence:

- recent successful restore test;
- offline or immutable backup copy;
- documented recovery time expectations;
- backup access limited to named administrators.

## Defensive Telemetry Priorities

For low-budget deployments, collect the following first:

1. Windows Security logs from billing servers, cashier hosts, and a representative set of client PCs.
2. Sysmon or equivalent process telemetry where operationally feasible.
3. Billing software audit exports for login, adjustment, refund, and service state events.
4. Firewall, DNS, DHCP, and VPN logs.
5. File integrity baselines for billing binaries, configuration, scripts, and deployment shares.
6. Backup job and restore-test records.

High-value Windows events for later checklists include:

- 4624 and 4625 for successful and failed logon activity;
- 4688 for process creation when enabled;
- 4697 for service installation;
- 7034, 7035, and 7036 for service state changes;
- 4657 for registry value changes when auditing is configured;
- 1102 for Windows Security log clearing.

## Out of Scope

This threat model does not authorize testing against third-party venues, vendors, or networks. It does not include exploit steps, bypass tooling, or vendor-specific vulnerability claims.

Detailed legal interpretation for Dubai, UAE, East Asia, or other jurisdictions is out of scope. This project can identify security controls and evidence needs, but operators must validate legal obligations separately.

## Validation Plan

Each checklist that follows this threat model should include:

- a control statement that maps to one or more assets or threat events above;
- a verification command, query, or manual inspection step;
- expected evidence for a pass condition;
- likely false positives or operational tradeoffs;
- references to primary sources.

Field validation should record:

- venue type and approximate host count without identifying the venue;
- control tested;
- command or procedure used;
- result;
- operational impact;
- recommended adjustment.

## References

- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- MITRE ATT&CK T1055 Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1562.001 Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1112 Modify Registry: https://attack.mitre.org/techniques/T1112/
- MITRE ATT&CK T1547 Boot or Logon Autostart Execution: https://attack.mitre.org/techniques/T1547/
- MITRE ATT&CK T1078 Valid Accounts: https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1133 External Remote Services: https://attack.mitre.org/techniques/T1133/
- MITRE ATT&CK T1195 Supply Chain Compromise: https://attack.mitre.org/techniques/T1195/
- MITRE ATT&CK T1486 Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK T1490 Inhibit System Recovery: https://attack.mitre.org/techniques/T1490/
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- NIST SP 800-30, Guide for Conducting Risk Assessments: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
- NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- Microsoft Security Compliance Toolkit and Windows security baselines: https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- Dubai Electronic Security Center: https://www.desc.gov.ae/
