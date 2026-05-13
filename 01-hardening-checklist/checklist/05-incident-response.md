# Incident Response Checklist

This checklist defines a practical incident response baseline for internet cafes, gaming venues, esports hotels, and managed shared-PC environments. It focuses on suspected billing tampering, client PC compromise, cashier account misuse, ransomware, vendor remote-access abuse, network intrusion, and physical tampering.

The goal is to help venue staff make good first decisions: preserve evidence, contain the right systems, keep customers and revenue operations safe where possible, and know when to escalate to professional responders, vendors, insurers, legal counsel, or local authorities.

This document assumes the threat model in [`00-threat-model.md`](00-threat-model.md), the Windows host baseline in [`01-windows-host.md`](01-windows-host.md), the billing software baseline in [`02-billing-software.md`](02-billing-software.md), the network isolation baseline in [`03-network-isolation.md`](03-network-isolation.md), and the physical security baseline in [`04-physical-security.md`](04-physical-security.md).

This document is not legal advice. Dubai and UAE reporting, evidence, privacy, labor, and payment obligations should be reviewed with qualified counsel and the appropriate authority or regulator.

## Threat Background

Incidents in shared-PC venues often begin as operational noise: a billing agent stops, a customer disputes session time, a cashier account performs an unusual adjustment, a client PC reboots repeatedly, a game launcher fails, a firewall rule is changed during support, or a customer finds a way to attach hardware. The first response can either preserve the truth or destroy it.

Relevant ATT&CK techniques include T1078 Valid Accounts, T1055 Process Injection, T1059 Command and Scripting Interpreter, T1105 Ingress Tool Transfer, T1021 Remote Services, T1133 External Remote Services, T1112 Modify Registry, T1543.003 Windows Service, T1562.001 Disable or Modify Tools, T1070.001 Clear Windows Event Logs, T1005 Data from Local System, T1041 Exfiltration Over C2 Channel, T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery, T1091 Replication Through Removable Media, and T1200 Hardware Additions.

## Response Principles

1. Protect people first, then preserve evidence, then restore service.
2. Do not reimage, reboot, power off, or run cleanup tools before deciding whether evidence matters.
3. Isolate systems at the network level when possible instead of immediately changing the system state.
4. Record every action, time, person, command, and observation.
5. Use known-good administrative systems and accounts.
6. Keep suspected accounts, devices, and logs available for review.
7. Escalate early when the incident affects billing integrity, personal data, payment data, ransomware, vendor access, or multiple systems.

## Severity Model

| Severity | Example | First Response | Escalation |
| --- | --- | --- | --- |
| SEV-1 Critical | Ransomware, billing database manipulation, confirmed data theft, active attacker on server, public exposure of sensitive data | Isolate affected zones, preserve evidence, activate incident lead, stop risky operations | Owner, vendor, professional IR, legal counsel, insurer, appropriate authority |
| SEV-2 High | Billing service tampering, cashier account abuse, unauthorized remote access, multiple compromised clients | Contain affected hosts, preserve logs, suspend suspect accounts, begin timeline | Owner, vendor, IT contractor, possible professional IR |
| SEV-3 Medium | Single suspicious client PC, unknown USB device, blocked execution, unusual DNS or firewall activity | Isolate host, collect triage evidence, review logs | Shift manager, IT contractor |
| SEV-4 Low | Failed login noise, one-off service restart with known cause, policy misconfiguration | Document and correct, monitor recurrence | Normal maintenance owner |

## First 15 Minutes

- [ ] **IR-01: Assign one incident lead before technical work begins.**
  - Risk: Multiple staff members changing systems independently can destroy evidence and create conflicting timelines.
  - Recommended action: Name one incident lead for the shift. All staff should report observations and actions to that person.
  - Verification: Incident record includes incident lead, start time, affected systems, and initial classification.
  - References: NIST SP 800-61 Rev. 3, NIST CSF 2.0 RS.MA.

- [ ] **IR-02: Open an incident log immediately.**
  - Risk: Memory-based reconstruction after the event will miss actions, times, and evidence sources.
  - Recommended action: Record time, reporter, symptom, hostnames, IP addresses, user accounts, physical location, observed screens, and first decisions. Use UTC or clearly state the local time zone.
  - Verification: Incident log exists before containment or recovery work begins.
  - References: NIST SP 800-92, NIST SP 800-86.

- [ ] **IR-03: Classify the incident using the venue severity model.**
  - Risk: Treating a billing database event like a normal client glitch can delay escalation; treating every alert as a crisis can exhaust staff.
  - Recommended action: Assign SEV-1 through SEV-4 based on business impact, evidence of compromise, affected zones, and data sensitivity.
  - Verification: Incident record includes severity, reason, and escalation decision.
  - References: NIST SP 800-61 Rev. 3, NIST CSF 2.0 RS.AN.

- [ ] **IR-04: Preserve volatile evidence before rebooting when safe and feasible.**
  - Risk: Rebooting can destroy process, network, memory, and attacker-session evidence.
  - Recommended action: If the system is stable and safe, capture volatile triage data before rebooting: logged-in users, processes, network connections, services, time state, and recent events. Use known-good tools.
  - Verification: Triage bundle includes command output and collection time.
  - References: NIST SP 800-86, RFC 3227 evidence collection guidance.

- [ ] **IR-05: Isolate suspected hosts from the network without wiping or reimaging.**
  - Risk: Leaving a compromised host connected can allow spread; reimaging too early can destroy evidence.
  - Recommended action: Move the switch port to quarantine, disable Wi-Fi, unplug network cable, or apply a firewall block. Prefer network isolation over power-off unless encryption, destruction, or safety concerns require immediate shutdown.
  - Verification: Firewall, switch, or physical record shows isolation time and method.
  - References: NIST SP 800-61 Rev. 3, MITRE ATT&CK T1105 and T1021.

- [ ] **IR-06: Do not log in with high-value admin credentials on a suspect host.**
  - Risk: If the host is compromised, new admin logons can expose credentials or tokens.
  - Recommended action: Use a dedicated incident response account or manage containment from a known-good admin workstation, firewall, switch, or EDR console.
  - Verification: Incident log confirms no owner, domain admin, database admin, or vendor master account was used interactively on the suspect host.
  - References: MITRE ATT&CK T1078 and T1552, NIST SP 800-53 IA-5.

- [ ] **IR-07: Photograph or screenshot visible anomalies before changing them.**
  - Risk: Error messages, tamper warnings, unknown devices, ransom notes, and billing discrepancies may disappear after cleanup.
  - Recommended action: Capture screen state, physical state, visible device connections, error codes, and staff observations. Avoid including unrelated customer personal data where possible.
  - Verification: Evidence folder contains photos or screenshots with time and collector name.
  - References: NIST SP 800-86, NIST SP 800-61 Rev. 3.

- [ ] **IR-08: Notify the owner or accountable manager for SEV-1 and SEV-2 incidents.**
  - Risk: Staff may make business, legal, or vendor decisions without authority.
  - Recommended action: Escalate immediately for ransomware, billing database issues, suspected staff misuse, vendor access abuse, personal data exposure, payment data exposure, or multi-host compromise.
  - Verification: Incident log includes notification time, recipient, and decision.
  - References: NIST CSF 2.0 RS.CO and GV.RR, NIST SP 800-61 Rev. 3.

## Triage and Evidence Collection

- [ ] **IR-09: Record system identity and time state.**
  - Risk: Evidence correlation fails when hostname, IP, MAC address, serial number, and clock state are missing.
  - Recommended action: Record hostname, logged-in user, IP address, MAC address, asset tag, physical location, system time, time source, and time drift if known.
  - Verification: Triage record includes `hostname`, `whoami`, `ipconfig /all`, `Get-NetAdapter`, and `w32tm /query /status` output where feasible.
  - References: NIST SP 800-92, NIST SP 800-86.

- [ ] **IR-10: Capture process and network triage data.**
  - Risk: Suspicious process trees and outbound connections may terminate before later analysis.
  - Recommended action: Collect process list, command lines, parent process IDs, network connections, listening ports, and mapped executable paths.
  - Verification: Triage bundle includes `Get-Process`, `Get-CimInstance Win32_Process`, `Get-NetTCPConnection`, and `netstat -ano` output.
  - References: MITRE ATT&CK T1055, T1059, T1105, and T1041; NIST SP 800-86.

- [ ] **IR-11: Export Windows event logs before clearing, reimaging, or restoring.**
  - Risk: Local logs may be overwritten or destroyed during recovery.
  - Recommended action: Export Security, System, Application, PowerShell Operational, Defender Operational, AppLocker, CodeIntegrity, and relevant vendor logs to write-protected storage or a central evidence share.
  - Verification: Evidence folder includes `.evtx` exports and SHA-256 hashes for each file.
  - References: NIST SP 800-92, MITRE ATT&CK T1070.001.

- [ ] **IR-12: Preserve billing software logs and database audit records.**
  - Risk: Billing disputes and fraud investigations depend on application-level events that may not appear in Windows logs.
  - Recommended action: Export billing logins, session starts/stops, time grants, balance changes, refunds, manual overrides, service health, update logs, client check-ins, and database audit records.
  - Verification: Evidence set includes application log export, database audit export, and hash records.
  - References: NIST SP 800-92, OWASP ASVS logging requirements.

- [ ] **IR-13: Preserve network evidence for the affected time window.**
  - Risk: Firewall, DNS, DHCP, VPN, proxy, switch, and wireless logs may rotate quickly.
  - Recommended action: Export logs for at least 24 hours before first detection through the current time, or longer for SEV-1 and SEV-2 incidents.
  - Verification: Evidence set includes firewall, DNS, DHCP, VPN, switch, AP, and remote support logs where available.
  - References: NIST SP 800-92, MITRE ATT&CK T1046, T1071.004, and T1133.

- [ ] **IR-14: Preserve camera footage for physical or cashier-related incidents.**
  - Risk: CCTV retention may overwrite footage before review.
  - Recommended action: Export relevant footage for suspected device tampering, cashier disputes, server room access, vendor visits, theft, or customer conflicts. Avoid exporting unrelated footage.
  - Verification: Evidence record includes camera IDs, time range, export hash, approver, and storage location.
  - References: NIST SP 800-86, NIST SP 800-53 PE-6 and AU-9.

- [ ] **IR-15: Hash collected evidence and keep chain-of-custody notes.**
  - Risk: Evidence may be challenged or become unreliable if it cannot be shown to be unchanged.
  - Recommended action: Calculate SHA-256 hashes for exported logs, reports, disk images, memory captures, screenshots, and footage. Record collector, time, source, destination, and hash.
  - Verification: Evidence manifest includes file path, size, SHA-256 hash, collector, and transfer notes.
  - References: NIST SP 800-86, NIST SP 800-61 Rev. 3.

- [ ] **IR-16: Use trained responders for memory acquisition and disk imaging.**
  - Risk: Poorly executed acquisition can alter evidence, crash systems, expose sensitive data, or miss encrypted state.
  - Recommended action: For SEV-1 and SEV-2 incidents, use trained staff, an IT contractor, or a professional IR provider to acquire memory or forensic disk images with validated tools and sterile storage.
  - Verification: Acquisition notes include tool name and version, operator, start and end time, source device, destination device, hash, and any errors.
  - References: NIST SP 800-86, NIST SP 800-61 Rev. 3.

- [ ] **IR-17: Preserve suspected removable media and hardware devices without plugging them into production systems.**
  - Risk: Unknown USB drives, adapters, or mini-routers can execute code, alter evidence, or spread malware.
  - Recommended action: Bag, label, and store devices. Analyze only in an isolated lab or with professional support.
  - Verification: Evidence log includes device description, location found, finder, time, and storage location.
  - References: MITRE ATT&CK T1091 and T1200, NIST SP 800-86.

## Containment

- [ ] **IR-18: Contain by zone, not only by host, when multiple systems may be affected.**
  - Risk: Isolating one visible host may miss lateral movement through client, cashier, server, or remote access paths.
  - Recommended action: For SEV-1 and SEV-2 incidents, review whether the affected VLAN, remote access account, vendor tool, or shared credential should be temporarily blocked.
  - Verification: Containment record includes affected zones, firewall rules, switch changes, accounts disabled, and expected business impact.
  - References: NIST SP 800-61 Rev. 3, NIST SP 800-207.

- [ ] **IR-19: Suspend suspect accounts and active sessions.**
  - Risk: Valid accounts can remain active after the host is isolated.
  - Recommended action: Disable or reset suspect staff, vendor, local admin, VPN, billing admin, database, and remote support accounts. Preserve account state and logs first where feasible.
  - Verification: Identity or application logs show disablement, password reset, token revocation, or session termination time.
  - References: MITRE ATT&CK T1078, NIST SP 800-53 AC-2.

- [ ] **IR-20: Disable unauthorized remote access paths.**
  - Risk: Attackers or misused vendor accounts may reconnect after local containment.
  - Recommended action: Review VPN, RDP gateway, remote support tools, NAT rules, firewall rules, and vendor accounts. Disable unknown or unnecessary paths.
  - Verification: Remote access inventory and firewall rules reflect approved access only.
  - References: MITRE ATT&CK T1133 and T1021, NIST SP 800-207.

- [ ] **IR-21: Stop active data loss or encryption without destroying evidence unnecessarily.**
  - Risk: Ransomware or exfiltration can continue during analysis, but uncontrolled shutdown can lose volatile evidence.
  - Recommended action: If encryption or exfiltration is active, isolate the network path immediately. Power down only when continued operation is likely to cause greater harm and the decision is recorded.
  - Verification: Incident log records why network isolation or power-off was chosen.
  - References: NIST SP 800-61 Rev. 3, CISA ransomware guidance, MITRE ATT&CK T1486 and T1041.

- [ ] **IR-22: Preserve backups before restoring from them.**
  - Risk: Ransomware or destructive actors may target backups, and rushed restore can overwrite the last clean recovery point.
  - Recommended action: Protect backup repositories, disconnect offline media, verify backup integrity, and identify the last known-good restore point before any restore.
  - Verification: Backup manifest includes protected copies, restore candidate, verification result, and responsible approver.
  - References: NIST SP 800-34, MITRE ATT&CK T1490.

- [ ] **IR-23: Use a clean administrative workstation for response work.**
  - Risk: Responding from a compromised or customer-facing PC can expose credentials and contaminate evidence.
  - Recommended action: Use a known-good admin host on the management VLAN or a freshly prepared response laptop. Avoid browsing, email, and chat on affected systems.
  - Verification: Incident record identifies the response workstation and network used.
  - References: NIST SP 800-61 Rev. 3, NIST SP 800-53 AC-6.

## Scenario Playbooks

- [ ] **IR-24: Billing agent stopped or tampered on a client PC.**
  - Risk: The incident may indicate customer tampering, policy drift, malware, or a wider billing-agent failure.
  - Recommended action: Isolate the client, preserve billing agent logs, Windows service events, process data, file hashes, AppLocker or WDAC events, and camera footage for the session area. Compare the client with a known-good baseline before reimaging.
  - Verification: Evidence includes service events 7034, 7035, 7036, 7045 where available, billing agent logs, hashes, and restoration decision.
  - References: MITRE ATT&CK T1562.001, T1543.003, and T1112.

- [ ] **IR-25: Suspicious cashier adjustment, refund, or free-time grant.**
  - Risk: Insider misuse or account compromise can directly affect revenue and trust.
  - Recommended action: Preserve billing audit logs, cashier workstation logs, account login history, camera footage for the counter, and manager approval records. Suspend account access only after preserving key logs where feasible.
  - Verification: Timeline links user, workstation, transaction, camera range, and approval state.
  - References: MITRE ATT&CK T1078, NIST SP 800-92.

- [ ] **IR-26: Unauthorized vendor or remote support access.**
  - Risk: Vendor access can reach high-trust systems and may bypass normal staff workflows.
  - Recommended action: Disable the session, preserve VPN and remote tool logs, identify commands or file transfers, contact the vendor through a known channel, and review changes made during the session.
  - Verification: Evidence includes remote session ID, account, source IP, start and end time, affected systems, and vendor ticket.
  - References: MITRE ATT&CK T1133 and T1021, NIST SP 800-53 AC-17.

- [ ] **IR-27: Ransomware or destructive change.**
  - Risk: Rapid spread can affect billing, backups, client images, and cashier operations.
  - Recommended action: Isolate affected zones, protect backups, preserve ransom note and logs, do not pay or negotiate without owner, legal, insurer, and professional guidance, and identify the last known-good backup.
  - Verification: Incident record includes containment time, affected shares, backup state, ransom note hash, and professional escalation decision.
  - References: CISA ransomware guidance, NIST SP 800-61 Rev. 3, MITRE ATT&CK T1486 and T1490.

- [ ] **IR-28: Suspected database manipulation or billing inconsistency.**
  - Risk: Direct database edits or application logic abuse can cause financial loss and unreliable records.
  - Recommended action: Stop nonessential changes, preserve database audit logs, billing application logs, backup snapshots, and reporting exports. Use read-only analysis copies where possible.
  - Verification: Evidence includes affected tables or reports, backup candidate, database audit export, and reconciliation notes.
  - References: MITRE ATT&CK T1565, OWASP Database Security Cheat Sheet, NIST SP 800-92.

- [ ] **IR-29: Unknown USB device, inline adapter, or physical tampering.**
  - Risk: Hardware additions can support malware, credential capture, network bridging, or data theft.
  - Recommended action: Photograph the scene, preserve the device without plugging it in, isolate the associated host, export logs, and review camera footage.
  - Verification: Evidence includes device description, photo, location, host identity, collector, and storage location.
  - References: MITRE ATT&CK T1200, T1091, and T1052; NIST SP 800-86.

- [ ] **IR-30: Guest Wi-Fi or customer network abuse complaint.**
  - Risk: Abuse complaints can create legal, reputation, or ISP risk even when billing systems are not affected.
  - Recommended action: Preserve DHCP leases, NAT logs, DNS logs, firewall logs, captive portal logs where applicable, and camera footage only if lawful and relevant. Do not accuse customers without evidence.
  - Verification: Timeline links public IP, internal IP, MAC address, lease time, DNS or firewall activity, and retention status.
  - References: NIST SP 800-92, NIST SP 800-41, MITRE ATT&CK T1071.004.

## Eradication and Recovery

- [ ] **IR-31: Identify root cause before broad reimaging or service restoration.**
  - Risk: Reimaging without root cause may return compromised accounts, update channels, firewall paths, or vendor access to production.
  - Recommended action: Determine the likely entry path, affected accounts, affected hosts, persistence mechanism, and configuration drift before declaring recovery.
  - Verification: Incident report includes root cause or documented best-known hypothesis with residual risk.
  - References: NIST SP 800-61 Rev. 3, NIST CSF 2.0 RS.AN and RC.RP.

- [ ] **IR-32: Rebuild compromised hosts from known-good images or trusted media.**
  - Risk: Cleaning individual files may miss persistence, altered services, or unauthorized configuration.
  - Recommended action: For confirmed compromise, rebuild from a known-good image, trusted installer, or vendor-supported recovery path after evidence preservation.
  - Verification: Rebuilt host passes post-restore validation: services, Defender/EDR, application control, time sync, billing connectivity, and file hashes.
  - References: NIST SP 800-128, NIST SP 800-61 Rev. 3.

- [ ] **IR-33: Rotate credentials that could have been exposed.**
  - Risk: Attackers may return with captured staff, local admin, database, VPN, vendor, or service credentials.
  - Recommended action: Rotate passwords, tokens, API keys, local admin passwords, database credentials, VPN secrets, and vendor remote support credentials based on exposure scope.
  - Verification: Credential rotation record includes account, owner, system, rotation time, and validation result.
  - References: MITRE ATT&CK T1552 and T1078, NIST SP 800-53 IA-5.

- [ ] **IR-34: Validate billing data after recovery.**
  - Risk: Restoring service without financial reconciliation can hide revenue loss or incorrect customer balances.
  - Recommended action: Reconcile session records, balance changes, refunds, free-time grants, backup restore point, and accounting exports for the affected window.
  - Verification: Reconciliation record includes affected period, data sources, discrepancies, and owner approval.
  - References: NIST SP 800-92, OWASP ASVS logging requirements.

- [ ] **IR-35: Monitor aggressively after reopening affected systems.**
  - Risk: Persistence or stolen credentials may trigger a second incident after visible recovery.
  - Recommended action: Add temporary alerts for affected accounts, hosts, billing services, database logins, remote access, unusual DNS, and blocked application-control events.
  - Verification: Monitoring plan includes alert owners, expiration date, and review cadence.
  - References: NIST SP 800-61 Rev. 3, NIST CSF 2.0 DE.CM.

## Escalation, Reporting, and Communication

- [ ] **IR-36: Escalate to a professional incident response provider when scope or evidence exceeds local capability.**
  - Risk: Small venues may accidentally destroy evidence or miss lateral movement during serious incidents.
  - Recommended action: Use professional support for ransomware, suspected data theft, billing database compromise, server compromise, vendor remote-access compromise, multi-host compromise, or payment data exposure.
  - Verification: Incident record includes escalation decision, provider contacted, time, and owner approval.
  - References: NIST SP 800-61 Rev. 3, CISA incident response resources.

- [ ] **IR-37: Contact the billing software vendor through a known trusted channel when product behavior is involved.**
  - Risk: Attackers may impersonate vendor support, and informal chats can lose important evidence.
  - Recommended action: Use official support contacts, reference a ticket number, preserve all vendor communications, and ask for written change notes.
  - Verification: Incident file includes vendor ticket, contact identity, communications, and change record.
  - References: NIST SP 800-218 SSDF supplier relationship concepts, NIST SP 800-61 Rev. 3.

- [ ] **IR-38: Consider legal, insurer, regulator, and authority notification for serious incidents.**
  - Risk: Data exposure, payment impact, extortion, theft, or customer harm may create reporting obligations.
  - Recommended action: For SEV-1 or sensitive-data incidents, involve the owner, legal counsel, insurer, and appropriate local authority. In Dubai, public reporting paths may include Dubai Police eCrime services and the UAE Cybersecurity Council report-an-incident service, depending on incident type and business status.
  - Verification: Incident record includes who was consulted, what decision was made, and when.
  - References: Dubai Police eCrime services, UAE Cybersecurity Council resources, NIST SP 800-61 Rev. 3.

- [ ] **IR-39: Use controlled communication with staff and customers.**
  - Risk: Rumors, blame, or premature claims can harm the investigation and the business.
  - Recommended action: Prepare short factual updates: what is affected, what staff should do, what customers should avoid, and when the next update will occur. Do not speculate about attribution.
  - Verification: Communications are approved by the owner or incident lead and stored in the incident record.
  - References: NIST CSF 2.0 RS.CO, NIST SP 800-61 Rev. 3.

- [ ] **IR-40: Do not publicly name vendors, customers, staff, or suspected actors without approval and evidence.**
  - Risk: Irresponsible attribution can create legal and reputational harm and reduce vendor cooperation.
  - Recommended action: Keep public statements vendor-neutral unless coordinated disclosure, legal review, or law enforcement process requires specificity.
  - Verification: Incident report separates facts, hypotheses, and unresolved questions.
  - References: CERT/CC Coordinated Vulnerability Disclosure guidance, NIST SP 800-61 Rev. 3.

## Post-Incident Improvement

- [ ] **IR-41: Conduct a lessons-learned review after every SEV-1, SEV-2, and repeated SEV-3 incident.**
  - Risk: Incidents repeat when the venue restores service but never fixes the control gap.
  - Recommended action: Review timeline, root cause, controls that worked, controls that failed, missing logs, staff decisions, vendor behavior, and follow-up tasks.
  - Verification: Lessons-learned report has owners, due dates, and retest criteria.
  - References: NIST SP 800-61 Rev. 3, NIST CSF 2.0 IM.

- [ ] **IR-42: Convert incident findings into hardening backlog items.**
  - Risk: Security findings disappear into narrative reports without becoming operational improvements.
  - Recommended action: Create backlog items for firewall changes, audit policy, application control, account cleanup, backup changes, vendor requirements, staff training, and physical fixes.
  - Verification: Each accepted finding maps to an owner, priority, deadline, and validation method.
  - References: NIST CSF 2.0 GV.OV and ID.IM, NIST SP 800-128.

- [ ] **IR-43: Run tabletop exercises for the highest-risk scenarios.**
  - Risk: Staff will not perform well under pressure if the first rehearsal happens during a real outage.
  - Recommended action: Practice ransomware, billing database inconsistency, cashier account misuse, vendor remote-access abuse, unknown USB device, and guest Wi-Fi abuse complaint scenarios.
  - Verification: Exercise record includes scenario, participants, decisions, gaps, and follow-up tasks.
  - References: NIST SP 800-61 Rev. 3, CISA incident response playbooks.

- [ ] **IR-44: Update contact lists and authority matrix quarterly.**
  - Risk: Response slows down when owner, vendor, ISP, insurer, legal, police, or IR provider contacts are missing or outdated.
  - Recommended action: Maintain an offline and online contact list with primary and backup contacts, support hours, contract numbers, escalation rules, and approved decision makers.
  - Verification: Quarterly review record confirms contacts and authority levels.
  - References: NIST SP 800-61 Rev. 3, NIST CSF 2.0 GV.RR.

## Evidence Collection Quick Commands

Use these commands only on systems the venue owns or is authorized to inspect. Store outputs on controlled media or a protected evidence share. Calculate hashes after collection.

```powershell
# Create a basic evidence directory with local timestamp.
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dest = "C:\IR-Evidence\$env:COMPUTERNAME-$stamp"
New-Item -ItemType Directory -Force -Path $dest

# System identity and time state.
hostname | Out-File "$dest\hostname.txt"
whoami /all | Out-File "$dest\whoami-all.txt"
ipconfig /all | Out-File "$dest\ipconfig-all.txt"
w32tm /query /status | Out-File "$dest\w32tm-status.txt"

# Process and network triage.
Get-CimInstance Win32_Process |
    Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
    Export-Csv "$dest\processes.csv" -NoTypeInformation
Get-NetTCPConnection |
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
    Export-Csv "$dest\net-connections.csv" -NoTypeInformation
netstat -ano | Out-File "$dest\netstat-ano.txt"

# Services and scheduled tasks.
Get-CimInstance Win32_Service |
    Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
    Export-Csv "$dest\services.csv" -NoTypeInformation
Get-ScheduledTask | Export-Clixml "$dest\scheduled-tasks.xml"

# Export key Windows event logs.
wevtutil epl Security "$dest\Security.evtx"
wevtutil epl System "$dest\System.evtx"
wevtutil epl Application "$dest\Application.evtx"
wevtutil epl "Microsoft-Windows-PowerShell/Operational" "$dest\PowerShell-Operational.evtx"
wevtutil epl "Microsoft-Windows-Windows Defender/Operational" "$dest\Defender-Operational.evtx"

# Hash collected files.
Get-ChildItem -Path $dest -File |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv "$dest\sha256-manifest.csv" -NoTypeInformation
```

## Minimum Incident Record

Every incident record should include:

- incident ID, date, time zone, severity, incident lead, and owner;
- reporter, affected systems, affected accounts, affected zones, and affected business process;
- first observed symptom and suspected start time;
- containment actions with exact time and actor;
- evidence collected, hashes, storage location, and chain-of-custody notes;
- vendor, contractor, legal, insurer, authority, or professional IR contacts;
- recovery actions, validation results, and residual risk;
- customer or staff communication summary;
- lessons learned and backlog items.

## When to Escalate

Escalate beyond local staff when any of the following are true:

- billing database integrity is uncertain;
- ransomware, extortion, or destructive activity is suspected;
- payment card data or personal data may be exposed;
- a server, backup system, log collector, network device, or remote access gateway may be compromised;
- vendor remote access may have been misused;
- multiple client PCs show related compromise indicators;
- staff misuse or insider fraud is suspected;
- evidence may be needed for insurance, legal, regulatory, or law-enforcement action;
- local staff cannot preserve evidence without risking data loss or business disruption.

## References

- CafeSec Lab threat model foundation: `00-threat-model.md`
- CafeSec Lab Windows host hardening checklist: `01-windows-host.md`
- CafeSec Lab billing software security checklist: `02-billing-software.md`
- CafeSec Lab network isolation checklist: `03-network-isolation.md`
- CafeSec Lab physical security checklist: `04-physical-security.md`
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- MITRE ATT&CK T1078 Valid Accounts: https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1055 Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1059 Command and Scripting Interpreter: https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1021 Remote Services: https://attack.mitre.org/techniques/T1021/
- MITRE ATT&CK T1133 External Remote Services: https://attack.mitre.org/techniques/T1133/
- MITRE ATT&CK T1112 Modify Registry: https://attack.mitre.org/techniques/T1112/
- MITRE ATT&CK T1543.003 Windows Service: https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK T1562.001 Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1070.001 Clear Windows Event Logs: https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK T1005 Data from Local System: https://attack.mitre.org/techniques/T1005/
- MITRE ATT&CK T1041 Exfiltration Over C2 Channel: https://attack.mitre.org/techniques/T1041/
- MITRE ATT&CK T1486 Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK T1490 Inhibit System Recovery: https://attack.mitre.org/techniques/T1490/
- MITRE ATT&CK T1091 Replication Through Removable Media: https://attack.mitre.org/techniques/T1091/
- MITRE ATT&CK T1200 Hardware Additions: https://attack.mitre.org/techniques/T1200/
- NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response: https://csrc.nist.gov/pubs/sp/800/86/final
- NIST SP 800-92, Guide to Computer Security Log Management: https://csrc.nist.gov/publications/detail/sp/800-92/final
- NIST SP 800-34 Rev. 1, Contingency Planning Guide: https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final
- NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy: https://csrc.nist.gov/pubs/sp/800/41/r1/final
- NIST SP 800-128, Guide for Security-Focused Configuration Management: https://csrc.nist.gov/publications/detail/sp/800-128/final
- NIST SP 800-207, Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- CISA Cybersecurity Incident and Vulnerability Response Playbooks: https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks
- CISA StopRansomware Guide: https://www.cisa.gov/stopransomware
- CERT/CC Coordinated Vulnerability Disclosure Guide: https://certcc.github.io/CERT-Guide-to-CVD/
- OWASP Application Security Verification Standard: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Database Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- Dubai Police eCrime service, as listed by the UAE Cybersecurity Council: https://www.ecrime.ae/
- UAE Cybersecurity Council report an incident: https://csc.gov.ae/en/report-an-incident
- Dubai Electronic Security Center incident reporting: https://www.desc.gov.ae/incident-reporting/
- RFC 3227, Guidelines for Evidence Collection and Archiving: https://www.rfc-editor.org/rfc/rfc3227
