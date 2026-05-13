# Billing Software Security Checklist

This checklist defines vendor-neutral security expectations for internet cafe and gaming venue billing software. It is intended for operators, IT contractors, SOC teams, and software vendors who need a practical way to evaluate deployment risk without publishing bypass techniques.

The checklist applies to billing servers, client agents, cashier applications, manager consoles, databases, update mechanisms, licensing components, reporting exports, and vendor remote-support workflows. It assumes the threat model in [`00-threat-model.md`](00-threat-model.md) and the Windows host baseline in [`01-windows-host.md`](01-windows-host.md).

Commands and queries are examples. Replace placeholders such as `<billing-server>`, `<db-port>`, `<billing-service>`, `<database-name>`, and `<vendor-update-url>` with deployment-specific values.

## Threat Background

Billing software is the business-control plane for a venue. It decides who can start a session, how time and balance are recorded, which host is available, how staff perform manual adjustments, and what evidence exists when a dispute or incident occurs.

The main defensive concern is misplaced trust. A secure deployment should not assume that customer-facing client PCs, local configuration files, or unauthenticated network messages are trustworthy. The server and database should be the source of truth, and every privileged action should be attributable to a named identity.

Relevant ATT&CK techniques include T1078 Valid Accounts, T1055 Process Injection, T1112 Modify Registry, T1543.003 Windows Service, T1562.001 Disable or Modify Tools, T1565 Data Manipulation, T1021 Remote Services, T1105 Ingress Tool Transfer, T1195 Supply Chain Compromise, and T1486 Data Encrypted for Impact.

## Architectural Baseline

| Component | Defensive Expectation |
| --- | --- |
| Billing server | Authoritative state, minimal exposed ports, central audit trail, restricted admin access. |
| Database | Isolated network reachability, least-privilege accounts, encrypted connections, tested backups. |
| Client agent | No local authority over billing state, protected files and services, authenticated server communication. |
| Cashier application | Named staff accounts, role separation, strong audit logs, no direct unmanaged database access. |
| Update system | Signed packages, integrity verification, staged deployment, rollback and vendor accountability. |
| Reporting exports | Access-controlled, integrity-checked, retained according to business and legal requirements. |
| Vendor access | Named, time-bound, strongly authenticated, logged, and reviewed. |

## Checklist

### Deployment Architecture and Trust Boundaries

- [ ] **BS-01: Document the billing architecture before hardening controls are selected.**
  - Risk: Operators cannot defend an architecture they cannot describe. Unknown client-server paths, database paths, update paths, and remote support paths create blind spots.
  - Recommended configuration: Maintain a diagram that includes client PCs, billing servers, cashier hosts, database services, update sources, license servers, backup targets, remote support channels, and network zones.
  - Verification: Compare the diagram against `Get-NetTCPConnection`, firewall logs, switch ACLs, DNS records, and vendor documentation. Investigate any connection that is not on the diagram.
  - References: NIST CSF 2.0 ID.AM, OWASP ASVS architecture requirements, CISA Secure by Design guidance.

- [ ] **BS-02: Treat client PCs as untrusted inputs, not billing authorities.**
  - Risk: If the server accepts local client state as authoritative, tampering with a customer-facing PC can become revenue manipulation.
  - Recommended configuration: The server should independently validate session state, time accounting, balance changes, device identity, and policy decisions. Client messages should be authenticated and bounded by server-side rules.
  - Verification: Ask the vendor which billing fields are accepted from the client without server-side recomputation. Review server logs for authoritative decision points and failed validation events.
  - References: OWASP ASVS trust-boundary requirements, MITRE ATT&CK T1565 Data Manipulation.

- [ ] **BS-03: Separate client, cashier, manager, server, and database trust zones.**
  - Risk: A flat deployment lets a customer endpoint reach administrative services or database ports directly.
  - Recommended configuration: Place client PCs, cashier workstations, billing servers, databases, and management interfaces in separate network zones with explicit allow rules.
  - Verification: From a client PC, run `Test-NetConnection <billing-server> -Port <db-port>` and confirm database ports are blocked. Repeat from cashier and server roles according to the approved matrix.
  - References: NIST SP 800-41 firewall guidance, MITRE ATT&CK T1021 Remote Services and T1046 Network Service Discovery.

- [ ] **BS-04: Require a vendor-supported least-privilege deployment mode.**
  - Risk: Legacy billing systems sometimes require local administrator rights, shared service accounts, or broad database privileges because the installer was never threat-modeled.
  - Recommended configuration: Ask vendors to document required Windows privileges, service accounts, database permissions, firewall rules, file ACLs, registry ACLs, and update privileges. Reject undocumented "run everything as administrator" guidance for production.
  - Verification: Review vendor deployment documentation and compare it with actual service accounts, `icacls`, `sc.exe sdshow`, firewall rules, and database grants.
  - References: NIST SP 800-218 SSDF, NIST SP 800-53 AC-6, OWASP ASVS.

- [ ] **BS-05: Define authoritative roles for financial and session changes.**
  - Risk: Unclear authority over refunds, free time, balance corrections, and session overrides makes fraud and incident response difficult.
  - Recommended configuration: Configure role-based access for cashier, shift manager, owner, technician, and vendor roles. High-risk actions should require named users and manager review.
  - Verification: Export the billing software role matrix and compare it with the last 30 days of adjustment, refund, and override logs.
  - References: NIST SP 800-53 AC-2, AC-5, AU-2; MITRE ATT&CK T1078.

- [ ] **BS-06: Remove direct database access from cashier and client workflows.**
  - Risk: Direct SQL access from cashier or client systems bypasses application validation and increases the impact of endpoint compromise.
  - Recommended configuration: Cashier and client applications should communicate with an application service, not directly with the database, unless a documented compensating control exists.
  - Verification: Review connection strings, firewall rules, process network connections, and database login sources. Query database audit logs for logins from cashier or client subnets.
  - References: OWASP Database Security Cheat Sheet, OWASP ASVS data protection requirements, MITRE ATT&CK T1005 Data from Local System.

### Database Security

- [ ] **BS-07: Use distinct database accounts for application, reporting, backup, and administration.**
  - Risk: A single shared database account makes compromise harder to contain and user actions harder to attribute.
  - Recommended configuration: Create separate accounts with least privilege for runtime application access, read-only reporting, backup jobs, schema migration, and administration. Human administrators should use named accounts.
  - Verification: Review database users, roles, and grants. Confirm the application account cannot perform administrative actions such as creating users, disabling audit, or modifying unrelated schemas.
  - References: OWASP Database Security Cheat Sheet, NIST SP 800-53 AC-6, Microsoft SQL Server security best practices or the relevant database vendor guidance.

- [ ] **BS-08: Restrict database network reachability to approved servers only.**
  - Risk: Exposed database ports let compromised clients, guest Wi-Fi devices, or cashier hosts attempt direct authentication or discovery.
  - Recommended configuration: Bind the database to the server network only. Use host firewall rules and network ACLs so only approved application servers and backup hosts can connect.
  - Verification: Run connection tests from client, cashier, guest, and server zones. Review database listener bindings and firewall logs.
  - References: NIST SP 800-41, OWASP Database Security Cheat Sheet, MITRE ATT&CK T1046.

- [ ] **BS-09: Encrypt database connections where supported.**
  - Risk: Cleartext database traffic exposes credentials, session data, customer records, and financial records to network interception.
  - Recommended configuration: Use TLS for database connections with certificate validation. Avoid "trust server certificate" production settings unless there is a documented temporary exception.
  - Verification: Review database server TLS settings, client connection strings, and packet-capture evidence from a maintenance window. Confirm certificates are valid and not self-signed without trust management.
  - References: NIST SP 800-52 Rev. 2 TLS guidance, database vendor TLS documentation, MITRE ATT&CK T1557 Adversary-in-the-Middle.

- [ ] **BS-10: Protect connection strings and secrets outside source, scripts, and shared folders.**
  - Risk: Plain-text credentials in configuration files, deployment scripts, or shared folders are easy to reuse after a workstation compromise.
  - Recommended configuration: Store secrets in a controlled secret store, encrypted configuration mechanism, Windows DPAPI-protected store, or vendor-supported equivalent. Limit read access to the service identity.
  - Verification: Search deployment directories for connection strings and secrets with approved internal tooling. Review ACLs with `icacls` and confirm only the service account and administrators can read sensitive configuration.
  - References: MITRE ATT&CK T1552 Unsecured Credentials, OWASP Secrets Management Cheat Sheet, NIST SP 800-53 IA-5.

- [ ] **BS-11: Enable database auditing for privileged and financially relevant actions.**
  - Risk: Without database audit logs, direct edits, schema changes, privilege changes, and suspicious access may not be attributable.
  - Recommended configuration: Audit login failures, privileged logins, role changes, schema changes, direct table updates to billing-sensitive tables, backup operations, and audit configuration changes.
  - Verification: Review database audit configuration and generate a controlled test event, such as a failed login from an admin workstation, to confirm collection.
  - References: NIST SP 800-92 log management guidance, OWASP Database Security Cheat Sheet, MITRE ATT&CK T1565.

- [ ] **BS-12: Validate backup integrity with restore tests, not just successful jobs.**
  - Risk: A backup that cannot restore does not reduce ransomware, hardware failure, or accidental corruption risk.
  - Recommended configuration: Perform scheduled restore tests for the billing database and application configuration. Store at least one backup copy offline or in immutable storage.
  - Verification: Record restore-test date, target environment, database checksum or consistency check result, application startup result, and recovery time.
  - References: NIST SP 800-34 contingency planning guidance, MITRE ATT&CK T1486 and T1490.

### Client-Server Communication Integrity

- [ ] **BS-13: Require TLS for client-server communication.**
  - Risk: Cleartext billing traffic can expose session data and make tampering or replay easier on flat or compromised networks.
  - Recommended configuration: Use TLS 1.2 or newer with validated server certificates. Prefer TLS 1.3 where supported. Disable obsolete protocols and weak cipher suites.
  - Verification: Test the billing endpoint with an approved TLS scanner in a maintenance window. Confirm client configuration validates the server certificate and does not silently accept invalid certificates.
  - References: NIST SP 800-52 Rev. 2, OWASP ASVS transport security requirements.

- [ ] **BS-14: Authenticate clients and devices before accepting sensitive state changes.**
  - Risk: If any host can send billing-state messages, unauthorized devices or spoofed clients can affect operations.
  - Recommended configuration: Use per-device identities, certificates, signed enrollment tokens, or a vendor-supported device registration flow. Device identity should be revocable when a PC is retired or reimaged.
  - Verification: Attempt to register a test host through the documented process and confirm approval, logging, and revocation behavior. Review the device inventory against physical asset records.
  - References: OWASP ASVS authentication requirements, NIST SP 800-63B-4, MITRE ATT&CK T1078.

- [ ] **BS-15: Protect message integrity and replay resistance for billing-sensitive actions.**
  - Risk: TLS protects the channel, but applications still need to prevent duplicated, stale, or reordered business actions.
  - Recommended configuration: Billing-sensitive messages should include server-side authorization, timestamps, nonces or sequence numbers, and integrity checks such as HMAC or digital signatures where appropriate.
  - Verification: Ask the vendor to document replay protection and message validation. Review server logs for rejected stale, duplicate, or invalid messages without attempting live abuse against production.
  - References: OWASP ASVS session and business-logic requirements, CWE-345 Insufficient Verification of Data Authenticity, CWE-294 Authentication Bypass by Capture-replay.

- [ ] **BS-16: Fail closed when the billing server cannot validate client state.**
  - Risk: Fail-open behavior during network loss, time drift, or server unavailability can create billing disputes and abuse opportunities.
  - Recommended configuration: Define fail-closed behavior for session start, session extension, time grants, and privileged overrides. For customer experience, provide a controlled staff override that is logged and time-limited.
  - Verification: In a test environment, disconnect a pilot client from the billing server and confirm the documented behavior. Review logs for both the client and server.
  - References: OWASP ASVS business-logic requirements, NIST SP 800-160 secure system design concepts.

- [ ] **BS-17: Bind session state to both user/account context and device context.**
  - Risk: Session state that is only tied to a local process, local file, or weak client identifier can be misattributed or duplicated.
  - Recommended configuration: The server should bind active sessions to account, host identity, start time, authorized duration, pricing rule, and staff override status.
  - Verification: Review exported session records and confirm they include account, host, timestamp, pricing rule, and staff actor where relevant.
  - References: OWASP ASVS logging and business-logic requirements, NIST SP 800-92.

### Binary, Service, and Process Protection

- [ ] **BS-18: Verify digital signatures for vendor binaries and installers.**
  - Risk: Unsigned or unexpectedly signed binaries are harder to trust and easier to replace without immediate detection.
  - Recommended configuration: Require vendors to sign production binaries and installers. Record expected publisher names and hashes for critical components.
  - Verification: Run `Get-AuthenticodeSignature <path>` and `Get-FileHash <path> -Algorithm SHA256` for billing server, client agent, cashier application, updater, and driver components.
  - References: Microsoft Authenticode documentation, NIST SP 800-218 SSDF, SLSA provenance guidance.

- [ ] **BS-19: Restrict write access to billing binaries, plugins, scripts, and drivers.**
  - Risk: Writable application paths allow binary replacement, DLL hijacking, script tampering, or unauthorized plugin installation.
  - Recommended configuration: Grant write access only to trusted installers, update services, and approved administrators. Standard users and cashier users should not modify application directories.
  - Verification: Run `icacls "<billing-install-path>"` and review write permissions for `Users`, `Authenticated Users`, staff groups, and service accounts.
  - References: MITRE ATT&CK T1574 Hijack Execution Flow, NIST SP 800-53 CM-5, OWASP ASVS configuration requirements.

- [ ] **BS-20: Protect billing services from unauthorized stop, delete, or reconfiguration.**
  - Risk: Stopping or reconfiguring a billing service can create a blind spot or directly interrupt revenue operations.
  - Recommended configuration: Restrict service control permissions, configure service recovery, and alert on service creation, stop, crash, or configuration changes.
  - Verification: Run `sc.exe sdshow <billing-service>`, `sc.exe qfailure <billing-service>`, and query System events 7034, 7035, 7036, and 7045.
  - References: MITRE ATT&CK T1562.001 and T1543.003, Microsoft service security documentation.

- [ ] **BS-21: Use watchdog or supervisor services with clear limits.**
  - Risk: A single agent process can be stopped or crash without immediate operator awareness.
  - Recommended configuration: Use a vendor-supported watchdog, supervisor service, or health-check mechanism that restarts failed components and reports health centrally. The watchdog must not run with broader privileges than necessary.
  - Verification: Review service dependencies, recovery settings, health-check logs, and central status dashboards. Confirm failure events create an alert.
  - References: NIST CSF 2.0 DE.CM, MITRE ATT&CK T1562.001.

- [ ] **BS-22: Evaluate protected service or PPL-style design only where technically supportable.**
  - Risk: Process-protection claims are sometimes used as marketing language without meeting Windows signing and design requirements.
  - Recommended configuration: Ask the vendor whether components use Windows protected service, Protected Process Light, ELAM-related anti-malware patterns, or another supported protection mechanism. Treat unsupported custom anti-termination logic as a compensating control, not a guarantee.
  - Verification: Review vendor technical documentation and Windows process metadata. Validate that the process-protection model does not break patching, logging, or incident response.
  - References: Microsoft protected process and service-hardening documentation, MITRE ATT&CK T1562.001.

- [ ] **BS-23: Monitor for abnormal parent-child process relationships around billing components.**
  - Risk: Billing agents launching shells, script interpreters, archivers, downloaders, or unexpected child processes can indicate tampering, misconfiguration, or a vendor update defect.
  - Recommended configuration: Baseline expected process trees and alert on unusual child processes from billing agents, cashier applications, update services, and database services.
  - Verification: Collect process creation events with command lines and compare recent events against the expected process tree.
  - References: MITRE ATT&CK T1055 and T1059, Microsoft process creation auditing, Sysmon documentation.

- [ ] **BS-24: Separate anti-cheat, game launcher, and billing agent privileges.**
  - Risk: Game launchers and anti-cheat components often require elevated access; billing software should not inherit that trust boundary automatically.
  - Recommended configuration: Run billing components under dedicated identities and directories. Do not place billing binaries inside game-writable folders or launcher update paths.
  - Verification: Review service accounts, process owners, install paths, and ACLs for billing, games, launchers, anti-cheat tools, and update services.
  - References: NIST SP 800-53 AC-6 and CM-7, OWASP ASVS least privilege requirements.

### Configuration, Licensing, and Business Logic

- [ ] **BS-25: Protect billing configuration files and registry keys.**
  - Risk: Local configuration tampering can alter server addresses, pricing rules, update channels, logging behavior, or client enforcement state.
  - Recommended configuration: Store sensitive configuration in protected paths with restricted ACLs. Sign or integrity-check configuration where the vendor supports it.
  - Verification: Run `icacls` on configuration paths and review relevant registry ACLs. Compare configuration hashes against the approved baseline.
  - References: MITRE ATT&CK T1112 Modify Registry, NIST SP 800-53 CM-5.

- [ ] **BS-26: Maintain server-side pricing, discount, and promotion rules.**
  - Risk: Pricing logic stored only on clients or cashier workstations is difficult to validate and can produce inconsistent records.
  - Recommended configuration: Keep authoritative pricing and discount rules on the server. Staff overrides should be role-controlled, logged, and reviewed.
  - Verification: Export pricing configuration and compare it against recent session charges, discounts, and manual adjustments.
  - References: OWASP ASVS business-logic requirements, NIST SP 800-92.

- [ ] **BS-27: Require tamper-evident audit logs for financial adjustments.**
  - Risk: Refunds, balance changes, free-time grants, and deleted sessions can become insider fraud when logs are editable or incomplete.
  - Recommended configuration: Log actor, role, workstation, timestamp, affected customer/session, old value, new value, reason code, and approval state. Export logs to a protected location.
  - Verification: Perform a controlled adjustment in a test account and confirm the audit record contains all required fields and cannot be edited by cashier users.
  - References: NIST SP 800-92, NIST SP 800-53 AU controls, OWASP ASVS logging requirements.

- [ ] **BS-28: Ensure licensing failures do not silently weaken security.**
  - Risk: License outages or validation failures can unintentionally disable enforcement, monitoring, or update channels.
  - Recommended configuration: Document license-check behavior and fail states. Security enforcement and audit logging should not silently degrade because a license server is temporarily unavailable.
  - Verification: Ask the vendor for documented license-failure behavior. Review logs from a controlled license-interruption test in a non-production environment.
  - References: NIST SP 800-160 secure system design concepts, OWASP ASVS error handling requirements.

- [ ] **BS-29: Keep reporting exports access-controlled and integrity-checkable.**
  - Risk: Revenue exports and shift reports can be altered after generation, creating accounting disputes.
  - Recommended configuration: Store reports in restricted locations, include export timestamp and generating user, and produce hashes for monthly or incident-sensitive exports.
  - Verification: Review report directory ACLs, export logs, and sample `Get-FileHash <report>` records.
  - References: NIST SP 800-53 AU-9 and SC-28, NIST SP 800-92.

- [ ] **BS-30: Avoid storing payment card data unless the venue is prepared for PCI DSS obligations.**
  - Risk: Billing software that stores cardholder data can introduce major compliance and breach impact.
  - Recommended configuration: Prefer payment processors and terminals that keep cardholder data out of the billing system. If cardholder data is stored, processed, or transmitted, validate PCI DSS scope with qualified expertise.
  - Verification: Review application settings, database schema, logs, exports, and backups for payment card data. Confirm payment integration architecture with the provider.
  - References: PCI DSS, OWASP ASVS data protection requirements.

### Update, Supply Chain, and Vendor Access

- [ ] **BS-31: Require signed updates with integrity verification.**
  - Risk: Update mechanisms are a high-impact supply-chain path because they run trusted code across many systems.
  - Recommended configuration: Use signed update packages, HTTPS/TLS transport, version metadata, rollback protection, and hash verification. Do not run unsigned update scripts from shared folders.
  - Verification: Inspect update package signatures and hashes before deployment. Ask the vendor how the updater verifies authenticity before install.
  - References: NIST SP 800-218 SSDF, The Update Framework, CWE-494 Download of Code Without Integrity Check.

- [ ] **BS-32: Stage billing software updates before fleet-wide deployment.**
  - Risk: A defective update can interrupt revenue operations or disable controls across all client PCs.
  - Recommended configuration: Test updates on a pilot client, cashier workstation, and non-production server where feasible. Keep rollback packages and database migration rollback notes.
  - Verification: Review update test records, pilot host logs, database migration logs, and rollback procedure.
  - References: NIST SP 800-128 configuration management, NIST SP 800-218 SSDF.

- [ ] **BS-33: Request SBOM or component inventory from vendors where practical.**
  - Risk: Operators cannot assess exposure to vulnerable embedded components if vendors cannot identify what they ship.
  - Recommended configuration: Ask vendors for an SBOM or component inventory for server, client, updater, and web components. Track critical component updates over time.
  - Verification: Store vendor SBOMs or component lists with version and date. Compare reported components against public advisories when major vulnerabilities are announced.
  - References: CycloneDX, SPDX, NIST SP 800-218 SSDF, CISA SBOM guidance.

- [ ] **BS-34: Use named, time-bound vendor remote access.**
  - Risk: Always-on vendor support tools and shared credentials create an external path into the venue.
  - Recommended configuration: Require named vendor accounts, MFA where possible, support windows, session logging, and owner approval for privileged changes.
  - Verification: Review VPN, remote support, RDP gateway, and billing admin logs for named identities and session times.
  - References: MITRE ATT&CK T1133 External Remote Services and T1021 Remote Services, NIST SP 800-53 AC-2 and AC-17.

- [ ] **BS-35: Keep vendor change records for configuration, updates, and emergency support.**
  - Risk: Without a change record, operators cannot distinguish legitimate vendor work from unauthorized modification.
  - Recommended configuration: Require each vendor change to record date, actor, reason, affected systems, files changed, database changes, restart requirements, and rollback notes.
  - Verification: Compare vendor tickets or emails against file hashes, service changes, database audit entries, and Windows event logs.
  - References: NIST SP 800-128 configuration management, NIST SP 800-53 CM controls.

### Logging, Monitoring, and Incident Readiness

- [ ] **BS-36: Export billing audit logs to a protected location.**
  - Risk: Local-only application logs can be deleted, rotated, or overwritten before an investigation begins.
  - Recommended configuration: Export or forward billing logs to a central log server, SIEM, Wazuh, or write-restricted share. Cashier users should not be able to delete or modify exported logs.
  - Verification: Generate a controlled login, adjustment, failed login, service restart, and update event. Confirm each appears in the protected log destination.
  - References: NIST SP 800-92, MITRE ATT&CK T1070.001 Clear Windows Event Logs.

- [ ] **BS-37: Alert on critical billing-service health changes.**
  - Risk: Billing-service crashes, repeated restarts, or disabled agents can indicate tampering or operational failure.
  - Recommended configuration: Alert on billing server service stop, client agent stop, database disconnection, update failure, backup failure, and repeated authentication failures.
  - Verification: Review monitoring rules and test one controlled service restart in a maintenance window.
  - References: MITRE ATT&CK T1562.001, NIST CSF 2.0 DE.CM.

- [ ] **BS-38: Preserve billing logs before client restoration or server rebuild.**
  - Risk: Restoration and rebuild workflows can destroy evidence needed for revenue reconciliation or incident response.
  - Recommended configuration: Include billing application logs, database audit logs, server event logs, client agent logs, update logs, and configuration snapshots in the incident collection checklist.
  - Verification: Run a tabletop exercise and confirm staff can collect evidence without overwriting original files.
  - References: NIST SP 800-61 Rev. 3 incident response guidance, NIST SP 800-86 forensic guidance.

- [ ] **BS-39: Maintain a billing-software incident playbook.**
  - Risk: Staff may reimage hosts, restart services, or call vendors before preserving evidence or containing network paths.
  - Recommended configuration: Define steps for suspected billing tampering, database inconsistency, cashier account abuse, failed update, ransomware, and vendor compromise.
  - Verification: Review the playbook quarterly and run at least one tabletop exercise per year.
  - References: NIST SP 800-61 Rev. 3, CISA incident response resources, CafeSec Lab incident response checklist.

- [ ] **BS-40: Keep business continuity requirements explicit.**
  - Risk: Security controls that break peak-hour operations will be disabled unless availability expectations are built into the design.
  - Recommended configuration: Define acceptable downtime, manual fallback process, staff override limits, backup restore target, and vendor support escalation path.
  - Verification: Compare documented recovery time objectives with restore-test results and incident playbook steps.
  - References: NIST SP 800-34, NIST CSF 2.0 RC.RP.

## Minimum Validation Package

For a billing-software review, collect the following evidence without exposing customer personal data:

- architecture diagram and network port matrix;
- billing role matrix and privileged-user list;
- database user, role, and network reachability review;
- TLS configuration for client-server and database communication;
- binary signature and SHA-256 hash inventory for server, client, updater, and cashier components;
- ACL exports for billing binaries, plugins, scripts, configuration files, and logs;
- update mechanism documentation, recent update record, rollback plan, and package verification evidence;
- backup job records and latest restore-test evidence;
- billing audit logs for controlled test events;
- vendor remote-access and change records.

## Vendor Questions

Use these questions during procurement, renewal, or technical review:

1. Which component is the authoritative source for session state and billing balance?
2. Which client messages can change server-side billing state, and how are they authenticated?
3. Does the product support TLS with certificate validation for all client-server communication?
4. Does the product support separate database accounts for runtime, reporting, backup, and administration?
5. Which files, registry keys, services, scheduled tasks, and network ports are required?
6. Are production binaries and updates digitally signed?
7. How does the updater verify package authenticity and prevent rollback to vulnerable versions?
8. Is there an SBOM or component inventory for shipped server and client components?
9. Can application logs be exported to a central collector?
10. What happens when the license server, billing server, or database is temporarily unreachable?
11. How are vendor support sessions authenticated, logged, approved, and revoked?
12. What evidence should operators preserve during suspected tampering?

## References

- CafeSec Lab threat model foundation: `00-threat-model.md`
- CafeSec Lab Windows host hardening checklist: `01-windows-host.md`
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- MITRE ATT&CK T1078 Valid Accounts: https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1055 Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1112 Modify Registry: https://attack.mitre.org/techniques/T1112/
- MITRE ATT&CK T1543.003 Windows Service: https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK T1562.001 Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1565 Data Manipulation: https://attack.mitre.org/techniques/T1565/
- MITRE ATT&CK T1021 Remote Services: https://attack.mitre.org/techniques/T1021/
- MITRE ATT&CK T1105 Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1195 Supply Chain Compromise: https://attack.mitre.org/techniques/T1195/
- MITRE ATT&CK T1486 Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
- NIST Secure Software Development Framework, SP 800-218: https://csrc.nist.gov/publications/detail/sp/800-218/final
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- NIST SP 800-52 Rev. 2, Guidelines for TLS: https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final
- NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy: https://csrc.nist.gov/pubs/sp/800/41/r1/final
- NIST SP 800-53 Rev. 5, Security and Privacy Controls: https://csrc.nist.gov/Pubs/sp/800/53/r5/upd1/Final
- NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management: https://csrc.nist.gov/pubs/sp/800/63/B/4/final
- NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-92, Guide to Computer Security Log Management: https://csrc.nist.gov/publications/detail/sp/800-92/final
- NIST SP 800-34 Rev. 1, Contingency Planning Guide: https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final
- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response: https://csrc.nist.gov/pubs/sp/800/86/final
- NIST SP 800-128, Guide for Security-Focused Configuration Management: https://csrc.nist.gov/publications/detail/sp/800-128/final
- NIST SP 800-160 Vol. 1 Rev. 1, Engineering Trustworthy Secure Systems: https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final
- OWASP Application Security Verification Standard: https://owasp.org/www-project-application-security-verification-standard/
- OWASP API Security Top 10: https://owasp.org/API-Security/
- OWASP Database Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- CISA Secure by Design: https://www.cisa.gov/securebydesign
- CISA Software Bill of Materials: https://www.cisa.gov/sbom
- The Update Framework: https://theupdateframework.io/
- SLSA: https://slsa.dev/
- CycloneDX: https://cyclonedx.org/
- SPDX: https://spdx.dev/
- Microsoft SQL Server security best practices: https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-server-security-best-practices?view=sql-server-ver17
- Microsoft Authenticode: https://learn.microsoft.com/windows-hardware/drivers/install/authenticode
- Microsoft protecting anti-malware services: https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- Microsoft Sysmon overview: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview
- CWE-494 Download of Code Without Integrity Check: https://cwe.mitre.org/data/definitions/494.html
- CWE-345 Insufficient Verification of Data Authenticity: https://cwe.mitre.org/data/definitions/345.html
- CWE-294 Authentication Bypass by Capture-replay: https://cwe.mitre.org/data/definitions/294.html
- PCI Security Standards Council: https://www.pcisecuritystandards.org/
