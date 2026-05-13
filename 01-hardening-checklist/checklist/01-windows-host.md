# Windows Host Hardening Checklist

This checklist defines a defensive Windows baseline for internet cafes, gaming venues, esports hotels, and managed shared-PC environments. It applies to customer-facing client PCs, cashier workstations, manager workstations, billing servers, image-build systems, and support hosts.

The checklist assumes the threat model in [`00-threat-model.md`](00-threat-model.md): client PCs are untrusted, billing authority belongs on the server, privileged access must be attributable, and restoration software is a recovery layer rather than a complete security boundary.

Commands are written for PowerShell 5.1+ unless stated otherwise. Many verification steps require an elevated shell. Replace placeholders such as `<billing-service>` and `<approved-admin-group>` with venue-specific names.

## Threat Background

Windows hosts in a gaming venue face a mixture of physical access, customer-supplied tooling, insider misuse, remote support risk, and business-critical availability pressure. The most important host-level threats are:

- unauthorized local privilege escalation or shared administrator use, mapped to MITRE ATT&CK T1078 Valid Accounts and T1136 Create Account;
- tampering with billing agents, endpoint protection, services, startup entries, or registry policy, mapped to T1562.001 Disable or Modify Tools, T1112 Modify Registry, and T1547 Boot or Logon Autostart Execution;
- process injection, unsigned tools, script abuse, and execution from writable paths, mapped to T1055 Process Injection, T1059.001 PowerShell, T1105 Ingress Tool Transfer, T1204 User Execution, and T1027 Obfuscated Files or Information;
- abuse of removable media or boot paths on physically accessible systems, mapped to T1091 Replication Through Removable Media and T1552 Unsecured Credentials;
- remote administration misuse, mapped to T1021 Remote Services and T1133 External Remote Services;
- ransomware or destructive recovery interference, mapped to T1486 Data Encrypted for Impact and T1490 Inhibit System Recovery.

The defensive objective is not to make a customer-facing PC "trusted." The objective is to make abuse harder, reduce blast radius, generate reliable evidence, and keep the billing server, cashier workflow, and recovery path defensible.

## Role Baseline

| Host Role | Minimum Baseline |
| --- | --- |
| Client PC | Standard-user sessions, application control, removable media controls, restoration validation, local firewall, centralized logs, restricted client-to-server network path. |
| Cashier workstation | Named staff accounts, MFA where possible, no direct database access, enhanced audit logging, BitLocker, restricted remote access, strong browser and credential hygiene. |
| Billing server | No customer logon, strict local admin membership, dedicated service accounts, database access restriction, Defender/EDR, backup agent hardening, advanced audit policy, time sync. |
| Image-build host | Restricted administrators, signed packages, image hash records, change approvals, isolated management network, no casual browsing or gaming use. |
| Remote support host | Named accounts, MFA, session logging, time-bound access, no shared vendor credentials, no direct exposure to the public internet. |

## Checklist

### Identity, Local Users, and Privilege

- [ ] **WH-01: Run customer sessions as standard users.**
  - Risk: Local administrator rights on client PCs allow customers to stop billing services, modify registry policy, load drivers, or disable telemetry.
  - Recommended configuration: Customer-facing sessions must use non-administrator accounts. Administrative actions should require named staff credentials and should not be performed during customer sessions.
  - Verification: Run `whoami /groups` during a normal customer session and confirm that `BUILTIN\Administrators` is absent. Run `Get-LocalGroupMember -Group Administrators` and verify that no customer or shared gaming account is listed.
  - References: MITRE ATT&CK T1078, Microsoft Windows security baselines, CIS Microsoft Windows Desktop Benchmark.

- [ ] **WH-02: Keep local Administrators membership minimal and reviewed.**
  - Risk: Stale vendor, technician, or former staff accounts create durable privileged access.
  - Recommended configuration: Restrict local Administrators to the built-in local administrator where required, domain or Entra-managed admin groups, and approved break-glass accounts. Review membership monthly.
  - Verification: Run `Get-LocalGroupMember -Group Administrators | Sort-Object Name` on each host role and compare the output to an approved access list.
  - References: MITRE ATT&CK T1078, NIST SP 800-53 AC-2 and AC-6, Microsoft Windows local accounts guidance.

- [ ] **WH-03: Deploy Windows LAPS or an equivalent managed local-admin password control.**
  - Risk: Reused local administrator passwords allow lateral movement from one compromised host to many systems.
  - Recommended configuration: Use Windows LAPS with automatic password rotation, per-device uniqueness, restricted retrieval rights, and audit logging. Do not store local admin passwords in spreadsheets, chat messages, or vendor notes.
  - Verification: Confirm policy with `gpresult /h laps-policy.html` and review `Get-WinEvent -LogName Microsoft-Windows-LAPS/Operational -MaxEvents 20` for password rotation events.
  - References: Microsoft Windows LAPS documentation, MITRE ATT&CK T1078, NIST SP 800-53 IA-5.

- [ ] **WH-04: Disable the Guest account and remove anonymous access paths.**
  - Risk: Guest or anonymous access can bypass staff accountability and weaken file-share and local-login controls.
  - Recommended configuration: Keep the Guest account disabled. Disable anonymous enumeration and unauthenticated SMB access unless a documented legacy dependency exists.
  - Verification: Run `Get-LocalUser -Name Guest | Select-Object Name,Enabled`. Run `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymous`.
  - References: CIS Microsoft Windows Benchmark, Microsoft security baseline recommendations.

- [ ] **WH-05: Use named accounts for cashier, manager, owner, technician, and vendor roles.**
  - Risk: Shared accounts prevent reliable investigation of refunds, manual time grants, configuration changes, and remote support actions.
  - Recommended configuration: Create named accounts with role-based privileges. Shared accounts should be limited to non-privileged kiosk use and must not perform financial or administrative changes.
  - Verification: Review local, domain, or Entra ID users with `Get-LocalUser` and identity-provider exports. Compare billing software audit logs against named staff identities.
  - References: NIST SP 800-53 AC-2, AC-5, AU-2; MITRE ATT&CK T1078.

- [ ] **WH-06: Enforce account lockout and password policy appropriate to the venue.**
  - Risk: Weak or unlimited password guessing enables staff-account compromise, especially on cashier and remote support systems.
  - Recommended configuration: Configure lockout thresholds, minimum password length, and password history through Group Policy or the identity provider. Use MFA for remote and privileged access.
  - Verification: Run `net accounts` on standalone hosts or `Get-ADDefaultDomainPasswordPolicy` in domain environments. Confirm MFA state in the identity provider for privileged users.
  - References: NIST SP 800-63B-4, Microsoft password policy guidance, MITRE ATT&CK T1110 Brute Force.

- [ ] **WH-07: Keep User Account Control enabled with secure desktop prompts.**
  - Risk: Weak UAC settings make privilege boundaries easier to cross and reduce visibility into administrative actions.
  - Recommended configuration: Keep `EnableLUA` enabled. Require administrator consent prompts on the secure desktop for elevation on cashier, server, and build systems.
  - Verification: Run `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA` and `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop`.
  - References: Microsoft UAC documentation, Microsoft Windows security baselines.

- [ ] **WH-08: Protect credential material on high-value hosts.**
  - Risk: Cashier and server compromise can expose browser-saved passwords, cached credentials, VPN profiles, and database secrets.
  - Recommended configuration: Prohibit saved administrative passwords in browsers and remote tools. Enable Credential Guard where supported on server, cashier, and manager devices. Store service secrets in a controlled password vault.
  - Verification: Run `Get-ComputerInfo | Select-Object DeviceGuard*` on supported Windows versions. Review browser password settings and remote support tool profiles.
  - References: MITRE ATT&CK T1552 Unsecured Credentials and T1003 OS Credential Dumping, Microsoft Credential Guard documentation.

### Services, Startup, and System Configuration

- [ ] **WH-09: Maintain an inventory of billing, restoration, logging, and endpoint-protection services.**
  - Risk: Operators cannot detect tampering if they do not know which services should exist, their startup types, or their expected accounts.
  - Recommended configuration: Record service name, display name, binary path, startup mode, service account, recovery behavior, and business owner for each critical service.
  - Verification: Run `Get-CimInstance Win32_Service | Select-Object Name,DisplayName,StartMode,State,StartName,PathName | Export-Csv services.csv -NoTypeInformation` and compare with the approved inventory.
  - References: NIST CSF 2.0 ID.AM, MITRE ATT&CK T1562.001.

- [ ] **WH-10: Restrict who can stop or reconfigure critical services.**
  - Risk: A customer or low-privilege staff member who can stop a billing or monitoring service can create a blind spot or revenue dispute.
  - Recommended configuration: Lock service control permissions for billing agents, restoration agents, EDR, logging forwarders, backup agents, and database services. Only approved administrators should have stop, change-config, or delete rights.
  - Verification: Run `sc.exe sdshow <billing-service>` and review the security descriptor. Test from a standard user account that `Stop-Service <billing-service>` fails.
  - References: Microsoft service security and access rights documentation, MITRE ATT&CK T1562.001.

- [ ] **WH-11: Configure service recovery for critical local agents.**
  - Risk: Accidental crashes or deliberate service termination can keep a host unmanaged until staff notice manually.
  - Recommended configuration: Configure first and second failures to restart the service. Send service failure events to centralized logging.
  - Verification: Run `sc.exe qfailure <billing-service>` and review System log events from the Service Control Manager.
  - References: Microsoft service recovery options, MITRE ATT&CK T1562.001.

- [ ] **WH-12: Use dedicated least-privilege service accounts.**
  - Risk: Services running as overly privileged users can turn a local application bug into server or domain compromise.
  - Recommended configuration: Use LocalService, NetworkService, managed service accounts, or dedicated domain accounts with only the privileges needed. Do not run vendor applications as Domain Admin or shared human accounts.
  - Verification: Run `Get-CimInstance Win32_Service | Where-Object StartName -notmatch 'LocalSystem|LocalService|NetworkService' | Select-Object Name,StartName` and review each exception.
  - References: NIST SP 800-53 AC-6, Microsoft service account guidance.

- [ ] **WH-13: Review startup folders, Run keys, and persistence locations.**
  - Risk: Unauthorized startup entries can restore tampering tools after reboot or after restoration exceptions apply.
  - Recommended configuration: Baseline approved startup entries and alert on changes in user and machine startup locations.
  - Verification: Run `Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,User,Location`. Review `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
  - References: MITRE ATT&CK T1547 Boot or Logon Autostart Execution and T1112 Modify Registry.

- [ ] **WH-14: Review scheduled tasks outside Microsoft-controlled paths.**
  - Risk: Scheduled tasks are a common persistence and maintenance mechanism; unmanaged tasks can run unwanted tools with elevated privileges.
  - Recommended configuration: Baseline vendor-approved tasks and remove or disable tasks with unclear owners, writable script paths, or broad privileges.
  - Verification: Run `Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\Microsoft\*'} | Select-Object TaskName,TaskPath,State` and inspect actions with `Get-ScheduledTaskInfo` and `Export-ScheduledTask`.
  - References: MITRE ATT&CK T1053.005 Scheduled Task, Microsoft scheduled task auditing guidance.

- [ ] **WH-15: Alert on new service installation and service-state changes.**
  - Risk: Unauthorized service installation can create persistence, disable security tooling, or run tampering logic as SYSTEM.
  - Recommended configuration: Enable audit collection for service installation and state changes. Send Windows Security event 4697 and System events 7034, 7035, 7036, and 7045 to central logging.
  - Verification: Run `wevtutil qe Security /q:"*[System[(EventID=4697)]]" /c:5 /f:text` and `wevtutil qe System /q:"*[System[(EventID=7045 or EventID=7036)]]" /c:10 /f:text`.
  - References: Microsoft Windows event documentation, MITRE ATT&CK T1543.003 Windows Service.

- [ ] **WH-16: Define patch and reboot windows for each host role.**
  - Risk: Unpatched hosts remain exposed, while unmanaged reboots during business hours can interrupt billing or active sessions.
  - Recommended configuration: Use maintenance windows that separate client PCs, cashier hosts, and servers. Test patches against the golden image and at least one pilot client before broad deployment.
  - Verification: Run `Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10` and compare update compliance with the maintenance record.
  - References: Microsoft Windows Update for Business guidance, NIST CSF 2.0 GV.OV and PR.PS.

### Application Control and Executable Integrity

- [ ] **WH-17: Prefer Windows Defender Application Control for high-risk hosts.**
  - Risk: Unsigned or unapproved executables from Downloads, temp folders, USB media, or game directories can tamper with billing agents or security tools.
  - Recommended configuration: Start WDAC in audit mode on pilot systems, build a publisher and file-path policy for approved software, then enforce on client PCs, cashier hosts, and billing servers by role.
  - Verification: Review active policies with `Get-ChildItem "$env:windir\System32\CodeIntegrity\CiPolicies\Active" -ErrorAction SilentlyContinue` and CodeIntegrity events with `Get-WinEvent -LogName Microsoft-Windows-CodeIntegrity/Operational -MaxEvents 50`.
  - References: Microsoft Windows Defender Application Control documentation, MITRE ATT&CK T1204 User Execution and T1027 Obfuscated Files or Information.

- [ ] **WH-18: Use AppLocker where WDAC is not yet operational.**
  - Risk: Without application control, customer-accessible systems depend on antivirus detection after execution has already been attempted.
  - Recommended configuration: Use AppLocker executable, script, installer, and DLL rules to allow Windows, Program Files, approved game platforms, and approved billing software while blocking user-writable paths.
  - Verification: Run `Get-AppLockerPolicy -Effective -Xml > applocker-effective.xml` and review AppLocker logs under `Microsoft-Windows-AppLocker/EXE and DLL`.
  - References: Microsoft AppLocker documentation, CIS Microsoft Windows Benchmark.

- [ ] **WH-19: Block execution from user-writable paths unless explicitly approved.**
  - Risk: Downloads, Desktop, temp directories, browser caches, and removable drives are common staging locations for unwanted tools.
  - Recommended configuration: Deny executable and script launch from `%USERPROFILE%`, `%TEMP%`, `%APPDATA%`, browser download directories, and removable media. Create narrow exceptions only for signed, business-required software.
  - Verification: Test a harmless unsigned executable from `%TEMP%` and confirm it is blocked by WDAC or AppLocker. Review AppLocker or CodeIntegrity events for the block.
  - References: MITRE ATT&CK T1105 Ingress Tool Transfer, T1204 User Execution, Microsoft AppLocker and WDAC guidance.

- [ ] **WH-20: Maintain a signed-software allowlist for billing, games, launchers, drivers, and support tools.**
  - Risk: Path-only allow rules can be bypassed when attackers write to allowed locations or replace unsigned binaries.
  - Recommended configuration: Prefer publisher rules for signed applications. For unsigned legacy billing components, pin hashes and restrict write access to their directories.
  - Verification: Run `Get-AuthenticodeSignature <path-to-binary>` for critical binaries and `Get-FileHash <path-to-binary> -Algorithm SHA256` for hash-pinned exceptions.
  - References: Microsoft Authenticode documentation, Microsoft WDAC design guide.

- [ ] **WH-21: Include script, MSI, DLL, and driver control in the policy.**
  - Risk: Blocking only `.exe` files leaves PowerShell, batch files, MSI installers, DLL side-loading, and driver loading available as alternate execution paths.
  - Recommended configuration: Extend WDAC or AppLocker to scripts, Windows Installer packages, DLLs, and drivers where operationally feasible.
  - Verification: Review the exported AppLocker policy for `ScriptRuleCollection`, `MsiRuleCollection`, and `DllRuleCollection`, or review WDAC policy options and CodeIntegrity events.
  - References: MITRE ATT&CK T1574 Hijack Execution Flow, T1218 System Binary Proxy Execution, Microsoft AppLocker rule collections.

- [ ] **WH-22: Protect billing software directories with restrictive ACLs.**
  - Risk: Writable application directories allow replacement, configuration tampering, DLL hijacking, or unauthorized plugin installation.
  - Recommended configuration: Grant write access only to the installer, update service, or approved administrator group. Standard users should have read and execute only.
  - Verification: Run `icacls "C:\Path\To\BillingSoftware"` and confirm that `Users`, `Authenticated Users`, and customer accounts do not have write, modify, or full-control permissions.
  - References: MITRE ATT&CK T1574.001 DLL Search Order Hijacking, Microsoft file and folder permissions guidance.

### PowerShell, Scripting, and Administrative Shells

- [ ] **WH-23: Disable Windows PowerShell 2.0.**
  - Risk: PowerShell 2.0 lacks modern logging and security features, making script abuse harder to investigate.
  - Recommended configuration: Remove or disable the PowerShell 2.0 optional feature on supported systems.
  - Verification: Run `Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root` and confirm `State : Disabled`.
  - References: Microsoft PowerShell security guidance, MITRE ATT&CK T1059.001 PowerShell.

- [ ] **WH-24: Use application control to trigger PowerShell Constrained Language Mode for untrusted code.**
  - Risk: Full Language Mode allows broad access to .NET, COM, and Windows APIs that are unnecessary for customer sessions.
  - Recommended configuration: Use WDAC or AppLocker so untrusted interactive users run PowerShell in Constrained Language Mode. Do not rely on manually setting environment variables as a security boundary.
  - Verification: In an untrusted session, run `$ExecutionContext.SessionState.LanguageMode` and confirm `ConstrainedLanguage` where expected.
  - References: Microsoft `about_Language_Modes`, Microsoft WDAC documentation, MITRE ATT&CK T1059.001.

- [ ] **WH-25: Require signed or controlled administrative scripts.**
  - Risk: Unsigned maintenance scripts can be modified and reused as a privileged execution path.
  - Recommended configuration: Store scripts in restricted admin-only locations. Use `AllSigned` or `RemoteSigned` for administrator workstations where operationally realistic, and sign recurring scripts with a controlled code-signing certificate.
  - Verification: Run `Get-ExecutionPolicy -List` and `Get-AuthenticodeSignature <script.ps1>` for recurring scripts.
  - References: Microsoft PowerShell execution policies and script signing documentation.

- [ ] **WH-26: Enable PowerShell Script Block Logging, Module Logging, and Transcription on admin hosts.**
  - Risk: Without PowerShell logging, suspicious commands may only appear as `powershell.exe` process launches with little context.
  - Recommended configuration: Enable script block logging and module logging at least on cashier, manager, server, build, and remote support hosts. Store transcripts in a protected central path.
  - Verification: Run `gpresult /h powershell-logging.html` and inspect `HKLM:\Software\Policies\Microsoft\Windows\PowerShell`. Review events in `Microsoft-Windows-PowerShell/Operational`.
  - References: Microsoft PowerShell logging documentation, MITRE ATT&CK T1059.001.

- [ ] **WH-27: Restrict PowerShell Remoting and use JEA for delegated administration.**
  - Risk: Broad remoting permissions can turn a single credential compromise into full environment control.
  - Recommended configuration: Disable PowerShell Remoting where not required. For support operations, prefer Just Enough Administration roles with named users and transcript logging.
  - Verification: Run `Get-PSSessionConfiguration` and `winrm enumerate winrm/config/listener`. Confirm listeners, trusted hosts, and session configurations match the approved remote-administration design.
  - References: Microsoft PowerShell Remoting security and JEA documentation, MITRE ATT&CK T1021.006 Windows Remote Management.

- [ ] **WH-28: Log command-line process creation.**
  - Risk: Process events without command lines are often insufficient to distinguish normal administration from suspicious tool execution.
  - Recommended configuration: Enable Audit Process Creation and include command-line arguments in process creation events. Consider Sysmon where operations can support it.
  - Verification: Run `auditpol /get /subcategory:"Process Creation"` and `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled`.
  - References: Microsoft advanced audit policy documentation, MITRE ATT&CK Data Source DS0009 Process.

### USB, Boot, and Restoration-System Coordination

- [ ] **WH-29: Deny removable storage by default on customer-facing client PCs.**
  - Risk: USB storage can introduce unwanted executables, portable tooling, credential theft scripts, or malware.
  - Recommended configuration: Use Group Policy to deny read and write access to removable storage on client PCs unless the business has a documented exception.
  - Verification: Run `gpresult /h removable-storage.html` and confirm settings under `Computer Configuration\Administrative Templates\System\Removable Storage Access`.
  - References: Microsoft Removable Storage Access policy documentation, MITRE ATT&CK T1091.

- [ ] **WH-30: Allowlist necessary USB device classes and specific peripherals.**
  - Risk: Blanket USB allowance for keyboards and mice can accidentally permit storage, network adapters, or mobile device tethering.
  - Recommended configuration: Allow approved HID peripherals and block unapproved storage, network, modem, and debug classes. Use Device Installation Restrictions where available.
  - Verification: Run `pnputil /enum-devices /connected` and review Group Policy device installation restrictions with `gpresult /h device-policy.html`.
  - References: Microsoft device installation restriction policy, MITRE ATT&CK T1091.

- [ ] **WH-31: Disable AutoRun and AutoPlay for removable media.**
  - Risk: Automatic media handling can execute or prompt users to run unwanted content from removable drives.
  - Recommended configuration: Disable AutoRun and AutoPlay through Group Policy on all host roles.
  - Verification: Run `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun` and review `gpresult /h autoplay.html`.
  - References: Microsoft AutoRun and AutoPlay policy documentation, MITRE ATT&CK T1091.

- [ ] **WH-32: Treat restoration software exceptions as a privileged change list.**
  - Risk: Restoration exceptions can preserve malware, altered configuration, or billing-agent tampering across reboots.
  - Recommended configuration: Maintain a documented exception list for folders, registry keys, game caches, drivers, and billing components. Review each exception for write permissions and business justification.
  - Verification: Export the restoration policy from the vendor console and compare exceptions against `icacls` output and the approved change record.
  - References: MITRE ATT&CK T1565 Data Manipulation and T1490 Inhibit System Recovery, NIST CSF 2.0 PR.PS.

- [ ] **WH-33: Hash and version the golden image before deployment.**
  - Risk: If the master image is modified silently, every restored client can inherit the compromise or misconfiguration.
  - Recommended configuration: Generate SHA-256 hashes for golden images, critical installers, and driver bundles. Record image version, build date, author, test result, and rollback plan.
  - Verification: Run `Get-FileHash <golden-image-or-package> -Algorithm SHA256` and compare the value to the release record before deployment.
  - References: NIST SP 800-128 configuration management guidance, Microsoft deployment and image management guidance.

- [ ] **WH-34: Validate post-restore drift on pilot client PCs.**
  - Risk: Operators may assume restoration succeeded while billing services, Defender, AppLocker, or network policy remain broken.
  - Recommended configuration: After image deployment or restore-policy changes, run a post-restore validation script covering services, application-control status, Defender state, time sync, and billing client connectivity.
  - Verification: Compare `Get-Service`, `Get-MpComputerStatus`, `Get-AppLockerPolicy -Effective`, `w32tm /query /status`, and file hashes against the known-good baseline.
  - References: NIST CSF 2.0 PR.PS and RC.RP, CafeSec Lab threat model control objective "Validate Recovery, Not Just Backup."

- [ ] **WH-35: Lock firmware boot order and require Secure Boot where supported.**
  - Risk: Physical access can allow booting alternate media, tampering with local disks, or weakening OS controls before Windows starts.
  - Recommended configuration: Set BIOS/UEFI administrator passwords, lock boot order to the internal disk or managed network boot path, and enable Secure Boot on supported hardware.
  - Verification: Run `Confirm-SecureBootUEFI` on supported systems and manually verify firmware boot settings during maintenance audits.
  - References: Microsoft Secure Boot documentation, MITRE ATT&CK T1542 Pre-OS Boot.

### Microsoft Defender, ASR, and Endpoint Protection

- [ ] **WH-36: Keep Microsoft Defender Antivirus active or document the approved alternative.**
  - Risk: Disabled or stale endpoint protection allows commodity malware, cheating tools, and tampering utilities to run with little friction.
  - Recommended configuration: Use Microsoft Defender Antivirus with real-time protection, cloud-delivered protection, automatic sample submission policy appropriate to the business, and tamper protection where supported. If another EDR is used, document ownership and health checks.
  - Verification: Run `Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareSignatureLastUpdated,IsTamperProtected`.
  - References: Microsoft Defender Antivirus documentation, MITRE ATT&CK T1562.001.

- [ ] **WH-37: Deploy Defender Attack Surface Reduction rules in audit mode before block mode.**
  - Risk: ASR rules reduce common abuse paths, but immediate block mode can interrupt legitimate games, launchers, billing plugins, or vendor tools.
  - Recommended configuration: Pilot ASR rules in audit mode by host role, review events, create narrow exclusions, then move mature rules to block mode.
  - Verification: Run `Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions`. Review events in `Microsoft-Windows-Windows Defender/Operational`.
  - References: Microsoft ASR rules reference, Microsoft Defender for Endpoint deployment guidance.

- [ ] **WH-38: Prioritize ASR rules that protect credentials, scripts, and suspicious child processes.**
  - Risk: Shared-PC venues frequently face downloaded tools, script abuse, WMI/PsExec-style execution, and credential theft attempts.
  - Recommended configuration: Evaluate at minimum these ASR rules: block credential stealing from LSASS (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`), block process creations from PSExec and WMI (`d1e49aac-8f56-4280-b9ba-993a6d77406c`), block persistence through WMI event subscription (`e6db77e5-3df2-4cf1-b95a-636979351e5b`), block JavaScript or VBScript from launching downloaded executables (`d3e037e1-3eb8-44c8-a917-57927947596d`), and block executable files unless they meet prevalence, age, or trusted-list criteria (`01443614-cd74-433a-b99e-2ecdc07bfc25`).
  - Verification: Use `Get-MpPreference` to confirm rule IDs and actions. Use Event Viewer or central logging to confirm audit and block outcomes before broad enforcement.
  - References: Microsoft ASR rules reference, MITRE ATT&CK T1003, T1059, T1047, T1105.

- [ ] **WH-39: Enable controlled folder access on high-value workstations after compatibility testing.**
  - Risk: Ransomware or destructive tools can modify billing exports, accounting files, support scripts, and local evidence before backups run.
  - Recommended configuration: Pilot controlled folder access on cashier, manager, and server-adjacent administrative hosts. Add approved business applications only after observing audit results.
  - Verification: Run `Get-MpPreference | Select-Object EnableControlledFolderAccess,ControlledFolderAccessProtectedFolders,ControlledFolderAccessAllowedApplications`.
  - References: Microsoft controlled folder access documentation, MITRE ATT&CK T1486.

- [ ] **WH-40: Enable potentially unwanted application protection.**
  - Risk: Bundled installers, adware, proxy tools, and suspicious utilities can create operational and security risk even when they are not classified as malware.
  - Recommended configuration: Enable Microsoft Defender PUA protection on client and admin hosts unless a documented business dependency requires exceptions.
  - Verification: Run `Get-MpPreference | Select-Object PUAProtection`.
  - References: Microsoft Defender PUA protection documentation, MITRE ATT&CK T1204 User Execution.

- [ ] **WH-41: Keep the Microsoft vulnerable driver blocklist enabled where supported.**
  - Risk: Vulnerable signed drivers can be abused to disable security tools or gain kernel-level capability.
  - Recommended configuration: Enable memory integrity and the vulnerable driver blocklist on supported hardware after testing game and peripheral compatibility.
  - Verification: Review Windows Security device security state, or run `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard` where available.
  - References: Microsoft vulnerable driver blocklist documentation, MITRE ATT&CK T1068 Exploitation for Privilege Escalation and T1562.001.

### Audit Policy, Logging, and Time

- [ ] **WH-42: Enable Advanced Audit Policy through Group Policy.**
  - Risk: Default audit settings may miss logons, process creation, service changes, registry modifications, and policy changes needed for incident response.
  - Recommended configuration: Configure audit policy centrally for client, cashier, server, and admin roles. Prioritize Logon, Account Logon, Account Management, Policy Change, Object Access for selected keys, Process Creation, and System events.
  - Verification: Run `auditpol /get /category:*` and compare output with the approved audit baseline.
  - References: Microsoft advanced security audit policy documentation, NIST SP 800-92 log management guidance.

- [ ] **WH-43: Collect key Windows event IDs for venue operations.**
  - Risk: Investigations fail when logs do not include authentication, process, service, registry, or log-clearing events.
  - Recommended configuration: Collect at least Security 4624, 4625, 4688, 4697, 4657, 1102 and System 7034, 7035, 7036, 7045 from high-value hosts. Enable required subcategories first.
  - Verification: Run `wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4697 or EventID=4657 or EventID=1102)]]" /c:20 /f:text`.
  - References: Microsoft Windows event documentation, MITRE ATT&CK data sources.

- [ ] **WH-44: Increase event log size and forward logs off-host.**
  - Risk: Busy gaming clients and cashier hosts can overwrite local logs before an incident is detected. Attackers may also clear logs.
  - Recommended configuration: Increase Security, System, Application, PowerShell, Defender, AppLocker, and CodeIntegrity log sizes. Forward logs to Windows Event Forwarding, Wazuh, SIEM, or another central collector.
  - Verification: Run `wevtutil gl Security` to confirm max size and retention behavior. Confirm forwarded events arrive at the collector after a test event.
  - References: Microsoft Windows Event Forwarding documentation, NIST SP 800-92, MITRE ATT&CK T1070.001 Clear Windows Event Logs.

- [ ] **WH-45: Synchronize time across all host roles.**
  - Risk: Incorrect timestamps weaken billing dispute resolution, event correlation, and forensic timelines.
  - Recommended configuration: Use a trusted NTP hierarchy. Domain members should follow domain time policy. Standalone hosts should use approved NTP sources and block users from changing time.
  - Verification: Run `w32tm /query /status`, `w32tm /query /source`, and `w32tm /monitor` in domain environments. Check for time-service errors in System logs.
  - References: Microsoft Windows Time service documentation, NIST SP 800-92.

- [ ] **WH-46: Alert on Security log clearing.**
  - Risk: Clearing logs is a strong signal of possible tampering or insider misuse.
  - Recommended configuration: Generate a high-priority alert for Windows Security event 1102 and correlate it with the account, host, remote logon events, and administrative activity.
  - Verification: In a controlled test system only, clear a non-production log and confirm alerting. Query with `wevtutil qe Security /q:"*[System[(EventID=1102)]]" /c:5 /f:text`.
  - References: MITRE ATT&CK T1070.001, Microsoft Windows Security event documentation.

### Data Protection, Remote Access, and Host Firewall

- [ ] **WH-47: Enable BitLocker on billing servers, cashier workstations, manager laptops, and image-build systems.**
  - Risk: Theft, repair handling, or unauthorized physical access can expose billing records, credentials, logs, and configuration files.
  - Recommended configuration: Use BitLocker with TPM protection where supported, recovery keys escrowed to a controlled location, and documented recovery procedures.
  - Verification: Run `manage-bde -status` or `Get-BitLockerVolume` and confirm protection status and key protector type.
  - References: Microsoft BitLocker documentation, NIST SP 800-111 storage encryption guidance.

- [ ] **WH-48: Protect BitLocker recovery keys.**
  - Risk: Recovery keys stored in plain text, chat, or printed notes can bypass disk encryption.
  - Recommended configuration: Escrow recovery keys to Active Directory, Entra ID, or a controlled password vault. Limit retrieval permissions and audit access.
  - Verification: Review escrow location access logs and confirm no recovery keys exist in public shares, scripts, browser notes, or vendor tickets.
  - References: Microsoft BitLocker recovery guidance, NIST SP 800-53 IA-5 and SC-28.

- [ ] **WH-49: Disable direct RDP access to customer-facing client PCs.**
  - Risk: RDP increases lateral movement and credential exposure risk on hosts that should be considered untrusted.
  - Recommended configuration: Disable RDP on client PCs unless a documented support workflow requires it. Use time-bound remote tools through a management network instead.
  - Verification: Run `Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections` and confirm `fDenyTSConnections` is `1` for client PCs.
  - References: MITRE ATT&CK T1021.001 Remote Desktop Protocol, Microsoft Remote Desktop security guidance.

- [ ] **WH-50: Require VPN, MFA, and named accounts for remote administration.**
  - Risk: Exposed RDP, shared remote support accounts, or unattended vendor access can become the easiest path into the venue.
  - Recommended configuration: Place remote administration behind VPN or a managed remote access gateway with MFA, named accounts, logging, and explicit support windows.
  - Verification: Run `Get-NetTCPConnection -LocalPort 3389 -State Listen` on hosts, review firewall/NAT exposure, and inspect VPN or remote access logs for named identities.
  - References: MITRE ATT&CK T1133 External Remote Services and T1021 Remote Services, Microsoft remote access security guidance.

- [ ] **WH-51: Keep Windows Defender Firewall enabled on every profile.**
  - Risk: Flat venue networks and customer-facing hosts make host firewalls an important containment layer even when network firewalls exist.
  - Recommended configuration: Enable Domain, Private, and Public profiles. Use inbound deny-by-default and explicit allow rules by host role.
  - Verification: Run `Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction`.
  - References: Microsoft Defender Firewall documentation, CIS Microsoft Windows Benchmark.

- [ ] **WH-52: Review inbound firewall rules by host role.**
  - Risk: Legacy installers and vendor tools can leave broad inbound rules that expose services to client or guest networks.
  - Recommended configuration: Remove unused inbound rules. Scope allowed rules to management subnets or server subnets, not `Any`.
  - Verification: Run `Get-NetFirewallRule -Enabled True -Direction Inbound | Get-NetFirewallPortFilter | Select-Object Protocol,LocalPort` and inspect associated address filters with `Get-NetFirewallAddressFilter`.
  - References: Microsoft Defender Firewall rule management documentation, MITRE ATT&CK T1046 Network Service Discovery.

- [ ] **WH-53: Lock host DNS and proxy settings against customer modification.**
  - Risk: DNS or proxy tampering can redirect updates, block telemetry, or enable traffic interception.
  - Recommended configuration: Manage DNS and proxy settings through DHCP, Group Policy, MDM, or endpoint management. Standard users must not be able to change network adapter settings.
  - Verification: Run `Get-DnsClientServerAddress`, `netsh winhttp show proxy`, and `gpresult /h network-policy.html`. Confirm standard users cannot edit adapter settings.
  - References: MITRE ATT&CK T1557 Adversary-in-the-Middle, Microsoft Windows networking policy documentation.

- [ ] **WH-54: Separate administrative browsing from server and billing operations.**
  - Risk: Web browsing, email, chat, and file downloads on billing servers or image-build hosts increase exposure to phishing and drive-by compromise.
  - Recommended configuration: Do not use billing servers or image-build systems for casual browsing, email, gaming, or personal messaging. Use a separate administrative workstation for vendor portals and downloads.
  - Verification: Review browser history policy, installed browsers, download folders, and interactive logon records on servers and build hosts.
  - References: NIST SP 800-53 CM-7 least functionality, MITRE ATT&CK T1204 User Execution.

## Minimum Validation Package

For each venue audit, collect the following evidence without exposing customer data:

- `Get-LocalGroupMember -Group Administrators` output for each host role.
- `auditpol /get /category:*` output from one client PC, one cashier host, and the billing server.
- `Get-MpComputerStatus` and `Get-MpPreference` output for Defender and ASR state.
- `Get-AppLockerPolicy -Effective -Xml` or WDAC active policy evidence.
- `Get-CimInstance Win32_Service` export for billing, restoration, logging, endpoint protection, and database services.
- `w32tm /query /status` from each host role.
- Firewall profile and inbound rule exports.
- Golden image hash and restoration exception list.
- Central log collector confirmation for events 4624, 4625, 4688, 4697, 7034, 7035, 7036, 4657, and 1102.

## References

- CafeSec Lab threat model foundation: `00-threat-model.md`
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- MITRE ATT&CK T1055 Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1059.001 PowerShell: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1078 Valid Accounts: https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1091 Replication Through Removable Media: https://attack.mitre.org/techniques/T1091/
- MITRE ATT&CK T1112 Modify Registry: https://attack.mitre.org/techniques/T1112/
- MITRE ATT&CK T1133 External Remote Services: https://attack.mitre.org/techniques/T1133/
- MITRE ATT&CK T1486 Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK T1490 Inhibit System Recovery: https://attack.mitre.org/techniques/T1490/
- MITRE ATT&CK T1547 Boot or Logon Autostart Execution: https://attack.mitre.org/techniques/T1547/
- MITRE ATT&CK T1562.001 Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- Microsoft Attack surface reduction rules reference: https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference
- Microsoft Windows Defender Application Control documentation: https://learn.microsoft.com/windows/security/application-security/application-control/windows-defender-application-control/
- Microsoft AppLocker documentation: https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview
- Microsoft PowerShell language modes: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes
- Microsoft PowerShell execution policies: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies
- Microsoft Windows LAPS documentation: https://learn.microsoft.com/windows-server/identity/laps/laps-overview
- Microsoft BitLocker documentation: https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/
- Microsoft Advanced security audit policy documentation: https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
- Microsoft Windows Time service documentation: https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-top
- Microsoft Defender Firewall documentation: https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- NIST SP 800-53 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management: https://csrc.nist.gov/pubs/sp/800/63/B/4/final
- NIST SP 800-92 Guide to Computer Security Log Management: https://csrc.nist.gov/publications/detail/sp/800-92/final
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
