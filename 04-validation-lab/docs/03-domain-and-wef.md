# Domain + WEF + GPO (the native foundation for detection engineering)

## Why build a domain
Between workgroup (non-domain) machines, **source-initiated WEF over Kerberos cannot work** (Kerberos requires a KDC = domain controller).
After establishing the internal domain `cafesec.lab`:
- **WEF** source -> collector goes over Kerberos (HTTP/5985), with no certificate required.
- **GPO** centrally deploys Sysmon, audit policy, and WEF subscriptions (corresponding to the GPO requirements in step five).
- Closer to the real operational model of a "net cafe / shared PC management node".

> **Air gap unchanged**: the domain controller runs AD-integrated DNS, but **with no forwarders and no root hints**, resolving only the internal domain;
> the network layer has no egress to begin with. `Test-GuestIsolation.ps1` still forces a probe to `1.1.1.1` to prove that egress is blocked.

## Roles and addresses (inside the isolated network)
| Host | Role | Address | DNS pointing to |
|---|---|---|---|
| CSL-Server | **Domain Controller (DC) + AD DNS + WEF collector** | 10.10.10.20 | itself (127.0.0.1) |
| CSL-Client01/02 | Domain member (WEF source) | 10.10.10.31/32 | 10.10.10.20 (domain controller) |
| CSL-Wazuh | **Not domain-joined** (Linux, Wazuh SIEM) | 10.10.10.10 | none (static, Wazuh does not need DNS) |

## Build order (complete the domain join after "the OS is installed" in phase one, and before locking down isolation in phase two)

> Still follows the two-phase model; building/joining the domain is done inside the VMs and does not require external network access. Tools such as Sysmon/Wazuh/rules,
> if they need to be downloaded online, should be done in phase one; the domain join itself only requires communication within the isolated network.

### 1. Domain controller (CSL-Server, 10.10.10.20)
```powershell
# (first ensure the host is named CSL-Server and the static IP is configured)
cd <project>\scripts\domain
$dsrm = Read-Host -AsSecureString "Set the DSRM password"
.\Install-DomainController.ps1 -SafeModePassword $dsrm     # Install AD DS+DNS, promote to cafesec.lab, auto-reboot
# -- after reboot, log in with the local/domain administrator --
.\Set-DcDnsAirgap.ps1                                       # Clear root hints / confirm no forwarders, lock down the air-gapped DNS
..\guest\Configure-WEC-Collector.ps1                        # Configure the WEF collector + import subscriptions
.\New-WefGpo.ps1                                            # Use GPO to push the WEF source configuration to the clients
```

### 2. Clients (CSL-Client01 / 02)
```powershell
cd <project>\scripts\domain
$cred = Get-Credential CAFESEC\Administrator
.\Join-LabDomain.ps1 -DomainCredential $cred               # Point DNS at the domain controller and join the domain, auto-reboot
# After reboot, log in with a domain account, then:
gpupdate /force                                            # Pull the WEF GPO
```

## WEF data flow (domain mode)
```
CSL-Client01/02 (source, domain member)              CSL-Server (collector = domain controller)
  Security/Sysmon/PowerShell events                      ForwardedEvents log
        │  WinRM 5985 + Kerberos (source-initiated, GPO pushes SubscriptionManager)
        └───────────────────────────────────────────────►
  Authorization: AllowedSourceDomainComputers SDDL in the subscription XML (Domain Computers + Network Service)
```

## GPO configuration key points (`New-WefGpo.ps1` is already scripted + two items must be added manually)

`New-WefGpo.ps1` automatically completes (high confidence, scriptable):
1. **Configure target Subscription Manager**
   `Computer Configuration -> Administrative Templates -> Windows Components -> Event Forwarding`
   Value: `Server=http://CSL-Server.cafesec.lab:5985/wsman/SubscriptionManager/WEC,Refresh=60`
2. **Allow remote server management through WinRM** + set the **WinRM service startup type to Automatic** (registry policy, takes effect after each client reboot)
   > Note: neither of these will **immediately start** the WinRM service in the current session -- see manual addition item 5 below.

Must be added **manually / via GPP** (cannot be fully expressed with `Set-GPRegistryValue` alone):
3. **Add `NT AUTHORITY\NETWORK SERVICE` to the local `Event Log Readers` group on each source machine** (required to forward the Security log)
   - Method A: GPO -> `Computer Configuration -> Preferences -> Control Panel Settings -> Local Users and Groups` -> update group `Event Log Readers` -> add member `NETWORK SERVICE`.
   - Method B: run `..\guest\Configure-WEF-Source.ps1` on each client (it performs this step).
4. **Advanced audit policy** (make the Security log rich enough for Sigma/detection use)
   `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies`:
   - Logon/Logoff: **Audit Logon** (Success + Failure) -> 4624/4625
   - Detailed Tracking: **Audit Process Creation** (Success) -> 4688
   - Account Management, Privilege Use, etc., enabled as needed
   And enable: `Administrative Templates -> System -> Audit Process Creation -> Include command line in process creation events` -> 4688 carries the command line.
   > Sysmon's process/network/registry events are provided by `..\guest\Deploy-Sysmon.ps1`; the audit policy fills in the native Security dimension.
5. **Ensure the source-side WinRM (WS-Management) service is [running] and the startup type = Automatic** -- the `AllowAutoConfig` policy itself will not start the service
   (Win11 desktop edition defaults to Manual/triggered start). `New-WefGpo.ps1` has set the startup-type policy to Automatic (takes effect after each client reboot), but it still needs to actually be running:
   - Method A (native GPO): `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> System Services` -> set `Windows Remote Management (WS-Management)` to **Automatic**.
   - Method B (GPP): `Computer Configuration -> Preferences -> Control Panel Settings -> Services` -> WinRM -> startup type **Automatic** + service action **Start**.
   - Method C: run `..\guest\Configure-WEF-Source.ps1` on each client (includes `winrm quickconfig` + service restart, takes effect immediately).
   > Since the client has already rebooted once during the domain join, the "Automatic" startup type is essentially already in effect after joining; Method C ensures the current session is immediately usable.

## Verification checklist
```powershell
# Domain controller:
Get-ADDomain | ft DNSRoot, NetBIOSName, DistinguishedName
nltest /dsgetdc:cafesec.lab
wecutil gr CafeSec-Security          # Each source should show Active (prerequisite: the client has run gpupdate [and the WinRM service is running]; appears in about 1-2 minutes)

# Client:
(Get-CimInstance Win32_ComputerSystem).Domain     # Should be cafesec.lab
gpresult /r /scope computer | findstr CafeSec-WEF  # GPO is applied
# Forwarding plugin health: Event Viewer -> Applications and Services Logs\Microsoft\Windows\Eventlog-ForwardingPlugin\Operational

# Collector: confirm events are received
Get-WinEvent -LogName ForwardedEvents -MaxEvents 20
```

## Relationship to isolation / Wazuh
- **Wazuh** is still the primary SIEM (agent -> manager, 10.10.10.10), covering Windows + cross-platform, independent of WEF.
- **WEF** is a native, third-party-agent-free parallel aggregation channel that centrally archives key security / Sysmon events into `ForwardedEvents`.
- The two are complementary; introducing the domain only changes "how authentication and configuration deployment work", and **does not change the isolation topology** (private switch + no gateway + no DNS forwarding).
