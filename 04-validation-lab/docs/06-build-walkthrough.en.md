# 06 — Build walkthrough: from zero to live-fire evidence (English)

A linear, **reboot-resumable**, copy-paste path that takes the lab from "not built" to "producing
real live-fire detection evidence." Each milestone notes rough time, whether it needs admin / a
reboot, and where to **paste output back to the collaborating agent**. (Chinese version:
[`06-build-walkthrough.md`](06-build-walkthrough.md).)

> Safety: privileged steps (admin / Hyper-V / VM create / reboot / network switch) are run by **you**
> in an administrator PowerShell. The whole build only touches the Hyper-V platform, the isolated
> switch, and the 4 CSL VMs — never your real network. Every stimulus is benign / lab-owned.

| Milestone | Time | Admin | Reboot | ISOs |
|---|---|---|---|---|
| M0 prerequisites | 10 min + downloads | no | no | downloading |
| M1 host scaffold | 15–30 min | ✅ | ✅ once | no |
| M2 install OS ×4 | 1–3 h | ✅ (host-side mount) | — | ✅ |
| M3 domain + defense stack | 1–2 h | ✅ (in-VM) | several | no |
| M4 lock isolation + live-fire | 30–60 min | ✅ | — | no |

Set `$LAB` once per new window:
```powershell
$LAB = "C:\Users\Eshine\Documents\New project 2\netcafe-security-lab\04-validation-lab"
```

---

## M0 — Prerequisites (no privilege)
- [ ] Host meets requirements: `& "$LAB\scripts\00-Preflight-Check.ps1"` (read-only).
- [ ] Download the 3 evaluation ISOs to `E:\CafeSec-Lab\ISO\`, named to match [`config\lab.psd1`](../config/lab.psd1):
  `windows-11-enterprise-eval.iso` · `windows-server-2022-eval.iso` · `ubuntu-24.04-live-server-amd64.iso`
  (sources in [`downloads.md`](downloads.md)).
- [ ] (Optional) Lock reproducibility: record the downloaded ISO hashes in [`config\versions.psd1`](../config/versions.psd1).

## M1 — Host scaffold (admin + one reboot; **no ISOs needed**)
In an **administrator PowerShell**:
```powershell
$LAB = "C:\Users\Eshine\Documents\New project 2\netcafe-security-lab\04-validation-lab"
cd "$LAB\scripts"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-LabSetup.ps1            # preflight -> enable Hyper-V -> usually stops at the "reboot gate"
```
It will **stop at the reboot gate** (Hyper-V just enabled, `vmms` not ready yet). → **Reboot**, then:
```powershell
# After reboot, new admin PowerShell:
$LAB = "C:\Users\Eshine\Documents\New project 2\netcafe-security-lab\04-validation-lab"
cd "$LAB\scripts"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-LabSetup.ps1            # idempotent resume: isolated switch -> 4 Gen2+vTPM VMs -> host-side isolation check
```
**🔖 Paste back**: the orchestration summary table + the `04-Verify-Isolation` PASS/FAIL. `Steps 0–4 all OK` = M1 done.

## M2 — Install OS ×4 (admin; needs ISOs)
First build the unattended seed ISOs (no privilege); for Ubuntu, set the password hash first (see
[`05-unattended-provisioning.md`](05-unattended-provisioning.md)):
```powershell
cd "$LAB\scripts"
.\New-UnattendIso.ps1 -Os Ubuntu  -Hostname csl-wazuh
.\New-UnattendIso.ps1 -Os Windows -Hostname CSL-Server   -ImageName 'Windows Server 2022 SERVERSTANDARD'
.\New-UnattendIso.ps1 -Os Windows -Hostname CSL-Client01 -ImageName 'Windows 11 Enterprise Evaluation'
.\New-UnattendIso.ps1 -Os Windows -Hostname CSL-Client02 -ImageName 'Windows 11 Enterprise Evaluation'
```
Attach the OS install ISO + the seed ISO and boot (once per VM, e.g. CSL-Server):
```powershell
Set-VMDvdDrive -VMName CSL-Server -Path 'E:\CafeSec-Lab\ISO\windows-server-2022-eval.iso'
Add-VMDvdDrive -VMName CSL-Server -Path 'E:\CafeSec-Lab\ISO\unattend-windows-CSL-Server.iso'
Start-VM       -Name  CSL-Server
```
> Need internet during install? `.\Switch-LabNetwork.ps1 -Phase Provisioning -ProvisioningSwitch <your-NAT-switch>` (see [`02-network-isolation.md`](02-network-isolation.md)).
**🔖 Paste back**: if the first real build hits an image-index/partition error, paste it — I'll correct the template against the [`05`](05-unattended-provisioning.md) checklist.

## M3 — Domain + defense stack (in-VM; see [`03-domain-and-wef.md`](03-domain-and-wef.md))
```powershell
# Static IPs (inside each VM); domain members point DNS at the DC
.\guest\Set-StaticIP.ps1 -IPAddress 10.10.10.20 -DnsServer 127.0.0.1     # CSL-Server (DC)
.\guest\Set-StaticIP.ps1 -IPAddress 10.10.10.31 -DnsServer 10.10.10.20   # CSL-Client01

# Domain: promote CSL-Server to DC, lock DNS air-gap, join clients
.\domain\Install-DomainController.ps1 -SafeModePassword (Read-Host -AsSecureString "DSRM password")
.\domain\Set-DcDnsAirgap.ps1
.\domain\Join-LabDomain.ps1 -DomainCredential (Get-Credential CAFESEC\Administrator)

# Defense stack
bash scripts/wazuh/install-wazuh-manager.sh                    # Ubuntu (CSL-Wazuh)
.\guest\Deploy-Sysmon.ps1 -SysmonExe ... -ConfigXml ...        # each Windows VM
.\guest\Install-WazuhAgent.ps1 -MsiPath ...                    # point at manager 10.10.10.10
.\guest\Configure-WEC-Collector.ps1 ; .\domain\New-WefGpo.ps1  # DC: WEF collector + GPO
.\analysis\Setup-RuleEngines.ps1                               # analysis side: sigma-cli + yara
```
**🔖 Paste back**: the TC-08 four self-checks (Sysmon running / 4688 with command line / WEF `ForwardedEvents` shows client events / Wazuh agent `Active`). Only proceed to M4 once the pipeline is fully connected.

## M4 — Lock isolation + live-fire evidence (the last step to 10/10)
```powershell
.\Switch-LabNetwork.ps1 -Phase Isolated     # all NICs back to the isolated switch
.\04-Verify-Isolation.ps1                   # host side; inside each VM run guest\Test-GuestIsolation.ps1 / wazuh\test-guest-isolation.sh
```
> **Both sides must PASS** before any stimulus.

1. **Offline evidence (already runnable)**: `cd "$LAB\scripts\analysis"; .\Invoke-RuleValidation.ps1; .\Export-CvpEvidence.ps1` → expect 6/6, refreshing [`lab-validation-evidence.md`](../../docs/cvp/lab-validation-evidence.md).
2. **Live-fire (per [`04-defensive-validation-runbook.md`](04-defensive-validation-runbook.md) TC-01–09)**: in a maintenance window, apply a benign stimulus to a **lab-owned dummy**, confirm the hit in Wazuh/`ForwardedEvents`, record detection latency, then revert. **Each rule lit once = live-fire evidence.**
3. After passing [the `04` reviewer gate](04-defensive-validation-runbook.md), archive the live-fire results and flip the relevant `COVERAGE.md` rows to ✅.

**🔖 Paste back**: the `Invoke-RuleValidation` 6/6 + each TC's hit screenshot/record. At that point the runnability and evidence dimensions are complete — the lab reaches 10/10.

---

## Resuming / stuck?
- All host scripts are **idempotent**: if any step fails, fix and re-run (`Invoke-LabSetup.ps1` skips completed steps).
- Tear down and retry: `.\Reset-Lab.ps1 -WhatIf` to preview, then `.\Reset-Lab.ps1` (deletes only the 4 CSL VMs + the isolated switch; never your other VMs/switches).
- Paste any error verbatim and I'll take it from there.
