# Download Checklist (all official sources)

> Download these during the **temporary online phase** of the [two-phase setup]; afterwards disconnect from the network and verify isolation.
> Place the ISOs in `E:\CafeSec-Lab\ISO\`. The file names must match the `IsoFile` values in `config\lab.psd1`.

## Operating System Images (Microsoft official evaluation editions / Ubuntu official)

| Purpose | System | Official download page | Expected file name (configurable in config) |
|---|---|---|---|
| Clients ×2 | Windows 11 Enterprise Evaluation | Microsoft Evaluation Center: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise | `windows-11-enterprise-eval.iso` |
| Server ×1 | Windows Server 2022 Evaluation | Microsoft Evaluation Center: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022 | `windows-server-2022-eval.iso` |
| Wazuh ×1 | Ubuntu Server 24.04 LTS | https://ubuntu.com/download/server | `ubuntu-24.04-live-server-amd64.iso` |

> Windows evaluation editions are valid for about 180 days, which is enough for the lab; when they expire you can reset or rebuild the VM.
> You can also use Microsoft's "Windows 11 + Office Dev / Evaluation VMs", but this project is planned around clean evaluation-edition ISOs.

## Defensive Tools (purely defensive, all official)

| Tool | Purpose | Official source |
|---|---|---|
| Sysmon (Sysinternals) | In-depth endpoint event logging | https://learn.microsoft.com/sysinternals/downloads/sysmon |
| SwiftOnSecurity Sysmon config | Battle-tested Sysmon baseline configuration (open source MIT/no add-ons) | https://github.com/SwiftOnSecurity/sysmon-config — take `sysmonconfig-export.xml` |
| Wazuh (manager + agent) | Open-source SIEM/XDR, centralized detection and alerting | https://wazuh.com ; Windows agent: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html |
| Sigma CLI | Generic detection rules to SIEM query converter | https://github.com/SigmaHQ/sigma-cli (`pip install sigma-cli`) |
| Sigma rule library (optional reference) | Community open-source detection rules | https://github.com/SigmaHQ/sigma |
| YARA | File/memory signature matching | https://github.com/VirusTotal/yara/releases (take Windows `yara-x.y.z-win64.zip`) |
| Python 3 | Run sigma-cli | https://www.python.org/downloads/windows/ |

> WEF (Windows Event Forwarding) is a built-in Windows feature; no download required.

## Two ways to transfer files into the isolated VM (after disconnecting from the network)

1. **Copy-VMFile (recommended, no network needed)** — the VM already has the Guest Service Interface enabled in `03-New-LabVMs.ps1`:
   ```powershell
   Copy-VMFile -Name CSL-Client01 -SourcePath <repo>\04-validation-lab\downloads\tools\Sysmon64.exe `
       -DestinationPath C:\CafeSec\Sysmon64.exe -CreateFullPath -FileSource Host
   ```
   > On the host side, keep all tools together in the project's `downloads\tools\` (see README step B); `-DestinationPath` is the landing path inside the VM.
   (Only supported for Windows clients; use method 2 for Linux)
2. **Mount a data ISO** — package the tools into a single ISO, attach it to the VM with `Add-VMDvdDrive`, and copy from the optical drive inside the VM.
   To create an ISO on Windows you can use `oscdimg` (Windows ADK) or a third-party tool.
