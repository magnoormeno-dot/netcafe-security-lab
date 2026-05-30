# 下载清单(全部官方来源)

> 在【两阶段搭建】的**临时联网阶段**下载这些;之后断网并验证隔离。
> ISO 放到 `E:\CafeSec-Lab\ISO\`,文件名需与 `config\lab.psd1` 的 `IsoFile` 一致。

## 操作系统镜像(微软官方评估版 / Ubuntu 官方)

| 用途 | 系统 | 官方下载页 | 期望文件名(可改 config) |
|---|---|---|---|
| 客户机 ×2 | Windows 11 Enterprise 评估版 | Microsoft Evaluation Center: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise | `windows-11-enterprise-eval.iso` |
| 服务器 ×1 | Windows Server 2022 评估版 | Microsoft Evaluation Center: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022 | `windows-server-2022-eval.iso` |
| Wazuh ×1 | Ubuntu Server 24.04 LTS | https://ubuntu.com/download/server | `ubuntu-24.04-live-server-amd64.iso` |

> Windows 评估版有效期约 180 天,足够实验;到期可重置或重建 VM。
> 也可用微软 "Windows 11 + Office Dev / Evaluation VMs",但本项目按纯净评估版 ISO 规划。

## 防御工具(纯防御,全部官方)

| 工具 | 用途 | 官方来源 |
|---|---|---|
| Sysmon (Sysinternals) | 端点深度事件日志 | https://learn.microsoft.com/sysinternals/downloads/sysmon |
| SwiftOnSecurity Sysmon 配置 | 经过实战打磨的 Sysmon 基线配置(开源 MIT/无附加) | https://github.com/SwiftOnSecurity/sysmon-config — 取 `sysmonconfig-export.xml` |
| Wazuh (manager + agent) | 开源 SIEM/XDR,集中检测告警 | https://wazuh.com ;Windows agent: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html |
| Sigma CLI | 通用检测规则 → SIEM 查询 转换器 | https://github.com/SigmaHQ/sigma-cli (`pip install sigma-cli`) |
| Sigma 规则库(可选参考) | 社区开源检测规则 | https://github.com/SigmaHQ/sigma |
| YARA | 文件/内存特征匹配 | https://github.com/VirusTotal/yara/releases (取 Windows `yara-x.y.z-win64.zip`) |
| Python 3 | 跑 sigma-cli | https://www.python.org/downloads/windows/ |

> WEF(Windows Event Forwarding)是 Windows 内置功能,无需下载。

## 把文件送进隔离 VM 的两种方式(断网后)

1. **Copy-VMFile(推荐,无需联网)** —— VM 已在 `03-New-LabVMs.ps1` 中启用了 Guest Service Interface:
   ```powershell
   Copy-VMFile -Name CSL-Client01 -SourcePath <repo>\04-validation-lab\downloads\tools\Sysmon64.exe `
       -DestinationPath C:\CafeSec\Sysmon64.exe -CreateFullPath -FileSource Host
   ```
   > 宿主侧工具统一放项目内 `downloads\tools\`(见 README 步骤 B);`-DestinationPath` 是 VM 内落地路径。
   (仅支持 Windows 客户机;Linux 用方式 2)
2. **挂载数据 ISO** —— 把工具打包成一个 ISO,`Add-VMDvdDrive` 挂到 VM,VM 内从光驱拷贝。
   Windows 制作 ISO 可用 `oscdimg`(Windows ADK)或第三方工具。
