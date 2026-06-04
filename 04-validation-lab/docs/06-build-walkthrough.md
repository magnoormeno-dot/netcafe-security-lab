# 06 — 从零到 live-fire 证据:可复制粘贴的搭建走查 (Build walkthrough)

> English version: [`06-build-walkthrough.en.md`](06-build-walkthrough.en.md).

一条**线性、可断点续跑**的操作路径,把靶场从「未搭建」推到「产出真实 live-fire 证据」。
每个里程碑标了大致耗时、是否需要管理员/重启,以及**在哪一步把输出贴给协作的 agent**。

> 安全:特权步骤(管理员/Hyper-V/建 VM/重启/切网络)由**你本人**在管理员 PowerShell 执行。
> 全程只动 Hyper-V 平台、隔离交换机、4 台 CSL VM;不碰你的真实网络。所有刺激都是 benign/lab-owned。

| 里程碑 | 耗时 | 管理员 | 重启 | 需要 ISO |
|---|---|---|---|---|
| M0 前置 | 10 min + 下载 | 否 | 否 | 下载中 |
| M1 宿主脚手架 | 15–30 min | ✅ | ✅ 一次 | 否 |
| M2 装系统 ×4 | 1–3 h | ✅(宿主侧挂载) | — | ✅ |
| M3 域 + 防御栈 | 1–2 h | ✅(VM 内) | 多次 | 否 |
| M4 锁隔离 + live-fire 证据 | 30–60 min | ✅ | — | 否 |

`$LAB` 在每个新窗口先设一次:
```powershell
$LAB = "C:\Users\Eshine\Documents\New project 2\netcafe-security-lab\04-validation-lab"
```

---

## M0 — 前置(无特权)

- [ ] 宿主满足条件:`& "$LAB\scripts\00-Preflight-Check.ps1"`(只读)。
- [ ] 下载 3 个评估版 ISO 到 `E:\CafeSec-Lab\ISO\`,文件名对齐 [`config\lab.psd1`](../config/lab.psd1):
  `windows-11-enterprise-eval.iso` · `windows-server-2022-eval.iso` · `ubuntu-24.04-live-server-amd64.iso`(来源见 [`downloads.md`](downloads.md))。
- [ ] (可选)锁定可复现:把下好的 ISO 哈希填进 [`config\versions.psd1`](../config/versions.psd1)。

---

## M1 — 宿主脚手架(管理员 + 一次重启;**不需要 ISO**)

在**管理员 PowerShell**:
```powershell
$LAB = "C:\Users\Eshine\Documents\New project 2\netcafe-security-lab\04-validation-lab"
cd "$LAB\scripts"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-LabSetup.ps1            # 预检 → 启用 Hyper-V → 多半在“重启关口”停下
```
**会停在重启关口**(Hyper-V 刚启用、`vmms` 未就绪)。→ **重启电脑**,然后:
```powershell
# 重启后,新开管理员 PowerShell:
$LAB = "C:\Users\Eshine\Documents\New project 2\netcafe-security-lab\04-validation-lab"
cd "$LAB\scripts"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-LabSetup.ps1            # 幂等续跑:建隔离交换机 → 建 4 台 Gen2+vTPM VM → 宿主侧隔离验证
```
**🔖 贴回输出**:编排汇总表 + `04-Verify-Isolation` 的 PASS/FAIL。`Step 0–4 全 OK` = M1 完成。

---

## M2 — 装系统 ×4(管理员;需要 ISO)

**先做无人值守种子 ISO(无特权)**;Ubuntu 先改密码哈希(见 [`05-unattended-provisioning.md`](05-unattended-provisioning.md)):
```powershell
cd "$LAB\scripts"
.\New-UnattendIso.ps1 -Os Ubuntu  -Hostname csl-wazuh
.\New-UnattendIso.ps1 -Os Windows -Hostname CSL-Server   -ImageName 'Windows Server 2022 SERVERSTANDARD'
.\New-UnattendIso.ps1 -Os Windows -Hostname CSL-Client01 -ImageName 'Windows 11 Enterprise Evaluation'
.\New-UnattendIso.ps1 -Os Windows -Hostname CSL-Client02 -ImageName 'Windows 11 Enterprise Evaluation'
```
**挂主安装盘 + 种子盘并开机**(每台一次,示例 CSL-Server):
```powershell
Set-VMDvdDrive -VMName CSL-Server -Path 'E:\CafeSec-Lab\ISO\windows-server-2022-eval.iso'
Add-VMDvdDrive -VMName CSL-Server -Path 'E:\CafeSec-Lab\ISO\unattend-windows-CSL-Server.iso'
Start-VM       -Name  CSL-Server
```
> 装系统期间若需联网更新:`.\Switch-LabNetwork.ps1 -Phase Provisioning -ProvisioningSwitch <你的NAT交换机>`(见 [`02-network-isolation.md`](02-network-isolation.md))。
**🔖 贴回**:首次真机若 image-index/分区报错,贴给我;我据 [`05`](05-unattended-provisioning.md) 的清单帮你校正模板。

---

## M3 — 域 + 防御栈(VM 内操作;见 [`03-domain-and-wef.md`](03-domain-and-wef.md))

```powershell
# 静态 IP(各 VM 内):域成员指向域控 DNS
.\guest\Set-StaticIP.ps1 -IPAddress 10.10.10.20 -DnsServer 127.0.0.1     # CSL-Server(域控)
.\guest\Set-StaticIP.ps1 -IPAddress 10.10.10.31 -DnsServer 10.10.10.20   # CSL-Client01

# 域:CSL-Server 提升为域控,再锁 DNS 气隙;客户机加域
.\domain\Install-DomainController.ps1 -SafeModePassword (Read-Host -AsSecureString "DSRM 密码")
.\domain\Set-DcDnsAirgap.ps1
.\domain\Join-LabDomain.ps1 -DomainCredential (Get-Credential CAFESEC\Administrator)

# 防御栈
bash scripts/wazuh/install-wazuh-manager.sh                    # Ubuntu(CSL-Wazuh)
.\guest\Deploy-Sysmon.ps1 -SysmonExe ... -ConfigXml ...        # 各 Windows VM
.\guest\Install-WazuhAgent.ps1 -MsiPath ...                    # 指向 manager 10.10.10.10
.\guest\Configure-WEC-Collector.ps1 ; .\domain\New-WefGpo.ps1  # 域控:WEF 收集器 + GPO
.\analysis\Setup-RuleEngines.ps1                               # 分析侧:sigma-cli + yara
```
**🔖 贴回**:TC-08 四项自检(Sysmon 在跑 / 4688 含命令行 / WEF `ForwardedEvents` 有客户机事件 / Wazuh agent `Active`)。链路全通才进 M4。

---

## M4 — 锁隔离 + live-fire 证据(锁定 10/10 的最后一步)

```powershell
.\Switch-LabNetwork.ps1 -Phase Isolated     # 全部网卡切回隔离交换机
.\04-Verify-Isolation.ps1                   # 宿主侧;各 VM 内跑 guest\Test-GuestIsolation.ps1 / wazuh\test-guest-isolation.sh
```
> **两边全 PASS 才算隔离合规**,之后方可刺激。

1. **离线证据(已可跑)**:`cd "$LAB\scripts\analysis"; .\Invoke-RuleValidation.ps1; .\Export-CvpEvidence.ps1` —— 应得 6/6,刷新 [`lab-validation-evidence.md`](../../docs/cvp/lab-validation-evidence.md)。
2. **live-fire(按 [`04-defensive-validation-runbook.md`](04-defensive-validation-runbook.md) TC-01~09)**:在维护窗口内对 **lab-owned dummy** 施加 benign 刺激,到 Wazuh/`ForwardedEvents` 确认命中、记录检测延迟、还原。**每条规则点亮一次 = 实弹证据**。
3. 过 [`04` 的 reviewer gate](04-defensive-validation-runbook.md) 后,把 live-fire 结果归档,更新 `COVERAGE.md` 中相关项为 ✅。

**🔖 贴回**:`Invoke-RuleValidation` 的 6/6 + 各 TC 的命中截图/记录。到此 runnability 与 evidence 两维补齐,靶场达成 10/10。

---

## M2 装机踩坑速查(实测)

- **Win11 VM 开机报 `0xC000A002`「已计算的身份验证标记与输入的身份验证标记不匹配」**:
  vTPM 的 key protector 失效(常见于宿主 Guardian 密钥变动后)。VM 无法初始化、起不来。修复(管理员,VM 关机状态):
  ```powershell
  Stop-VM CSL-Client01 -TurnOff -Force -ErrorAction SilentlyContinue
  Set-VMKeyProtector -VMName CSL-Client01 -NewLocalKeyProtector   # 重建本地 key protector
  Enable-VMTPM       -VMName CSL-Client01                          # 重新挂上 vTPM
  Start-VM           -Name  CSL-Client01
  ```
  > Win11/Server 必须保留 `SecureBoot=On` + `SecureBootTemplate=MicrosoftWindows` + vTPM;别为了绕错而关掉它们(会触发 Win11 的 TPM 检查失败)。

- **CSL-Wazuh(Ubuntu)黑屏 / "Boot failed" / Secure Boot 报错**:Gen2 默认 Secure Boot 模板是 `MicrosoftWindows`,挡 Ubuntu。修复:
  ```powershell
  Stop-VM CSL-Wazuh -TurnOff -Force
  Set-VMFirmware CSL-Wazuh -SecureBootTemplate MicrosoftUEFICertificateAuthority
  Start-VM CSL-Wazuh
  ```

- **气隙下进 VM 跑命令 / 验证装机** —— 用 **PowerShell Direct**(走 VMBus,不需要网络,隔离全程不破):
  ```powershell
  $cred = [pscredential]::new('labadmin', (ConvertTo-SecureString 'CafeSecLab!2026' -AsPlainText -Force))
  Invoke-Command -VMName CSL-Server -Credential $cred -ScriptBlock { hostname; (Get-CimInstance Win32_OperatingSystem).Caption }
  ```
  起得来、能 `Invoke-Command` 进去 = 该台装完了(比单看 `Get-VM` 的 Uptime 可靠)。工具注入同理用 `Copy-VMFile`(见 [`downloads.md`](downloads.md)),无需切到联网交换机。

## 断点续跑 / 卡住了?
- 所有宿主脚本**幂等**:任意一步失败,排查后重跑即可(`Invoke-LabSetup.ps1` 会跳过已完成步骤)。
- 拆了重来:`.\Reset-Lab.ps1 -WhatIf` 看清单,确认后 `.\Reset-Lab.ps1`(只删 4 台 CSL VM + 隔离交换机,绝不碰你其它 VM/交换机)。
- 把任一步的报错原样贴出来,我接住给下一步。
