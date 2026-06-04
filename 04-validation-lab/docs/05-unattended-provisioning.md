# 05 — 无人值守 OS 装机 (Unattended provisioning)

把「建空 VM → 装系统」这一段从**手动点击**变成**可复现的模板装机**,缩小评估里「empty VM 之后全是手动」的缺口。

> **状态:◐ 模板 + 已验证的 ISO 构建器,装机本身需首次真机验证。**
> ISO 构建器 `New-UnattendIso.ps1`(底层复用 `New-PayloadIso.ps1` 的 IMAPI2)已被 Pester 实测能产出非空 ISO;
> 但「应答文件能否真正驱动一次完整安装」依赖你**第一次真机构建**时按下面的清单核验(Windows 的 image-index、Ubuntu 的密码哈希等是镜像/站点相关的,无法在不建 VM 的情况下证明)。

---

## 组成

| 路径 | 作用 |
|---|---|
| `config/unattend/windows/autounattend-template.xml` | Windows(UEFI/GPT, Gen2)应答文件模板,带 `{{HOSTNAME}}`/`{{IMAGE_NAME}}`/`{{ADMIN_USER}}`/`{{ADMIN_PASSWORD}}`/`{{TIMEZONE}}` 占位 |
| `config/unattend/ubuntu/user-data` `meta-data` | Ubuntu 24.04 cloud-init NoCloud(subiquity autoinstall)种子 |
| [`../scripts/New-UnattendIso.ps1`](../scripts/New-UnattendIso.ps1) | 渲染模板 → 调 `New-PayloadIso.ps1` 生成种子 ISO(无需管理员) |

## 用法(Phase-1 临时联网阶段)

```powershell
cd 04-validation-lab\scripts
# Ubuntu(CSL-Wazuh):先把 config/unattend/ubuntu/user-data 里的密码哈希替换为
#   openssl passwd -6 '<你的密码>'  的输出,再:
.\New-UnattendIso.ps1 -Os Ubuntu -Hostname csl-wazuh

# Windows(以 CSL-Server 为例):-ImageName 必须匹配你 eval ISO 里的版本名
#   (查看:Get-WindowsImage -ImagePath <挂载盘>\sources\install.wim)
.\New-UnattendIso.ps1 -Os Windows -Hostname CSL-Server -ImageName 'Windows Server 2022 SERVERSTANDARD'
.\New-UnattendIso.ps1 -Os Windows -Hostname CSL-Client01 -ImageName 'Windows 11 Enterprise Evaluation'
```

然后把 OS 安装 ISO 与该种子 ISO 一起挂到 VM 上开机:
```powershell
# OS 安装盘(主)+ 应答种子盘(次,自动被 Setup/subiquity 识别)
Set-VMDvdDrive  -VMName CSL-Server -Path E:\CafeSec-Lab\ISO\windows-server-2022-eval.iso
Add-VMDvdDrive  -VMName CSL-Server -Path E:\CafeSec-Lab\ISO\unattend-windows-CSL-Server.iso
Start-VM        -Name  CSL-Server
```

> **安全边界**:种子 ISO 只含应答文件(纯文本/XML),无任何工具或网络行为;装机在 Phase-1 临时联网网段进行,装完按主流程切回隔离(`Switch-LabNetwork.ps1 -Phase Isolated`)。lab admin 密码是一次性隔离实验凭据,生产/真实环境务必替换并改用 SecureString 传入(`-AdminPassword`)。

## 首次真机验证清单(把状态从 ◐ 推到 ✅)

- [ ] **Windows image-index**:`-ImageName` 与 eval ISO 中 `install.wim` 的版本名完全一致(`Get-WindowsImage`)。
- [ ] **Windows 磁盘布局**:模板按单盘 GPT(EFI 260MB + MSR 128MB + 主分区)写;若你的 VHDX/固件不同需调整。
- [ ] **Ubuntu 密码哈希**:`user-data` 里的占位哈希已替换为 `openssl passwd -6` 真值(占位值故意无效,会装机失败)。
- [ ] **Ubuntu 安装期网络**:走 DHCP(Phase-1 NAT);隔离静态 IP(10.10.10.10/24,无网关)在 Phase-2 由 netplan 应用。
- [ ] 装完一遍后,把该次的 `-ImageName` / 哈希 / 时区记进 `config\versions.psd1` 备注,使之可复现。

完成上述并真机跑通一次后,本流程即可标 ✅,并把 `COVERAGE.md` 中相关「单主机可演示」项的人工装机步骤替换为本自动化。

## 相关
- [`downloads.md`](downloads.md) — ISO/工具来源;[`00-overview.md`](00-overview.md) — 拓扑;[`../README.md`](../README.md) — A–G 主流程。
- [`../scripts/New-PayloadIso.ps1`](../scripts/New-PayloadIso.ps1) — 被复用的 IMAPI2 ISO 构建器(也用于把工具注入气隙 VM)。
