# CafeSec Lab — 网络隔离的防御安全研究实验环境

本机隔离虚拟化实验环境,用于研究 **Windows 主机加固、Sysmon 日志、检测规则(Sigma/YARA)、SIEM 告警**。
平台:**Hyper-V**(本机已检测到 hypervisor 运行,且为 Win11 Pro,原生最优)。
网络:**Private 虚拟交换机**,完全隔离 —— VM 出不了外网、碰不到宿主真实 LAN。
域:**CSL-Server = 内部域控 `cafesec.lab`**(让源发起型 WEF 走 Kerberos、并用 GPO 下发);AD DNS 无转发器,仍气隙。

> **范围声明**:这是**防御工程 setup**(仓库的"验证靶场"模块)。本模块只含虚拟化/隔离网络/防御工具的
> 部署脚本与文档,**不含任何攻击、利用、渗透或漏洞利用模拟代码**,也不配置任何指向真实设备/网络的东西。

---

## 它在 CafeSec Lab 仓库中的位置

本模块 `04-validation-lab/` 是整个项目的**可复现验证靶场**:把仓库其它模块的"主张"变成在真实遥测上跑出来的**实验室证据**。

```
01-hardening-checklist  ──(Sigma/YARA 规则 + 加固基线 NI-xx)──┐
                                                              ▼
       04-validation-lab(本模块)── 隔离 Hyper-V/域 + Sysmon/Wazuh/WEF 遥测
                                                              │ 部署 & 验证
       02-integrity-monitor(Python)── 在靶场 VM 内运行 ──► 真实检测 / 误报调优
                                                              │ 产出 lab 证据
       docs/pilot + docs/cvp(证据包)── 反哺 ──► 03-blog(研究文章)
```

**五条接缝**(详见 [`COVERAGE.md`](COVERAGE.md)):
1. **规则消费** — `scripts\analysis\Invoke-RuleValidation.ps1` 直接校验 [`../01-hardening-checklist/detection`](../01-hardening-checklist/detection) 里的**真实** Sigma/YARA 规则(转换/编译 + 可选扫描),不复制规则。
2. **监控部署** — `scripts\guest\Deploy-IntegrityMonitor.ps1` 把 [`../02-integrity-monitor`](../02-integrity-monitor) 装进靶场 Windows VM,用真实 Sysmon/WEF 数据替代合成 fixtures。
3. **隔离实现** — 本模块 [`docs/02-network-isolation.md`](docs/02-network-isolation.md) 是 [`../01-hardening-checklist/checklist/03-network-isolation.md`](../01-hardening-checklist/checklist/03-network-isolation.md) 基线的参考实现与验证。
4. **覆盖矩阵** — [`COVERAGE.md`](COVERAGE.md) 把 NI-xx / 检测规则 映射到实现/验证它们的靶场脚本与遥测。
5. **证据产出** — `Invoke-RuleValidation.ps1` 产出结构化报告,可反哺 [`../docs/pilot`](../docs/pilot) 与 [`../docs/cvp`](../docs/cvp)。

> **诚实边界**:本靶场产出的是**可复现的合成实验室证据**,不是现场部署结论。引用到商业/CVP 文档时须按仓库 README
> "What This Project Will Not Publish" 的要求人工复核 —— 不得把 lab 输出当作 field-validated evidence。

---

## 已确认的环境(本机预检结果)
| 项 | 值 |
|---|---|
| 宿主 OS | Windows 11 专业版 (Build 26200) — 支持 Hyper-V ✅ |
| 内存 | 63.7 GB ✅ |
| CPU | i9-14900K,32 逻辑核 ✅ |
| 虚拟化 (VT-x) | 已启用(HypervisorPresent=True 反证 BIOS 已开)✅ |
| 磁盘 | C: 1569GB 空闲 / E: 1688GB 空闲 ✅(VM 存 E:) |
| 已装虚拟化软件 | 无第三方;改用本机原生 Hyper-V |

---

## 目录结构
```
CafeSec-Lab/
├─ README.md                     ← 本文件(总 runbook)
├─ config/
│  ├─ lab.psd1                   ← 中央配置:IP/规格/路径/域(改这一个文件即可调整全局)
│  ├─ wef/cafesec-subscription.xml  ← WEF 订阅定义(域模式)
│  └─ ubuntu/                    ← CSL-Wazuh 的 netplan / 可选 dnsmasq
├─ scripts/
│  ├─ Invoke-LabSetup.ps1        ← ★ 宿主侧一键编排(按序跑 00→04,自动处理 Hyper-V 重启关口)
│  ├─ 00-Preflight-Check.ps1     ← 预检(只读)
│  ├─ 01-Enable-HyperV.ps1       ← 启用 Hyper-V(管理员,可能重启)
│  ├─ 02-New-IsolatedSwitch.ps1  ← 建 Private 隔离交换机(关键)
│  ├─ 03-New-LabVMs.ps1          ← 建 4 台 VM(Gen2 + vTPM)
│  ├─ 04-Verify-Isolation.ps1    ← 宿主侧隔离验证
│  ├─ Switch-LabNetwork.ps1      ← 在 Provisioning/Isolated 两阶段间切换 VM 网卡
│  ├─ Reset-Lab.ps1              ← 拆除环境(破坏性,带 -WhatIf/-Force/交互确认)
│  ├─ New-PayloadIso.ps1         ← 把工具打包成 ISO 注入气隙 VM(离线,无需 ADK)
│  ├─ lib/Common.ps1             ← 共用函数
│  ├─ domain/                    ← 【域控/客户机内运行】域 + WEF GPO
│  │  ├─ Install-DomainController.ps1  (CSL-Server 提升为域控)
│  │  ├─ Set-DcDnsAirgap.ps1           (锁死 AD DNS 气隙)
│  │  ├─ Join-LabDomain.ps1            (客户机加域)
│  │  └─ New-WefGpo.ps1                (GPO 下发 WEF 源配置)
│  ├─ guest/                     ← 【在 VM 内运行】的脚本
│  │  ├─ Set-StaticIP.ps1              (-DnsServer 供域成员指向域控)
│  │  ├─ Test-GuestIsolation.ps1 ← 客户机侧隔离验证
│  │  ├─ Deploy-Sysmon.ps1
│  │  ├─ Install-WazuhAgent.ps1
│  │  ├─ Configure-WEC-Collector.ps1   (服务器/域控)
│  │  └─ Configure-WEF-Source.ps1      (客户机,GPO 的手动替代)
│  ├─ wazuh/                     ← 【Ubuntu 内运行】
│  │  ├─ install-wazuh-manager.sh
│  │  └─ test-guest-isolation.sh ← Ubuntu 侧隔离验证
│  └─ analysis/                  ← Sigma/YARA 引擎与扫描
│     ├─ Setup-RuleEngines.ps1
│     └─ Invoke-YaraScan.ps1
├─ rules/{sigma,yara}/           ← 你之后放自己的规则
├─ docs/                         ← 总览、隔离原理、域+WEF、下载清单、防御验证 runbook(04)
└─ downloads/                    ← 下载的安装包/工具暂存
```

---

## 执行顺序(交付物为脚本,由你审阅后自行执行)

> 全程在**管理员 PowerShell** 中,工作目录切到 `scripts\`。脚本均幂等,可重复运行。
> 先读 `docs\02-network-isolation.md` 理解【两阶段搭建】再开始。
> 搭好后用 `docs\04-defensive-validation-runbook.md` 驱动测试与证据产出(纯 benign 刺激,含 reviewer gate)。

### A. 宿主准备(+ 建 VM)
> **推荐**:用一键编排把宿主侧步骤 A+C 跑完(预检→启用 Hyper-V→建隔离交换机→建 VM→验证),
> 它会自动在 Hyper-V 需要重启时停下、重启后重跑即从断点继续:
> ```powershell
> cd 04-validation-lab\scripts            # 从克隆下来的仓库根目录进入本模块
> .\Invoke-LabSetup.ps1 -DryRun     # 先预览(无需管理员)
> .\Invoke-LabSetup.ps1             # 管理员下实际编排;若提示重启,重启后再次运行
> ```
> 手动逐步等价如下:
```powershell
cd 04-validation-lab\scripts            # 从克隆下来的仓库根目录进入本模块
.\00-Preflight-Check.ps1        # 确认条件(只读)
.\01-Enable-HyperV.ps1          # 启用 Hyper-V(若已启用会跳过;可能要求重启)
.\02-New-IsolatedSwitch.ps1     # 建 Private 隔离交换机 + 自检
```

### B. 下载镜像与工具(临时联网阶段)
- 按 `docs\downloads.md` 下载 **3 个 ISO**(Win11 Enterprise、Server 2022、Ubuntu 24.04;两台客户机 CSL-Client01/02 复用同一 Win11 镜像)到 `E:\CafeSec-Lab\ISO\`(文件名对齐 config)。
- 下载 Sysmon、SwiftOnSecurity 配置、Wazuh agent MSI、YARA、Python 等到 `downloads\`。

### C. 建 VM 并装系统
```powershell
.\03-New-LabVMs.ps1             # 建 4 台 VM(Gen2 + vTPM,可先 -WhatIf 预览)
```
- 用 Hyper-V 管理器逐台开机,完成 OS 安装。
- **阶段一**:此时可临时给 VM 接 External/NAT 交换机以联网装更新与工具:
  `.\Switch-LabNetwork.ps1 -Phase Provisioning -ProvisioningSwitch <你的NAT交换机>`(见隔离文档)。

### D. 建立域(CSL-Server 域控 + 客户机加域)— 见 `docs\03-domain-and-wef.md`
> 工作组下源发起型 WEF 无法走 Kerberos,故先建域。可在阶段一(联网)或隔离网内进行(只需 VM 间互通)。
```powershell
# 在 CSL-Server(先配好静态 IP 10.10.10.20):
$dsrm = Read-Host -AsSecureString "设置 DSRM 密码"
.\domain\Install-DomainController.ps1 -SafeModePassword $dsrm   # 提升为 cafesec.lab 域控,自动重启
.\domain\Set-DcDnsAirgap.ps1                                    # 锁死 AD DNS 气隙(无转发/无根提示)
# 在每台客户机(DNS 会自动指向域控):
$cred = Get-Credential CAFESEC\Administrator
.\domain\Join-LabDomain.ps1 -DomainCredential $cred            # 加域,自动重启
```

### E. 部署防御栈(仍在阶段一,VM 内操作)
- **Ubuntu (CSL-Wazuh)**:`bash scripts/wazuh/install-wazuh-manager.sh`(装 Wazuh 单机版)。
- **各 Windows VM**:
  - `guest\Deploy-Sysmon.ps1 -SysmonExe ... -ConfigXml ...`
  - `guest\Install-WazuhAgent.ps1 -MsiPath ...`(指向 manager 10.10.10.10)
- **CSL-Server(域控)**:`guest\Configure-WEC-Collector.ps1`(WEF 收集器)→ `domain\New-WefGpo.ps1`(GPO 下发源配置)
  - 客户机 `gpupdate /force`;`Event Log Readers` 成员与审核策略按 `docs\03` 补齐。
  - (手动替代 GPO:各客户机跑 `guest\Configure-WEF-Source.ps1 -CollectorFqdn CSL-Server.cafesec.lab`)
- **分析侧**:`analysis\Setup-RuleEngines.ps1`(Sigma CLI + opensearch 后端 + YARA 目录)

### F. 锁定隔离并验证(进入阶段二)
```powershell
# 把每台 VM 网卡切回隔离交换机(等价于 Connect-VMNetworkAdapter)
.\Switch-LabNetwork.ps1 -Phase Isolated
# 各 VM 内配静态 IP:域成员加 -DnsServer 指向域控
#   .\guest\Set-StaticIP.ps1 -IPAddress 10.10.10.31 -DnsServer 10.10.10.20   (客户机)
#   .\guest\Set-StaticIP.ps1 -IPAddress 10.10.10.20 -DnsServer 127.0.0.1     (域控)
# 宿主侧验证
.\04-Verify-Isolation.ps1
# 客户机侧验证:Windows 跑 guest\Test-GuestIsolation.ps1;Ubuntu 跑 wazuh/test-guest-isolation.sh
```
**宿主侧 + 客户机侧两边全 PASS = 隔离合规**,环境就绪。

### G. 放入你的检测规则
- Sigma 规则 → `rules\sigma\`,用 `sigma convert -t opensearch_lucene -p ecs_windows --disable-pipeline-check <rule>.yml` 转换(Wazuh 基于 OpenSearch;backend target 为 `opensearch_lucene`)。
- YARA 规则 → `rules\yara\`,用 `analysis\Invoke-YaraScan.ps1 -TargetPath ...` 扫描。

---

## 安全须知
- 任何研究/攻击模拟只在**阶段二(完全隔离)**进行,且由你本人手动操作 —— 不在本搭建范围内。
- 每次结构性改动(加 VM、改网卡)后,**重跑隔离验证**再继续。
- 工具与镜像**只从官方来源**获取(见 `docs\downloads.md`)。
