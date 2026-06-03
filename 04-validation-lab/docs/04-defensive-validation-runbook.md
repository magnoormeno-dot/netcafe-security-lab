# 04 — 防御验证 Runbook (Defensive Validation Runbook)

把 `04-validation-lab` 从「脚手架 / DryRun」推进到「可测试、可产出 **CVP / 防御验证证据**」的端到端操作手册。
本 runbook 覆盖：**实验室目的 → 前置条件 → 搭建检查点 → 测试用例 → 证据采集 → CVP 证据措辞 → 安全边界 → 复核关口**。

> **范围与安全声明（与 [`../../01-hardening-checklist/detection/validation-scenarios.md`](../../01-hardening-checklist/detection/validation-scenarios.md) 同源）**
>
> - 本 runbook 验证的是「检测**会不会命中**、遥测**全不全**、响应**能不能动**」，**不是**攻击剧本。
> - 全部刺激(stimulus)都是 **benign / synthetic / lab-owned**:在完全隔离的实验网内,对**实验室自有的占位对象**(dummy 服务/文件/注册表占位键/良性样本)施加**正常的、可回滚的管理动作**,在维护窗口内公开执行、观察、还原。
> - 本文**不含**、也**禁止**加入:攻击命令、exploit、payload、检测绕过 / 日志或 AMSI 绕过、混淆、凭据获取、真实目标 / 真实公司系统 / 生产环境 / 测试网探测、恶意样本构造。
> - 触发动作的「具体怎么敲」由操作者通过**已审批、可追溯的测试 harness 或文档化的手动维护动作**驱动 —— 目标是一个**已知良性的刺激**,被观测后还原,而不是一个可复用的技术。
> - 产物是**可复现的合成实验室证据**,不是现场结论。引用进商业 / CVP 文档前须按仓库 README "What This Project Will Not Publish" 人工复核。

---

## 1. 实验室目的 (Lab purpose)

`04-validation-lab` 是整个仓库的**可复现验证靶场**:把 01 的检测规则、02 的完整性监控的「主张」,在**真实遥测**上跑成**实验室证据**。本 runbook 让你能回答三个防御问题:

1. **检测可用吗?** —— 仓库的 Sigma / YARA 规则能否在本靶场的真实 Sysmon / WEF / Wazuh 数据上,被一个**良性刺激**正确点亮。
2. **遥测全吗?** —— 规则所依赖的事件源(4688+命令行、Sysmon 1/12/13、System 7034-7045、Security 4657)是否真的在采集并集中转发。
3. **隔离牢吗?** —— 在做任何验证前,实验网确实出不了外网、碰不到宿主真实 LAN(宿主侧 + 客户机侧两边全 PASS)。

接缝映射见 [`../COVERAGE.md`](../COVERAGE.md);证据回流见本文第 6 节与 [`../scripts/analysis/Export-CvpEvidence.ps1`](../scripts/analysis/Export-CvpEvidence.ps1)。

---

## 2. 前置条件 (Prerequisites)

> 本 runbook 假设[宿主侧编排](../README.md)(隔离交换机 + 4 台 VM)已经做完。当前状态可随时用只读检查复核(见第 3 节)。

| 前置 | 怎么满足 | 怎么核对(只读) |
|---|---|---|
| 宿主硬件 / Hyper-V | [`../README.md`](../README.md) A 节 | `../scripts/00-Preflight-Check.ps1` |
| 隔离交换机 `CafeSec-Isolated` | `../scripts/02-New-IsolatedSwitch.ps1`(需管理员) | `Get-VMSwitch -Name CafeSec-Isolated` |
| 4 台 VM(Wazuh/Server/Client01/02) | `../scripts/03-New-LabVMs.ps1`(需管理员) | `Get-VM CSL-*` |
| 3 个 ISO 到位 | 见 [`downloads.md`](downloads.md),放 `E:\CafeSec-Lab\ISO\` | `00-Preflight-Check.ps1` 的「镜像检查」段 |
| 域 `cafesec.lab`(WEF 走 Kerberos) | [`03-domain-and-wef.md`](03-domain-and-wef.md) | 客户机 `whoami /fqdn` |
| 防御栈(Sysmon/Wazuh/WEF) | [`../README.md`](../README.md) E 节 | 见 TC-08 遥测路径自检 |
| 规则引擎(sigma-cli + yara64.exe) | `../scripts/analysis/Setup-RuleEngines.ps1`(临时联网阶段) | `Get-Command sigma`;`Test-Path downloads\tools\yara64.exe` |
| 完整性监控(Python 3.10+) | `../scripts/guest/Deploy-IntegrityMonitor.ps1` | `python -m integrity_monitor --help` |

**必须由操作者用管理员 PowerShell 亲自执行**的步骤(本 runbook 与本 agent **不会擅自代跑**):启用 Hyper-V、建交换机 / VM、装系统、建域、切网络、删 VM。

---

## 3. 搭建检查点 (Setup checkpoint)

每次结构性改动后、以及任何测试前,先跑这两条**只读**门禁。任一不过,**先停**,排查后再继续。

### 3.1 状态门禁(随时可跑,无需管理员)
```powershell
cd 04-validation-lab\scripts
.\00-Preflight-Check.ps1            # 只读:OS/RAM/CPU/磁盘/ISO
.\Invoke-LabSetup.ps1 -DryRun       # 只读:打印宿主侧编排计划,不做任何改动
```

### 3.2 隔离门禁(**进入测试前的硬关口**)
> 隔离是所有验证的前提。**宿主侧 + 客户机侧两边全 PASS 才算隔离合规**,否则不得开始任何刺激。
```powershell
# 宿主侧(管理员)
.\04-Verify-Isolation.ps1
# 每台 Windows VM 内
.\guest\Test-GuestIsolation.ps1     # 见 ../scripts/guest/Test-GuestIsolation.ps1
# Ubuntu(CSL-Wazuh)内
bash scripts/wazuh/test-guest-isolation.sh
```
判据:同隔离网内 VM 可达(正向),而公网 IPv4/IPv6、公网 DNS、真实 LAN 网关、默认网关**全部不可达**(反向)。任何「本应失败却成功」= 隔离破裂 = 立即停用排查。

### 3.3 规则可编译门禁(无需管理员,无需运行中的 VM)
```powershell
cd 04-validation-lab\scripts\analysis
.\Invoke-RuleValidation.ps1         # 就地校验 ../01-.../detection 的 Sigma 转换 + YARA 编译
```
这一步只证明「规则语法 / 字段 / 可编译」成立,**不**证明「在真实遥测上命中」—— 后者由第 4 节的 live-fire 用例完成。

---

## 4. 测试用例 (Test cases)

**统一模板**:每个用例只含 `benign stimulus / expected telemetry / expected alert / evidence / FP-handling / rollback / safety-boundary`,**不含**攻击命令、exploit、payload、绕过、真实目标。

> Sigma 三条规则的「防御目标 / ATT&CK / FP 风险 / 缓解」叙述已在
> [`validation-scenarios.md`](../../01-hardening-checklist/detection/validation-scenarios.md) 的 **Card 1-3** 写全。
> 下面 TC-01~03 **不重复**那些内容,只补「靶场里怎么落地刺激 + 怎么还原」,请配合卡片阅读。

通用流程(每个 live-fire 用例都遵循,源自卡片末尾的 Validation run checklist):
1. 确认相关日志源已开启并在转发(见 TC-08)。2. 截一段干净 baseline 窗口使刺激可归因。3. 在维护窗口内、对 lab-owned 占位对象施加良性刺激。4. 记录:是否命中、检测延迟、字段完整度、可用的关联枢轴。5. 还原一切改动回到 baseline。6. 给该次运行打 lab-validation 标签,排除出生产 FP 指标。

---

### TC-01 — Billing/Control 进程终止检测
**Maps to:** [`sigma/billing_process_termination.yml`](../../01-hardening-checklist/detection/sigma/billing_process_termination.yml)(rule id `58f9bf1a-…74f8`, level **high**, status experimental) · 详见 Card 1。

- **Benign stimulus**:在客户机上,对一个**实验室自有的占位「控制进程」**(例如一个名字含 `billing`/`watchdog` 字样的 do-nothing 占位进程/dummy 服务,由你创建)施加**一次正常的管理性停止动作**,从一个**非已审批父路径**的普通用户 shell 发起,在维护窗口内公开进行。占位对象不含任何真实收银/billing 厂商代码。
- **Expected telemetry**:Windows `process_creation` —— Sysmon **EID 1** + Security **4688(含命令行)**,字段 `Image / ParentImage / CommandLine / ParentCommandLine / User / Computer / UtcTime` 已填充;被点名占位代理的 health/heartbeat 流出现相应停止记录。
- **Expected alert**:`billing_process_termination.yml` 命中(经 sigma-cli 转换后在 Wazuh / `ForwardedEvents` 可见);approved-admin-path 过滤器对「从已审批路径发起的同类动作」应**不**告警。
- **Evidence**:原始匹配的 process-creation 记录 + 产生的告警;事件生成→告警浮现的时间差(检测延迟);占位代理是否真的被停 / 是否被保护自启;操作者三连(谁、主机角色、是否在窗口内)。
- **FP-handling**:已审批维护脚本、厂商更新自停自起、EDR 受控修复都会进入此规则;**给本次 lab run 打标签并排除**出 FP 指标。需要例外时按 [`tuning-guide.md`](../../01-hardening-checklist/detection/tuning-guide.md) 用**精确命名**的维护账户(勿用 `admin`/`operator` 宽匹配)。
- **Rollback / cleanup**:重启/移除占位进程与 dummy 服务,确认占位代理回到 baseline;删除为本测试临时创建的对象。
- **Safety boundary**:刺激只作用于 lab-owned 占位对象;不触碰任何真实 billing 软件、不打印武器化命令行、不演示如何躲过该检测。

### TC-02 — 关键服务被停 / 禁用检测
**Maps to:** [`sigma/critical_service_disabled.yml`](../../01-hardening-checklist/detection/sigma/critical_service_disabled.yml)(rule id `92bd2cf4-…5d96`, level **high**, status experimental) · 详见 Card 2。

- **Benign stimulus**:对一个**实验室自有的 dummy 服务**(名字含 `billing`/`watchdog`/`backup` 等被规则关注的字样,由你 `New-Service` 创建的空壳)做一次**正常的服务控制变更**(停止,或把启动类型改为 disabled),在维护窗口内进行。不触碰 Wazuh/Sysmon/Defender 等真实防御服务。
- **Expected telemetry**:System 日志 SCM 事件 **7034 / 7035 / 7036 / 7040 / 7045**;字段 `Provider_Name(Service Control Manager) / EventID / Message / Computer / TimeCreated`,Message 含 bad-state 措辞(`stopped` / `disabled` / `start type`)+ 关键服务名。
- **Expected alert**:`critical_service_disabled.yml` 命中;`ApprovedMaintenance` / `VendorUpdateWindow` 维护过滤器对「计划内变更」应正确抑制。
- **Evidence**:匹配的 System 记录 + 告警;关联枢轴(同主机/时窗内最近的 process-creation、logon、billing-audit);服务前后状态及是否自恢复;维护过滤是否按预期抑制了一次计划内变更。
- **FP-handling**:厂商更新先停后换、计划补丁/重启窗口、首装部署、资源/电源导致的重启都属正常;调优时把关键服务名表对齐到**实验室实际的 dummy 名**,并把计划内变更走维护标签路径。
- **Rollback / cleanup**:把 dummy 服务启动类型/状态改回原值或直接 `Remove-Service`(删除测试空壳)。
- **Safety boundary**:只动 dummy 空壳服务;绝不停用靶场真实防御服务(那会致盲遥测);不含绕过 SCM 审计的任何方法。

### TC-03 — 异常注册表修改检测
**Maps to:** [`sigma/anomalous_registry_modification.yml`](../../01-hardening-checklist/detection/sigma/anomalous_registry_modification.yml)(rule id `e1fc50ea-…f4ac`, level **medium**, status experimental) · 详见 Card 3。

- **Benign stimulus**:在一个**被监控的占位键**(例如实验室自建的 `HKLM\Software\VenueBilling` 占位路径,或一个 lab-only 的 Run/服务键占位)写入一个**良性测试值**,由非 `svc_patch`/`svc_config` 的账户发起,在维护窗口内进行。前提是该键已开启**对象访问审核(SACL)**。
- **Expected telemetry**:Security **EID 4657**(注册表值被修改);字段 `ObjectName(被监控键路径) / ObjectValueName(如 Run 项、服务 Start/ImagePath、日志开关、Proxy/DNS 值) / SubjectUserName / ProcessName / NewValue / Computer / TimeCreated`。
- **Expected alert**:`anomalous_registry_modification.yml` 命中;approved-change 账户过滤(`svc_patch`/`svc_config`)对已审批变更应不告警。**若根本没有 4657 流** —— 这本身是发现(检测盲点,而非「无事」),说明该键审核未开。
- **Evidence**:匹配的 4657 记录 + 告警;被改键的前/后值及其属于哪类被监控路径(autostart / policy / network / billing config);操作进程与用户;是否在审批窗口内;以及**审核确实在被监控键上开着**的证明。
- **FP-handling**:GPO 刷新、审批窗口内的厂商更新、端点管理基线、首装/lab 测试都会进入;把 logging 与 application-control 开关类改动的优先级置于良性 autostart 改动之上。
- **Rollback / cleanup**:把占位键的测试值删回 / 改回原值;若为测试临时建的占位键则整键删除。
- **Safety boundary**:只写 lab-owned 占位键的良性测试值;**不**改动任何真实的 Defender/PowerShell-logging/AppLocker 策略键去削弱防御(那是绕过,禁止)。

> **YARA 三条(TC-04~06)阅读说明**:下面各用例 *Expected telemetry* 里列出的 Windows API 导入名与 PE 节名,是这些防御 YARA 规则**所匹配的检测特征(它检测什么)**,**不是** API 调用指令、注入步骤或构造任何二进制的配方。正样本一律用合法良性工具(见各用例),本 runbook 不构造、不投放任何工具。

### TC-04 — 通用内存扫描器特征(YARA)
**Maps to:** [`yara/generic_memory_scanner.yar`](../../01-hardening-checklist/detection/yara/generic_memory_scanner.yar)(`CafeSec_Generic_Memory_Scanner_Behavior`, status experimental)。

- **Benign stimulus**(三选一,均不构造恶意样本):
  1. **编译校验**:`Invoke-RuleValidation.ps1`(对空探针文件编译,退出码 0 = 规则可用)。
  2. **已知良性基线扫描(主验证)**:用 `Invoke-YaraScan.ps1 -TargetPath <golden-image / Program Files>` 扫干净基线,**期望 0 命中**(FP baseline)——这正是规则自带 "Scan a known-good baseline" 的要求。
  3. **良性 trait 正样本**:扫一个**合法**且天然带该 trait 的工具(如签名的调试器 / profiler —— 这些正是规则列出的 *expected false positives*),期望命中 → 走分诊 → 判定良性 → 演练 allowlist/调优工作流。**不**编写/投放任何内存扫描器或作弊工具。
- **Expected telemetry**:文件/内存字节特征(`OpenProcess`/`ReadProcessMemory`/`VirtualQueryEx`/`CreateToolhelp32Snapshot` 等导入 + scan/compare 文案);live 内存扫描需 YARA 跑在运行中的 VM 上(COVERAGE 标 ◐)。
- **Expected alert**:`Invoke-YaraScan.ps1` 输出该规则在目标上的匹配行;基线扫描应为空。
- **Evidence**:`reports\rule-validation-*.md/.jsonl`(编译结果)+ YARA 扫描输出(命中路径 / 计数);对良性正样本的分诊记录(路径、发布者、判定良性的理由)。
- **FP-handling**:调试器、profiler、anti-cheat、EDR、内存诊断工具都会命中 —— 这是 triage 规则,不自动阻断;良性命中按 [`tuning-guide.md`](../../01-hardening-checklist/detection/tuning-guide.md) 记录例外。
- **Rollback / cleanup**:删除 `reports\` 下本次产物(如不需留档);移除临时拷入的良性正样本。
- **Safety boundary**:正样本只用**合法、良性、可公开**的工具;不构造、不投放、不发布任何内存扫描器/作弊/PoC 二进制。

### TC-05 — 未签名注入器特征(YARA)
**Maps to:** [`yara/unsigned_injector_patterns.yar`](../../01-hardening-checklist/detection/yara/unsigned_injector_patterns.yar)(`CafeSec_Unsigned_Process_Injection_Traits`)。

- **Benign stimulus**:① 编译校验(`Invoke-RuleValidation.ps1`);② 已知良性基线扫描期望 0 命中;③ 正样本用一个**合法但未签名**、天然导入这些 API 的良性工具(如开源诊断/调试小工具 —— 规则列出的 *expected false positives*),验证 `not pe.is_signed` + import 组合逻辑能点亮 → 分诊判定良性。
- **Expected telemetry**:PE 元数据 —— 未签名 + `OpenProcess`+`WriteProcessMemory`+`VirtualAllocEx` 导入 + 1 个线程创建/APC API + 1 个 `GetProcAddress`/`LoadLibrary`/`VirtualProtectEx`。
- **Expected alert**:YARA 扫描在该未签名良性工具上命中;签名良性工具与干净基线应不命中。
- **Evidence**:编译报告 + 扫描输出;正样本分诊(为何良性、host role、是否可加 allowlist 例外)。
- **FP-handling**:未签名但合法的厂商支持工具、anti-cheat、安装器/更新器会命中;按 tuning-guide 记录例外,优先看 host role 与路径(customer-writable 更可疑)。
- **Rollback / cleanup**:移除临时正样本与不需留档的报告。
- **Safety boundary**:**绝不**编写、编译或投放任何进程注入器 / loader / PoC;正样本仅为合法良性工具;本规则的 *intent* 注释已明确「不描述如何注入」——本 runbook 同样不描述。

### TC-06 — 可疑加壳特征(YARA)
**Maps to:** [`yara/suspicious_packer_traits.yar`](../../01-hardening-checklist/detection/yara/suspicious_packer_traits.yar)(`CafeSec_Suspicious_Packer_Traits`)。

- **Benign stimulus**:① 编译校验;② 干净基线扫描期望可控的低命中(规则自带「classify known packed-but-legit software」要求);③ 正样本用**良性开源工具的 UPX 压缩版**(UPX 是合法压缩器,压缩良性程序不构成恶意),触发高熵节 + `UPX0/UPX1` 节名 → 分诊判定「良性已加壳软件」。
- **Expected telemetry**:PE 节熵 > 7.1、导入数 < 20、运行期 API 解析字符串、或 `UPX0`/`UPX1`/`.packed`/`.aspack`/`.vmp` 节名匹配。
- **Expected alert**:YARA 在 UPX 压缩的良性样本上命中;原始未压缩良性程序通常不命中。
- **Evidence**:编译报告 + 扫描输出;正样本分诊(发布者、是否厂商文档化的加壳、golden image 哈希比对)。
- **FP-handling**:合法 protector(游戏 launcher / anti-cheat)、厂商 billing 组件、自解压安装器都会命中;**生产中不可仅凭此规则阻断**,先核对 host role/路径/签名。
- **Rollback / cleanup**:删除临时 UPX 样本与不需留档的报告。
- **Safety boundary**:只用合法压缩器压缩**良性**程序作正样本;不构造、不发布加壳的恶意/作弊二进制。

### TC-07 — 完整性监控 baseline / scan / verify
**Maps to:** [`../scripts/guest/Deploy-IntegrityMonitor.ps1`](../scripts/guest/Deploy-IntegrityMonitor.ps1) → [`../../02-integrity-monitor`](../../02-integrity-monitor/README.md)(`baseline`/`scan`/`verify`)。

- **Benign stimulus**:在靶场 Windows VM 内对一个 **billing 风格的占位路径**(默认 `C:\CafeBilling`,放几个良性占位文件)建立 HMAC 签名基线,然后**良性地改动一个占位文件**(改一行内容 / 加一个文件),再次 scan 以观察 **drift 检出**。工具是保守只读的(只读取/哈希/比对),**不修改/绕过/篡改**任何真实 billing 软件。
  ```powershell
  cd 04-validation-lab\scripts\guest
  .\Deploy-IntegrityMonitor.ps1 -SourceDir C:\CafeSec\02-integrity-monitor -BillingPath C:\CafeBilling
  # 等价底层命令(见 02-integrity-monitor/README.md):
  #   python -m integrity_monitor baseline create --path C:\CafeBilling --store baseline.json --hmac-key-file hmac.key
  #   python -m integrity_monitor scan   --path C:\CafeBilling --store baseline.json --hmac-key-file hmac.key
  #   python -m integrity_monitor verify --store baseline.json --hmac-key-file hmac.key
  ```
- **Expected telemetry**:baseline 建立后,对占位文件的良性改动应被 `scan` 报告为 drift;`verify` 校验基线 HMAC 签名完好(被篡改则签名校验失败)。进程/事件日志异常检查会消费本机真实 Sysmon/Security 日志。
- **Expected alert**:`scan` 输出 file drift 条目;若配 `--webhook` 指向 Wazuh/collector,则去重告警发出(COVERAGE 标 ◐)。
- **Evidence**:baseline.json、scan 的 drift 报告、verify 的签名校验结果;改动前/后哈希对照。
- **FP-handling**:合法更新会产生预期 drift —— 改动前后重建 baseline,并把 HMAC 密钥放到收银用户**不可写**的位置(勿与 baseline 同目录)。
- **Rollback / cleanup**:把占位文件改回基线内容,或删除 `C:\CafeBilling` 与 `C:\CafeSec\integrity` 工作目录(含 venv/baseline/key)。
- **Safety boundary**:只对 lab-owned 占位路径建基线/扫描;不接触真实 billing 二进制;HMAC 密钥不入库、不外泄。

### TC-08 — Sysmon / WEF / Wazuh 遥测路径
**Maps to:** `guest\Deploy-Sysmon.ps1` · `guest\Install-WazuhAgent.ps1` · `guest\Configure-WEC-Collector.ps1` + `domain\New-WefGpo.ps1`(见 [`03-domain-and-wef.md`](03-domain-and-wef.md))。

> 这是 TC-01~03 的**前提**:规则点不亮往往不是规则错,而是遥测没到。先证明数据链通,再做 live-fire。

- **Benign stimulus**:产生一条**良性、可预期的端点事件**(例如一次正常登录、或启动一个普通进程),用作「数据链探针」。无需任何攻击动作。
- **Expected telemetry / 自检**:
  - **Sysmon 在跑**:`Get-Service Sysmon*`;`Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5`。
  - **4688 含命令行已开**:审核策略 GPO 已下发(见 docs/03);`auditpol /get /subcategory:"Process Creation"`。
  - **WEF 转发在工作**:收集器(CSL-Server)上 `Get-WinEvent -LogName ForwardedEvents -MaxEvents 5` 能看到来自客户机的事件;客户机 `wecutil gr <subscription>` / `Event Viewer → Subscriptions` 状态正常。
  - **Wazuh agent 已连**:客户机 agent 服务在跑,manager(`10.10.10.10`)上该 agent 状态 `Active`。
- **Expected alert**:良性探针事件应能在 Wazuh / `ForwardedEvents` 端到端看到(证明 Sysmon→WEF→收集器、以及 agent→manager 两条链都通)。
- **Evidence**:四项自检的截图/输出;一条探针事件从端点到 Wazuh/收集器的端到端时间戳。
- **FP-handling**:此处的"误报"是**良性探针没出现却并非真盲点** —— 可能是 WEF/agent 的瞬时转发延迟、去重窗口或预期内的采集间隔。判别:重发探针、查 WEF 订阅运行态(`wecutil gr`)与 agent 心跳(manager 上 agent `Active`);仍缺失才判定为真盲点。**确认的缺失事件流本身是发现**(检测盲点),需补齐后再做 TC-01~03。
- **Rollback / cleanup**:无持久产物 —— 让瞬时探针进程自然退出即可;给探针事件打 lab-validation 标签,排除出生产指标(同 TC-01~03)。
- **Safety boundary**:只读自检 + 良性探针事件;不注入伪造日志、不演示日志篡改/绕过。

### TC-09 — 实验室隔离验证
**Maps to:** [`../scripts/04-Verify-Isolation.ps1`](../scripts/04-Verify-Isolation.ps1)(宿主) · [`../scripts/guest/Test-GuestIsolation.ps1`](../scripts/guest/Test-GuestIsolation.ps1)(Windows 客户机) · `../scripts/wazuh/test-guest-isolation.sh`(Ubuntu)。

- **Benign stimulus**:只读探测 —— ping 同网段 peer(正向连通)、尝试到达刻意固定的公网 IP / 公网 DNS / 常见真实 LAN 网关(反向,**应全部失败**)。无任何攻击意味。
- **Expected telemetry / 判据**:同隔离网 peer 可达(PASS);公网 IPv4(`1.1.1.1`/`8.8.8.8`)与 IPv6、公网 DNS 解析、真实 LAN 网关(`192.168.x.1`/`10.0.0.1`)、默认网关 **全部不可达 / 不存在**(PASS = 出不去)。列出的公网 IP/DNS/网关仅作**不可达性锚点**以证明出口被阻断,绝非探测目标。
- **Expected alert**:脚本结尾 `PASS=n FAIL=0`;客户机脚本以 `exit $fail` 返回(0 = 合规)。
- **Evidence**:宿主侧 + 各 VM 侧脚本输出(两边都要留)。**两边全 PASS 才算隔离合规。**
- **FP-handling**:peer 不可达只 `WARN`(可能未开机/丢 ICMP),与隔离破裂无关;任何「本应失败却 PASS」才是真问题。
- **Rollback / cleanup**:无(纯只读)。
- **Safety boundary**:探测目标为刻意固定的公共 IP,仅用于证明**出口被阻断**;不对任何真实目标做连通性以外的探测。

---

## 5. 证据采集 (Evidence collection)

| 用例 | 产物 | 落地位置 |
|---|---|---|
| TC-01~03(Sigma live-fire) | 原始匹配记录 + 告警 + 检测延迟 + 操作者三连 | Wazuh / `ForwardedEvents` 导出 + 手记 |
| TC-04~06(YARA) | 编译报告 + 扫描输出 + 正样本分诊 | `04-validation-lab\reports\rule-validation-*.{md,jsonl}` |
| TC-07(完整性监控) | baseline.json + drift 报告 + verify 结果 | VM 内 `C:\CafeSec\integrity\` |
| TC-08(遥测路径) | 四项自检输出 + 端到端时间戳 | 截图 / 手记 |
| TC-09(隔离) | 宿主 + 各 VM 脚本输出 | 截图 / 手记 |

规则校验结果回流为 CVP 证据:
```powershell
cd 04-validation-lab\scripts\analysis
.\Invoke-RuleValidation.ps1     # 产出 reports\rule-validation-<run>.{md,jsonl}
.\Export-CvpEvidence.ps1        # 渲染为 ../../docs/cvp/lab-validation-evidence.md(带 reviewer gate)
```

---

## 6. CVP 证据措辞 (CVP evidence wording)

引用本靶场产物进任何商业 / CVP 文档时,**必须**带上以下边界措辞(英文,与
[`../../docs/cvp/lab-validation-evidence.md`](../../docs/cvp/lab-validation-evidence.md) 的 "Scope & safety boundary" 段及仓库数据政策一致;canonical 措辞由 `Export-CvpEvidence.ps1` 维护):

> This evidence is **synthetic and reproducible** lab output, **not field-validated** results.
> It was produced in a fully network-isolated single-host Hyper-V lab against **lab-owned objects only**.
> There was **no production, test-net, or third-party probing**, and **no exploit, payload, or
> detection-bypass content** was used or produced. The lab validates **defensive workflows only**:
> that the repository's detection rules convert/compile and fire on controlled **benign** telemetry,
> that the integrity monitor detects benign drift, and that network isolation holds.
> A human reviewer must approve this file before it is cited (see the reviewer gate below).

**禁止**把 lab 输出写成 "field-validated" / "tested in production" / "verified against a real venue" —— 那违反仓库
"What This Project Will Not Publish" 政策。

---

## 7. 安全边界 (Safety boundary) — 总表

| 允许(本 runbook 范围内) | 禁止(超范围,本 agent 不会做) |
|---|---|
| benign / synthetic / lab-owned 刺激 | 攻击命令、exploit、payload、漏洞利用链 |
| 对 dummy 服务/文件/占位键的正常可回滚管理动作 | 检测绕过 / 日志或 AMSI 绕过 / 混淆 / 凭据获取 |
| 合法良性工具(调试器/UPX 压缩的 OSS)作 YARA 正样本 | 构造/投放/发布内存扫描器、注入器、加壳恶意/作弊二进制 |
| 完全隔离网内、维护窗口、公开执行、观测后还原 | 真实目标 / 真实公司系统 / 生产 / 测试网探测 |
| 防御工具(校验/扫描/完整性/隔离验证)可执行命令 | 削弱靶场真实防御服务/策略键 |
| 需管理员/建 VM/重启/删 VM/切网络 → **先停,交还操作者** | agent 擅自执行特权 / 破坏性操作;`--dangerously-skip-permissions` |

任何步骤一旦触及右栏,**立即停止**并交还操作者人工决定。

---

## 8. 复核关口 (Reviewer gate)

证据被引用进 CVP/pilot 文档前,逐项核对:

- [ ] 隔离门禁(TC-09)宿主 + 客户机**两边全 PASS**,且证据时间戳在隔离合规之后。
- [ ] 每个被引用用例都齐备:benign stimulus / expected telemetry / expected alert / evidence / FP-handling / rollback / safety-boundary,且**无**任何攻击/绕过/真实目标内容。
- [ ] 规则校验 pass/fail 数与所链 `reports\rule-validation-*.jsonl` 一致(由 `Export-CvpEvidence.ps1` 渲染)。
- [ ] 措辞保持 "synthetic / reproducible",**绝不**写成 "field-validated"。
- [ ] 无 host-specific 路径 / 敏感数据 / 真实 IP 泄漏进证据表。
- [ ] 仓库 commit 与被引用的 release/branch 对应。
- [ ] 所有 lab run 已打 lab-validation 标签,排除出生产 FP 指标。

---

## 相关引用
- [`validation-scenarios.md`](../../01-hardening-checklist/detection/validation-scenarios.md) — Sigma Card 1-3 完整叙述(本 runbook 的 TC-01~03 基础)。
- [`../COVERAGE.md`](../COVERAGE.md) — 规则/checklist → 靶场遥测/脚本 的覆盖矩阵。
- [`02-network-isolation.md`](02-network-isolation.md) / [`03-domain-and-wef.md`](03-domain-and-wef.md) / [`00-overview.md`](00-overview.md) / [`downloads.md`](downloads.md)。
- [`tuning-guide.md`](../../01-hardening-checklist/detection/tuning-guide.md) — FP 处理 / 调优治理 / 例外审查。
- [`../../docs/business/validation-runbook.md`](../../docs/business/validation-runbook.md) — 端到端验证流程(商业侧)。
- [`../../docs/cvp/lab-validation-evidence.md`](../../docs/cvp/lab-validation-evidence.md) — 自动生成的 CVP 证据(reviewer gate)。
