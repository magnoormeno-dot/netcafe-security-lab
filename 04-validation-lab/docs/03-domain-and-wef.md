# 域 + WEF + GPO(检测工程的原生底座)

## 为什么建域
工作组(非域)机器间的**源发起型 WEF 走 Kerberos 无法工作**(Kerberos 需要 KDC=域控)。
建立内部域 `cafesec.lab` 后:
- **WEF** 源→收集器走 Kerberos(HTTP/5985),无需任何证书。
- **GPO** 统一下发 Sysmon、审核策略、WEF 订阅(对应第五步的 GPO 要求)。
- 更贴近真实"网吧/共享 PC 管理节点"的运维形态。

> **气隙不变**:域控运行 AD 集成 DNS,但**无转发器、无根提示**,只解析内部域;
> 网络层本就无出口。`Test-GuestIsolation.ps1` 仍强制向 `1.1.1.1` 探测来证明出口被阻断。

## 角色与地址(在隔离网内)
| 主机 | 角色 | 地址 | DNS 指向 |
|---|---|---|---|
| CSL-Server | **域控 (DC) + AD DNS + WEF 收集器** | 10.10.10.20 | 自身 (127.0.0.1) |
| CSL-Client01/02 | 域成员(WEF 源) | 10.10.10.31/32 | 10.10.10.20(域控) |
| CSL-Wazuh | **不加域**(Linux,Wazuh SIEM) | 10.10.10.10 | 无(静态,Wazuh 不需 DNS) |

## 搭建顺序(在阶段一"已装好系统"之后、阶段二锁定隔离之前完成域加入)

> 仍遵循两阶段模型;域的建立/加入在 VM 内进行,不需要外网。Sysmon/Wazuh/规则等工具
> 若要联网下载,在阶段一完成;域加入本身只在隔离网内通信即可。

### 1. 域控(CSL-Server,10.10.10.20)
```powershell
# (先确保本机名为 CSL-Server、静态 IP 已配)
cd <项目>\scripts\domain
$dsrm = Read-Host -AsSecureString "设置 DSRM 密码"
.\Install-DomainController.ps1 -SafeModePassword $dsrm     # 安装 AD DS+DNS,提升为 cafesec.lab,自动重启
# —— 重启后,用本地/域管理员登录 ——
.\Set-DcDnsAirgap.ps1                                       # 清根提示/确认无转发器,锁死气隙 DNS
..\guest\Configure-WEC-Collector.ps1                        # 配置 WEF 收集器 + 导入订阅
.\New-WefGpo.ps1                                            # 用 GPO 给客户机下发 WEF 源配置
```

### 2. 客户机(CSL-Client01 / 02)
```powershell
cd <项目>\scripts\domain
$cred = Get-Credential CAFESEC\Administrator
.\Join-LabDomain.ps1 -DomainCredential $cred               # DNS 指向域控并加域,自动重启
# 重启后用域账户登录,然后:
gpupdate /force                                            # 拉取 WEF GPO
```

## WEF 数据流(域模式)
```
CSL-Client01/02 (源, 域成员)                         CSL-Server (收集器=域控)
  Security/Sysmon/PowerShell 事件                        ForwardedEvents 日志
        │  WinRM 5985 + Kerberos(源发起型,GPO 下发 SubscriptionManager)
        └───────────────────────────────────────────────►
  授权:订阅 XML 的 AllowedSourceDomainComputers SDDL(Domain Computers + Network Service)
```

## GPO 配置要点(`New-WefGpo.ps1` 已脚本化 + 需手工补充两项)

`New-WefGpo.ps1` 自动完成(高置信、可脚本化):
1. **Configure target Subscription Manager**
   `计算机配置 → 管理模板 → Windows 组件 → 事件转发`
   值:`Server=http://CSL-Server.cafesec.lab:5985/wsman/SubscriptionManager/WEC,Refresh=60`
2. **Allow remote server management through WinRM** + 把 **WinRM 服务启动类型设为自动**(注册表策略,客户机次次重启后生效)
   > 注意:这两项都**不会立刻启动**当前会话的 WinRM 服务 —— 见下方手工补充第 5 项。

需**手工 / 用 GPP** 补充(无法仅靠 `Set-GPRegistryValue` 完整表达):
3. **把 `NT AUTHORITY\NETWORK SERVICE` 加入各源机本地 `Event Log Readers`**(转发 Security 日志所需)
   - 方式 A:GPO → `计算机配置 → 首选项 → 控制面板设置 → 本地用户和组` → 更新组 `Event Log Readers` → 添加成员 `NETWORK SERVICE`。
   - 方式 B:在每台客户机跑 `..\guest\Configure-WEF-Source.ps1`(它会做这一步)。
4. **高级审核策略**(让 Security 日志足够丰富,供 Sigma/检测使用)
   `计算机配置 → 策略 → Windows 设置 → 安全设置 → 高级审核策略配置 → 审核策略`:
   - 登录/注销:**审核登录**(成功+失败)→ 4624/4625
   - 详细跟踪:**审核进程创建**(成功)→ 4688
   - 账户管理、特权使用等按需开启
   并启用:`管理模板 → 系统 → 审核进程创建 → 在进程创建事件中包含命令行` → 4688 携带命令行。
   > Sysmon 的进程/网络/注册表事件由 `..\guest\Deploy-Sysmon.ps1` 提供;审核策略补足原生 Security 维度。
5. **确保源端 WinRM (WS-Management) 服务【正在运行】且启动类型=自动** —— `AllowAutoConfig` 策略本身不会启动该服务
   (Win11 桌面版默认=手动/触发启动)。`New-WefGpo.ps1` 已把启动类型策略设为自动(客户机次次重启后生效),仍需让它实际在跑:
   - 方式 A(GPO 原生):`计算机配置 → 策略 → Windows 设置 → 安全设置 → 系统服务` → `Windows Remote Management (WS-Management)` 设为 **自动**。
   - 方式 B(GPP):`计算机配置 → 首选项 → 控制面板设置 → 服务` → WinRM → 启动类型 **自动** + 服务操作 **启动**。
   - 方式 C:在每台客户机跑 `..\guest\Configure-WEF-Source.ps1`(含 `winrm quickconfig` + 重启服务,立即生效)。
   > 加域时客户机已重启一次,故"自动"启动类型在加域后基本已生效;方式 C 可确保当前会话立即可用。

## 验证清单
```powershell
# 域控:
Get-ADDomain | ft DNSRoot, NetBIOSName, DistinguishedName
nltest /dsgetdc:cafesec.lab
wecutil gr CafeSec-Security          # 各源应显示 Active(前提:客户机已 gpupdate【且 WinRM 服务在运行】,约 1-2 分钟出现)

# 客户机:
(Get-CimInstance Win32_ComputerSystem).Domain     # 应为 cafesec.lab
gpresult /r /scope computer | findstr CafeSec-WEF  # GPO 已应用
# 转发插件健康:事件查看器 → 应用程序和服务日志\Microsoft\Windows\Eventlog-ForwardingPlugin\Operational

# 收集器:确认收到事件
Get-WinEvent -LogName ForwardedEvents -MaxEvents 20
```

## 与隔离/Wazuh 的关系
- **Wazuh** 仍是主 SIEM(agent→manager,10.10.10.10),覆盖 Windows + 跨平台,独立于 WEF。
- **WEF** 是原生、无第三方 agent 的并行汇聚通道,集中存档关键安全/ Sysmon 事件到 `ForwardedEvents`。
- 两者互补;域的引入只改变"如何认证与下发配置",**不改变隔离拓扑**(私有交换机 + 无网关 + 无 DNS 转发)。
