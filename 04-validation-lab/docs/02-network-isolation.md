# 网络隔离(最关键)—— 设计、原理与验证

隔离是整个环境合规的**根本**。本文说明为什么这样设计、如何确认隔离真的生效。

## 1. 为什么用 Hyper-V 的 Private 交换机

你原计划用 VirtualBox 的 "Internal Network"(VM 之间互通、连宿主都碰不到)。在 Hyper-V 上的**等价且更严格**选项是 **Private 虚拟交换机**:

| Hyper-V 交换机类型 | VM↔VM | VM↔宿主 | VM↔外网 | 用于本实验 |
|---|:--:|:--:|:--:|:--:|
| **Private** | ✅ | ❌ | ❌ | ✅ **就用这个** |
| Internal | ✅ | ✅(宿主多一块 vNIC) | ❌ | ❌ 比需要的弱 |
| External | ✅ | ✅ | ✅ | ❌ **严禁** |

**关键机制**:创建 Private 交换机时,Hyper-V **不会**在宿主机上生成 `vEthernet` 虚拟网卡。也就是说,宿主机的网络协议栈里**根本不存在**通往 `10.10.10.0/24` 的接口 —— 不是"有接口但被防火墙挡住",而是"接口压根不存在"。这是比 host-only/防火墙规则更强的隔离。

## 2. 地址规划(静态,无网关无 DNS)

| 主机 | 角色 | IP | 备注 |
|---|---|---|---|
| CSL-Wazuh | Wazuh SIEM / 日志汇聚 | 10.10.10.10 | Ubuntu |
| CSL-Server | 管理/收银节点 + WEF 收集器 | 10.10.10.20 | Windows Server |
| CSL-Client01 | 网吧客户终端 | 10.10.10.31 | Windows 11 |
| CSL-Client02 | 网吧客户终端 | 10.10.10.32 | Windows 11 |

- 网段 `10.10.10.0/24`,掩码 `255.255.255.0`。
- **刻意不配默认网关、不配 DNS**:即使将来误接了上行链路,没有网关也出不去——多一道保险。
- 无 DHCP:每台手动静态 IP(Windows 用 `guest\Set-StaticIP.ps1`,Ubuntu 用 netplan,见 wazuh 脚本顶部)。
  - (可选)若想要 DHCP,可在 Ubuntu 上装 `dnsmasq` 只做 DHCP、不做转发——但静态更简单可控。
- **域模式的 DNS 例外**:启用域后,域成员(CSL-Client01/02)与域控自身的 DNS 需指向域控
  10.10.10.20 的内部 AD DNS。该 DNS **无转发器、无根提示**,只解析 `cafesec.lab`、绝不向外递归——
  网络层本就无出口,故仍**完全气隙**。配置:`Set-StaticIP.ps1 -DnsServer 10.10.10.20`;
  域控自身由 `domain\Set-DcDnsAirgap.ps1` 锁死。CSL-Wazuh(Linux)不加域,保持无 DNS。详见 `03-domain-and-wef.md`。

## 3. 两阶段搭建(务必理解)

矛盾点:**隔离网无法联网**,但装系统更新、Wazuh、agent、工具又**需要**联网。解决办法是分两阶段:

```
阶段一  PROVISIONING(临时联网)
  ├─ 可临时给 VM 接一个 External/NAT 交换机
  ├─ 装好 OS、打补丁、装 Sysmon/Wazuh/agent/Python/YARA、下载规则
  └─ 下载好 docs\downloads.md 里的所有东西

        ↓ 切换网卡 ↓

阶段二  LOCKED-DOWN(完全隔离)  ← 研究只能在此阶段进行
  ├─ 把每台 VM 的网卡【改接】到 CafeSec-Isolated (Private)
  │     Connect-VMNetworkAdapter -VMName CSL-Client01 -SwitchName CafeSec-Isolated
  ├─ 运行 04-Verify-Isolation.ps1(宿主侧)
  ├─ 在各 Windows VM 内运行 guest\Test-GuestIsolation.ps1(客户机侧)
  └─ 两侧全 PASS → 合规,可开始研究
```

> 之后所有攻击模拟由你本人在**阶段二**手动进行 —— 不在本搭建任务范围内。
> 断网后还要装东西?用 `Copy-VMFile` 或数据 ISO 注入(见 docs\downloads.md)。

## 4. 如何确认隔离真的生效

### 宿主侧(运行 `scripts\04-Verify-Isolation.ps1`)
逐项检查并给出 PASS/FAIL:
1. 交换机类型 = `Private`
2. 交换机未绑定任何物理网卡(无外部上行链路)
3. 宿主**没有**该交换机的 `vEthernet` 网卡
4. 宿主路由表**没有** `10.10.10.0/24` 的路由
5. 所有 CSL VM 的网卡都接在隔离交换机上(无"漏接")

手动佐证:
```powershell
Get-VMSwitch CafeSec-Isolated | fl Name,SwitchType,NetAdapterInterfaceDescription
Get-NetAdapter | Where-Object Name -like '*CafeSec*'   # 期望:无输出
Get-NetRoute -DestinationPrefix 10.10.10.0/24          # 期望:无输出
```

### 客户机侧(在 VM 内运行 `scripts\guest\Test-GuestIsolation.ps1`)
期望结果:
| 测试 | 期望 | 含义 |
|---|---|---|
| ping 10.10.10.10 (peer) | ✅ 通 | VM 间能通信(日志收集需要) |
| ping 1.1.1.1 / 8.8.8.8 | ❌ 不通 | 出不了外网 |
| 解析 www.microsoft.com | ❌ 失败 | 无 DNS、无出口 |
| ping 192.168.x.1 / 10.0.0.1 | ❌ 不通 | 碰不到真实家用/企业 LAN |
| 默认网关 | ❌ 不存在 | 三层也出不去 |
| TCP 443 → 公网 | ❌ 失败 | 应用层也出不去 |

**任何"本应失败却成功"的项 = 隔离破裂**,立即停用环境排查(多半是某台 VM 还连着 External/NAT 交换机没切回来)。

## 5. 常见隔离破口排查
- VM 还接着阶段一的 External/NAT 交换机 → `Get-VMNetworkAdapter * | ft VMName,SwitchName`,把非隔离的都 `Connect-VMNetworkAdapter` 改回。
- VM 有第二块网卡 → 移除多余网卡 `Remove-VMNetworkAdapter`。
- 误建成 Internal/External 交换机 → `Remove-VMSwitch` 后用 `02-New-IsolatedSwitch.ps1` 重建为 Private。
- 客户机配了默认网关 → 重跑 `Set-StaticIP.ps1`(它会清网关)。
