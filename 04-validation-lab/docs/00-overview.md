# CafeSec Lab — 架构总览

防御性安全研究实验环境:聚焦网吧/共享 PC/Windows 环境的**主机加固与检测工程**。
完全网络隔离,在本机虚拟化层内运行。本仓库只做**防御工程 setup**(平台、隔离网络、
防御工具栈、脚本与文档),不含任何攻击/利用代码。

## 拓扑

```
   宿主机 Windows 11 Pro (i9-14900K / 64GB)  ── 真实网络/外网(VM 完全触达不到)
        │
        │  Hyper-V
        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  CafeSec-Isolated  (Private 虚拟交换机, 10.10.10.0/24)         │
  │  ※ 宿主无 vEthernet 网卡接入,VM 出不了外网、碰不到真实 LAN     │
  │                                                               │
  │   CSL-Wazuh        CSL-Server         CSL-Client01  CSL-Client02│
  │   10.10.10.10      10.10.10.20        10.10.10.31   10.10.10.32 │
  │   Ubuntu 24.04     Win Server 2022    Win 11 Ent    Win 11 Ent  │
  │   Wazuh SIEM       WEF 收集器+管理节点  客户终端       客户终端    │
  │   8GB/4vCPU/100G   8GB/4vCPU/80G       4GB/2vCPU/60G 4GB/2vCPU/60G│
  └─────────────────────────────────────────────────────────────┘

  防御数据流:
    Sysmon(各 Windows 主机) ─┐
    Windows 安全日志          ├─► Wazuh agent ──► Wazuh manager (10.10.10.10) ──► 告警/Dashboard
    PowerShell 脚本块日志    ─┘
    关键安全事件 ──WEF──► WEC 收集器 (10.10.10.20, ForwardedEvents)
    Sigma 规则 ──转换──► Wazuh 检测;  YARA ──► 文件/取证扫描
```

> **域**:CSL-Server 同时是 `cafesec.lab` 域控 + 内部 AD DNS(无转发器/根提示,仍气隙);
> CSL-Client01/02 加域,WEF 走 Kerberos、由 GPO 下发。CSL-Wazuh(Linux)不加域。详见 `03-domain-and-wef.md`。

## 资源核算(64GB 宿主)
- VM 内存合计:8+8+4+4 = **24 GB**(宿主余 ~40GB,安全)
- vCPU 合计:4+4+2+2 = **12 / 32 逻辑核**(充裕)
- 磁盘(动态 VHDX 上限合计):100+80+60+60 = **300 GB**,存于 E:(余 1688GB)

## 防御栈职责
| 组件 | 部署在 | 作用 |
|---|---|---|
| Sysmon + SwiftOnSecurity 配置 | 所有 Windows VM | 端点深度遥测(进程/网络/文件/注册表) |
| Wazuh agent → manager | Windows → CSL-Wazuh | 集中检测、关联、告警(开源 SIEM/XDR) |
| Windows Event Forwarding (WEF) | 域成员客户机 → CSL-Server(域控+收集器) | 原生事件集中转发,走 Kerberos;由 GPO 下发(见 docs\03) |
| Sigma CLI | 分析侧 | 通用检测规则 → Wazuh 查询转换 |
| YARA | 分析侧 | 文件/内存特征匹配、取证分诊 |

## 边界声明
- ✅ 本仓库:虚拟化平台、隔离网络、防御工具部署脚本、配置、文档。
- ❌ 不含:攻击/利用/渗透代码、漏洞利用模拟、任何指向真实设备/网络的配置。
- 攻击模拟(如有)由使用者本人在**隔离阶段**手动进行,不在本搭建范围内。

## 文档索引
- 前置条件与实操顺序 — 见根目录 `README.md`(主机预检表 + 执行顺序 A–G)
- `02-network-isolation.md` — **网络隔离(最关键,先读)**
- `03-domain-and-wef.md` — 域(cafesec.lab)+ WEF + GPO + 审核策略
- `downloads.md` — 全部官方下载地址 + 文件注入方法
- `04-defensive-validation-runbook.md` — **防御验证 runbook(测试用例 + 证据 + CVP 措辞 + reviewer gate;搭好后看这个)**
- `05-unattended-provisioning.md` — 无人值守装机(Windows autounattend / Ubuntu cloud-init 模板 + 已测的 ISO 构建器)
- `06-build-walkthrough.md` — **从零到 live-fire 证据的可复制粘贴搭建走查(M0→M4,可断点续跑)**
