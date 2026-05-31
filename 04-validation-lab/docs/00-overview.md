# CafeSec Lab — Architecture Overview

A defensive security research lab environment: focused on **host hardening and detection engineering** for internet cafe / shared PC / Windows environments.
Fully network-isolated, running inside the host's virtualization layer. This repository only covers **defensive engineering setup** (the platform, isolated network,
defensive tooling stack, scripts, and documentation); it contains no offensive/exploit code whatsoever.

## Topology

```
   Host Windows 11 Pro (i9-14900K / 64GB)  ── Real network/Internet (VMs cannot reach it at all)
        │
        │  Hyper-V
        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  CafeSec-Isolated  (Private virtual switch, 10.10.10.0/24)    │
  │  ※ No host vEthernet adapter attached; VMs cannot reach the Internet or touch the real LAN │
  │                                                               │
  │   CSL-Wazuh        CSL-Server         CSL-Client01  CSL-Client02│
  │   10.10.10.10      10.10.10.20        10.10.10.31   10.10.10.32 │
  │   Ubuntu 24.04     Win Server 2022    Win 11 Ent    Win 11 Ent  │
  │   Wazuh SIEM       WEF collector + management node  Client endpoint  Client endpoint │
  │   8GB/4vCPU/100G   8GB/4vCPU/80G       4GB/2vCPU/60G 4GB/2vCPU/60G│
  └─────────────────────────────────────────────────────────────┘

  Defensive data flow:
    Sysmon (each Windows host) ─┐
    Windows Security logs        ├─► Wazuh agent ──► Wazuh manager (10.10.10.10) ──► Alerts/Dashboard
    PowerShell script block logs ─┘
    Key security events ──WEF──► WEC collector (10.10.10.20, ForwardedEvents)
    Sigma rules ──convert──► Wazuh detection;  YARA ──► File/forensic scanning
```

> **Domain**: CSL-Server is both the `cafesec.lab` domain controller and the internal AD DNS (no forwarders/root hints, still air-gapped);
> CSL-Client01/02 are domain-joined, WEF runs over Kerberos and is delivered via GPO. CSL-Wazuh (Linux) is not domain-joined. See `03-domain-and-wef.md` for details.

## Resource Accounting (64GB host)
- Total VM memory: 8+8+4+4 = **24 GB** (host has ~40GB free, safe)
- Total vCPU: 4+4+2+2 = **12 / 32 logical cores** (ample)
- Disk (sum of dynamic VHDX maximums): 100+80+60+60 = **300 GB**, stored on E: (1688GB free)

## Defensive Stack Responsibilities
| Component | Deployed on | Purpose |
|---|---|---|
| Sysmon + SwiftOnSecurity config | All Windows VMs | Deep endpoint telemetry (process/network/file/registry) |
| Wazuh agent → manager | Windows → CSL-Wazuh | Centralized detection, correlation, alerting (open-source SIEM/XDR) |
| Windows Event Forwarding (WEF) | Domain-member clients → CSL-Server (DC + collector) | Native centralized event forwarding over Kerberos; delivered via GPO (see docs\03) |
| Sigma CLI | Analysis side | Convert generic detection rules → Wazuh queries |
| YARA | Analysis side | File/memory signature matching, forensic triage |

## Scope Statement
- ✅ This repository: virtualization platform, isolated network, defensive tooling deployment scripts, configuration, documentation.
- ❌ Not included: offensive/exploit/penetration code, vulnerability exploitation simulation, or any configuration pointing at real devices/networks.
- Attack simulation (if any) is performed manually by the user during the **isolated phase**; it is outside the scope of this setup.

## Documentation Index
- Prerequisites and hands-on order — see the root `README.md` (host preflight checklist + execution order A–G)
- `02-network-isolation.md` — **Network isolation (most critical, read first)**
- `03-domain-and-wef.md` — Domain (cafesec.lab) + WEF + GPO + audit policy
- `downloads.md` — All official download URLs + file injection methods
