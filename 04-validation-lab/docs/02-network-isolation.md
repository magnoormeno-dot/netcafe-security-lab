# Network Isolation (Most Critical) -- Design, Principles, and Validation

Isolation is the **foundation** of the entire environment's compliance. This document explains why it is designed this way and how to confirm that isolation is truly in effect.

## 1. Why Use Hyper-V's Private Switch

You originally planned to use VirtualBox's "Internal Network" (VMs communicate with each other, with no contact to the host at all). The **equivalent and stricter** option on Hyper-V is the **Private virtual switch**:

| Hyper-V Switch Type | VM<->VM | VM<->Host | VM<->Internet | Used in This Lab |
|---|:--:|:--:|:--:|:--:|
| **Private** | Yes | No | No | Yes **use this one** |
| Internal | Yes | Yes (host gets an extra vNIC) | No | No, weaker than needed |
| External | Yes | Yes | Yes | No **strictly forbidden** |

**Key mechanism**: When you create a Private switch, Hyper-V **does not** generate a `vEthernet` virtual NIC on the host machine. In other words, no interface leading to `10.10.10.0/24` **exists at all** in the host's network stack -- it is not "an interface that exists but is blocked by the firewall," but rather "the interface simply does not exist." This is stronger isolation than host-only/firewall rules.

## 2. Address Plan (Static, No Gateway, No DNS)

| Host | Role | IP | Notes |
|---|---|---|---|
| CSL-Wazuh | Wazuh SIEM / log aggregation | 10.10.10.10 | Ubuntu |
| CSL-Server | Management/POS node + WEF collector | 10.10.10.20 | Windows Server |
| CSL-Client01 | Net cafe client terminal | 10.10.10.31 | Windows 11 |
| CSL-Client02 | Net cafe client terminal | 10.10.10.32 | Windows 11 |

- Subnet `10.10.10.0/24`, mask `255.255.255.0`.
- **Deliberately no default gateway and no DNS configured**: even if an uplink is mistakenly connected in the future, without a gateway nothing can get out -- one extra layer of insurance.
- No DHCP: each machine is statically assigned an IP manually (Windows uses `guest\Set-StaticIP.ps1`, Ubuntu uses netplan, see the top of the wazuh script).
  - (Optional) If you want DHCP, you can install `dnsmasq` on Ubuntu to do DHCP only and no forwarding -- but static is simpler and more controllable.
- **DNS exception for domain mode**: After enabling the domain, the DNS for domain members (CSL-Client01/02) and the domain controller itself must point to the internal AD DNS on the domain controller
  10.10.10.20. This DNS **has no forwarders and no root hints**, resolves only `cafesec.lab`, and never recurses outward --
  the network layer has no egress to begin with, so it remains **fully air-gapped**. Configuration: `Set-StaticIP.ps1 -DnsServer 10.10.10.20`;
  the domain controller itself is locked down by `domain\Set-DcDnsAirgap.ps1`. CSL-Wazuh (Linux) is not joined to the domain and keeps no DNS. See `03-domain-and-wef.md` for details.

## 3. Two-Phase Setup (Be Sure to Understand)

The conflict: **the isolated network cannot reach the internet**, but installing system updates, Wazuh, agents, and tools **requires** internet access. The solution is to split into two phases:

```
Phase 1  PROVISIONING (temporary internet)
  ├─ Temporarily connect VMs to an External/NAT switch
  ├─ Install the OS, apply patches, install Sysmon/Wazuh/agent/Python/YARA, download rules
  └─ Download everything listed in docs\downloads.md

        ↓ Switch NIC ↓

Phase 2  LOCKED-DOWN (fully isolated)  ← Research may only be conducted in this phase
  ├─ [Re-attach] each VM's NIC to CafeSec-Isolated (Private)
  │     Connect-VMNetworkAdapter -VMName CSL-Client01 -SwitchName CafeSec-Isolated
  ├─ Run 04-Verify-Isolation.ps1 (host side)
  ├─ Run guest\Test-GuestIsolation.ps1 inside each Windows VM (guest side)
  └─ Both sides all PASS → compliant, research can begin
```

> All subsequent attack simulations are performed manually by you personally in **Phase 2** -- they are outside the scope of this setup task.
> Need to install something after disconnecting? Use `Copy-VMFile` or data ISO injection (see docs\downloads.md).

## 4. How to Confirm Isolation Is Truly in Effect

### Host side (run `scripts\04-Verify-Isolation.ps1`)
Checks each item and reports PASS/FAIL:
1. Switch type = `Private`
2. Switch is not bound to any physical NIC (no external uplink)
3. The host **does not have** a `vEthernet` NIC for this switch
4. The host routing table **has no** route for `10.10.10.0/24`
5. The NICs of all CSL VMs are attached to the isolated switch (none "left unattached")

Manual corroboration:
```powershell
Get-VMSwitch CafeSec-Isolated | fl Name,SwitchType,NetAdapterInterfaceDescription
Get-NetAdapter | Where-Object Name -like '*CafeSec*'   # Expected: no output
Get-NetRoute -DestinationPrefix 10.10.10.0/24          # Expected: no output
```

### Guest side (run `scripts\guest\Test-GuestIsolation.ps1` inside the VM)
Expected results:
| Test | Expected | Meaning |
|---|---|---|
| ping 10.10.10.10 (peer) | Yes, reachable | VMs can communicate (required for log collection) |
| ping 1.1.1.1 / 8.8.8.8 | No, unreachable | Cannot reach the internet |
| resolve www.microsoft.com | No, fails | No DNS, no egress |
| ping 192.168.x.1 / 10.0.0.1 | No, unreachable | Cannot reach the real home/enterprise LAN |
| default gateway | No, does not exist | Cannot get out at layer 3 either |
| TCP 443 → public internet | No, fails | Cannot get out at the application layer either |

**Any item that "should fail but succeeds" = isolation breach**, immediately take the environment out of service and investigate (most likely some VM is still connected to an External/NAT switch and was not switched back).

## 5. Troubleshooting Common Isolation Breaches
- A VM is still connected to the Phase 1 External/NAT switch → `Get-VMNetworkAdapter * | ft VMName,SwitchName`, and `Connect-VMNetworkAdapter` all non-isolated ones back.
- A VM has a second NIC → remove the extra NIC with `Remove-VMNetworkAdapter`.
- A switch was mistakenly created as Internal/External → `Remove-VMSwitch`, then rebuild it as Private with `02-New-IsolatedSwitch.ps1`.
- A guest was configured with a default gateway → re-run `Set-StaticIP.ps1` (it clears the gateway).
