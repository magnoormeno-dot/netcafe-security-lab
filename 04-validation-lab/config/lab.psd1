#
# CafeSec Lab - Central configuration (Single Source of Truth)
# ------------------------------------------------------------------
# Every script reads its configuration from here. Edit this one file to adjust the entire environment.
# Usage: $cfg = Import-PowerShellDataFile .\config\lab.psd1
#
@{
    # ---- Project paths ----
    Paths = @{
        VmRoot   = 'E:\CafeSec-Lab\VMs'      # Drive where virtual hard disks (VHDX) are stored -> E: (independent of the repo location)
        IsoRoot  = 'E:\CafeSec-Lab\ISO'      # Place the installation images you download here
        ProjectRoot = ''                     # Informational only: this module lives at <repo>\04-validation-lab\; scripts locate themselves relative to $PSScriptRoot
    }

    # ---- Seam with the main repo (paths relative to this module root 04-validation-lab\) ----
    # This lab is the repo's "validation range": it consumes the detection rules from 01, deploys the integrity monitor from 02, and produces lab evidence.
    Repo = @{
        DetectionSigma  = '..\01-hardening-checklist\detection\sigma'   # Source of truth for rules (not a copy)
        DetectionYara   = '..\01-hardening-checklist\detection\yara'
        IntegrityMonitor= '..\02-integrity-monitor'                      # Python integrity monitor tool source
        HardeningChecklist = '..\01-hardening-checklist\checklist'       # Baseline items such as NI-xx
    }

    # ---- Isolated network ----
    Network = @{
        SwitchName = 'CafeSec-Isolated'      # Hyper-V private switch name
        SwitchType = 'Private'               # Private = VMs can reach each other; neither the host nor the internet is reachable
        Subnet     = '10.10.10.0/24'
        Prefix     = 24
        Mask       = '255.255.255.0'
        # No gateway and no DNS on the isolated network (intentional). If VMs need to reach each other by hostname,
        # write them statically into each VM's hosts file, or run dnsmasq on Ubuntu (optional).
        Gateway    = ''                      # Leave empty = no default gateway = no way out
    }

    # ---- Domain (prerequisite for WEF over Kerberos; see docs\03-domain-and-wef.md) ----
    Domain = @{
        Enabled = $true                      # Domain mode: under a workgroup, source-initiated WEF cannot use Kerberos, so a domain is built
        Fqdn    = 'cafesec.lab'              # Purely internal domain, does not conflict with any real domain
        Netbios = 'CAFESEC'
        DcVm    = 'CSL-Server'               # The VM acting as domain controller (also the WEF collector)
        DcIp    = '10.10.10.20'              # Domain controller = internal AD DNS (no forwarders / no root hints, still fully air-gapped)
        DcFqdn  = 'CSL-Server.cafesec.lab'   # Kerberos/WEF use this FQDN; a bare IP cannot be used
        Members = @('CSL-Client01', 'CSL-Client02')  # Domain-joined clients; Ubuntu (CSL-Wazuh) is not domain-joined
    }

    # ---- Virtual machine inventory ----
    # Role: WazuhSIEM | MgmtServer | Client
    # Gen 2 = UEFI/Secure Boot; Linux uses the MicrosoftUEFICertificateAuthority template
    VMs = @(
        @{
            Name        = 'CSL-Wazuh'
            Role        = 'WazuhSIEM'
            OS          = 'Ubuntu Server 24.04 LTS'
            MemoryGB    = 8
            CPU         = 4
            DiskGB      = 100
            IP          = '10.10.10.10'
            Generation  = 2
            SecureBoot  = 'Linux'             # Uses the MS UEFI CA template
            IsoFile     = 'ubuntu-24.04-live-server-amd64.iso'
        },
        @{
            Name        = 'CSL-Server'
            Role        = 'MgmtServer'         # Management/POS node + WEF collector
            OS          = 'Windows Server 2022 (Eval)'
            MemoryGB    = 8
            CPU         = 4
            DiskGB      = 80
            IP          = '10.10.10.20'
            Generation  = 2
            SecureBoot  = 'Windows'
            IsoFile     = 'windows-server-2022-eval.iso'
        },
        @{
            Name        = 'CSL-Client01'
            Role        = 'Client'
            OS          = 'Windows 11 Enterprise (Eval)'
            MemoryGB    = 4
            CPU         = 2
            DiskGB      = 60
            IP          = '10.10.10.31'
            Generation  = 2
            SecureBoot  = 'Windows'
            IsoFile     = 'windows-11-enterprise-eval.iso'
        },
        @{
            Name        = 'CSL-Client02'
            Role        = 'Client'
            OS          = 'Windows 11 Enterprise (Eval)'
            MemoryGB    = 4
            CPU         = 2
            DiskGB      = 60
            IP          = '10.10.10.32'
            Generation  = 2
            SecureBoot  = 'Windows'
            IsoFile     = 'windows-11-enterprise-eval.iso'
        }
    )

    # ---- Resource usage check (64GB host) ----
    # Total VM memory: 8+8+4+4 = 24GB  -> leaves ~40GB for the host, safe
    # Total vCPU:      4+4+2+2 = 12 / 32 logical cores -> plenty

    # ---- Defense stack versions/sources (see docs\downloads.md for details) ----
    Defense = @{
        SysmonConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
        WazuhVersion    = '4.x'
    }
}
