#
# CafeSec Lab - 中央配置 (Single Source of Truth)
# ------------------------------------------------------------------
# 所有脚本都从这里读取配置。改这一个文件即可调整整套环境。
# 用法: $cfg = Import-PowerShellDataFile .\config\lab.psd1
#
@{
    # ---- 项目路径 ----
    Paths = @{
        VmRoot   = 'E:\CafeSec-Lab\VMs'      # 虚拟硬盘(VHDX)存放盘 -> E:(与仓库位置无关)
        IsoRoot  = 'E:\CafeSec-Lab\ISO'      # 你下载的安装镜像放这里
        ProjectRoot = ''                     # 仅信息性:本模块位于 <repo>\04-validation-lab\;脚本均用 $PSScriptRoot 相对定位
    }

    # ---- 与主仓的接缝(相对本模块根 04-validation-lab\ 的路径)----
    # 本实验室是仓库的"验证靶场":消费 01 的检测规则、部署 02 的完整性监控,产出 lab 证据。
    Repo = @{
        DetectionSigma  = '..\01-hardening-checklist\detection\sigma'   # 规则的事实来源(非复制)
        DetectionYara   = '..\01-hardening-checklist\detection\yara'
        IntegrityMonitor= '..\02-integrity-monitor'                      # Python 完整性监控工具源码
        HardeningChecklist = '..\01-hardening-checklist\checklist'       # NI-xx 等基线条目
    }

    # ---- 隔离网络 ----
    Network = @{
        SwitchName = 'CafeSec-Isolated'      # Hyper-V 私有交换机名
        SwitchType = 'Private'               # Private = VM互通,宿主与外网均不可达
        Subnet     = '10.10.10.0/24'
        Prefix     = 24
        Mask       = '255.255.255.0'
        # 隔离网内无网关、无 DNS(刻意为之)。如需 VM 互访用主机名,
        # 在各 VM 的 hosts 文件里静态写死,或在 Ubuntu 上跑 dnsmasq(可选)。
        Gateway    = ''                      # 留空 = 无默认网关 = 出不去
    }

    # ---- 域(WEF 走 Kerberos 的前提;见 docs\03-domain-and-wef.md)----
    Domain = @{
        Enabled = $true                      # 域模式:工作组下源发起型 WEF 无法走 Kerberos,故建域
        Fqdn    = 'cafesec.lab'              # 纯内部域,不与任何真实域冲突
        Netbios = 'CAFESEC'
        DcVm    = 'CSL-Server'               # 充当域控的 VM(同时是 WEF 收集器)
        DcIp    = '10.10.10.20'              # 域控 = 内部 AD DNS(无转发器/无根提示,仍完全气隙)
        DcFqdn  = 'CSL-Server.cafesec.lab'   # Kerberos/WEF 用此 FQDN,不能用裸 IP
        Members = @('CSL-Client01', 'CSL-Client02')  # 加域的客户机;Ubuntu(CSL-Wazuh)不加域
    }

    # ---- 虚拟机清单 ----
    # Role: WazuhSIEM | MgmtServer | Client
    # Gen 2 = UEFI/Secure Boot;Linux 用 MicrosoftUEFICertificateAuthority 模板
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
            SecureBoot  = 'Linux'             # 用 MS UEFI CA 模板
            IsoFile     = 'ubuntu-24.04-live-server-amd64.iso'
        },
        @{
            Name        = 'CSL-Server'
            Role        = 'MgmtServer'         # 管理/收银节点 + WEF收集器
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

    # ---- 资源占用核对(64GB 宿主)----
    # VM 内存合计: 8+8+4+4 = 24GB  → 留 ~40GB 给宿主,安全
    # vCPU 合计:    4+4+2+2 = 12 / 32 逻辑核 → 充裕

    # ---- 防御栈版本/来源(详见 docs\downloads.md)----
    Defense = @{
        SysmonConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
        WazuhVersion    = '4.x'
    }
}
