#requires -Version 5.1
<#
.SYNOPSIS
  按 config\lab.psd1 创建 4 台 Gen2 虚拟机,全部接入隔离私有交换机。
.DESCRIPTION
  创建内容:动态 VHDX、指定内存/vCPU、连接 CafeSec-Isolated 交换机、挂载安装 ISO。
  Linux(Ubuntu)使用 MicrosoftUEFICertificateAuthority Secure Boot 模板;
  Windows 使用默认 MicrosoftWindows 模板。
  幂等:同名 VM 已存在则跳过(不会覆盖你已安装的系统)。
.PARAMETER WhatIf
  只打印将要执行的动作,不实际创建。
#>
[CmdletBinding(SupportsShouldProcess)]
param()
. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin
$cfg = Get-LabConfig

# 确保存放目录存在
foreach ($p in @($cfg.Paths.VmRoot, $cfg.Paths.IsoRoot)) {
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null; Write-Ok "已创建目录 $p" }
}

$switch = Get-VMSwitch -Name $cfg.Network.SwitchName -ErrorAction SilentlyContinue
if (-not $switch) { Write-Fail "隔离交换机 '$($cfg.Network.SwitchName)' 不存在。请先运行 02-New-IsolatedSwitch.ps1"; return }

foreach ($vm in $cfg.VMs) {
    Write-Step "VM: $($vm.Name)  [$($vm.Role)]  $($vm.OS)"

    if (Get-VM -Name $vm.Name -ErrorAction SilentlyContinue) {
        Write-Warn2 "VM '$($vm.Name)' 已存在,跳过创建。"
        continue
    }

    $vmDir   = Join-Path $cfg.Paths.VmRoot $vm.Name
    $vhdPath = Join-Path $vmDir "$($vm.Name).vhdx"
    $isoPath = Join-Path $cfg.Paths.IsoRoot $vm.IsoFile

    if ($PSCmdlet.ShouldProcess($vm.Name, "创建 Gen$($vm.Generation) VM,内存 $($vm.MemoryGB)GB,$($vm.CPU) vCPU,磁盘 $($vm.DiskGB)GB 动态")) {

        New-VM -Name $vm.Name -Generation $vm.Generation `
               -MemoryStartupBytes ($vm.MemoryGB * 1GB) `
               -NewVHDPath $vhdPath -NewVHDSizeBytes ($vm.DiskGB * 1GB) `
               -SwitchName $cfg.Network.SwitchName -Path $cfg.Paths.VmRoot | Out-Null

        Set-VMProcessor   -VMName $vm.Name -Count $vm.CPU
        # 固定内存(实验环境求稳定可预测;如需动态内存自行调整)
        Set-VMMemory      -VMName $vm.Name -DynamicMemoryEnabled $false -StartupBytes ($vm.MemoryGB * 1GB)

        # Secure Boot 模板
        if ($vm.SecureBoot -eq 'Linux') {
            Set-VMFirmware -VMName $vm.Name -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
        } else {
            Set-VMFirmware -VMName $vm.Name -EnableSecureBoot On
        }

        # vTPM:Windows 11 安装强制要求 TPM 2.0,而 Gen2 VM 默认【无】TPM,必须显式启用,
        # 否则两台 Win11 客户机会卡在 "这台电脑无法运行 Windows 11" 而装不下去。
        # 顺序关键:先 Set-VMKeyProtector(本地密钥保护器)再 Enable-VMTPM,反之会失败。
        # 独立宿主(无 HGS/域)用本地密钥保护器即可;Win11/Server 2022 宿主会自动生成所需证书。
        if ($vm.Generation -eq 2 -and $vm.SecureBoot -eq 'Windows') {
            Set-VMKeyProtector -VMName $vm.Name -NewLocalKeyProtector
            Enable-VMTPM       -VMName $vm.Name
            Write-Ok "$($vm.Name) 已启用 vTPM (Win11 安装前置要求)"
        }

        # 始终添加 DVD 光驱并设为首选启动;镜像可现在挂或稍后手动挂。
        # (空 VHDX 无法引导、Gen2 无传统 BIOS 回退 —— 若仅在有 ISO 时才设启动项,
        #  那么"先建 VM 后挂镜像"的路径会因无引导项而开不了机。)
        Add-VMDvdDrive -VMName $vm.Name
        $dvd = Get-VMDvdDrive -VMName $vm.Name
        Set-VMFirmware -VMName $vm.Name -FirstBootDevice $dvd
        if (Test-Path $isoPath) {
            Set-VMDvdDrive -VMName $vm.Name -Path $isoPath
            Write-Ok "已挂载安装镜像并设为首选启动: $($vm.IsoFile)"
        } else {
            Write-Warn2 "未找到 ISO: $isoPath  —— VM 已建好,光驱已设为首选启动;稍后只需 Set-VMDvdDrive -VMName $($vm.Name) -Path <iso> 即可开机。"
        }

        # 启用 Guest Service Interface:便于隔离状态下用 Copy-VMFile 注入文件(无需联网)
        Enable-VMIntegrationService -VMName $vm.Name -Name 'Guest Service Interface' -ErrorAction SilentlyContinue

        Write-Ok "$($vm.Name) 创建完成 -> 计划静态 IP $($vm.IP)/$($cfg.Network.Prefix)"
    }
}

Write-Step "所有 VM 处理完毕"
Get-VM | Where-Object Name -like 'CSL-*' |
    Format-Table Name, State, ProcessorCount, @{n='MemGB';e={[math]::Round($_.MemoryStartup/1GB,0)}}, @{n='Switch';e={(Get-VMNetworkAdapter $_.Name).SwitchName}} -AutoSize

Write-Host "提示:VM 网卡现已接入隔离交换机。系统装完后,在每台 VM 内运行 guest\Set-StaticIP.ps1 配置 10.10.10.x。" -ForegroundColor Gray
Write-Host "重要:OS 与防御工具的安装见 docs\02-network-isolation.md 的【两阶段搭建】说明。" -ForegroundColor Yellow
