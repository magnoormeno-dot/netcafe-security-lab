#requires -Version 5.1
<#
.SYNOPSIS
  CafeSec Lab 预检:在动手前确认宿主机满足搭建条件。只读,不做任何改动。
.NOTES
  无需管理员也能跑大部分检查;Hyper-V 功能状态查询需要管理员。
#>
[CmdletBinding()]
param()
. "$PSScriptRoot\lib\Common.ps1"

$cfg = Get-LabConfig
Write-Step "CafeSec Lab 预检 (Preflight Check)"

# 1. 操作系统 / 版本
# 用 EditionID(与界面语言无关)判定,而非 Caption —— 中文系统 Caption 是"专业版"而非 "Pro",
# 用 Caption -match 'Pro' 会在中文机上误判为 Home。Home 版 EditionID 以 Core 开头。
$os = Get-CimInstance Win32_OperatingSystem
$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
Write-Host "OS          : $($os.Caption) [$edition] (Build $($os.BuildNumber), $($os.OSArchitecture))"
if ($edition -and $edition -notmatch '^Core') { Write-Ok "Windows 版本支持 Hyper-V (EditionID=$edition)" }
elseif ($edition -match '^Core') { Write-Fail "Home 版($edition)不含 Hyper-V。需要 Pro/Enterprise/Education/Server。" }
else { Write-Warn2 "无法读取 EditionID,跳过版本判定(Caption: $($os.Caption))。" }

# 2. 内存
$ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)
Write-Host "RAM         : $ramGB GB"
$needGB = ($cfg.VMs.MemoryGB | Measure-Object -Sum).Sum
if ($ramGB -ge ($needGB + 8)) { Write-Ok "内存充足:VM 需 ${needGB}GB,宿主余量 >= 8GB" }
else { Write-Warn2 "内存偏紧:VM 需 ${needGB}GB,总内存 ${ramGB}GB" }

# 3. CPU 虚拟化
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$hvPresent = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
Write-Host "CPU         : $($cpu.Name) ($($cpu.NumberOfLogicalProcessors) 逻辑核)"
Write-Host "HypervisorPresent      : $hvPresent"
Write-Host "VirtFirmwareEnabled    : $($cpu.VirtualizationFirmwareEnabled)"
if ($hvPresent) {
    Write-Ok "已有 hypervisor 运行 -> VT-x 必然已在 BIOS 开启(无需进 BIOS)"
} elseif ($cpu.VirtualizationFirmwareEnabled) {
    Write-Ok "VT-x 已在固件启用"
} else {
    Write-Fail "VT-x 似乎未启用。请进 BIOS/UEFI 开启 Intel VT-x,再重试。"
}

# 4. 磁盘空间(检查 VM 存放盘)
$vmDrive = (Split-Path -Qualifier $cfg.Paths.VmRoot)   # 例如 'E:'
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$vmDrive'"
if ($disk) {
    $freeGB = [math]::Round($disk.FreeSpace/1GB,1)
    $needDisk = ($cfg.VMs.DiskGB | Measure-Object -Sum).Sum
    Write-Host "VM 存放盘   : $vmDrive 剩余 $freeGB GB (动态磁盘上限合计 ${needDisk}GB)"
    if ($freeGB -ge 200) { Write-Ok "磁盘空间充足 (>=200GB)" }
    else { Write-Warn2 "剩余空间 < 200GB,留意动态磁盘增长" }
} else {
    Write-Fail "找不到盘 $vmDrive,请检查 config\lab.psd1 的 Paths.VmRoot"
}

# 5. Hyper-V 功能是否已启用(需要管理员)
if (Test-IsAdmin) {
    $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($hv) {
        Write-Host "Hyper-V 功能 : $($hv.State)"
        if ($hv.State -eq 'Enabled') { Write-Ok "Hyper-V 已启用" }
        else { Write-Warn2 "Hyper-V 未启用 -> 运行 01-Enable-HyperV.ps1" }
    }
} else {
    Write-Warn2 "未以管理员运行,跳过 Hyper-V 功能状态检查(非阻塞)"
}

# 6. ISO 是否到位
Write-Step "镜像 (ISO) 检查"
foreach ($vm in $cfg.VMs) {
    $isoPath = Join-Path $cfg.Paths.IsoRoot $vm.IsoFile
    if (Test-Path $isoPath) { Write-Ok "$($vm.Name): 找到 $($vm.IsoFile)" }
    else { Write-Warn2 "$($vm.Name): 缺 $($vm.IsoFile)  (放到 $($cfg.Paths.IsoRoot),下载地址见 docs\downloads.md)" }
}

Write-Step "预检完成"
Write-Host "若有 FAIL 先解决;WARN 多为提示(如 ISO 未下载)。下一步: 01-Enable-HyperV.ps1" -ForegroundColor Gray
