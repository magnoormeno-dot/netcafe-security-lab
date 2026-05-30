#requires -Version 5.1
<#
.SYNOPSIS
  【破坏性】拆除 CafeSec Lab:删除 4 台 CSL 虚拟机、它们的 VHDX 以及隔离交换机。
.DESCRIPTION
  这是清场脚本,会【永久删除】数据。设计上层层设防,确保只删该删的:

    * 删除范围严格限定为 config\lab.psd1 中列出的 CSL VM、它们的虚拟硬盘
      (位于 Paths.VmRoot,默认 E:\CafeSec-Lab\VMs),以及隔离交换机
      (Network.SwitchName,默认 CafeSec-Isolated)。
    * 【绝不】触碰任何非 CSL 虚拟机,【绝不】删除隔离交换机以外的任何交换机
      (例如你阶段一用的 NAT/External 交换机会被原样保留)。
    * 删除前先把正在运行的目标 VM 关机(优先正常关机,超时则强制关机)。
    * 删 VM 后单独删除其 VHDX —— 因为 Remove-VM 只删配置/注册,VHDX 文件不会被一并删除。
    * 只删空的 VM 子目录;非空目录(可能有你额外放进去的东西)保留并提示。

  确认机制(三选一,缺一不可):
    -WhatIf         只预览将删除的清单,不做任何改动(可单独使用,最安全的"看一眼")。
    -Force          显式表示"我确认要删",跳过交互式输入(适合脚本化/无人值守)。
    交互式          以上都不给时,脚本会列清单并要求你【手动输入大写 DELETE】才会执行。
.PARAMETER WhatIf
  演练模式:打印将要删除的所有对象,但不实际删除。优先级最高(给了就只预览)。
.PARAMETER Force
  非交互确认开关。给了 -Force 即视为已同意删除,不再要求输入 DELETE。
  (改名自 -Confirm:-Confirm 是 PowerShell 保留通用参数,其约定语义是"删除前逐项询问",
   与本处"跳过询问直接删"相反,易误用,故改用 -Force。)
.PARAMETER ShutdownTimeoutSec
  正常关机的等待秒数,超时后强制关机(Stop-VM -Force)。默认 120。
.EXAMPLE
  # 先看一眼会删什么(强烈建议第一步)
  .\Reset-Lab.ps1 -WhatIf
.EXAMPLE
  # 交互确认:脚本列清单后要求你输入 DELETE
  .\Reset-Lab.ps1
.EXAMPLE
  # 无人值守:已明确知道后果,直接执行
  .\Reset-Lab.ps1 -Force
.NOTES
  需要管理员。沿用 lib\Common.ps1 的 Get-LabConfig / Write-* 约定。
  本脚本【不】使用 CmdletBinding 的 SupportsShouldProcess,改为自管 -WhatIf / -Force,
  以便严格按规范实现"显式 -Force 或交互式输入 DELETE"的双重确认语义。
#>
[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force,            # 非交互确认:给了即视为已同意删除。改名自 -Confirm,避免占用保留名并反转其语义。
    [int]$ShutdownTimeoutSec = 120
)

. "$PSScriptRoot\lib\Common.ps1"
Assert-Admin
$cfg = Get-LabConfig

$vmRoot         = $cfg.Paths.VmRoot
$isolatedSwitch = $cfg.Network.SwitchName
$cslNames       = @($cfg.VMs | ForEach-Object { $_.Name })

Write-Step "CafeSec Lab 拆除 (Reset-Lab) —— 破坏性操作"
Write-Warn2 "本操作会【永久删除】下列对象。请仔细核对清单。"

# =====================================================================
# 1) 盘点将被删除的对象(只读,不改动)
# =====================================================================

# --- 1a. 目标 VM:仅限配置清单里、且确实存在于宿主上的 CSL VM ---
$targetVMs = @()
foreach ($name in $cslNames) {
    $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
    if ($vm) { $targetVMs += $vm }
}

# --- 1b. 这些 VM 当前挂载的 VHDX(Remove-VM 不会删它们,需单独删)---
$targetVhds = @()
foreach ($vm in $targetVMs) {
    foreach ($hd in (Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue)) {
        if ($hd.Path) { $targetVhds += $hd.Path }
    }
}

# --- 1c. 兜底:扫 Paths.VmRoot 下各 CSL VM 子目录里的 *.vhdx / *.avhdx(含检查点差分盘,防止残留)---
if (Test-Path $vmRoot) {
    foreach ($name in $cslNames) {
        $vmDir = Join-Path $vmRoot $name
        if (Test-Path $vmDir) {
            Get-ChildItem -Path $vmDir -Recurse -File -Include *.vhdx,*.avhdx -ErrorAction SilentlyContinue |
                ForEach-Object { $targetVhds += $_.FullName }
        }
    }
}
# 去重(同一盘可能既被挂载又被目录扫描命中)
$targetVhds = @($targetVhds | Sort-Object -Unique)

# --- 1d. 隔离交换机(仅此一个;NAT/External 等绝不在此列)---
$targetSwitch = Get-VMSwitch -Name $isolatedSwitch -ErrorAction SilentlyContinue

# --- 1e. 删 VM 后可清理的【空】子目录 ---
$targetDirs = @()
if (Test-Path $vmRoot) {
    foreach ($name in $cslNames) {
        $vmDir = Join-Path $vmRoot $name
        if (Test-Path $vmDir) { $targetDirs += $vmDir }
    }
}

# =====================================================================
# 2) 打印清单
# =====================================================================
Write-Step "将删除的【虚拟机】(仅 CSL,配置清单内且存在的)"
if ($targetVMs.Count -gt 0) {
    $targetVMs | Format-Table Name, State,
        @{n = 'MemGB'; e = { [math]::Round($_.MemoryStartup / 1GB, 0) } },
        @{n = 'Switch'; e = { (Get-VMNetworkAdapter -VMName $_.Name | Select-Object -First 1).SwitchName } } -AutoSize
} else {
    Write-Host "  (无:这些 CSL VM 目前都不存在)" -ForegroundColor Gray
}

Write-Step "将删除的【虚拟硬盘 VHDX】(位于 $vmRoot)"
if ($targetVhds.Count -gt 0) {
    $targetVhds | ForEach-Object {
        $size = if (Test-Path $_) { '{0:N1} GB' -f ((Get-Item $_).Length / 1GB) } else { '?' }
        Write-Host ("  - {0}  [{1}]" -f $_, $size)
    }
} else {
    Write-Host "  (无)" -ForegroundColor Gray
}

Write-Step "将删除的【隔离交换机】(仅此一个)"
if ($targetSwitch) {
    Write-Host ("  - {0}  (类型 {1})" -f $targetSwitch.Name, $targetSwitch.SwitchType)
} else {
    Write-Host "  (无:'$isolatedSwitch' 当前不存在)" -ForegroundColor Gray
}

Write-Step "将清理的【空目录】(仅当删盘后变空时)"
if ($targetDirs.Count -gt 0) {
    $targetDirs | ForEach-Object { Write-Host ("  - {0}" -f $_) }
} else {
    Write-Host "  (无)" -ForegroundColor Gray
}

# 明确告知:不会动的东西。
Write-Host ""
Write-Warn2 "以下对象【不会】被触碰:任何非 CSL 虚拟机、隔离交换机以外的任何交换机(含你的 NAT/External)、$vmRoot 下的非空/无关目录。"

# 没有任何东西可删,直接收工。
if ($targetVMs.Count -eq 0 -and $targetVhds.Count -eq 0 -and -not $targetSwitch) {
    Write-Ok "没有发现任何可删除的 CafeSec 对象,环境已是干净状态。无需操作。"
    return
}

# =====================================================================
# 3) -WhatIf:只预览,绝不改动
# =====================================================================
if ($WhatIf) {
    Write-Step "WhatIf 演练模式"
    Write-Ok "以上为将要删除的完整清单。当前为 -WhatIf,未做任何改动。"
    Write-Host "确认无误后,去掉 -WhatIf 重跑(交互输入 DELETE),或加 -Force 直接执行。" -ForegroundColor Gray
    return
}

# =====================================================================
# 4) 确认门:-Confirm 显式同意,否则要求交互输入大写 DELETE
# =====================================================================
if (-not $Force) {
    Write-Step "最终确认"
    Write-Warn2 "这将【永久删除】上面列出的 VM、VHDX 与隔离交换机,且不可恢复。"
    $answer = Read-Host "若确认删除,请【完整输入大写】 DELETE 后回车(其它任何输入都会取消)"
    if ($answer -cne 'DELETE') {
        Write-Fail "未输入 DELETE(收到:'$answer')。已取消,未做任何改动。"
        return
    }
    Write-Ok "已收到 DELETE 确认。"
} else {
    Write-Warn2 "已通过 -Force 显式确认,跳过交互输入,开始执行删除。"
}

# =====================================================================
# 5) 执行删除
# =====================================================================

# --- 5a. 先关机(只关目标 VM)---
Write-Step "停止正在运行的目标 VM"
foreach ($vm in $targetVMs) {
    $live = Get-VM -Name $vm.Name -ErrorAction SilentlyContinue
    if ($live -and $live.State -ne 'Off') {
        Write-Host "  关闭 $($vm.Name)(当前 $($live.State))..."
        # 先尝试正常关机(走集成服务),给一定等待时间。
        Stop-VM -Name $vm.Name -ErrorAction SilentlyContinue
        $deadline = (Get-Date).AddSeconds($ShutdownTimeoutSec)
        while ((Get-Date) -lt $deadline) {
            $st = (Get-VM -Name $vm.Name -ErrorAction SilentlyContinue).State
            if ($st -eq 'Off') { break }
            Start-Sleep -Seconds 3
        }
        if ((Get-VM -Name $vm.Name -ErrorAction SilentlyContinue).State -ne 'Off') {
            Write-Warn2 "  $($vm.Name) 正常关机超时($ShutdownTimeoutSec s),改为强制关机。"
            Stop-VM -Name $vm.Name -TurnOff -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "  $($vm.Name) 已停止。"
    } else {
        Write-Ok "  $($vm.Name) 已是关机状态。"
    }
}

# --- 5b. 删除 VM(注意:Remove-VM 只删配置/注册,不删 VHDX)---
Write-Step "删除虚拟机(仅 CSL)"
foreach ($vm in $targetVMs) {
    # 用 try/catch:单台删除失败时报告并继续,不让整次拆除半途中止(与 5c 删盘逻辑一致)。
    try {
        Remove-VM -Name $vm.Name -Force -ErrorAction Stop
        Write-Ok "  已删除 VM '$($vm.Name)'(其 VHDX 将在下一步单独删除)。"
    } catch {
        Write-Fail "  无法删除 VM '$($vm.Name)': $($_.Exception.Message)"
    }
}

# --- 5c. 删除 VHDX 文件 ---
Write-Step "删除虚拟硬盘 VHDX"
foreach ($path in $targetVhds) {
    if (Test-Path $path) {
        try {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            Write-Ok "  已删除 $path"
        } catch {
            Write-Fail "  无法删除 $path : $($_.Exception.Message)"
        }
    } else {
        Write-Warn2 "  跳过(文件已不存在):$path"
    }
}

# --- 5d. 清理空的 VM 子目录(非空则保留)---
Write-Step "清理空目录"
foreach ($dir in $targetDirs) {
    if (Test-Path $dir) {
        $remaining = @(Get-ChildItem -LiteralPath $dir -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })
        if ($remaining.Count -eq 0) {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok "  已删除空目录 $dir"
        } else {
            Write-Warn2 "  保留 $dir(仍有 $($remaining.Count) 个文件,非 CafeSec 创建的内容不予删除)。"
        }
    }
}

# --- 5e. 删除隔离交换机(且仅删这一个)---
Write-Step "删除隔离交换机"
if ($targetSwitch) {
    Remove-VMSwitch -Name $targetSwitch.Name -Force -ErrorAction Stop
    Write-Ok "  已删除交换机 '$($targetSwitch.Name)'。"
} else {
    Write-Host "  (无隔离交换机可删)" -ForegroundColor Gray
}

# =====================================================================
# 6) 收尾
# =====================================================================
Write-Step "拆除完成"
Write-Ok "CafeSec Lab 已清场。非 CSL 的 VM 与隔离交换机以外的交换机均未受影响。"
Write-Host "如需重建:02-New-IsolatedSwitch.ps1  ->  03-New-LabVMs.ps1。" -ForegroundColor Gray
