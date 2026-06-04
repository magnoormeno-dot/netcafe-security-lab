#requires -Version 5.1
<#
.SYNOPSIS
  CafeSec Lab 宿主侧一键编排:按序运行 00→04 主机脚本(预检 → 启用 Hyper-V → 建隔离交换机
  → 建 VM → 宿主侧隔离验证),自动处理 Hyper-V 启用后的重启关口,并在结束时给出 VM 内 / 域 的后续指引。

.DESCRIPTION
  本脚本只编排【宿主侧】可自动化的步骤。VM 内的步骤(装系统、配静态 IP、域控提升 / 加域、
  部署 Sysmon/Wazuh/WEF、规则引擎)无法从宿主代跑 —— 结束时会列出清单与文档指引。

  设计:
    * 每个子步骤在【独立 powershell.exe 子进程】中运行 —— 隔离子脚本里的 `exit`(如 04 用 exit $fail),
      避免其终止本编排会话;用子进程 ExitCode 判定成败。子脚本输出实时显示在本控制台。
    * 幂等:所有子脚本可重复运行;启用 Hyper-V 需重启时本脚本会停下,重启后再次运行即从断点继续。
    * 安全:-DryRun 只打印计划不执行(且无需管理员);硬性步骤失败立即停止;破坏性操作不在本脚本内。

.PARAMETER StartAt
  起始步骤号(0-4),默认 0。重启后可用 -StartAt 2 跳过已完成步骤(直接重跑也安全,子脚本幂等)。
.PARAMETER StopAt
  结束步骤号(0-4),默认 4。
.PARAMETER DryRun
  只打印将要执行的步骤与命令,不实际运行任何子脚本(无需管理员,适合先预览)。
.PARAMETER VmWhatIf
  给步骤 3(建 VM)传 -WhatIf,只预览将创建的 VM 而不实际创建。
.PARAMETER NoPrompt
  非交互:跳过开始前的确认。
.EXAMPLE
  .\Invoke-LabSetup.ps1 -DryRun          # 先看计划(无需管理员)
.EXAMPLE
  .\Invoke-LabSetup.ps1                   # 管理员下实际编排 00→04
.EXAMPLE
  .\Invoke-LabSetup.ps1 -StartAt 2        # 启用 Hyper-V 重启后,从"建交换机"继续
.NOTES
  实际执行需管理员(-DryRun 除外)。本脚本只覆盖宿主侧;域 / 防御栈见 README 的 D–G 与 docs\03。
#>
[CmdletBinding()]
param(
    [ValidateRange(0,4)][int]$StartAt = 0,
    [ValidateRange(0,4)][int]$StopAt  = 4,
    [switch]$DryRun,
    [switch]$VmWhatIf,
    [switch]$NoPrompt
)
. "$PSScriptRoot\lib\Common.ps1"

# 在独立子进程里跑一个宿主脚本:隔离其 exit、捕获 ExitCode、输出直通控制台。
function Invoke-HostStep {
    param(
        [int]$Num,
        [string]$Title,
        [string]$ScriptName,
        [string[]]$ScriptArgs = @()
    )
    $path = Join-Path $PSScriptRoot $ScriptName
    Write-Host ""
    Write-Host ("===== 步骤 {0} / {1} =====" -f $Num, $Title) -ForegroundColor Magenta
    Write-Host ("  -> {0} {1}" -f $ScriptName, ($ScriptArgs -join ' ')) -ForegroundColor DarkGray
    if (-not (Test-Path $path)) { Write-Fail "找不到脚本: $path"; return 1 }
    if ($DryRun) { Write-Warn2 "  [DryRun] 不实际执行。"; return 0 }

    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $path
    if ($ScriptArgs.Count) { $argLine += ' ' + ($ScriptArgs -join ' ') }
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -NoNewWindow -Wait -PassThru
    if ($null -ne $p.ExitCode) { return [int]$p.ExitCode } else { return 0 }
}

# DryRun 无需管理员(只预览);实际执行才要求管理员。
if (-not $DryRun) { Assert-Admin }
Get-LabConfig | Out-Null   # 提前校验 lab.psd1 可加载(各子脚本运行时再各自读取)

Write-Step "CafeSec Lab 宿主侧编排 (Invoke-LabSetup)"
Write-Host ("范围: 步骤 {0} → {1}{2}" -f $StartAt, $StopAt, $(if ($DryRun) { '   [DryRun]' } else { '' })) -ForegroundColor Gray
if ($StartAt -gt $StopAt) { Write-Fail "StartAt($StartAt) 大于 StopAt($StopAt)。"; return }

# ---- 前置硬性检查(locale-safe;不满足直接停)----
$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
if (Test-IsHomeEdition -EditionId $edition) {
    Write-Fail "当前为 Home 版($edition),不含 Hyper-V。需要 Pro/Enterprise/Education/Server。"
    return
}
$hvPresent = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
$vtFw = (Get-CimInstance Win32_Processor | Select-Object -First 1).VirtualizationFirmwareEnabled
if (-not ($hvPresent -or $vtFw)) {
    Write-Fail "未检测到虚拟化(VT-x)。请进 BIOS/UEFI 开启 Intel VT-x 后重试。"
    return
}
Write-Ok ("前置检查通过: EditionID={0}, HypervisorPresent={1}" -f $edition, $hvPresent)

# ---- 步骤计划 ----
$vmArgs = if ($VmWhatIf) { @('-WhatIf') } else { @() }
$steps = @(
    @{ Num = 0; Title = '预检 (只读)';        Script = '00-Preflight-Check.ps1';   Args = @();           Advisory = $true;  RebootGate = $false }
    @{ Num = 1; Title = '启用 Hyper-V';        Script = '01-Enable-HyperV.ps1';     Args = @('-NoPrompt');Advisory = $false; RebootGate = $true  }
    @{ Num = 2; Title = '建隔离私有交换机';     Script = '02-New-IsolatedSwitch.ps1';Args = @();           Advisory = $false; RebootGate = $false }
    @{ Num = 3; Title = '创建 4 台实验 VM';     Script = '03-New-LabVMs.ps1';        Args = $vmArgs;       Advisory = $false; RebootGate = $false }
    @{ Num = 4; Title = '宿主侧隔离验证';       Script = '04-Verify-Isolation.ps1';  Args = @();           Advisory = $true;  RebootGate = $false }
)

# 打印计划
Write-Host "`n将按序编排(仅宿主侧):" -ForegroundColor Cyan
$steps | Where-Object { $_.Num -ge $StartAt -and $_.Num -le $StopAt } |
    ForEach-Object { Write-Host ("  [{0}] {1}  ({2})" -f $_.Num, $_.Title, $_.Script) -ForegroundColor Gray }

if (-not $NoPrompt -and -not $DryRun) {
    $ans = Read-Host "`n开始执行? [y/N]"
    if ($ans -notmatch '^(y|Y)') { Write-Warn2 "已取消。"; return }
}

# ---- 执行 ----
$results = @()
foreach ($s in $steps) {
    if ($s.Num -lt $StartAt -or $s.Num -gt $StopAt) { continue }

    $code = Invoke-HostStep -Num $s.Num -Title $s.Title -ScriptName $s.Script -ScriptArgs $s.Args
    $ok = ($code -eq 0)
    $status = if ($ok) { 'OK' } elseif ($s.Advisory) { 'WARN' } else { 'FAIL' }
    $results += [pscustomobject]@{ Step = $s.Num; Title = $s.Title; ExitCode = $code; Status = $status }

    # Hyper-V 重启关口:启用后,创建交换机/VM 依赖 vmms 服务运行 + Hyper-V 模块就绪。
    if ($s.RebootGate -and -not $DryRun) {
        $vmms = Get-Service vmms -ErrorAction SilentlyContinue
        $rebootPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        # reboot-gate 判定抽进 LabLogic\Test-HyperVRebootGate(纯函数,见 tests\LabLogic.Tests.ps1)。
        $needsReboot = Test-HyperVRebootGate -VmmsStatus ([string]$vmms.Status) -HasSwitchCmdlet ([bool](Get-Command New-VMSwitch -ErrorAction SilentlyContinue)) -RebootPending $rebootPending
        if ($needsReboot) {
            Write-Host ""
            Write-Warn2 "Hyper-V 已启用,但需要【重启】后才能继续(vmms 服务/Hyper-V 模块尚未就绪)。"
            Write-Host  "请重启本机,然后重新运行(子脚本幂等,会自动跳过已完成步骤):" -ForegroundColor Yellow
            Write-Host  "    .\Invoke-LabSetup.ps1            # 或   .\Invoke-LabSetup.ps1 -StartAt 2" -ForegroundColor Yellow
            Write-Step "已在重启关口暂停"
            $results | Format-Table Step, Title, ExitCode, Status -AutoSize
            return
        }
        Write-Ok "Hyper-V 就绪(vmms 运行中),继续。"
    }

    # 硬性步骤失败 -> 停止;提示性步骤失败 -> 仅告警继续。
    if (-not $ok -and -not $s.Advisory) {
        Write-Host ""
        Write-Fail "步骤 $($s.Num)($($s.Title))失败(ExitCode=$code)。已停止编排,请排查后重跑。"
        break
    }
    if (-not $ok -and $s.Advisory) {
        Write-Warn2 "步骤 $($s.Num)($($s.Title))返回非零(ExitCode=$code);该步为提示性,继续。"
    }
}

# ---- 汇总 ----
Write-Step "编排汇总"
$results | Format-Table Step, Title, ExitCode, Status -AutoSize

if ($DryRun) {
    Write-Warn2 "DryRun 结束:以上为计划,未做任何改动。去掉 -DryRun 并以管理员运行以实际编排。"
}

# ---- 后续步骤(VM 内 / 域 —— 无法从宿主代跑)----
Write-Step "后续步骤(VM 内 / 域)"
Write-Host @'
宿主侧脚手架就位后(隔离交换机 + 4 台 VM),按 README 的 D–G 继续:

  阶段一(临时联网装系统/工具):
    .\Switch-LabNetwork.ps1 -Phase Provisioning -ProvisioningSwitch <你的NAT交换机>
    - 逐台开机装 OS;按 docs\downloads.md 下载并安装 Sysmon / Wazuh agent / 工具
    - 离线注入工具可用 .\New-PayloadIso.ps1 打包成 ISO

  建域(见 docs\03-domain-and-wef.md):
    CSL-Server:  .\domain\Install-DomainController.ps1 -SafeModePassword (Read-Host -AsSecureString)
                 重启后:  .\domain\Set-DcDnsAirgap.ps1
    客户机:      .\domain\Join-LabDomain.ps1 -DomainCredential (Get-Credential CAFESEC\Administrator)

  防御栈:
    Ubuntu:      bash scripts/wazuh/install-wazuh-manager.sh
    Windows:     guest\Deploy-Sysmon.ps1  /  guest\Install-WazuhAgent.ps1
    域控:        guest\Configure-WEC-Collector.ps1  ->  domain\New-WefGpo.ps1
    分析侧:      analysis\Setup-RuleEngines.ps1

  阶段二(锁定隔离并验证):
    .\Switch-LabNetwork.ps1 -Phase Isolated
    各 VM 配静态 IP(域成员加 -DnsServer 10.10.10.20;域控 -DnsServer 127.0.0.1)
    宿主侧:  .\04-Verify-Isolation.ps1
    各 VM 内: Windows -> guest\Test-GuestIsolation.ps1 ; Ubuntu -> wazuh/test-guest-isolation.sh
    >> 宿主侧 + 客户机侧两边全 PASS 才算隔离合规,之后方可进行研究。<<
'@ -ForegroundColor Gray
