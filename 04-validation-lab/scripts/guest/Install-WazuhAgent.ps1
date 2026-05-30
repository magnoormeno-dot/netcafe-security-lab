#requires -Version 5.1
<#
.SYNOPSIS
  【在 Windows 客户机/服务器内部运行】安装 Wazuh agent 并连接到隔离网内的 Wazuh manager。
.DESCRIPTION
  纯防御:Wazuh agent 把端点的安全事件(含 Sysmon、Windows 安全日志)上报给
  Wazuh manager(10.10.10.10)做集中检测/告警(开源 SIEM/XDR)。
  隔离网无法联网,需先把 wazuh-agent MSI 用 Copy-VMFile 注入或放进 ISO。
  下载地址见 docs\downloads.md(在【联网的临时阶段】下载,再断网部署)。
.PARAMETER MsiPath
  wazuh-agent-<ver>.msi 的本地完整路径。
.PARAMETER ManagerIP
  Wazuh manager 的 IP,默认 10.10.10.10。
.PARAMETER AgentName
  本 agent 注册名,默认取计算机名。
.EXAMPLE
  .\Install-WazuhAgent.ps1 -MsiPath C:\CafeSec\wazuh-agent-4.9.2-1.msi
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$MsiPath,
    [string]$ManagerIP = '10.10.10.10',
    [string]$AgentName = $env:COMPUTERNAME,
    [System.Security.SecureString]$RegistrationPassword   # 仅当 manager 端 authd 设了注册密码时才需要(SecureString)
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $MsiPath)) { throw "找不到 MSI: $MsiPath" }

# 把 SecureString 物化为明文(仅驻留内存,用完即弃):MSI 属性与 agent-auth -P 都只接受明文。
$regPwPlain = $null
if ($RegistrationPassword) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($RegistrationPassword)
    try   { $regPwPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

Write-Host "安装 Wazuh agent -> manager $ManagerIP, 名称 $AgentName ..." -ForegroundColor Cyan
# MSI 参数:写入 manager 与注册服务器地址、agent 名 —— Wazuh 4.x 据此在服务首启时自动注册。
# 注意:变量【不要】用 $args —— 它是 PowerShell 自动变量,复用会引入隐患。
$msiArgs = "/i `"$MsiPath`" /q WAZUH_MANAGER=`"$ManagerIP`" WAZUH_REGISTRATION_SERVER=`"$ManagerIP`" WAZUH_AGENT_NAME=`"$AgentName`""
if ($regPwPlain) { $msiArgs += " WAZUH_REGISTRATION_PASSWORD=`"$regPwPlain`"" }
$p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
# 0=成功;3010/1641=成功但需要/已触发重启 —— 均视为成功,不应当失败处理。
if (@(0,3010,1641) -notcontains $p.ExitCode) { throw "msiexec 退出码 $($p.ExitCode)" }
if (@(3010,1641) -contains $p.ExitCode) { Write-Host "[WARN] MSI 安装成功,但需要重启 (退出码 $($p.ExitCode)) 才能完成。" -ForegroundColor Yellow }
Write-Host "[ OK ] MSI 安装完成。" -ForegroundColor Green

# 注册:首选由上面 MSI 的 WAZUH_MANAGER/WAZUH_REGISTRATION_SERVER 在服务首启时自动注册。
# 仅当未生成 client.keys 时,才回退到旧版 agent-auth。
# 关键:Wazuh agent 是 32 位,装在 "Program Files (x86)" —— 用 $env:ProgramFiles 会找不到而静默跳过注册。
$pf86      = ${env:ProgramFiles(x86)}
$ossecBase = if ($pf86 -and (Test-Path (Join-Path $pf86 'ossec-agent\agent-auth.exe'))) { Join-Path $pf86 'ossec-agent' } else { Join-Path $env:ProgramFiles 'ossec-agent' }
$authd     = Join-Path $ossecBase 'agent-auth.exe'
$keyFile   = Join-Path $ossecBase 'client.keys'
$hasKey    = (Test-Path $keyFile) -and ((Get-Item $keyFile -ErrorAction SilentlyContinue).Length -gt 0)
if (-not $hasKey -and (Test-Path $authd)) {
    Write-Host "回退:未发现 client.keys,改用 agent-auth 向 manager 注册(需 manager 端 authd 已开启)..." -ForegroundColor Cyan
    $authArgs = @('-m', $ManagerIP, '-A', $AgentName)
    if ($regPwPlain) { $authArgs += @('-P', $regPwPlain) }
    & $authd @authArgs
} elseif (-not (Test-Path $authd)) {
    Write-Host "[WARN] 未找到 agent-auth.exe ($authd)。将依赖 MSI 的自动注册;若 manager 未开启 authd,请用 manage_agents 预生成 key 手动注册。" -ForegroundColor Yellow
}

# 启动服务
Start-Service -Name WazuhSvc -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') { Write-Host "[ OK ] WazuhSvc 运行中,正在向 $ManagerIP 上报。" -ForegroundColor Green }
else { Write-Host "[WARN] WazuhSvc 未运行。检查 ossec.conf 中的 <server><address> 是否为 $ManagerIP,并确认已注册。" -ForegroundColor Yellow }

Write-Host "`n在 manager 上用  /var/ossec/bin/agent_control -l  确认本 agent 已连接(Active)。" -ForegroundColor Gray
