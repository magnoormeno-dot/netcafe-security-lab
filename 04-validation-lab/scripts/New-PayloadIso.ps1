#requires -Version 5.1
<#
.SYNOPSIS
  把一个【已下载好的工具文件夹】打包成一个 .iso 数据光盘镜像,
  以便在 Phase 2(断网/隔离)阶段通过 Add-VMDvdDrive 挂载进气隙 VM,
  完全无需联网即可把防御工具送进虚拟机。纯防御工具,不产生任何网络行为。

.DESCRIPTION
  设计要点(对照 docs\downloads.md 第 39-40 行留下的缺口:此前只提到 oscdimg):
    * 不依赖 Windows ADK / oscdimg —— 这两者在本宿主上可能并未安装。
    * 仅使用 Windows 系统【内置】的 IMAPI2 COM 组件:
        - IMAPI2FS.MsftFileSystemImage  生成文件系统镜像(本脚本用它)
        - (IMAPI2.MsftDiscFormat2Data 是用来【刻录到物理光盘】的,本脚本不需要,
           因为我们只是把镜像写成一个 .iso 文件,不烧盘)
    * 通过 IFileSystemImage->CreateResultImage() 拿到结果镜像,
      再把结果的 COM IStream(ImageStream)按块复制到磁盘上的 .iso 文件。
      由于 PowerShell 不能直接操作 System.Runtime.InteropServices.ComTypes.IStream,
      这里用 Add-Type 内联编译一个极小的 C# 助手(ISOFile)完成 IStream -> 文件 的复制。
    * 自动选择同时生成 ISO9660 + Joliet + UDF 文件系统,以支持长文件名、深目录与 >4GB 单文件。

  全程离线、纯本地:本脚本不发起任何网络连接,产物是一个静态 .iso 文件。
  典型用法:Phase 1 临时联网时把工具下载到 downloads\tools(或任意文件夹),
  本脚本打成 payload.iso;Phase 2 断网后用 Add-VMDvdDrive 挂到 CSL-Client01,
  VM 内从光驱把工具拷出来安装。这是 Copy-VMFile(仅 Windows 客户机)之外的通用方式,
  且对 Linux 客户机(CSL-Wazuh)同样适用。

.PARAMETER SourceFolder
  要打包的源文件夹(其【内容】会被放到镜像根目录)。必填。
  例如 downloads\tools —— 里面的 Sysmon64.exe、yara64.exe、wazuh-agent.msi 等都会进 ISO。

.PARAMETER IsoPath
  输出 .iso 的完整路径。可选;缺省为 <IsoRoot>\payload.iso(IsoRoot 取自 config\lab.psd1)。
  父目录不存在会自动创建;目标已存在需配合 -Force 才会覆盖。

.PARAMETER VolumeName
  光盘卷标(VM 内显示的盘符名称)。可选;缺省 'CAFESEC_PAYLOAD'。
  ISO9660 卷标上限 32 字符,且会被规整为大写字母/数字/下划线。

.PARAMETER Force
  目标 IsoPath 已存在时允许覆盖。

.EXAMPLE
  # 1) 打包 downloads\tools 下的所有工具为默认的 <IsoRoot>\payload.iso
  .\New-PayloadIso.ps1 -SourceFolder ..\downloads\tools

.EXAMPLE
  # 2) 指定输出路径与卷标,并覆盖已存在的同名 ISO
  .\New-PayloadIso.ps1 -SourceFolder E:\CafeSec-Lab\downloads\tools `
      -IsoPath E:\CafeSec-Lab\ISO\payload.iso -VolumeName CAFESEC_TOOLS -Force

.EXAMPLE
  # 3) 制成后,在【宿主】上把 ISO 挂载进气隙客户机 CSL-Client01(无需联网):
  Add-VMDvdDrive -VMName CSL-Client01 -Path E:\CafeSec-Lab\ISO\payload.iso
  # 之后在 CSL-Client01 内,光盘会出现为只读盘符(如 D:),把工具拷到 C:\CafeSec\ 即可。
  # 用完卸载光驱(避免占用 / 保持干净):
  #   Get-VMDvdDrive -VMName CSL-Client01 | Where-Object Path -eq 'E:\CafeSec-Lab\ISO\payload.iso' | Remove-VMDvdDrive

.NOTES
  纯防御实验工具(CafeSec Lab)。仅生成本地静态 .iso 文件,不触网、不刻盘、不执行被打包的内容。
  兼容 Windows PowerShell 5.1。无需管理员权限(写 ISO 仅需对输出目录有写权限)。
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$SourceFolder,

    [string]$IsoPath,

    [ValidateNotNullOrEmpty()]
    [string]$VolumeName = 'CAFESEC_PAYLOAD',

    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# 载入项目公共函数(Write-Step/Ok/Warn2/Fail、Get-LabConfig 等)。
. "$PSScriptRoot\lib\Common.ps1"

# ---------------------------------------------------------------------------
# 0) 参数规整与前置校验
# ---------------------------------------------------------------------------
Write-Step "离线 Payload ISO 构建器(IMAPI2,无需 ADK/oscdimg)"

# 源文件夹必须存在,且必须是目录、且非空(空 ISO 没有意义,通常是路径搞错了)。
$src = (Resolve-Path -LiteralPath $SourceFolder -ErrorAction SilentlyContinue)
if (-not $src) { throw "源文件夹不存在: $SourceFolder" }
$SourceFolder = $src.ProviderPath
if (-not (Test-Path -LiteralPath $SourceFolder -PathType Container)) {
    throw "源路径不是文件夹: $SourceFolder (请指向一个目录,其内容会被放进 ISO 根目录)"
}
$items = Get-ChildItem -LiteralPath $SourceFolder -Force -ErrorAction SilentlyContinue
if (-not $items) {
    throw "源文件夹为空: $SourceFolder —— 没有任何文件可打包。请先把要送进 VM 的工具放进该目录。"
}

# 缺省 IsoPath:取 config\lab.psd1 的 IsoRoot;若读不到配置则退回源文件夹同级。
if (-not $IsoPath) {
    try {
        $cfg     = Get-LabConfig
        $isoRoot = $cfg.Paths.IsoRoot
    } catch {
        Write-Warn2 "未能读取 lab.psd1($($_.Exception.Message));改用源文件夹父目录作为输出位置。"
        $isoRoot = Split-Path -Parent $SourceFolder
    }
    $IsoPath = Join-Path $isoRoot 'payload.iso'
}
# 强制 .iso 扩展名,避免误写成无扩展名文件。
if ([System.IO.Path]::GetExtension($IsoPath) -ne '.iso') { $IsoPath += '.iso' }

# 确保输出目录存在。
$isoDir = Split-Path -Parent $IsoPath
if ($isoDir -and -not (Test-Path -LiteralPath $isoDir)) {
    New-Item -ItemType Directory -Path $isoDir -Force | Out-Null
    Write-Ok "已创建输出目录 $isoDir"
}

# 覆盖保护。
if (Test-Path -LiteralPath $IsoPath) {
    if (-not $Force) {
        throw "目标已存在: $IsoPath  (加 -Force 覆盖,或换一个 -IsoPath)"
    }
    Write-Warn2 "目标已存在,将被覆盖(-Force): $IsoPath"
}

# 规整卷标:ISO9660 仅允许大写 A-Z/0-9/下划线,长度 <=32。
$cleanVol = ($VolumeName.ToUpperInvariant() -replace '[^A-Z0-9_]', '_')
if ($cleanVol.Length -gt 32) { $cleanVol = $cleanVol.Substring(0, 32) }
if ($cleanVol -ne $VolumeName) { Write-Warn2 "卷标已规整为合法形式: '$VolumeName' -> '$cleanVol'" }
$VolumeName = $cleanVol

$sizeMB = [math]::Round((Get-ChildItem -LiteralPath $SourceFolder -Recurse -File -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum / 1MB, 1)
Write-Host ("  源目录 : {0}" -f $SourceFolder)        -ForegroundColor Gray
Write-Host ("  文件量 : 约 {0} MB"  -f $sizeMB)         -ForegroundColor Gray
Write-Host ("  输出   : {0}" -f $IsoPath)              -ForegroundColor Gray
Write-Host ("  卷标   : {0}" -f $VolumeName)           -ForegroundColor Gray

if (-not $PSCmdlet.ShouldProcess($IsoPath, "用 IMAPI2 把 '$SourceFolder' 打包为 ISO")) {
    return
}

# ---------------------------------------------------------------------------
# 1) 编译 IStream -> 文件 的 C# 助手(只编译一次)
#    说明:CreateResultImage().ImageStream 是 COM IStream;PowerShell 无法直接遍历它,
#    故用一段极小的 C# 把它按 BlockSize 块逐块读出并写入目标 .iso 文件。
# ---------------------------------------------------------------------------
if (-not ('CafeSec.IsoStreamWriter' -as [type])) {
    Add-Type -CompilerParameters (
        New-Object System.CodeDom.Compiler.CompilerParameters -Property @{
            CompilerOptions = '/unsafe'
        }
    ) -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;

namespace CafeSec {
    public static class IsoStreamWriter {
        // 把 IMAPI2FS 结果镜像的 COM IStream 按块复制到磁盘上的 .iso 文件。
        // stream      : result.ImageStream (拆箱为 ComTypes.IStream)
        // blockSize   : result.BlockSize   (通常 2048 字节 / 扇区)
        // totalBlocks : result.TotalBlocks (镜像总块数)
        public unsafe static void Create(string path, object stream, int blockSize, int totalBlocks) {
            if (stream == null) { throw new ArgumentNullException("stream"); }
            IStream comStream = stream as IStream;
            if (comStream == null) { throw new InvalidCastException("传入对象不是 COM IStream。"); }

            int bytesRead = 0;
            byte[] buffer  = new byte[blockSize];
            IntPtr pRead   = (IntPtr)(&bytesRead);

            using (FileStream output = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None)) {
                while (totalBlocks-- > 0) {
                    comStream.Read(buffer, blockSize, pRead);
                    // 短读/零读保护:截断的流应中止,而不是把陈旧缓冲区当数据写出去(避免静默产生损坏 ISO)。
                    if (bytesRead == 0) { break; }
                    output.Write(buffer, 0, bytesRead);
                }
                output.Flush();
            }
        }
    }
}
'@
}

# ---------------------------------------------------------------------------
# 2) 用 IMAPI2FS 构建文件系统镜像
# ---------------------------------------------------------------------------
$fsi    = $null
$result = $null
try {
    Write-Host "  正在初始化 IMAPI2FS.MsftFileSystemImage ..." -ForegroundColor Gray
    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage

    # 选择介质默认值:用 DISK(硬盘文件),不受物理光盘容量限制。
    # 常量来自 IMAPI_MEDIA_PHYSICAL_TYPE:IMAPI_MEDIA_TYPE_DISK = 0xC = 12。
    $IMAPI_MEDIA_TYPE_DISK = 12
    $fsi.ChooseImageDefaultsForMediaType($IMAPI_MEDIA_TYPE_DISK)

    # FreeMediaBlocks = 0:微软文档定义 0 = "无限块数",用以解除光盘容量上限,
    # 从而可打包任意大小(>CD/DVD)的工具目录。必须在 ChooseImageDefaultsForMediaType 之后设置。
    # (旧脚本常用 -1,但那是未文档化行为,个别 Windows 版本会误判为超大正数上限,故改用 0。)
    try { $fsi.FreeMediaBlocks = 0 } catch { Write-Warn2 "无法设置 FreeMediaBlocks=0,沿用介质默认容量上限。" }

    # 同时生成 ISO9660 + Joliet + UDF:
    #   ISO9660(1) 兼容性;Joliet(2) 长文件名;UDF(4) 支持 >4GB 单文件与深目录。
    # FsiFileSystems 位标志:ISO9660=1, Joliet=2, UDF=4 -> 7 = 全开。
    try {
        $fsi.FileSystemsToCreate = 7
    } catch {
        Write-Warn2 "无法设置 FileSystemsToCreate=7,回退为系统默认(通常 ISO9660+Joliet)。"
    }

    # 卷标(对 ISO9660 生效)。
    $fsi.VolumeName = $VolumeName

    # 把源文件夹的【内容】挂到镜像根目录:
    # AddTree(sourcePath, bIncludeBaseDirectory=$false) -> 仅放入目录内的项,不带最外层目录名。
    Write-Host "  正在添加文件树(AddTree)..." -ForegroundColor Gray
    $fsi.Root.AddTree($SourceFolder, $false)

    # 生成结果镜像(包含可被流式读出的 ImageStream)。
    Write-Host "  正在生成结果镜像(CreateResultImage)..." -ForegroundColor Gray
    $result = $fsi.CreateResultImage()

    $blockSize   = [int]$result.BlockSize
    $totalBlocks = [int]$result.TotalBlocks
    if ($totalBlocks -le 0) { throw "结果镜像块数为 0,源目录可能没有可用文件。" }

    # ---------------------------------------------------------------------------
    # 3) 把结果 IStream 写到 .iso 文件
    # ---------------------------------------------------------------------------
    Write-Host ("  正在写出 ISO({0} 块 x {1} 字节)..." -f $totalBlocks, $blockSize) -ForegroundColor Gray
    [CafeSec.IsoStreamWriter]::Create($IsoPath, $result.ImageStream, $blockSize, $totalBlocks)
}
catch {
    Write-Fail "ISO 构建失败: $($_.Exception.Message)"
    # 失败时清理可能产生的半成品文件,避免误挂载到 VM。
    if ($IsoPath -and (Test-Path -LiteralPath $IsoPath)) {
        Remove-Item -LiteralPath $IsoPath -Force -ErrorAction SilentlyContinue
        Write-Warn2 "已删除不完整的输出文件: $IsoPath"
    }
    throw
}
finally {
    # 释放 COM 对象,避免句柄泄漏。
    foreach ($obj in @($result, $fsi)) {
        if ($obj) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($obj) } catch { $null = $_ }
        }
    }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

# ---------------------------------------------------------------------------
# 4) 校验并收尾
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $IsoPath)) { throw "构建结束但未找到输出文件: $IsoPath" }
$out = Get-Item -LiteralPath $IsoPath
if ($out.Length -le 0) {
    Remove-Item -LiteralPath $IsoPath -Force -ErrorAction SilentlyContinue
    throw "输出 ISO 大小为 0,已删除。请检查源目录内容。"
}

Write-Ok ("ISO 构建完成: {0}  ({1} MB)" -f $IsoPath, [math]::Round($out.Length / 1MB, 1))
Write-Host ""
Write-Host "下一步(Phase 2,断网后在【宿主】PowerShell 执行)——把它挂进气隙客户机:" -ForegroundColor Cyan
Write-Host ("  Add-VMDvdDrive -VMName CSL-Client01 -Path '{0}'" -f $IsoPath) -ForegroundColor Gray
Write-Host "  # VM 内出现只读光盘盘符,将工具拷到 C:\CafeSec\ 后安装。用完卸载光驱:" -ForegroundColor DarkGray
Write-Host ("  # Get-VMDvdDrive -VMName CSL-Client01 | Where-Object Path -eq '{0}' | Remove-VMDvdDrive" -f $IsoPath) -ForegroundColor DarkGray
Write-Host "提示:Linux 客户机(CSL-Wazuh)同样可挂载本 ISO;Windows 客户机也可改用 Copy-VMFile(见 docs\downloads.md)。" -ForegroundColor Gray
