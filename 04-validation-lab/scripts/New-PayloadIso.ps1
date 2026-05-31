#requires -Version 5.1
<#
.SYNOPSIS
  Packages an [already-downloaded tools folder] into a .iso data disc image,
  so that during Phase 2 (offline/isolated) it can be mounted into an air-gapped VM via Add-VMDvdDrive,
  delivering defensive tools into the virtual machine with no network access required at all. Defensive tools only; produces no network activity.

.DESCRIPTION
  Design notes (addressing the gap left at lines 39-40 of docs\downloads.md, which previously only mentioned oscdimg):
    * Does not depend on the Windows ADK / oscdimg -- neither may be installed on this host.
    * Uses only the [built-in] IMAPI2 COM components of Windows:
        - IMAPI2FS.MsftFileSystemImage  generates the file system image (this script uses it)
        - (IMAPI2.MsftDiscFormat2Data is for [burning to a physical disc], which this script does not need,
           because we only write the image out to a .iso file rather than burning a disc)
    * Obtains the result image via IFileSystemImage->CreateResultImage(),
      then copies the result's COM IStream (ImageStream) block by block to the on-disk .iso file.
      Because PowerShell cannot directly operate on System.Runtime.InteropServices.ComTypes.IStream,
      a tiny inline-compiled C# helper (ISOFile) is used here via Add-Type to perform the IStream -> file copy.
    * Automatically generates ISO9660 + Joliet + UDF file systems together, to support long file names, deep directories, and single files >4GB.

  Fully offline, purely local: this script does not initiate any network connection, and the output is a static .iso file.
  Typical usage: while temporarily online in Phase 1, download tools into downloads\tools (or any folder),
  use this script to build payload.iso; after going offline in Phase 2, mount it onto CSL-Client01 with Add-VMDvdDrive,
  and inside the VM copy the tools off the optical drive and install them. This is a general-purpose method besides Copy-VMFile (Windows guests only),
  and it works equally well for Linux guests (CSL-Wazuh).

.PARAMETER SourceFolder
  The source folder to package (its [contents] are placed at the image root). Required.
  For example downloads\tools -- the Sysmon64.exe, yara64.exe, wazuh-agent.msi, etc. inside it all go into the ISO.

.PARAMETER IsoPath
  The full path of the output .iso. Optional; defaults to <IsoRoot>\payload.iso (IsoRoot is taken from config\lab.psd1).
  A missing parent directory is created automatically; overwriting an existing target requires -Force.

.PARAMETER VolumeName
  The disc volume label (the drive name shown inside the VM). Optional; defaults to 'CAFESEC_PAYLOAD'.
  The ISO9660 volume label is limited to 32 characters and is normalized to uppercase letters/digits/underscores.

.PARAMETER Force
  Allows overwriting when the target IsoPath already exists.

.EXAMPLE
  # 1) Package all tools under downloads\tools into the default <IsoRoot>\payload.iso
  .\New-PayloadIso.ps1 -SourceFolder ..\downloads\tools

.EXAMPLE
  # 2) Specify the output path and volume label, and overwrite an existing ISO of the same name
  .\New-PayloadIso.ps1 -SourceFolder E:\CafeSec-Lab\downloads\tools `
      -IsoPath E:\CafeSec-Lab\ISO\payload.iso -VolumeName CAFESEC_TOOLS -Force

.EXAMPLE
  # 3) After building, on the [host] mount the ISO into the air-gapped guest CSL-Client01 (no network needed):
  Add-VMDvdDrive -VMName CSL-Client01 -Path E:\CafeSec-Lab\ISO\payload.iso
  # Then inside CSL-Client01 the disc appears as a read-only drive letter (e.g. D:); copy the tools to C:\CafeSec\.
  # When done, dismount the optical drive (to avoid holding it / keep things clean):
  #   Get-VMDvdDrive -VMName CSL-Client01 | Where-Object Path -eq 'E:\CafeSec-Lab\ISO\payload.iso' | Remove-VMDvdDrive

.NOTES
  Defensive lab tooling only (CafeSec Lab). Generates only a local static .iso file; no network access, no disc burning, and does not execute the packaged content.
  Compatible with Windows PowerShell 5.1. No administrator privileges required (writing the ISO only needs write access to the output directory).
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

# Load the project's common functions (Write-Step/Ok/Warn2/Fail, Get-LabConfig, etc.).
. "$PSScriptRoot\lib\Common.ps1"

# ---------------------------------------------------------------------------
# 0) Parameter normalization and pre-flight validation
# ---------------------------------------------------------------------------
Write-Step "Offline Payload ISO builder (IMAPI2, no ADK/oscdimg required)"

# The source folder must exist, must be a directory, and must be non-empty (an empty ISO is meaningless and usually means a wrong path).
$src = (Resolve-Path -LiteralPath $SourceFolder -ErrorAction SilentlyContinue)
if (-not $src) { throw "Source folder does not exist: $SourceFolder" }
$SourceFolder = $src.ProviderPath
if (-not (Test-Path -LiteralPath $SourceFolder -PathType Container)) {
    throw "Source path is not a folder: $SourceFolder (point it at a directory; its contents will be placed at the ISO root)"
}
$items = Get-ChildItem -LiteralPath $SourceFolder -Force -ErrorAction SilentlyContinue
if (-not $items) {
    throw "Source folder is empty: $SourceFolder -- no files to package. Place the tools you want to deliver into the VM in this directory first."
}

# Default IsoPath: take IsoRoot from config\lab.psd1; if the config cannot be read, fall back to the source folder's sibling.
if (-not $IsoPath) {
    try {
        $cfg     = Get-LabConfig
        $isoRoot = $cfg.Paths.IsoRoot
    } catch {
        Write-Warn2 "Could not read lab.psd1 ($($_.Exception.Message)); using the source folder's parent directory as the output location instead."
        $isoRoot = Split-Path -Parent $SourceFolder
    }
    $IsoPath = Join-Path $isoRoot 'payload.iso'
}
# Force the .iso extension, to avoid accidentally writing an extension-less file.
if ([System.IO.Path]::GetExtension($IsoPath) -ne '.iso') { $IsoPath += '.iso' }

# Ensure the output directory exists.
$isoDir = Split-Path -Parent $IsoPath
if ($isoDir -and -not (Test-Path -LiteralPath $isoDir)) {
    New-Item -ItemType Directory -Path $isoDir -Force | Out-Null
    Write-Ok "Created output directory $isoDir"
}

# Overwrite protection.
if (Test-Path -LiteralPath $IsoPath) {
    if (-not $Force) {
        throw "Target already exists: $IsoPath  (add -Force to overwrite, or choose a different -IsoPath)"
    }
    Write-Warn2 "Target already exists and will be overwritten (-Force): $IsoPath"
}

# Normalize the volume label: ISO9660 only allows uppercase A-Z/0-9/underscore, length <=32.
$cleanVol = ($VolumeName.ToUpperInvariant() -replace '[^A-Z0-9_]', '_')
if ($cleanVol.Length -gt 32) { $cleanVol = $cleanVol.Substring(0, 32) }
if ($cleanVol -ne $VolumeName) { Write-Warn2 "Volume label normalized to a valid form: '$VolumeName' -> '$cleanVol'" }
$VolumeName = $cleanVol

$sizeMB = [math]::Round((Get-ChildItem -LiteralPath $SourceFolder -Recurse -File -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum / 1MB, 1)
Write-Host ("  Source dir : {0}" -f $SourceFolder)     -ForegroundColor Gray
Write-Host ("  File size  : about {0} MB"  -f $sizeMB)  -ForegroundColor Gray
Write-Host ("  Output     : {0}" -f $IsoPath)           -ForegroundColor Gray
Write-Host ("  Volume     : {0}" -f $VolumeName)        -ForegroundColor Gray

if (-not $PSCmdlet.ShouldProcess($IsoPath, "Package '$SourceFolder' into an ISO using IMAPI2")) {
    return
}

# ---------------------------------------------------------------------------
# 1) Compile the IStream -> file C# helper (compiled only once)
#    Note: CreateResultImage().ImageStream is a COM IStream; PowerShell cannot iterate it directly,
#    so a tiny piece of C# reads it out block by block by BlockSize and writes it to the target .iso file.
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
        // Copies the COM IStream of the IMAPI2FS result image block by block to the on-disk .iso file.
        // stream      : result.ImageStream (unboxed as ComTypes.IStream)
        // blockSize   : result.BlockSize   (typically 2048 bytes / sector)
        // totalBlocks : result.TotalBlocks (total number of blocks in the image)
        public unsafe static void Create(string path, object stream, int blockSize, int totalBlocks) {
            if (stream == null) { throw new ArgumentNullException("stream"); }
            IStream comStream = stream as IStream;
            if (comStream == null) { throw new InvalidCastException("The passed object is not a COM IStream."); }

            int bytesRead = 0;
            byte[] buffer  = new byte[blockSize];
            IntPtr pRead   = (IntPtr)(&bytesRead);

            using (FileStream output = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None)) {
                while (totalBlocks-- > 0) {
                    comStream.Read(buffer, blockSize, pRead);
                    // Short-read/zero-read guard: a truncated stream should abort rather than writing out a stale buffer as data (to avoid silently producing a corrupt ISO).
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
# 2) Build the file system image with IMAPI2FS
# ---------------------------------------------------------------------------
$fsi    = $null
$result = $null
try {
    Write-Host "  Initializing IMAPI2FS.MsftFileSystemImage ..." -ForegroundColor Gray
    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage

    # Choose media defaults: use DISK (hard-disk file), which is not subject to physical disc capacity limits.
    # The constant comes from IMAPI_MEDIA_PHYSICAL_TYPE: IMAPI_MEDIA_TYPE_DISK = 0xC = 12.
    $IMAPI_MEDIA_TYPE_DISK = 12
    $fsi.ChooseImageDefaultsForMediaType($IMAPI_MEDIA_TYPE_DISK)

    # FreeMediaBlocks = 0: per Microsoft documentation, 0 = "unlimited blocks", used to lift the disc capacity ceiling,
    # so a tools directory of any size (>CD/DVD) can be packaged. Must be set after ChooseImageDefaultsForMediaType.
    # (Older scripts often used -1, but that is undocumented behavior; some Windows versions misinterpret it as a huge positive upper bound, so 0 is used instead.)
    try { $fsi.FreeMediaBlocks = 0 } catch { Write-Warn2 "Could not set FreeMediaBlocks=0; using the media default capacity ceiling." }

    # Generate ISO9660 + Joliet + UDF together:
    #   ISO9660(1) compatibility; Joliet(2) long file names; UDF(4) supports single files >4GB and deep directories.
    # FsiFileSystems bit flags: ISO9660=1, Joliet=2, UDF=4 -> 7 = all enabled.
    try {
        $fsi.FileSystemsToCreate = 7
    } catch {
        Write-Warn2 "Could not set FileSystemsToCreate=7; falling back to the system default (usually ISO9660+Joliet)."
    }

    # Volume label (takes effect for ISO9660).
    $fsi.VolumeName = $VolumeName

    # Attach the [contents] of the source folder to the image root:
    # AddTree(sourcePath, bIncludeBaseDirectory=$false) -> only adds the items inside the directory, without the outermost directory name.
    Write-Host "  Adding the file tree (AddTree)..." -ForegroundColor Gray
    $fsi.Root.AddTree($SourceFolder, $false)

    # Generate the result image (which contains the ImageStream that can be read out as a stream).
    Write-Host "  Generating the result image (CreateResultImage)..." -ForegroundColor Gray
    $result = $fsi.CreateResultImage()

    $blockSize   = [int]$result.BlockSize
    $totalBlocks = [int]$result.TotalBlocks
    if ($totalBlocks -le 0) { throw "The result image has 0 blocks; the source directory may have no usable files." }

    # ---------------------------------------------------------------------------
    # 3) Write the result IStream to the .iso file
    # ---------------------------------------------------------------------------
    Write-Host ("  Writing out the ISO ({0} blocks x {1} bytes)..." -f $totalBlocks, $blockSize) -ForegroundColor Gray
    [CafeSec.IsoStreamWriter]::Create($IsoPath, $result.ImageStream, $blockSize, $totalBlocks)
}
catch {
    Write-Fail "ISO build failed: $($_.Exception.Message)"
    # On failure, clean up any partially produced file to avoid mistakenly mounting it into a VM.
    if ($IsoPath -and (Test-Path -LiteralPath $IsoPath)) {
        Remove-Item -LiteralPath $IsoPath -Force -ErrorAction SilentlyContinue
        Write-Warn2 "Deleted the incomplete output file: $IsoPath"
    }
    throw
}
finally {
    # Release the COM objects to avoid handle leaks.
    foreach ($obj in @($result, $fsi)) {
        if ($obj) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($obj) } catch { $null = $_ }
        }
    }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

# ---------------------------------------------------------------------------
# 4) Validate and wrap up
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $IsoPath)) { throw "Build finished but the output file was not found: $IsoPath" }
$out = Get-Item -LiteralPath $IsoPath
if ($out.Length -le 0) {
    Remove-Item -LiteralPath $IsoPath -Force -ErrorAction SilentlyContinue
    throw "The output ISO is 0 bytes and has been deleted. Check the source directory contents."
}

Write-Ok ("ISO build complete: {0}  ({1} MB)" -f $IsoPath, [math]::Round($out.Length / 1MB, 1))
Write-Host ""
Write-Host "Next step (Phase 2, run in [host] PowerShell after going offline) -- mount it into the air-gapped guest:" -ForegroundColor Cyan
Write-Host ("  Add-VMDvdDrive -VMName CSL-Client01 -Path '{0}'" -f $IsoPath) -ForegroundColor Gray
Write-Host "  # A read-only optical drive letter appears inside the VM; copy the tools to C:\CafeSec\ and install. When done, dismount the optical drive:" -ForegroundColor DarkGray
Write-Host ("  # Get-VMDvdDrive -VMName CSL-Client01 | Where-Object Path -eq '{0}' | Remove-VMDvdDrive" -f $IsoPath) -ForegroundColor DarkGray
Write-Host "Tip: the Linux guest (CSL-Wazuh) can mount this ISO as well; Windows guests may also use Copy-VMFile instead (see docs\downloads.md)." -ForegroundColor Gray
