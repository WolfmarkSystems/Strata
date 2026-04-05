$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$containersDir = Join-Path $root "containers"
New-Item -ItemType Directory -Force -Path $containersDir | Out-Null

$rawPath = Join-Path $containersDir "test_ntfs.dd"
$vhdPath = Join-Path $containersDir "test.vhd"
$vmdkPath = Join-Path $containersDir "test.vmdk"

Write-Host "Creating RAW fixture: $rawPath"
if (-not (Test-Path $rawPath)) {
    # Create a sparse 10 MB RAW placeholder image.
    $fs = [System.IO.File]::Open($rawPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    try {
        $fs.SetLength(10MB)
    } finally {
        $fs.Dispose()
    }
}

Write-Host "Creating VHD fixture (if Hyper-V module is available): $vhdPath"
$newVhdCmd = Get-Command -Name New-VHD -ErrorAction SilentlyContinue
if ($null -ne $newVhdCmd) {
    if (-not (Test-Path $vhdPath)) {
        New-VHD -Path $vhdPath -SizeBytes 16MB -Fixed | Out-Null
    }
} else {
    # Fallback placeholder to keep fixture pipeline deterministic on non-Hyper-V hosts.
    if (-not (Test-Path $vhdPath)) {
        Set-Content -Path $vhdPath -Value "VHD fixture placeholder (Hyper-V cmdlets unavailable)." -NoNewline
    }
}

Write-Host "Creating VMDK descriptor fixture: $vmdkPath"
$descriptor = @'
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicFlat"

# Extent description
RW 32768 FLAT "test-flat.vmdk" 0

# The Disk Data Base
#DDB
ddb.adapterType = "lsilogic"
ddb.geometry.cylinders = "2"
ddb.geometry.heads = "16"
ddb.geometry.sectors = "63"
'@
Set-Content -Path $vmdkPath -Value $descriptor -NoNewline

Write-Host "Fixture generation complete."
