# Run as Administrator
param(
    [string]$InstallDir = "C:\Program Files\SOSECURE\Threat inSight",
    [switch]$SkipServiceInstall
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$srcExe = Join-Path $root "bin\insite-agent.exe"
if (-not (Test-Path $srcExe)) {
    $srcExe = Join-Path (Split-Path $root -Parent) "dist\insite-agent.exe"
}
if (-not (Test-Path $srcExe)) {
    Write-Error "insite-agent.exe not found. Build with: go build -o bin\insite-agent.exe ./cmd/insite-agent"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $srcExe (Join-Path $InstallDir "insite-agent.exe") -Force

$yaraSrc = Join-Path (Split-Path $root -Parent) "Engine\Yara"
$yaraDst = Join-Path $InstallDir "Engine\Yara"
if (Test-Path $yaraSrc) {
    New-Item -ItemType Directory -Force -Path $yaraDst | Out-Null
    Copy-Item (Join-Path $yaraSrc "yara64.exe") $yaraDst -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $yaraSrc "*.yar") $yaraDst -Force -ErrorAction SilentlyContinue
}

# Migrate existing config if upgrading in-place
$legacyConfig = Join-Path $InstallDir "Config\Key\config.json"
if (Test-Path $legacyConfig) {
    Write-Host "Legacy config found — will migrate on first service start."
}

Push-Location $InstallDir
if (-not $SkipServiceInstall) {
    & ".\insite-agent.exe" -mode install
}
Pop-Location

$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("$env:PUBLIC\Desktop\SOSECURE Threat inSight.lnk")
$lnk.TargetPath = Join-Path $InstallDir "insite-agent.exe"
$lnk.Arguments = "-mode ui"
$lnk.WorkingDirectory = $InstallDir
$lnk.Save()

Write-Host "Installed to $InstallDir"
Write-Host "Service: SOSECURE Threat inSight"
