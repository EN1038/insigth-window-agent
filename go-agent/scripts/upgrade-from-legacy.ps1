# Run as Administrator — upgrades from legacy .NET agent to Go agent in-place
param(
    [string]$InstallDir = "C:\Program Files\SOSECURE\Threat inSight"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$stopScript = Join-Path $repoRoot "scripts\stop-sosecure-services.ps1"
if (Test-Path $stopScript) {
    Write-Host "Stopping legacy services..."
    & $stopScript
}

# Copy binary + YARA engine (same as fresh install)
& (Join-Path $PSScriptRoot "install-agent.ps1") -InstallDir $InstallDir -SkipServiceInstall

$exe = Join-Path $InstallDir "insite-agent.exe"
Push-Location $InstallDir
& ".\insite-agent.exe" -mode upgrade
Pop-Location

Write-Host "Upgrade complete. Legacy .NET services removed; Go service active."
