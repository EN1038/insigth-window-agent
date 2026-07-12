# Run as Administrator
param(
    [string]$InstallDir = "C:\Program Files\SOSECURE\Threat inSight"
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "insite-agent.exe"
if (-not (Test-Path $exe)) {
    Write-Error "insite-agent.exe not found at $exe"
}

Push-Location $InstallDir
& ".\insite-agent.exe" -mode uninstall
Pop-Location

$desktop = "$env:PUBLIC\Desktop\SOSECURE Threat inSight.lnk"
if (Test-Path $desktop) { Remove-Item $desktop -Force }

Write-Host "Service removed."
