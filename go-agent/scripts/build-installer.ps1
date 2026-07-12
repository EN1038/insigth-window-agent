# Build release artifacts for Inno Setup (setup_go.iss)
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$dist = Join-Path $repoRoot "dist"
$yaraSrc = Join-Path $repoRoot "bin\Debug\Engine\Yara"
if (-not (Test-Path (Join-Path $yaraSrc "yara64.exe"))) {
    $yaraSrc = Join-Path $repoRoot "Engine\Yara"
}

Write-Host "Building insite-agent.exe..."
Push-Location (Join-Path $repoRoot "go-agent")
go build -ldflags="-s -w" -o (Join-Path $dist "insite-agent.exe") .\cmd\insite-agent
Pop-Location

Write-Host "Copying YARA engine..."
$yaraDst = Join-Path $dist "Engine\Yara"
New-Item -ItemType Directory -Force -Path $yaraDst | Out-Null
if (Test-Path (Join-Path $yaraSrc "yara64.exe")) {
    Copy-Item (Join-Path $yaraSrc "yara64.exe") $yaraDst -Force
} else {
    Write-Warning "yara64.exe not found under $yaraSrc"
}

Write-Host "Done. Output: $dist"
Get-ChildItem $dist -Recurse | Select-Object FullName, Length

$iscc = Get-Command ISCC -ErrorAction SilentlyContinue
if ($iscc) {
    Write-Host "Compiling setup_go.iss..."
    & $iscc.Source (Join-Path $repoRoot "setup_go.iss")
} else {
    Write-Host "ISCC not found. Install Inno Setup 6, then run: ISCC setup_go.iss"
}
