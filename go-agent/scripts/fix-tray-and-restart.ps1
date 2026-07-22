# Build + restart agent UI.
# Prefer: Run as Administrator in Windows PowerShell (outside Cursor).
$ErrorActionPreference = "Continue"
$repo = "C:\Users\USER\Projects\insigth-window-agent"
$exe = Join-Path $repo "dist\insite-agent.exe"
$goAgent = Join-Path $repo "go-agent"
$cgo = "C:\Program Files\Go\pkg\tool\windows_amd64\cgo.exe"

Write-Host "Stopping old agent..."
Stop-Service "SOSECURE Threat inSight" -Force -ErrorAction SilentlyContinue
Stop-Service "SOSECURE Threat inSight Watchdog" -Force -ErrorAction SilentlyContinue
Get-Process -Name "insite-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
cmd /c "taskkill /F /IM insite-agent.exe >nul 2>&1"
Start-Sleep -Seconds 2

if (Test-Path $cgo) {
    try { Unblock-File -Path $cgo -ErrorAction SilentlyContinue } catch {}
}

Write-Host "Building..."
$env:Path = "C:\Program Files\Go\bin;" + $env:Path
Push-Location $goAgent
go mod tidy
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    throw "go mod tidy failed"
}
go build -ldflags="-s -w -H windowsgui" -o $exe .\cmd\insite-agent
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Write-Host ""
    Write-Host "BUILD FAILED: Application Control blocked cgo.exe" -ForegroundColor Red
    Write-Host "Fix options:" -ForegroundColor Yellow
    Write-Host " 1) Run this script in an elevated PowerShell OUTSIDE Cursor"
    Write-Host " 2) Ask IT to allow: $cgo"
    Write-Host " 3) Or temporarily: Set-ExecutionPolicy / WDAC exclusion for Go tools"
    throw "go build failed"
}
Pop-Location
Write-Host "Built:" (Get-Item $exe).LastWriteTime -ForegroundColor Green

Write-Host "Starting services + UI..."
Start-Service "SOSECURE Threat inSight" -ErrorAction SilentlyContinue
Start-Service "SOSECURE Threat inSight Watchdog" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-Process -FilePath $exe -ArgumentList "-mode","ui" -WorkingDirectory (Split-Path $exe)
Start-Sleep -Seconds 2
Get-Service "SOSECURE Threat inSight*" | Format-Table Name, Status -AutoSize
Get-Process insite-agent -ErrorAction SilentlyContinue | Format-Table Id, ProcessName, StartTime -AutoSize
Write-Host "Done. Test: X hides; left-click tray or Open should show window." -ForegroundColor Green
