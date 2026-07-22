# Requires Administrator: force-restart SOSECURE agent services + UI (tray Open/Exit fix).
$ErrorActionPreference = "Stop"
$exe = "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe"

Write-Host "Stopping services and killing processes..."
Stop-Service "SOSECURE Threat inSight" -Force -ErrorAction SilentlyContinue
Stop-Service "SOSECURE Threat inSight Watchdog" -Force -ErrorAction SilentlyContinue
taskkill /F /IM insite-agent.exe 2>$null | Out-Null
Start-Sleep -Seconds 2

if (-not (Test-Path $exe)) {
    throw "Missing $exe — build the agent first."
}

Write-Host "Starting services..."
Start-Service "SOSECURE Threat inSight"
Start-Service "SOSECURE Threat inSight Watchdog"
Start-Sleep -Seconds 1

Write-Host "Starting UI..."
Start-Process -FilePath $exe -ArgumentList "-mode","ui" -WorkingDirectory (Split-Path $exe)

Start-Sleep -Seconds 2
Get-Service "SOSECURE Threat inSight*" | Format-Table Name, Status -AutoSize
Get-Process insite-agent -ErrorAction SilentlyContinue | Format-Table Id, ProcessName -AutoSize
Write-Host "Done. Test tray Open / Exit."
