$ErrorActionPreference = "Continue"
Stop-Service "SOSECURE Threat inSight Watchdog" -Force -EA SilentlyContinue
Stop-Service "SOSECURE Threat inSight" -Force -EA SilentlyContinue
Start-Sleep 2
Start-Service "SOSECURE Threat inSight"
Start-Sleep 3
Write-Host "main=$(Get-Service 'SOSECURE Threat inSight' | Select-Object -ExpandProperty Status)"
Start-Service "SOSECURE Threat inSight Watchdog"
Start-Sleep 2
Write-Host "wd=$(Get-Service 'SOSECURE Threat inSight Watchdog' | Select-Object -ExpandProperty Status)"
$exe = "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe"
Start-Process $exe -ArgumentList "-mode","ui" -WorkingDirectory (Split-Path $exe)
Get-Service "SOSECURE Threat inSight*" | Format-Table Name, Status -AutoSize
