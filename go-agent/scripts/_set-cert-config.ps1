Set-Location 'C:\Users\USER\Projects\insigth-window-agent\go-agent'
$env:CGO_ENABLED = '0'
& 'C:\Program Files\Go\bin\go.exe' run _tmp_setcert.go 'P@ssw0rd@Sosecure'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Stop-Service 'SOSECURE Threat inSight' -Force -ErrorAction SilentlyContinue
Stop-Service 'SOSECURE Threat inSight Watchdog' -Force -ErrorAction SilentlyContinue
Get-Process -Name 'insite-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
Start-Service 'SOSECURE Threat inSight'
Start-Service 'SOSECURE Threat inSight Watchdog' -ErrorAction SilentlyContinue
Start-Sleep 2
$exe = 'C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe'
Start-Process -FilePath $exe -ArgumentList '-mode','ui' -WorkingDirectory (Split-Path $exe)
Write-Host 'restarted'
Get-Service 'SOSECURE Threat inSight*' | Format-Table Name, Status -AutoSize
