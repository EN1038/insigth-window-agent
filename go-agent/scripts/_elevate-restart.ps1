$ErrorActionPreference = 'Continue'
$log = 'C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_restart-log.txt'
function L($m){ Add-Content -Path $log -Value ("[{0}] {1}" -f (Get-Date -Format o), $m) }
Remove-Item $log -ErrorAction SilentlyContinue
L 'begin'
$exe = 'C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe'
L ("exe exists=" + (Test-Path $exe) + " size=" + (Get-Item $exe).Length)
try {
  Stop-Service 'SOSECURE Threat inSight' -Force -ErrorAction SilentlyContinue
  Stop-Service 'SOSECURE Threat inSight Watchdog' -Force -ErrorAction SilentlyContinue
  Get-Process -Name 'insite-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep 2
  L 'stopped'
  Start-Service 'SOSECURE Threat inSight'
  L 'main started'
  Start-Service 'SOSECURE Threat inSight Watchdog' -ErrorAction SilentlyContinue
  L 'watchdog attempted'
  Start-Sleep 2
  Start-Process -FilePath $exe -ArgumentList '-mode','ui' -WorkingDirectory (Split-Path $exe)
  L 'ui launched'
} catch {
  L ("ERROR: " + $_.Exception.Message)
  L ($_.ScriptStackTrace)
}
Get-Service 'SOSECURE Threat inSight*' | ForEach-Object { L ("svc " + $_.Name + "=" + $_.Status) }
Get-Process insite-agent -ErrorAction SilentlyContinue | ForEach-Object { L ("proc id=" + $_.Id) }
L 'end'
