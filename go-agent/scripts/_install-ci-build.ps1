$ErrorActionPreference = "Continue"
$log = "C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_restart-log.txt"
function L($m){ Add-Content $log $m }
Remove-Item $log -EA SilentlyContinue
$dist = "C:\Users\USER\Projects\insigth-window-agent\dist"
$exe = Join-Path $dist "insite-agent.exe"
$src = "C:\Users\USER\Projects\insigth-window-agent\dist\ci-build-30425645239\insite-agent.exe"
Stop-Service "SOSECURE Threat inSight Watchdog" -Force -EA SilentlyContinue
Stop-Service "SOSECURE Threat inSight" -Force -EA SilentlyContinue
Get-Process insite-agent -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 3
Copy-Item $src $exe -Force
L ("installed=" + (Get-Item $exe).Length)
Start-Service "SOSECURE Threat inSight"
Start-Sleep 4
Start-Service "SOSECURE Threat inSight Watchdog" -EA SilentlyContinue
Start-Sleep 2
Start-Process $exe -ArgumentList "-mode","ui" -WorkingDirectory $dist
Get-Service "SOSECURE Threat inSight*" | ForEach-Object { L ("svc $($_.Name)=$($_.Status)") }
L end
