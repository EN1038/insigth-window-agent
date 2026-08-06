$log = "C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_reinstall-svc-log.txt"
Remove-Item $log -EA SilentlyContinue
function L($m){ Add-Content $log $m }
$exe = "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe"
L ("exe=" + (Test-Path $exe) + " size=" + (Get-Item $exe).Length)
Set-Location (Split-Path $exe)
& $exe -mode uninstall 2>&1 | ForEach-Object { L "$_" }
Start-Sleep 2
& $exe -mode install 2>&1 | ForEach-Object { L "$_" }
Start-Sleep 2
Start-Service "SOSECURE Threat inSight" -ErrorAction SilentlyContinue
Start-Sleep 4
L ("main=" + (Get-Service "SOSECURE Threat inSight" -EA SilentlyContinue | Select-Object -ExpandProperty Status))
Start-Service "SOSECURE Threat inSight Watchdog" -ErrorAction SilentlyContinue
Start-Sleep 2
L ("wd=" + (Get-Service "SOSECURE Threat inSight Watchdog" -EA SilentlyContinue | Select-Object -ExpandProperty Status))
sc.exe query "SOSECURE Threat inSight" | ForEach-Object { L $_ }
Start-Process $exe -ArgumentList "-mode","ui" -WorkingDirectory (Split-Path $exe)
L end
