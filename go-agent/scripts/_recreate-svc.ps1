$log = "C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_recreate-svc-log.txt"
Remove-Item $log -EA SilentlyContinue
function L($m){ Add-Content $log $m }
$exe = "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe"
Stop-Service "SOSECURE Threat inSight*" -Force -EA SilentlyContinue
Start-Sleep 2
sc.exe stop "SOSECURE Threat inSight" | Out-Null
sc.exe stop "SOSECURE Threat inSight Watchdog" | Out-Null
sc.exe delete "SOSECURE Threat inSight" | ForEach-Object { L $_ }
sc.exe delete "SOSECURE Threat inSight Watchdog" | ForEach-Object { L $_ }
Start-Sleep 3
cmd /c "sc create `"SOSECURE Threat inSight`" binPath= `"\`"$exe\`" -mode service`" start= auto DisplayName= `"SOSECURE Threat inSight Agent`"" | ForEach-Object { L $_ }
cmd /c "sc create `"SOSECURE Threat inSight Watchdog`" binPath= `"\`"$exe\`" -mode watchdog`" start= auto DisplayName= `"SOSECURE Threat inSight Watchdog`"" | ForEach-Object { L $_ }
Start-Sleep 1
Start-Service "SOSECURE Threat inSight"
Start-Sleep 5
L ("main=" + (Get-Service "SOSECURE Threat inSight").Status)
Start-Service "SOSECURE Threat inSight Watchdog"
Start-Sleep 2
L ("wd=" + (Get-Service "SOSECURE Threat inSight Watchdog").Status)
sc.exe query "SOSECURE Threat inSight" | ForEach-Object { L $_ }
Start-Process $exe -ArgumentList "-mode","ui" -WorkingDirectory (Split-Path $exe)
L end
