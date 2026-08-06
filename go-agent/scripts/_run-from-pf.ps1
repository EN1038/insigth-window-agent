$log = "C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_run-from-pf-log.txt"
Remove-Item $log -EA SilentlyContinue
function L($m){ Add-Content $log $m }
$dir = "C:\Program Files\SOSECURE\Threat inSight"
$exe = Join-Path $dir "insite-agent.exe"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe" $exe -Force
L ("copied=" + (Get-Item $exe).Length)
cmd /c "sc config `"SOSECURE Threat inSight`" binPath= `"\`"$exe\`" -mode service`"" | ForEach-Object { L $_ }
cmd /c "sc config `"SOSECURE Threat inSight Watchdog`" binPath= `"\`"$exe\`" -mode watchdog`"" | ForEach-Object { L $_ }
sc.exe qc "SOSECURE Threat inSight" | ForEach-Object { L $_ }
try { Start-Service "SOSECURE Threat inSight" -ErrorAction Stop; L "main started" } catch { L ("main err: " + $_.Exception.Message) }
Start-Sleep 5
L ("main=" + (Get-Service "SOSECURE Threat inSight").Status)
sc.exe query "SOSECURE Threat inSight" | ForEach-Object { L $_ }
try { Start-Service "SOSECURE Threat inSight Watchdog" -ErrorAction Stop; L "wd started" } catch { L ("wd err: " + $_.Exception.Message) }
Start-Sleep 2
L ("wd=" + (Get-Service "SOSECURE Threat inSight Watchdog").Status)
Start-Process $exe -ArgumentList "-mode","ui" -WorkingDirectory $dir
L end
