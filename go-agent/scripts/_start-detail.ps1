$log = "C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_start-detail-log.txt"
Remove-Item $log -EA SilentlyContinue
function L($m){ Add-Content $log $m; Write-Host $m }
try {
  L "starting main..."
  Start-Service "SOSECURE Threat inSight" -ErrorAction Stop
  L "start returned"
} catch { L ("ERR " + $_.Exception.Message) }
Start-Sleep 5
L ("status=" + (Get-Service "SOSECURE Threat inSight").Status)
sc.exe query "SOSECURE Threat inSight" | ForEach-Object { L $_ }
try { Start-Service "SOSECURE Threat inSight Watchdog" -ErrorAction Stop; L "wd ok" } catch { L ("wd ERR " + $_.Exception.Message) }
$exe = "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe"
Start-Process $exe -ArgumentList "-mode","ui" -WorkingDirectory (Split-Path $exe)
L "ui launched"
