$ErrorActionPreference = "Continue"
$log = "C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_cert-env-log.txt"
function L($m){ Add-Content $log $m }
Remove-Item $log -EA SilentlyContinue

# Service-specific environment (picked up on next service start without reboot)
$svcName = "SOSECURE Threat inSight"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
$certPath = "C:\ProgramData\SOSECURE Threat inSight\Config\Key\client.p12"
$pass = "P@ssw0rd@Sosecure"
$envLines = @(
  "INSITE_CLIENT_CERT_PATH=$certPath",
  "INSITE_CLIENT_CERT_PASS=$pass"
)
New-ItemProperty -Path $regPath -Name Environment -PropertyType MultiString -Value $envLines -Force | Out-Null
L "service Environment set"

# Also clear authorized stop flag via settings if we can - use a minimal approach:
# write through existing agent -mode if any; else leave for watchdog

Stop-Service "SOSECURE Threat inSight Watchdog" -Force -EA SilentlyContinue
Stop-Service "SOSECURE Threat inSight" -Force -EA SilentlyContinue
Start-Sleep 2
# Mark stop unauthorized (false) by ensuring service can run - delete authorized flag from settings is hard without tool
Start-Service "SOSECURE Threat inSight"
Start-Sleep 4
L ("main=" + (Get-Service "SOSECURE Threat inSight").Status)
Start-Service "SOSECURE Threat inSight Watchdog" -EA SilentlyContinue
Start-Sleep 2
L ("wd=" + (Get-Service "SOSECURE Threat inSight Watchdog").Status)
L ("main2=" + (Get-Service "SOSECURE Threat inSight").Status)
Get-Process insite-agent -EA SilentlyContinue | ForEach-Object { L ("proc " + $_.Id) }
$exe = "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe"
Start-Process $exe -ArgumentList "-mode","ui" -WorkingDirectory (Split-Path $exe)
L "end"
