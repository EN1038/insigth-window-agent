sc.exe start "SOSECURE Threat inSight" | Out-String | Write-Host
Start-Sleep 4
sc.exe query "SOSECURE Threat inSight" | Out-String | Write-Host
sc.exe start "SOSECURE Threat inSight Watchdog" | Out-String | Write-Host
Start-Sleep 2
Get-Service "SOSECURE Threat inSight*" | Format-Table Name, Status -AutoSize
Get-Process insite-agent -EA SilentlyContinue | Format-Table Id -AutoSize
