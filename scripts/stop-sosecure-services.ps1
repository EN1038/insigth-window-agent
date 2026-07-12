# Run as Administrator
$names = @(
    'SOSECURE Threat inSights Agent Service',
    'SOSECURE Threat inSights Service'
)

foreach ($name in $names) {
    Write-Host "Stopping $name ..."
    sc.exe control $name 128 | Out-Host
    Start-Sleep -Seconds 2
    sc.exe stop $name | Out-Host
    Start-Sleep -Seconds 3
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($s) { Write-Host "  Status: $($s.Status)" }
}

taskkill /F /IM sosecure-engine.exe 2>&1 | Out-Host
taskkill /F /IM insight.sosecure.legacy.exe 2>&1 | Out-Host
Start-Sleep -Seconds 2

Get-Service "SOSECURE Threat inSights Service","SOSECURE Threat inSights Agent Service" | Format-Table Name, Status -AutoSize
Get-Process | Where-Object { $_.ProcessName -like '*insight*' -or $_.ProcessName -like '*sosecure*' } | Format-Table Id, ProcessName -AutoSize
