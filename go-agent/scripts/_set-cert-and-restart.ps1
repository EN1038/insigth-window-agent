$ErrorActionPreference = 'Continue'
$log = 'C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_cert-config-log.txt'
Remove-Item $log -ErrorAction SilentlyContinue
function L($m){ Add-Content $log $m; Write-Host $m }
Set-Location 'C:\Users\USER\Projects\insigth-window-agent\go-agent'
$env:CGO_ENABLED = '0'
$env:Path = 'C:\Program Files\Go\bin;' + $env:Path
L '--- setcert ---'
L ('file_exists=' + (Test-Path '_tmp_setcert.go'))
& go run ./_tmp_setcert.go 'P@ssw0rd@Sosecure' 2>&1 | ForEach-Object { L ($_ | Out-String).TrimEnd() }
L ('go_exit=' + $LASTEXITCODE)
L ('config_mtime=' + (Get-Item 'C:\ProgramData\SOSECURE Threat inSight\Config\Key\config.enc').LastWriteTime)
L ('config_len=' + (Get-Item 'C:\ProgramData\SOSECURE Threat inSight\Config\Key\config.enc').Length)

L '--- restart ---'
# Stop watchdog first so it does not race
Stop-Service 'SOSECURE Threat inSight Watchdog' -Force -ErrorAction SilentlyContinue
Stop-Service 'SOSECURE Threat inSight' -Force -ErrorAction SilentlyContinue
cmd /c 'taskkill /F /IM insite-agent.exe >nul 2>&1'
Start-Sleep 4
$r = Start-Service 'SOSECURE Threat inSight' -PassThru -ErrorAction SilentlyContinue
L ('after_start status=' + (Get-Service 'SOSECURE Threat inSight').Status)
Start-Sleep 3
L ('after_3s status=' + (Get-Service 'SOSECURE Threat inSight').Status)
Get-Process insite-agent -ErrorAction SilentlyContinue | ForEach-Object { L ('proc ' + $_.Id) }
Start-Service 'SOSECURE Threat inSight Watchdog' -ErrorAction SilentlyContinue
Start-Sleep 2
$exe = 'C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe'
Start-Process -FilePath $exe -ArgumentList '-mode','ui' -WorkingDirectory (Split-Path $exe)
Get-Service 'SOSECURE Threat inSight*' | ForEach-Object { L ('svc ' + $_.Name + '=' + $_.Status) }
L 'end'
