$ErrorActionPreference = 'Stop'
$log = 'C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_cert-install-log.txt'
function L($m){ Add-Content -Path $log -Value ('[{0}] {1}' -f (Get-Date -Format o), $m) }
Remove-Item $log -ErrorAction SilentlyContinue
L 'begin'
$src = 'C:\Users\USER\Downloads\client-new.p12'
$destDir = 'C:\ProgramData\SOSECURE Threat inSight\Config\Key'
$dest = 'C:\ProgramData\SOSECURE Threat inSight\Config\Key\client.p12'
New-Item -ItemType Directory -Force -Path $destDir | Out-Null
Copy-Item -Force $src $dest
L ('copied size=' + (Get-Item $dest).Length + ' path=' + $dest)
[Environment]::SetEnvironmentVariable('INSITE_CLIENT_CERT_PATH', $dest, 'Machine')
[Environment]::SetEnvironmentVariable('INSITE_CLIENT_CERT_PASS', 'P@ssw0rd@Sosecure', 'Machine')
L 'machine env set'
Stop-Service 'SOSECURE Threat inSight' -Force -ErrorAction SilentlyContinue
Stop-Service 'SOSECURE Threat inSight Watchdog' -Force -ErrorAction SilentlyContinue
Get-Process -Name 'insite-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 3
Start-Service 'SOSECURE Threat inSight'
Start-Service 'SOSECURE Threat inSight Watchdog' -ErrorAction SilentlyContinue
Start-Sleep 2
$exe = 'C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe'
Start-Process -FilePath $exe -ArgumentList '-mode','ui' -WorkingDirectory (Split-Path $exe)
Get-Service 'SOSECURE Threat inSight*' | ForEach-Object { L ('svc ' + $_.Name + '=' + $_.Status) }
L ('env path set=' + [bool][Environment]::GetEnvironmentVariable('INSITE_CLIENT_CERT_PATH','Machine'))
L ('env pass set=' + (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable('INSITE_CLIENT_CERT_PASS','Machine'))))
L 'end'
