$ErrorActionPreference = 'Continue'
$log = 'C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_restart-log.txt'
function L($m){ Add-Content -Path $log -Value ("[{0}] {1}" -f (Get-Date -Format o), $m) }
Remove-Item $log -ErrorAction SilentlyContinue
L 'begin install ti-sync schedule build'
$src = 'C:\Users\USER\Projects\insigth-window-agent\dist\ci-build-30428447878\insite-agent-windows\insite-agent.exe'
$dst = 'C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe'
$pfDir = 'C:\Program Files\SOSECURE\Threat inSight'
$pf = Join-Path $pfDir 'insite-agent.exe'
if (-not (Test-Path $src)) {
  L ("ERROR missing src: " + $src)
  exit 1
}
L ("src size=" + (Get-Item $src).Length)
try {
  Stop-Service 'SOSECURE Threat inSight' -Force -ErrorAction SilentlyContinue
  Stop-Service 'SOSECURE Threat inSight Watchdog' -Force -ErrorAction SilentlyContinue
  Get-Process -Name 'insite-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep 3
  L 'stopped'
  Copy-Item $src $dst -Force
  L ("dist copied size=" + (Get-Item $dst).Length)
  New-Item -ItemType Directory -Force -Path $pfDir | Out-Null
  Copy-Item $src $pf -Force
  L ("PF copied size=" + (Get-Item $pf).Length)
  Start-Service 'SOSECURE Threat inSight'
  L 'main started'
  Start-Service 'SOSECURE Threat inSight Watchdog' -ErrorAction SilentlyContinue
  L 'watchdog attempted'
  Start-Sleep 2
  Start-Process -FilePath $pf -ArgumentList '-mode','ui' -WorkingDirectory $pfDir
  L 'ui launched'
} catch {
  L ("ERROR: " + $_.Exception.Message)
  L ($_.ScriptStackTrace)
}
Get-Service 'SOSECURE Threat inSight*' | ForEach-Object { L ("svc " + $_.Name + "=" + $_.Status) }
Get-Process insite-agent -ErrorAction SilentlyContinue | ForEach-Object { L ("proc id=" + $_.Id) }
L ("final dist size=" + (Get-Item $dst -ErrorAction SilentlyContinue).Length)
L ("final PF size=" + (Get-Item $pf -ErrorAction SilentlyContinue).Length)
L 'end'
