$ErrorActionPreference = "Continue"
$log = "C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_deploy-latest-log.txt"
function L($m){ $line = "$(Get-Date -Format o) $m"; Add-Content $log $line; Write-Host $line }
Remove-Item $log -Force -ErrorAction SilentlyContinue
L "start"

$src = "C:\Users\USER\Projects\insigth-window-agent\go-agent\dist\insite-agent.exe"
$dir = "C:\Program Files\SOSECURE\Threat inSight"
$exe = Join-Path $dir "insite-agent.exe"
if (-not (Test-Path $src)) { L "MISSING $src"; exit 1 }

L "stop processes/services"
Get-Process | Where-Object { $_.ProcessName -match 'insite' } | Stop-Process -Force -ErrorAction SilentlyContinue
Stop-Service "SOSECURE Threat inSight" -Force -ErrorAction SilentlyContinue
Stop-Service "SOSECURE Threat inSight Watchdog" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
taskkill /F /IM insite-agent.exe 2>$null | Out-Null
taskkill /F /IM insite-agent-ui.exe 2>$null | Out-Null
Start-Sleep -Seconds 1

New-Item -ItemType Directory -Force -Path $dir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $dir "Engine\Yara") | Out-Null
Copy-Item $src $exe -Force
L ("copied exe bytes=" + (Get-Item $exe).Length + " time=" + (Get-Item $exe).LastWriteTime)

$yaraSrc = @(
  "C:\ProgramData\SOSECURE Threat inSight\Engine\Yara\yara64.exe",
  "C:\Users\USER\Projects\insigth-window-agent\go-agent\Engine\Yara\yara64.exe",
  "C:\Users\USER\Projects\insigth-window-agent\go-agent\dist\Engine\Yara\yara64.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($yaraSrc) {
  Copy-Item $yaraSrc (Join-Path $dir "Engine\Yara\yara64.exe") -Force -ErrorAction SilentlyContinue
  L "yara from $yaraSrc"
}

# Mesa DLLs if present beside old ui
foreach ($dll in @("opengl32.dll","libgallium_wgl.dll")) {
  $d = "C:\Users\USER\Projects\insigth-window-agent\go-agent\bin\test-agent\$dll"
  if (Test-Path $d) { Copy-Item $d (Join-Path $dir $dll) -Force -ErrorAction SilentlyContinue }
}

# Ensure services point at PF exe if they exist
cmd /c "sc query `"SOSECURE Threat inSight`"" | Out-Null
if ($LASTEXITCODE -eq 0) {
  cmd /c "sc config `"SOSECURE Threat inSight`" binPath= `"\`"$exe\`" -mode service`"" | ForEach-Object { L $_ }
  cmd /c "sc config `"SOSECURE Threat inSight Watchdog`" binPath= `"\`"$exe\`" -mode watchdog`"" | ForEach-Object { L $_ }
  try { Start-Service "SOSECURE Threat inSight" -ErrorAction Stop; L "service started" } catch { L ("service: " + $_.Exception.Message) }
  Start-Sleep 2
  try { Start-Service "SOSECURE Threat inSight Watchdog" -ErrorAction Stop; L "watchdog started" } catch { L ("watchdog: " + $_.Exception.Message) }
} else {
  L "services not installed; launching UI-only"
}

L "launch UI"
try {
  $p = Start-Process -FilePath $exe -ArgumentList "-mode","ui" -WorkingDirectory $dir -PassThru -ErrorAction Stop
  Start-Sleep -Seconds 3
  L ("ui pid=" + $p.Id + " exited=" + $p.HasExited)
} catch {
  L ("UI START FAILED: " + $_.Exception.Message)
}

Get-Process | Where-Object { $_.ProcessName -match 'insite' } | ForEach-Object { L ("proc " + $_.Id + " " + $_.ProcessName + " " + $_.Path) }
L "end"
