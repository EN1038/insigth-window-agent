$log = "C:\Users\USER\Projects\insigth-window-agent\go-agent\scripts\_restore-log.txt"
function L($m){ Add-Content -Path $log -Value ("[{0}] {1}" -f (Get-Date -Format o), $m) }
Remove-Item $log -ErrorAction SilentlyContinue
L "begin"
$target = "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe"
$bak = "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.ci.bak.exe"
try {
  if (-not (Test-Path $bak)) {
    Copy-Item $target $bak -Force
    L "saved CI copy to bak"
  }
} catch { L "bak err: $_" }

# List VSS
$shadows = vssadmin list shadows 2>&1 | Out-String
L $shadows

# Try Previous Versions via WMI shadow copy
$vols = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
L ("shadow count=" + @($vols).Count)
foreach ($v in @($vols)) {
  L ("shadow DeviceObject=" + $v.DeviceObject + " InstallDate=" + $v.InstallDate)
  $src = Join-Path $v.DeviceObject "Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe"
  # DeviceObject like \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
  $src2 = $v.DeviceObject.TrimEnd('\') + "\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe"
  if (Test-Path $src2) {
    $len = (Get-Item $src2).Length
    L ("FOUND shadow copy size=$len path=$src2")
    if ($len -eq 30578688 -or $len -lt 31730176) {
      Copy-Item -LiteralPath $src2 -Destination "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.restored.exe" -Force
      L "copied restored"
    }
  } else {
    L "not in this shadow: $src2"
  }
}

# Also try starting services with current file after adding path exception is impossible; report status
Get-Service "SOSECURE Threat inSight*" | ForEach-Object { L ("svc $($_.Name)=$($_.Status)") }
L "end"
