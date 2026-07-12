# SOSECURE Go Agent - verification script (no admin required for IPC tests)
# Run: powershell -ExecutionPolicy Bypass -File go-agent\scripts\verify-agent.ps1
param(
    [string]$ExePath = "",
    [int]$TimeoutSec = 15
)

$ErrorActionPreference = "Continue"
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if ($ExePath -eq "") {
    $ExePath = Join-Path $repoRoot "dist\insite-agent.exe"
    if (-not (Test-Path $ExePath)) {
        $ExePath = Join-Path $repoRoot "go-agent\bin\insite-agent.exe"
    }
}

$results = @()
function Add-Result($name, $ok, $detail) {
    $script:results += [PSCustomObject]@{ Check = $name; OK = $ok; Detail = $detail }
    $mark = if ($ok) { "PASS" } else { "FAIL" }
    Write-Host "[$mark] $name - $detail"
}

Write-Host "=== SOSECURE Go Agent Verification ===" -ForegroundColor Cyan
Write-Host "Exe: $ExePath"
Write-Host ""

# 1. Binary exists
Add-Result "Binary exists" (Test-Path $ExePath) $(if (Test-Path $ExePath) { (Get-Item $ExePath).Length.ToString() + " bytes" } else { "not found" })

# 2. YARA engine
$yara = Join-Path $repoRoot "Engine\Yara\yara64.exe"
$binYara = Join-Path $repoRoot "bin\Debug\Engine\Yara\yara64.exe"
$yaraOk = (Test-Path $yara) -or (Test-Path $binYara)
Add-Result "yara64.exe present" $yaraOk $(if ($yaraOk) { "found" } else { "MISSING - copy to Engine\Yara before installer" })

# 3. Inno Setup compiler
$iscc = Get-Command ISCC -ErrorAction SilentlyContinue
Add-Result "Inno Setup (ISCC)" ($null -ne $iscc) $(if ($iscc) { $iscc.Source } else { "not installed - compile setup_go.iss manually" })

# 4. Admin check for install
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Result "Running as Administrator" $isAdmin $(if ($isAdmin) { "install/upgrade can run" } else { "elevate for -mode install" })

# 5. Legacy services
$legacy = @(
    "SOSECURE Threat inSights Service",
    "SOSECURE Threat inSights Agent Service",
    "SOSECURE_INSINTS_AGENT",
    "SOSECURE_WATCHDOG_AGENT"
)
$foundLegacy = @()
foreach ($n in $legacy) {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if ($s) { $foundLegacy += "$n ($($s.Status))" }
}
# Legacy still registered is OK before upgrade; only warn
$legacyOk = $true
$legacyDetail = if ($foundLegacy.Count -eq 0) { "none" } else { "present (run -mode upgrade): " + ($foundLegacy -join "; ") }
Add-Result "Legacy services" $legacyOk $legacyDetail

# 6. Go service (optional until install)
$goSvc = Get-Service -Name "SOSECURE Threat inSight" -ErrorAction SilentlyContinue
Add-Result "Go service registered" ($null -ne $goSvc) $(if ($goSvc) { $goSvc.Status } else { "not yet - run -mode install as Admin" })

# Stop stray agents
Get-Process insite-agent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 7. Start embedded host via console (spawns IPC)
$proc = $null
if (Test-Path $ExePath) {
    $proc = Start-Process -FilePath $ExePath -ArgumentList "-mode","ui" -PassThru -WindowStyle Minimized
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $healthOk = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $h = Invoke-RestMethod -Uri "http://127.0.0.1:19877/v1/health" -TimeoutSec 2
            if ($h.ok) { $healthOk = $true; break }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    Add-Result "IPC /v1/health" $healthOk $(if ($healthOk) { "ok" } else { "timeout - is port 19877 blocked?" })

    if ($healthOk) {
        try {
            $st = Invoke-RestMethod -Uri "http://127.0.0.1:19877/v1/status" -TimeoutSec 5
            Add-Result "IPC /v1/status" $true "has_config=$($st.has_config) approved=$($st.approved)"
        } catch {
            Add-Result "IPC /v1/status" $false $_.Exception.Message
        }

        try {
            $cfg = Invoke-RestMethod -Uri "http://127.0.0.1:19877/v1/config" -TimeoutSec 5
            $ok = ($cfg.site_ip -ne "") -and ($cfg.site_id -ne "")
            Add-Result "IPC GET /v1/config" $ok "site_ip=$($cfg.site_ip)"
        } catch {
            Add-Result "IPC GET /v1/config" $false $_.Exception.Message
        }

        try {
            $st2 = Invoke-RestMethod -Uri "http://127.0.0.1:19877/v1/status" -TimeoutSec 5
            Add-Result "Config persisted" $st2.has_config "has_config=$($st2.has_config)"
        } catch {
            Add-Result "Config persisted" $false $_.Exception.Message
        }

        try {
            $hist = Invoke-RestMethod -Uri "http://127.0.0.1:19877/v1/history?limit=5" -TimeoutSec 5
            Add-Result "IPC /v1/history" ($hist -is [array]) "entries=$($hist.Count)"
        } catch {
            Add-Result "IPC /v1/history" $false $_.Exception.Message
        }
    }

    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    Get-Process insite-agent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# 8. Install dry-run (only if admin)
if ($isAdmin -and (Test-Path $ExePath)) {
    Push-Location (Split-Path $ExePath -Parent)
    $out = & ".\insite-agent.exe" -mode install 2>&1
    $installOk = $LASTEXITCODE -eq 0
    Add-Result "Service install (-mode install)" $installOk $(if ($installOk) { "SOSECURE Threat inSight" } else { "$out" })
    $svc = Get-Service -Name "SOSECURE Threat inSight" -ErrorAction SilentlyContinue
    if ($svc) {
        Add-Result "Service running" ($svc.Status -eq "Running") $svc.Status
    }
    Pop-Location
}

Write-Host ""
$fail = @($results | Where-Object { -not $_.OK })
$coreNames = @("Binary exists", "yara64.exe present", "IPC /v1/health", "IPC /v1/status", "IPC GET /v1/config", "Config persisted", "IPC /v1/history")
$coreFail = @($fail | Where-Object { $coreNames -contains $_.Check })
$optionalFail = @($fail | Where-Object { $coreNames -notcontains $_.Check })

Write-Host "=== Summary: $($results.Count - $fail.Count)/$($results.Count) passed ===" -ForegroundColor $(if ($coreFail.Count -eq 0) { "Green" } else { "Red" })
if ($optionalFail.Count -gt 0) {
    Write-Host "Optional / manual steps:" -ForegroundColor Yellow
    $optionalFail | Format-Table -AutoSize
}
if ($coreFail.Count -gt 0) {
    Write-Host "CORE failures:" -ForegroundColor Red
    $coreFail | Format-Table -AutoSize
    exit 1
}
exit 0
