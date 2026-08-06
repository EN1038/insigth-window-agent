# Watch SOSECURE agent API flow via local IPC history.
# Run OUTSIDE Cursor in an elevated PowerShell if WDAC blocks the exe.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\go-agent\scripts\watch-api-flow.ps1
#   powershell -ExecutionPolicy Bypass -File .\go-agent\scripts\watch-api-flow.ps1 -StartUI

param(
    [switch]$StartUI,
    [string]$Exe = "C:\Users\USER\Projects\insigth-window-agent\dist\insite-agent.exe",
    [int]$PollSeconds = 2,
    [int]$HistoryLimit = 40
)

$ErrorActionPreference = "Continue"
$ipc = "http://127.0.0.1:19877"

function Get-Ipc([string]$Path) {
    try {
        return Invoke-RestMethod -Uri ($ipc + $Path) -TimeoutSec 5
    } catch {
        return $null
    }
}

Write-Host "=== SOSECURE API flow watcher ===" -ForegroundColor Cyan
Write-Host "IPC: $ipc"
Write-Host ""

if ($StartUI) {
    if (-not (Test-Path $Exe)) {
        Write-Host "EXE not found: $Exe" -ForegroundColor Red
        exit 1
    }
    Write-Host "Starting UI: $Exe -mode ui"
    try {
        Start-Process -FilePath $Exe -ArgumentList "-mode", "ui" -WorkingDirectory (Split-Path $Exe)
    } catch {
        Write-Host "Start failed (WDAC?): $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Open Explorer and double-click the exe, or: Start-Service 'SOSECURE Threat inSight'"
    }
    Start-Sleep -Seconds 3
}

# Wait for IPC
Write-Host "Waiting for IPC..."
for ($i = 0; $i -lt 30; $i++) {
    $h = Get-Ipc "/v1/health"
    if ($h) {
        Write-Host "IPC UP: $($h | ConvertTo-Json -Compress)" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 1
}
if (-not (Get-Ipc "/v1/health")) {
    Write-Host "IPC still down. Start the agent first, then re-run this script." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Expected server API order after config is saved:" -ForegroundColor Yellow
Write-Host "  1) dataInfo"
Write-Host "  2) checkedAgentApproved  (retry ~10s until admin approves)"
Write-Host "  3) getConfig / getRule / ssdeep sync (after approved)"
Write-Host "  4) agentOnlineTimestamp   (heartbeat)"
Write-Host "  5) loginAgent             (when you log in on UI)"
Write-Host "  6) sendLog* / scan APIs   (when scanning)"
Write-Host ""
Write-Host "Watching /v1/history (Ctrl+C to stop)..." -ForegroundColor Cyan
Write-Host ""

$seen = New-Object 'System.Collections.Generic.HashSet[string]'
while ($true) {
    $st = Get-Ipc "/v1/status"
    if ($st) {
        $line = "STATUS hasConfig=$($st.has_config) approved=$($st.approved) loggedIn=$($st.logged_in)"
        if (-not $seen.Contains("status|$line")) {
            [void]$seen.Add("status|$line")
            Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $line) -ForegroundColor DarkCyan
        }
    }

    try {
        $hist = Invoke-RestMethod -Uri "$ipc/v1/history?limit=$HistoryLimit" -TimeoutSec 5
    } catch {
        $hist = $null
    }

    if ($hist -and $hist.events) {
        # Show oldest-of-batch first so flow reads top→bottom
        $events = @($hist.events)
        [array]::Reverse($events)
        foreach ($e in $events) {
            $key = "$($e.time)|$($e.kind)|$($e.message)"
            if ($seen.Contains($key)) { continue }
            [void]$seen.Add($key)

            $color = "Gray"
            if ($e.kind -like "api.ok*" -or $e.kind -like "approve.ok*" -or $e.kind -like "heartbeat.ok*") { $color = "Green" }
            elseif ($e.kind -like "api.error*" -or $e.kind -like "scan.error*") { $color = "Red" }
            elseif ($e.kind -like "api.warn*" -or $e.kind -like "approve.wait*") { $color = "Yellow" }
            elseif ($e.kind -like "approve.progress*" -or $e.kind -like "api.*") { $color = "White" }

            $t = $e.time
            if ($t -and $t.Length -ge 19) { $t = $t.Substring(11, 8) }
            Write-Host ("[{0}] {1,-22} {2}" -f $t, $e.kind, $e.message) -ForegroundColor $color
        }
    }

    Start-Sleep -Seconds $PollSeconds
}
