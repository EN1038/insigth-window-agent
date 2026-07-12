# SOSECURE Threat inSight — Installer & Legacy Migration (Go Agent)

## Overview

The Go agent replaces the legacy stack:

| Legacy | Go agent |
|--------|----------|
| `insight.sosecure.legacy.exe` (WPF + .NET 3.5) | `insite-agent.exe` (single binary) |
| `sosecure-engine.exe` sidecar | embedded in service |
| 2 Windows services | **1** service: `SOSECURE Threat inSight` |
| Plaintext / SQLCipher stores | AES-GCM + DPAPI encrypted files |

## Fresh install

### Option A — Inno Setup (recommended for production)

1. Build release binary:
   ```powershell
   cd go-agent
   go build -ldflags="-s -w" -o ..\dist\insite-agent.exe .\cmd\insite-agent
   ```
2. Copy `Engine\Yara\yara64.exe` and rule entry files to `dist\Engine\Yara\`
3. Compile `setup_go.iss` with Inno Setup 6+
4. Run the generated `SOSECURE_Threat_inSight_Go_Setup_*.exe` **as Administrator**

### Option B — PowerShell (dev / lab)

```powershell
# Run as Administrator
.\go-agent\scripts\install-agent.ps1 -InstallDir "C:\Program Files\SOSECURE\Threat inSight"
```

### Option C — CLI only

```powershell
# Run as Administrator from install directory
.\insite-agent.exe -mode install
```

Service args: `-mode service`  
UI shortcut: `-mode ui`

## Upgrade from legacy (.NET)

```powershell
# Run as Administrator
.\go-agent\scripts\upgrade-from-legacy.ps1 -InstallDir "C:\Program Files\SOSECURE\Threat inSight"
```

Or:

```powershell
.\insite-agent.exe -mode upgrade
```

### Upgrade steps performed

1. Stop legacy services (`sc control 128`, `sc stop`)
2. Kill `insight.sosecure.legacy.exe`, `sosecure-engine.exe`
3. Delete legacy service registrations
4. Install Go service `SOSECURE Threat inSight`
5. On first start, auto-migrate:
   - `Config\Key\config.json` → `Data\config.enc`
   - `Data\settings.cfg` → `Data\settings.enc`
   - Existing `Data\` quarantine/history preserved where compatible

### Data kept vs replaced

| Path | Action |
|------|--------|
| `Config\Key\config.json` | Migrated to encrypted `Data\config.enc` |
| `Data\settings.cfg` | Migrated to `Data\settings.enc` |
| `Data\snapshot.dat` | New agent uses `Data\snapshot.enc` (fresh incremental baseline) |
| `Engine\Yara\rules*.yar` | Used until server rule sync; optional import |
| `rules.db` (SQLCipher) | **Not used** — rules re-downloaded from server |
| Legacy services | Removed |

## Uninstall

```powershell
.\go-agent\scripts\uninstall-agent.ps1
# or
.\insite-agent.exe -mode uninstall
```

Inno Setup uninstaller runs the same logic.

## Deprecating legacy

After successful Go deployment on a site:

1. Uninstall legacy via `upgrade-from-legacy.ps1` or Inno `setup_go.iss`
2. Remove from repo build pipeline:
   - `insight.sosecure.legacy.csproj`
   - `sosecure-engine` sidecar packaging
3. Retire `setup_v3.iss` (keep for historical rollback only)
4. Document minimum OS: **Windows Server 2012 R2+** (no .NET 3.5 requirement)

## Security notes

- Install requires **Administrator** (service registration + DPAPI LocalMachine)
- Restrict `{app}\Data` ACL: SYSTEM + Administrators (installer sets via script)
- Site key stored only in `config.enc`; email/password never persisted

## References

- Architecture plan: `GO_REWRITE_PLAN.md` (M5)
- Stop legacy services manually: `scripts\stop-sosecure-services.ps1`
