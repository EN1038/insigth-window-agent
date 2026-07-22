# Bundled ssdeep signatures (plaintext)

Place `signatures.db` here before build or first run. On startup the agent imports it into encrypted storage under `%ProgramData%/SOSECURE Threat inSight/Data/ssdeep/` (same vault pattern as YARA rules).

Copy from the scanner project:

```powershell
go run ./cmd/ssdeep-bundled -src "C:\path\to\signatures.db"
go run ./cmd/ssdeep-bundled -src "C:\path\to\signatures.db" -seal
```

The file is large (~130MB); it is gitignored. Installer can ship `Engine\Ssdeep\signatures.db` instead.
