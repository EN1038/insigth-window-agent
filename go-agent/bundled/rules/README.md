# Bundled YARA rules (optional offline seed)

Place rule packs here before build / first run:

- `*.zip` containing `.yar` files (recommended for large catalogs)
- Or plaintext `.yar` under install `Engine\Yara\`

On startup, if the encrypted store is **empty**, the agent imports bundled
rules into `%ProgramData%\SOSECURE Threat inSight\Data\rules\`, then removes
plaintext copies from the install tree (same pattern as ssdeep).

```powershell
# Example: copy a Center-exported pack
Copy-Item C:\path\to\rules_pack.zip .\bundled\rules\

# Or seal into ProgramData during dev
go run ./cmd/insite-agent -mode seal
```

Center sync remains the source of truth; bundled packs only seed first run.
