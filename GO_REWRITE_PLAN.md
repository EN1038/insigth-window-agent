# SOSECURE Threat inSight — Go-only Agent Rewrite Plan (Windows Server 2012 R2)

## Goal

Replace the legacy **.NET Framework 3.5 WPF + Windows Services** agent with a **single Go executable** that:

- Runs as a **Windows Service** (background, 24/7): heartbeat, approval loop, rule sync, scan pipeline, realtime watcher, USB protection, scheduler, reporting.
- Optionally runs as a **UI controller** (interactive, Fyne): keeps the legacy flow (Config → dataInfo → approve loop → login → main).
- Stores all sensitive local data using **AES‑256‑GCM encrypted file store** with envelope encryption (no SQLCipher).
- Does **not** store email/password on disk (site key remains required for current API auth model, but is stored encrypted).

## Why AES‑GCM Encrypted File Store instead of SQLCipher

SQLCipher provides at-rest protection by encrypting SQLite pages with **AES‑256‑CBC** and using **HMAC** to detect tampering; it also uses PBKDF2 for key derivation.

AES‑GCM is an authenticated-encryption mode (AEAD) that provides confidentiality + integrity in one construction. With correct design (unique IV per key, tag verification, AAD binding), an AES‑GCM file store provides the same core security properties at rest. The main trade-off is losing SQLite query/transaction features, which are not required because reporting/search/filtering is done on the server.

References:
- SQLCipher design (AES‑256‑CBC + per-page IV + HMAC): https://zetetic.net/sqlcipher/design/
- NIST SP 800‑38D (GCM is authenticated encryption): https://csrc.nist.gov/pubs/sp/800/38/d/final
- Envelope encryption pattern (DEK/KEK, AES‑GCM): https://cloud.google.com/kms/docs/envelope-encryption

## Deliverables / Milestones

### M1 — Go service skeleton (runs on 2012 R2)
- Windows service install/start/stop
- Structured logging + log rotation
- Loads encrypted config + settings

### M2 — API parity (no scan yet)
- Implements all legacy API flows:
  - dataInfo, loginAgent, checkedAgentApproved, getConfig, updateConfig
  - getRule, downloadRuleSite, downloadRuleSiteComplete, updateRuleDownload
  - agentOnlineTimestamp, sendLogYara, sendAgentScanLog, sendHash
- Retry/backoff & offline queue (encrypted)

### M3 — Rules + scan engine embedded
- Rules store: encrypted records + minimal index
- Scan pipeline: enumerate → batch scan → report
- Real-time watcher + USB detection (server-grade)

### M4 — UI (Fyne)
- Implements the flow screens with a stable minimal UX:
  - Config, Approval waiting, Login, Main (status/settings/logs/manual scan)
- UI communicates with service via local IPC (named pipe or 127.0.0.1)

### M5 — Installer + migration
- MSI/installer actions:
  - install single EXE
  - register service
  - create folders + ACL
  - migrate legacy config/settings if present

## Proposed repo layout (new)

```
go-agent/
  cmd/insite-agent/           # main entry (service or UI mode)
  internal/
    app/                      # composition root (wires modules)
    service/                  # windows service runtime
    ipc/                      # local IPC API UI<->service
    api/                      # server API client (all endpoints)
    crypto/                   # AES-GCM envelope, HKDF/PBKDF2, zeroization helpers
    keystore/                 # DPAPI LocalMachine key protection (KEK)
    storage/                  # encrypted file store: config/settings/rules/history/queue
    rules/                    # rule index + materialization to temp dir for yara
    scan/                     # enumerator, batching, scheduler
    watcher/                  # realtime FS watcher
    usb/                      # USB detection + drive scan trigger
    ui/                       # Fyne UI
```

## Security requirements (must not regress)

- Email/password are **never** persisted.
- Site key is persisted only in **encrypted config.enc** (DPAPI-protected KEK).
- All local data files are encrypted:
  - config, settings, rules store, scan history, snapshot/cache, offline queue, quarantine.
- AES‑GCM rules:
  - Unique 96-bit IV per encryption under a given DEK.
  - Use AAD to bind (site_id, agent_id, file type, schema version).
- Restrict directories via ACL (SYSTEM + Administrators).
- No plaintext secrets in logs.

## Runtime/Operational requirements (Server 2012 R2)

- Works without a logged-in user.
- Recovers after reboot.
- Low CPU overhead for watcher/USB.
- Bounded disk usage (retention & compaction).

