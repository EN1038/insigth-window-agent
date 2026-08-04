# Agent binary allowlist / Application Control

Test machines may block newly built `insite-agent.exe` (WDAC / AppLocker / third-party Application Control). When launch fails with "Application Control policy has blocked this file":

## Recommended flow

1. Build signed release (or copy the tested binary to a fixed install path).
2. Allowlist the publisher certificate **or** the exact path/hash:
   - Path example: `C:\Program Files\SOSECURE\Threat inSight\insite-agent.exe`
   - Prefer publisher allow over path-only rules.
3. Stop running agent processes.
4. Replace the binary.
5. Start: `insite-agent.exe -mode ui`
6. Smoke checks:
   - `GET http://127.0.0.1:19877/v1/health`
   - `GET http://127.0.0.1:19877/v1/rules/info`
   - `GET http://127.0.0.1:19877/v1/ssdeep/info`
   - Open Info page — Connection should match header Online/Offline.

## Auto schedules (defaults)

| Job | Setting | Default |
|-----|---------|---------|
| Rules + ssdeep TI sync | `ti_sync_everydate` | every **60** minutes |
| Agent version check/update | `agent_update_schedule` | every **360** minutes |
| Batch/auto scan | `batchjob_everydate` | every **1440** minutes |

While a scan is running, scheduled TI sync and agent update **download/install** are deferred. When the scan stops or completes, deferred work runs on the next idle tick (and immediately via `OnScanIdle`).

## Center deploy companion (Phase 1)

On the Center host (e.g. `192.168.10.222`):

```bash
php cleanup_missing_rule_packs.php --delete-orphan-rows
php reset_all_ti_queues.php
```

Deploy updated `ApiAgentController.php` so `getRule` counts on-disk packs and `downloadRuleSite` soft-disables missing ZIPs.

Then Sync TI from the agent UI once.
