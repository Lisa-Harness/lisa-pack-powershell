# lisa-pack-powershell

PowerShell execution capability pack for Lisa — the Windows-native sibling
of the bash pack. It runs scripts in a persistent, agent-optimized pwsh
session with **verified** layered containment (Windows Job Objects +
ConstrainedLanguage runspaces), background jobs, batches, spill-to-file,
and PowerShell-idiomatic result shaping.

## Installation

```powershell
pip install -e ./powershell
```

Requires `pwsh` (PowerShell 7+) on PATH. Windows hosts additionally get
Job-Object containment automatically; nothing else to configure.

## Tool: `pwsh_run`

| Parameter | Meaning |
| --- | --- |
| `command` | One PowerShell script (mutually exclusive with `commands`) |
| `commands` | Up to 8 independent scripts run against a state snapshot |
| `timeout_seconds` | 1-300; on timeout foreground work is **auto-backgrounded** (except `Start-Sleep`/`git`-touching scripts) |
| `run_in_background` | Return a `job_id` immediately; poll `rc_path`/`status_path` |
| `tier` | Tighten containment for one call: `basic` or `contained` |
| `overrides` | Tighten further: `process_count`, `memory_mb`, `kill_on_close` |

### Result contract (what the harness already does — do not re-implement)

- **Session state carries across calls**: `Set-Location` and
  `$variable = ...` persist via a per-session state file.
- **`return_code` is authoritative.** rc=1 from `Select-String`,
  `Test-Path`, `Compare-Object`, `Wait-Job`, `Receive-Job` is
  informational (`shaping_note`); other nonzero codes are real failures.
- **Empty success is explicit** (`shaping_note`), large output spills to
  `stdout_path`/`stderr_path`.
- **Timeouts background work instead of killing it**
  (`auto_backgrounded_on_timeout: true`), tracked under `background_jobs`
  on every later result.

## Containment model (no bwrap on Windows)

Two primitives, both **verified by real probes** (see `_clm_engine.py` and
the `live` tests):

1. **Job Objects** — the pwsh child (whole process tree) lives in a job
   with kill-on-close plus optional process-count/memory caps. Verified:
   `TerminateJobObject` kills the tree; a memory cap kills an
   over-allocating child with `0xC0000005`.
2. **Nested ConstrainedLanguage runspace** (`contained` tier) — the
   wrapper opens a nested runspace whose language mode is engine-enforced.
   Verified blocked: `Add-Type`, P/Invoke, .NET methods-with-args,
   `New-Object` of network/file classes, `[type]::GetType`. Verified
   working: core cmdlets, pipeline processing, conversions.

Honest limits: CLM does **not** block plain filesystem writes/deletes,
`Start-Process`, or `Invoke-Expression`; the Job Object governs process
lifetime, not file persistence. Overlay capture (bwrap overlayfs
equivalent) is deferred — the plan is VSS snapshots.

### Tier table

| Tier | Mechanisms | Writes |
| --- | --- | --- |
| `bare` | none | permanent (real host) |
| `basic` | Job Object | process-tree controlled; filesystem real |
| `contained` | Job Object + nested CLM runspace | same as basic; language surface limited |

The floor comes from the harness (`execution_floor_for("pwsh_run")`); a
missing floor never authorizes bare execution. The model may only tighten.

## Mode: `shell_pwsh`

Routable via `/pwsh`, `/powershell`, or PowerShell-intent keywords.
Pre-turn `pwsh_sandbox_facts` primes the session and publishes the
containment fact the host approval engine reads.

## Tests

```powershell
$py = "..\lisa\.venv\Scripts\python.exe"
& $py -m pytest lisa_packs\powershell\tests -m "not live" -v   # unit
& $py -m pytest lisa_packs\powershell\tests -m "live" -v        # real pwsh children
```

The `live` tests exercise real containment enforcement — they are the
executable version of the claims above.

## Design history

The full design (containment lattice, pythonnet evaluation and why the
in-process path was rejected, deferred VSS plan) lives in
[`docs/PWSH_PACK_DESIGN.md`](../docs/PWSH_PACK_DESIGN.md) in the
[lisa-packs](https://github.com/Lisa-Framework/lisa-packs) umbrella repo.