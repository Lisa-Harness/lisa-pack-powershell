# PowerShell containment model

There is no bwrap on Windows. The powershell pack approximates bwrap's
containment with two VERIFIED primitives, composed per call:

- **Job Objects** — the child pwsh (and its whole process tree) lives in a
  job with kill-on-close plus optional process-count and memory caps.
  Verified: `TerminateJobObject` kills the tree; a memory cap kills an
  over-allocating child. This is the hard boundary.
- **Nested ConstrainedLanguage runspace** — in the `contained` tier, the
  user script runs inside a nested runspace whose language mode is
  enforced at the engine level. Verified blocked surface: `Add-Type`,
  P/Invoke via member definitions, .NET methods with arguments outside the
  CLM allowlist, `New-Object` of network/file classes, `[type]::GetType`.
  Verified working surface: core cmdlets, pipeline cmdlets, conversions,
  static property reads.

## Honest limits

CLM is a language-surface limiter, NOT a filesystem sandbox:

- plain filesystem writes/deletes are NOT blocked by CLM
- `Start-Process` is NOT blocked
- `Invoke-Expression` on a string is NOT blocked

So the `contained` tier is: Job Object process-tree control + restricted
language surface. It does NOT provide filesystem isolation. Destructive
filesystem commands need the same bare-tier caution.

## Tier table

| Tier | Mechanisms | Writes |
| --- | --- | --- |
| `bare` | none | permanent (real host) |
| `basic` | Job Object | process-tree controlled; filesystem real |
| `contained` | Job Object + nested CLM runspace | same as basic; language surface limited |
| `readonly` | resolved to `contained` + cwd-only state carry | advisory |

## What is deferred

Overlay capture (bwrap overlayfs equivalent) is deferred: the plan is
VSS snapshots in a later iteration. Writes in contained tiers land on the
real filesystem today; the Job Object boundary governs process lifetime,
not file persistence.