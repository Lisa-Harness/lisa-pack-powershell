# Shell is running without containment

The `pwsh_run` shell works, but the harness floor for this session permits
bare execution, so scripts are running **directly on the host**. Every
result carries `contained: false` and `mode: "bare"` so this is visible to
you and to the user.

## What containment adds

- **basic**: the child pwsh process tree lives inside a Job Object —
  killed with the call; optional process-count and memory caps.
- **contained**: additionally runs the user script inside a nested
  ConstrainedLanguage runspace — `Add-Type`, P/Invoke, .NET network/file
  classes, and method-with-argument invocation are blocked.

## How to tighten one call

Pass `tier: "basic"` or `tier: "contained"` on the call, or any resource
override (for example `{"memory_mb": 512}`); under a bare floor ANY
override opts that single call into containment. Nothing needs to be
installed — on Windows the Job Object API and pwsh are enough.