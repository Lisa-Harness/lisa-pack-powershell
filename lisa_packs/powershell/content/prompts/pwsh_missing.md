# pwsh is not available

`pwsh_run` needs PowerShell 7+ (`pwsh`) on this host; PowerShell is a hard
dependency and cannot be installed as a Python package.

## Install pwsh

- **winget**: `winget install --id Microsoft.PowerShell --source winget`
- **msi**: download from
  [github.com/PowerShell/PowerShell/releases](https://github.com/PowerShell/PowerShell/releases)
- **Store**: search "PowerShell" in the Microsoft Store

## After installing

Ensure `pwsh` is on the `PATH` that Lisa's host process sees (open a NEW
terminal after installing so PATH changes propagate). Once pwsh is
available, `pwsh_run` will work without further configuration — contained
tiers compose automatically when the Job Object API is present (Windows).
On non-Windows hosts, pwsh runs bare only; containment tiers are
unavailable and the harness floor will refuse `execute` effects that
mandate containment.