---
schema_version: 2
name: e2e-pwsh-sandbox
surface:
  type: personal_dm
  id: host-console
  memory_scope: personal
resources:
  packs:
    configuration:
      lisa-pack-powershell:
        sandbox:
          floor:
            execution: sandbox
            persistence: direct-write
            network: allow
    required:
      - lisa-pack-core
      - lisa-pack-powershell
providers:
  modes:
    shell_pwsh: lisa-pack-powershell
  tools:
    web_search: e2etest-offline
  capabilities:
    sandbox: lisa-pack-powershell
routing: { from: { pack: lisa-pack-core, session: default } }
execution:
  max_session_tokens: 200000
  max_completion_tokens: 50000
  max_capability_calls: 50
---
# E2E powershell sandbox session (scripted containment scenario)

The scripted model drives this session; no provider is contacted. It
exercises the sandbox capability end to end on a Windows host: the
session selects ``providers.capabilities.sandbox: lisa-pack-powershell``,
the pack's ``lisa.extensions.sandbox`` entry point owns the capability
with an authored floor, and the shell_pwsh mode's ``pwsh_run`` proves
its containment stamp from a real Job-Object child. The scenario pins
the 2026-11-14 branding-session regression: a session that selected the
powershell pack as sandbox owner must actually resolve one.
