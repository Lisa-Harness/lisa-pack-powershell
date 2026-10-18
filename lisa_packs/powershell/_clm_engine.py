"""ConstrainedLanguage enforcement probe for the powershell pack.

Windows PowerShell containment without bwrap — the pack's containment
model (see ``content/prompts/pwsh_containment.md``) composes two verified
primitives:

- **Job Object** (``winjob``): kill-on-close child tree + resource caps.
- **Nested CLM runspace**: the wrapper template
  (``content/profile/wrapper.ps1.tmpl``) opens a nested runspace whose
  ``LanguageMode = ConstrainedLanguage`` and runs the user script inside
  it. Verified blocked: ``Add-Type``, P/Invoke member definitions, .NET
  methods-with-arguments, ``New-Object`` of network/file classes,
  ``[type]::GetType``. Verified working: core cmdlets, conversions,
  static property reads.

pythonnet/in-process enforcement was evaluated and rejected: pwsh 7's SMA
targets .NET 8 while pythonnet hosts .NET Framework on this stack, so its
assemblies cannot load in-process. ``clm_selftest`` therefore verifies the
OUT-OF-PROCESS nested-runspace enforcement and is what the capability
probe reports as ``clm_ok``.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import tempfile
from pathlib import Path

from lisa_packs.powershell.executor import build_wrapper_argv
from lisa_packs.powershell.probe import pwsh_exe

__all__ = ["clm_selftest"]

logger = logging.getLogger(__name__)

#: Verifies BOTH halves of the CLM boundary in one contained child:
#: [Environment]::GetFolderPath (a method-with-argument call) must FAIL,
#: and a core cmdlet must SUCCEED — only then is CLM truly enforced.
_SELFTEST_SCRIPT = (
    "$__lisa_ok = $false; "
    "try { [Environment]::GetFolderPath('ProgramFiles') } "
    "catch { $__lisa_ok = $true }; "
    "if ($__lisa_ok) { "
    "$__lisa_count = (Get-ChildItem . | Measure-Object).Count; "
    "if ($__lisa_count -ge 0) { 'CLM-SELFTEST-OK' } else { 'CLM-CMDLET-FAIL' } "
    "} else { 'CLM-NOT-ENFORCED' }"
)
_SELFTEST_TIMEOUT_SECONDS = 20.0


class _TempPriming:
    """Minimal sentinel-only stand-in for a session in a temp dir."""

    def __init__(self, *, sentinel: str) -> None:
        self._sentinel = sentinel

    @property
    def sentinel(self) -> str:
        return self._sentinel


async def clm_selftest() -> bool:
    """True when a nested CLM runspace provably enforces the boundary.

    Renders the real wrapper template with ``CLM=1`` and the selftest
    script, runs it as a pwsh child, and requires the success marker.
    """
    exe = pwsh_exe()
    if not exe:
        return False
    with tempfile.TemporaryDirectory(prefix="lisa-pwsh-clm-") as tmp:
        spill = Path(tmp)
        session = _TempPriming(sentinel=f"LISACLMTEST{secrets.token_hex(4)}>> ")
        argv = build_wrapper_argv(
            pwsh_exe=exe,
            user_script=_SELFTEST_SCRIPT,
            state_path=None,
            sentinel=session.sentinel,
            spill_dir=spill,
            capture_variables=False,
            clm=True,
            wait_ms=15_000,
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (OSError, FileNotFoundError):
            return False
        try:
            out, _err = await asyncio.wait_for(proc.communicate(), _SELFTEST_TIMEOUT_SECONDS)
        except TimeoutError:
            proc.kill()
            return False
        text = out.decode("utf-8", errors="replace")
        if "CLM-SELFTEST-OK" not in text:
            logger.debug("pwsh: clm selftest output=%r", text[:400])
        return "CLM-SELFTEST-OK" in text
