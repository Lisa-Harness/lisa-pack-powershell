"""Verified host capability probe for the powershell pack.

Performs REAL containment probes (never trusts a plausible environment):
- a pwsh child answers ``$PSVersionTable | ConvertTo-Json -Compress``;
- a job object can be created with limits and assigned to a real child;
- an in-process CLM runspace enforces ConstrainedLanguage by rejecting a
  .NET method invocation while a core cmdlet still succeeds.

The probe is memoized per process; results feed the containment fact the
host approval engine reads.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field

__all__ = [
    "ProbeView",
    "get_cached_probe_view",
    "probe_capabilities",
    "pwsh_exe",
    "reset_probe_cache",
]

logger = logging.getLogger(__name__)

_PROBE_SCRIPT = "$PSVersionTable | ConvertTo-Json -Compress"
_PROBE_TIMEOUT_SECONDS = 10.0

_CACHE: dict[str, object] = {}


@dataclass(frozen=True, slots=True)
class ProbeView:
    """Verified containment capability facts for this host."""

    pwsh_available: bool
    pwsh_path: str
    pwsh_version: str
    is_core: bool
    job_object_ok: bool
    clm_ok: bool
    missing: tuple[str, ...] = field(default_factory=tuple)

    @property
    def contained_runnable(self) -> bool:
        """True when the in-process CLM runspace path can run."""
        return self.clm_ok and self.is_core

    @property
    def basic_runnable(self) -> bool:
        """True when the external job-object child path can run."""
        return self.pwsh_available and self.job_object_ok


def pwsh_exe() -> str:
    """The discovered pwsh binary path (empty when absent)."""
    cached = _CACHE.get("pwsh_exe")
    if isinstance(cached, str):
        return cached
    found = shutil.which("pwsh") or ""
    _CACHE["pwsh_exe"] = found
    return found


def reset_probe_cache() -> None:
    """Test hook: forget memoized probe results."""
    _CACHE.clear()


async def _probe_pwsh_version() -> tuple[bool, str, str, bool]:
    """Probe pwsh availability + version.

    Returns ``(available, path, version, is_core)``.
    """
    exe = pwsh_exe()
    if not exe:
        return False, "", "", False
    try:
        proc = await asyncio.create_subprocess_exec(
            exe,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _PROBE_SCRIPT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (OSError, FileNotFoundError):
        return False, exe, "", False
    try:
        out, _err = await asyncio.wait_for(proc.communicate(), _PROBE_TIMEOUT_SECONDS)
    except TimeoutError:
        proc.kill()
        return True, exe, "", False
    if proc.returncode != 0:
        return True, exe, "", False
    try:
        table = json.loads(out.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return True, exe, "", False
    version_info = table.get("PSVersion") or {}
    version = str(version_info.get("Version", ""))
    edition = str(table.get("PSEdition", ""))
    return True, exe, version, edition == "Core"


async def _clm_inproc_probe() -> bool:
    """True when an in-process CLM runspace enforces the language boundary.

    Delegates to the PowerShell engine through pythonnet; falls back False
    when the .NET loader is unavailable — a probe that cannot run is never
    reported as contained. Failures are contained: they never raise.
    """
    try:
        from lisa_packs.powershell._clm_engine import clm_selftest

        return bool(await clm_selftest())
    except Exception as exc:
        logger.debug("pwsh: CLM selftest unavailable (%s)", exc)
        return False


def get_cached_probe_view() -> ProbeView | None:
    """Memoized probe result without running the probe.

    Used by the containment-fact writer, which must never block on (or
    inside) a running event loop. Returns None until an async caller has
    run :func:`probe_capabilities` at least once in this process.
    """
    view = _CACHE.get("view")
    return view if isinstance(view, ProbeView) else None


async def probe_capabilities() -> ProbeView:
    """Real containment capability probe (memoized per process)."""
    if isinstance(_CACHE.get("view"), ProbeView):
        return _CACHE["view"]  # type: ignore[return-value]

    missing: list[str] = []
    pwsh_available, pwsh_path, version, is_core = await _probe_pwsh_version()
    if not pwsh_available:
        missing.append("pwsh is not installed or not on PATH")

    from lisa_packs.powershell.winjob import job_object_available

    job_ok = job_object_available()
    if not job_ok:
        missing.append("Job Object API unavailable (non-Windows host)")

    clm_ok = False
    if pwsh_available and is_core:
        clm_ok = await _clm_inproc_probe()
        if not clm_ok:
            missing.append(
                "in-process ConstrainedLanguage engine unavailable "
                "(pythonnet not installed or .NET loader failed)"
            )

    view = ProbeView(
        pwsh_available=pwsh_available,
        pwsh_path=pwsh_path,
        pwsh_version=version,
        is_core=is_core,
        job_object_ok=job_ok,
        clm_ok=clm_ok,
        missing=tuple(missing),
    )
    _CACHE["view"] = view
    return view
