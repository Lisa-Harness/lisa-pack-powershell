"""Persistent pwsh session management for Lisa.

A session owns: per-call script spool, audit log, containment facts, and a
background-job registry. Unlike bash (forked shells + state replay), pwsh
sessions carry state by replaying a small state file the wrapper sources —
cwd and named variables only (full object fidelity is not preserved across
process boundaries; the design accepts that and keeps the surface honest).

pwsh is a hard dependency: no pwsh binary means no shell (see
``content/prompts/pwsh_missing.md``). The harness floor (from
``ctx.execution_floor_for("pwsh_run")``) decides the posture; a missing
floor never authorizes host execution.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kernel.capability_binding import ExecutionFloorView
from kernel.models import ToolExecutionContext
from sdk.identity import execution_scope_key

from lisa_packs.powershell.priming import SessionPriming

__all__ = [
    "SANDBOX_FACTS_DIRNAME",
    "PwshSession",
    "pwsh_available",
    "resolve_or_create_session",
]

logger = logging.getLogger(__name__)

_SESSIONS: dict[str, PwshSession] = {}

SANDBOX_FACTS_DIRNAME = "sandbox-facts.json"
_RUN_DIR_NAME = "run"


def pwsh_available() -> bool:
    """True when a pwsh binary is on PATH."""
    return shutil.which("pwsh") is not None


#: Default state-carryover policy: cwd and named variables carry. Function
#: replay is not supported (functions don't serialize via CLIXML reliably in
#: a nested runspace); pack_config may tighten cwd/variables off.
_DEFAULT_SESSION_STATE = {
    "cwd": True,
    "variables": True,
}
_VARIABLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _session_state_policy(ctx: ToolExecutionContext) -> dict[str, Any]:
    """Resolve the carryover policy for this ctx (pack_config override)."""
    policy = dict(_DEFAULT_SESSION_STATE)
    pack_config = getattr(ctx, "pack_config", None)
    if not isinstance(pack_config, Mapping):
        return policy
    override = pack_config.get("session_state")
    if not isinstance(override, Mapping):
        return policy
    if override.get("cwd") is False:
        policy["cwd"] = False
    if override.get("variables") is False:
        policy["variables"] = False
    return policy


def _session_key(ctx: ToolExecutionContext) -> str:
    return execution_scope_key(ctx)


def _floor_view(ctx: ToolExecutionContext) -> ExecutionFloorView | None:
    floor_for = ctx.execution_floor_for
    return floor_for("pwsh_run") if floor_for is not None else None


def _floor_requires_containment(ctx: ToolExecutionContext) -> bool:
    """Only an explicit bare floor permits host execution."""
    floor = _floor_view(ctx)
    return floor is None or floor.execution != "bare"


class PwshSession:
    """One Lisa session's PowerShell: priming, logging, state, and jobs."""

    def __init__(
        self,
        *,
        session_key: str,
        data_dir: Path,
        priming: SessionPriming,
        contained: bool,
        state_policy: dict[str, Any] | None = None,
    ) -> None:
        self.session_key = session_key
        self.data_dir = data_dir
        self.priming = priming
        self.contained = contained
        self._state_policy: dict[str, Any] = dict(_DEFAULT_SESSION_STATE, **(state_policy or {}))
        self.jobs: dict[str, dict[str, Any]] = {}

    @property
    def jobs_dir(self) -> Path:
        """Directory for job artifacts and spill files (host-visible)."""
        return self.data_dir / _RUN_DIR_NAME / self.session_key / "jobs"

    def record_post_run_state(self, *, cwd: str, variables: dict[str, str]) -> None:
        """Persist the per-call state delta for the next wrapper to replay."""
        lines: list[str] = ["# Auto-managed by lisa powershell pack. Do not edit."]
        if self._state_policy["cwd"] and cwd:
            lines.append(f"Set-Location -LiteralPath {ps_quote(cwd)}")
        if self._state_policy["variables"]:
            for name, value in sorted(variables.items()):
                if name and _VARIABLE_NAME.match(name):
                    lines.append(f"${name} = {ps_quote(value)}")
        path = self.priming.state_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".ps1.tmp")
            tmp.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
            tmp.replace(path)
        except OSError as exc:
            logger.debug("pwsh: state file write failed (%s)", exc)

    def apply_cwd(self, cwd: str) -> None:
        """After a batch: adopt cwd only when every child agreed."""
        if not self._state_policy["cwd"] or not cwd:
            return
        path = self.priming.state_path
        try:
            existing = (
                path.read_text(encoding="utf-8-sig")
                if path.is_file()
                else "# Auto-managed by lisa powershell pack. Do not edit.\n"
            )
            lines = [ln for ln in existing.splitlines() if not ln.startswith("Set-Location ")]
            if not lines:
                lines = ["# Auto-managed by lisa powershell pack. Do not edit."]
            lines.insert(1, f"Set-Location -LiteralPath {ps_quote(cwd)}")
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".ps1.tmp")
            tmp.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
            tmp.replace(path)
        except OSError as exc:
            logger.debug("pwsh: cwd apply failed (%s)", exc)

    def job_artifacts(self, job_id: str) -> tuple[Path, Path, Path]:
        """(log, rc, status) paths for one job under jobs_dir."""
        base = self.jobs_dir / job_id
        return (
            base.with_suffix(".log"),
            base.with_suffix(".rc"),
            base.with_suffix(".status.json"),
        )

    def register_job(self, job_id: str, meta: dict[str, Any]) -> None:
        """Track a running background job and write its running status file."""
        self.jobs[job_id] = {"job_id": job_id, "done": False, **meta}
        log_path, rc_path, status_path = self.job_artifacts(job_id)
        self._write_job_status(
            status_path,
            {
                "job_id": job_id,
                "state": "running",
                "started_at": datetime.now(UTC).isoformat(),
                "log_path": str(log_path),
                "rc_path": str(rc_path),
            },
        )

    def complete_job(self, job_id: str, *, rc: int | None, killed: bool) -> None:
        """Persist a finished job's status and drop it from the running set."""
        _log_path, rc_path, status_path = self.job_artifacts(job_id)
        self._write_job_status(
            status_path,
            {
                "job_id": job_id,
                "state": "killed" if killed else "done",
                "rc": rc,
                "ended_at": datetime.now(UTC).isoformat(),
                "rc_path": str(rc_path),
            },
        )
        self.jobs.pop(job_id, None)

    def _write_job_status(self, status_path: Path, payload: dict[str, Any]) -> None:
        try:
            status_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = status_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(status_path)
        except OSError as exc:
            logger.debug("pwsh: job status write failed (%s)", exc)

    def jobs_summary(self) -> list[dict[str, Any]]:
        """Snapshot of running jobs for a result's ``background_jobs``."""
        return [
            {
                "job_id": job_id,
                "done": meta.get("done", False),
                "log_path": str(self.job_artifacts(job_id)[0]),
            }
            for job_id, meta in self.jobs.items()
        ]

    @property
    def log_path(self) -> Path:
        return self.priming.log_path

    @property
    def sentinel(self) -> str:
        return self.priming.sentinel


def ps_quote(value: str) -> str:
    """Single-quote a value for safe embedding in a PowerShell literal."""
    return "'" + value.replace("'", "''") + "'"


def _write_containment_fact(session: PwshSession, ctx: ToolExecutionContext | None = None) -> None:
    """Publish this session's containment fact for the host approval engine.

    ``<data_dir>/run/<session_key>/sandbox-facts.json``, atomically, without
    importing pack code on the read side. The pack reports the fact; the
    host owns the approve/ask/deny decision. Best-effort: publishing never
    blocks or fails a shell call.
    """
    from lisa_packs.powershell.probe import get_cached_probe_view

    contained = session.contained
    state = "contained" if contained else "none"
    reasons: list[str] = []
    if ctx is not None and not _floor_requires_containment(ctx):
        state = "deliberate_bare"
    elif not contained:
        reasons = ["pwsh or Job Object API unavailable on this host"]
    payload: dict[str, Any] = {
        "tool_id": "pwsh_run",
        "containment": state,
        "reasons": reasons,
        "probed_at": datetime.now(UTC).isoformat(),
    }
    view = get_cached_probe_view()
    if view is not None:
        payload["pwsh_version"] = view.pwsh_version
        payload["clm_ok"] = view.clm_ok
        payload["job_object_ok"] = view.job_object_ok
        if view.missing and state != "deliberate_bare":
            payload["reasons"] = list(view.missing)
    path = session.data_dir / _RUN_DIR_NAME / session.session_key / SANDBOX_FACTS_DIRNAME
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:  # pragma: no cover - logging only, non-fatal
        logger.debug("pwsh: containment fact write failed (%s)", exc)


def resolve_or_create_session(
    ctx: ToolExecutionContext,
    *,
    contained: bool | None = None,
) -> PwshSession:
    """Return (creating if needed) the session for this ctx identity.

    ``contained`` may be forced by tests; when None it reflects the probe.
    An explicitly-passed posture updates the cached session in place so the
    per-call decision is never pinned by whichever posture created it.
    """
    key = _session_key(ctx)
    session = _SESSIONS.get(key)
    if session is not None:
        if contained is not None:
            session.contained = contained
        _write_containment_fact(session, ctx)
        return session

    data_dir = Path(ctx.data_dir) if ctx.data_dir else Path.home() / ".lisa"
    priming = SessionPriming(data_dir=data_dir, session_key=key)
    resolved = contained
    if resolved is None:
        resolved = pwsh_available()
    session = PwshSession(
        session_key=key,
        data_dir=data_dir,
        priming=priming,
        contained=resolved,
        state_policy=_session_state_policy(ctx),
    )
    _SESSIONS[key] = session
    _write_containment_fact(session, ctx)
    return session


def _reset_sessions() -> None:
    """Test hook: drop all cached sessions."""
    _SESSIONS.clear()
