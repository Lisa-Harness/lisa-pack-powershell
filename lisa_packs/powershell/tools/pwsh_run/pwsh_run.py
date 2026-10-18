"""Persistent, agent-optimized pwsh session tool for Lisa."""

from __future__ import annotations

from typing import Any

from kernel.models import ToolExecutionContext, ToolResult
from pydantic import BaseModel, Field, model_validator

from lisa_packs.powershell import read_authored_text
from lisa_packs.powershell.containment import PolicyError, resolve_effective_tier
from lisa_packs.powershell.executor import (
    MAX_BATCH_COMMANDS,
    run_batch_in_session,
    run_in_session,
)
from lisa_packs.powershell.probe import ProbeView, probe_capabilities
from lisa_packs.powershell.session import (
    PwshSession,
    pwsh_available,
    resolve_or_create_session,
)

TOOL_ID = "pwsh_run"

#: Override keys that count as a tightening request under a bare floor.
_TIGHTENING_OVERRIDE_KEYS = (
    "tier",
    "process_count",
    "memory_mb",
    "kill_on_close",
)


class Parameters(BaseModel):
    """Structured input for pwsh_run."""

    command: str | None = Field(
        default=None,
        min_length=1,
        max_length=10_000,
        description="PowerShell script to execute. Mutually exclusive with `commands`.",
    )
    commands: list[str] | None = Field(
        default=None,
        description=(
            f"Independent PowerShell scripts to run as one batch (cap "
            f"{MAX_BATCH_COMMANDS}). Mutually exclusive with `command`. "
            "Prefer this for independent read-only fan-outs. Batch children "
            "share a snapshot of session state; variable deltas are "
            "discarded, cwd is adopted only if every child agrees."
        ),
    )
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    run_in_background: bool = Field(
        default=False,
        description=(
            "Run this command in the background and return a job_id "
            "immediately. Useful for long-running builds, tests, or servers. "
            "A timed-out foreground command is auto-backgrounded (instead of "
            "killed) unless it starts with Start-Sleep or involves git - so "
            "work is never silently lost. Not valid with `commands`."
        ),
    )
    tier: str | None = Field(
        default=None,
        description=(
            "Containment tier override: bare, basic (Job Object child), "
            "contained (adds nested CLM runspace). May only RAISE above the "
            "session floor, never lower it. None = use the floor."
        ),
    )
    overrides: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Tightening overrides, keyed by axis: process_count (int), "
            "memory_mb (int), kill_on_close (bool). Under a bare floor, ANY "
            "override opts this call into containment; with no overrides the "
            "call runs on the host."
        ),
    )

    @model_validator(mode="after")
    def _exclusive_command_or_commands(self) -> Parameters:
        has_command = bool(self.command)
        has_commands = bool(self.commands)
        if has_command == has_commands:
            raise ValueError("provide exactly one of `command` or `commands`")
        if self.commands is not None:
            if self.run_in_background:
                raise ValueError("`run_in_background` is not valid with `commands`")
            if len(self.commands) > MAX_BATCH_COMMANDS:
                raise ValueError(
                    f"commands is capped at {MAX_BATCH_COMMANDS} (got {len(self.commands)})"
                )
            if any(not isinstance(item, str) or not item.strip() for item in self.commands):
                raise ValueError("every item in `commands` must be a non-empty string")
        return self


async def resolve_posture(
    ctx: ToolExecutionContext, params: Parameters
) -> tuple[bool, str, dict[str, Any]]:
    """Join the harness floor with the per-call request and host probe.

    Returns ``(contained, mode, extras)``: ``mode`` is one of ``bare``,
    ``basic``, ``contained``, or ``unavailable``; ``extras`` carries the
    tier/degradation/missing detail for the result stamp.
    """
    probe = await probe_capabilities()
    floor = None
    floor_for = ctx.execution_floor_for
    if floor_for is not None:
        floor = floor_for("pwsh_run")
    effective = resolve_effective_tier(floor, params.tier, params.overrides)
    extras: dict[str, Any] = {"tier": effective}
    if effective == "bare":
        return False, "bare", extras
    return _contained_posture(effective, probe, extras)


def _contained_posture(
    effective: str, probe: ProbeView, extras: dict[str, Any]
) -> tuple[bool, str, dict[str, Any]]:
    """Posture for a containment tier against a probed host."""
    tier = "contained" if effective == "readonly" else effective
    if not probe.basic_runnable:
        extras["missing"] = list(probe.missing)
        extras["doc"] = read_authored_text("prompts/pwsh_missing.md")
        return False, "unavailable", extras
    if tier == "contained" and not probe.contained_runnable:
        # CLM engine unavailable: degrade to basic, loudly.
        extras["tier"] = "basic"
        extras["degraded"] = True
        extras["note"] = (
            "CLM engine unavailable; degrading to basic (Job Object, full "
            "language). See pwsh_containment.md."
        )
        tier = "basic"
    return True, tier, extras


async def _dispatch(
    ctx: ToolExecutionContext, params: Parameters, session: PwshSession
) -> dict[str, Any]:
    """Route validated parameters into the executor."""
    if params.commands is not None:
        return await run_batch_in_session(
            ctx, session, params.commands, timeout_seconds=params.timeout_seconds
        )
    return await run_in_session(
        ctx,
        session,
        params.command or "",
        timeout_seconds=params.timeout_seconds,
        run_in_background=params.run_in_background,
    )


def _result_json(
    result: dict[str, Any], posture: dict[str, Any], session: PwshSession
) -> dict[str, Any]:
    """Shape the executor's dict into the tool result's output_json."""
    if result.get("error"):
        return _error_json(result, posture, session)
    if result.get("backgrounded"):
        return _backgrounded_json(result, posture, session)
    if result.get("batch"):
        return _batch_json(result, posture, session)
    return _single_json(result, posture, session)


def _error_json(
    result: dict[str, Any], posture: dict[str, Any], session: PwshSession
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "contained": result.get("contained", session.contained),
        "tier": posture.get("tier", ""),
    }
    if result.get("missing"):
        out["missing"] = result["missing"]
    return out


def _backgrounded_json(
    result: dict[str, Any], posture: dict[str, Any], session: PwshSession
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "backgrounded": True,
        "job_id": result.get("job_id"),
        "log_path": result.get("log_path"),
        "rc_path": result.get("rc_path"),
        "status_path": result.get("status_path"),
        "status": "running",
        "contained": result.get("contained", session.contained),
        "tier": posture.get("tier", ""),
    }
    if result.get("auto_backgrounded_on_timeout"):
        out["auto_backgrounded_on_timeout"] = True
        out["note"] = (
            f"Command did not complete within {result['timeout_seconds']}s and "
            "was moved to the background. Poll rc_path / log_path for "
            "completion; the rc file will contain the exit code when done."
        )
    else:
        out["note"] = (
            "Running in the background. Poll rc_path / log_path for "
            "completion; the rc file will contain the exit code when done."
        )
    return out


def _batch_json(
    result: dict[str, Any], posture: dict[str, Any], session: PwshSession
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "batch": True,
        "results": result.get("results") or [],
        "return_code": result.get("return_code", 0),
        "contained": result.get("contained", session.contained),
        "tier": posture.get("tier", ""),
        "timed_out": result.get("timed_out", False),
        "truncated": result.get("truncated", False),
        "log_path": str(session.log_path),
    }
    if result.get("note"):
        out["shaping_note"] = result["note"]
    return out


def _single_json(
    result: dict[str, Any], posture: dict[str, Any], session: PwshSession
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "return_code": result["return_code"],
        "stderr": result["stderr"],
        "contained": result["contained"],
        "tier": posture.get("tier", ""),
        "timed_out": result["timed_out"],
        "truncated": result["truncated"],
        "log_path": str(session.log_path),
    }
    for spill_key in ("stdout_path", "stderr_path", "stdout_bytes", "stderr_bytes"):
        if result.get(spill_key):
            out[spill_key] = result[spill_key]
    if result.get("note"):
        out["shaping_note"] = result["note"]
    if result.get("cwd"):
        out["cwd"] = result["cwd"]
    if result.get("errors"):
        out["errors"] = result["errors"]
    if result.get("background_jobs"):
        out["background_jobs"] = result["background_jobs"]
    return out


def _concluding_tool_result(
    result: dict[str, Any], posture: dict[str, Any], mode: str, session: PwshSession
) -> ToolResult:
    """Apply the bare/degraded posture stamps and conclude the result."""
    output_json = _result_json(result, posture, session)
    if result.get("error"):
        return ToolResult(tool_id=TOOL_ID, error=str(result["error"]), output_json=output_json)
    _apply_posture_stamps(result, output_json, mode, posture)
    text = "" if (result.get("backgrounded") or result.get("batch")) else result.get("stdout", "")
    return ToolResult(tool_id=TOOL_ID, output_text=text, output_json=output_json)


def _apply_posture_stamps(
    result: dict[str, Any], output_json: dict[str, Any], mode: str, posture: dict[str, Any]
) -> None:
    """Stamp posture mode/note fields onto a single-call result."""
    if not result.get("contained") and not result.get("batch"):
        output_json["mode"] = mode
        output_json["note"] = (
            "Running unsandboxed on the host because the containment floor for "
            "this session permits bare execution. Changes are permanent - "
            "confirm before mutating."
        )
    if posture.get("degraded"):
        output_json["degraded"] = True
        if not output_json.get("note"):
            output_json["note"] = str(posture.get("note", ""))


async def execute(ctx: ToolExecutionContext) -> ToolResult:
    """Execute a command in the persistent, containment-aware pwsh session."""
    try:
        params = Parameters.model_validate(ctx.parameters or {})
    except Exception as exc:
        return ToolResult(tool_id=TOOL_ID, error=f"Invalid parameters: {exc}")

    if not pwsh_available():
        install_doc = read_authored_text("prompts/pwsh_missing.md")
        return ToolResult(
            tool_id=TOOL_ID,
            error="pwsh is not installed or not on PATH; cannot start a PowerShell session.",
            output_json={"missing": ["pwsh"], "doc": install_doc},
        )

    session = resolve_or_create_session(ctx)
    try:
        contained, mode, posture = await resolve_posture(ctx, params)
    except PolicyError as exc:
        return ToolResult(tool_id=TOOL_ID, error=str(exc))
    if mode == "unavailable":
        return ToolResult(
            tool_id=TOOL_ID,
            error="contained execution is required by the harness floor but "
            "unavailable on this host",
            output_json=posture,
        )
    session.contained = contained

    try:
        result = await _dispatch(ctx, params, session)
    except Exception as exc:
        return ToolResult(
            tool_id=TOOL_ID,
            error=f"pwsh_run failed: {exc}",
            output_json={"contained": session.contained, "tier": posture.get("tier", "")},
        )

    return _concluding_tool_result(result, posture, mode, session)
