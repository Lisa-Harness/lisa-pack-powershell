"""Contained argv execution for the powershell pack.

This is the Windows-side sibling of the bash pack's composed
``bash_run → bwrap_run`` path: an explicit argument vector, no shell, run
inside a Job Object, with the containment evidence a composing pack needs.

It exists so that packs owning durable workflows (``lisa-pack-coding``'s
configured checks and preparation recipes) can run contained on Windows
through the same provider-neutral runner surface they already use on Linux,
without either pack naming the other.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kernel.models import ToolExecutionContext, ToolResult
from pydantic import BaseModel, Field

from lisa_packs.powershell.run_argv import (
    argv_containment_available,
    run_argv_contained,
)

TOOL_ID = "pwsh_argv_run"


class Parameters(BaseModel):
    """Structured input for ``pwsh_argv_run``.

    Deliberately not ``pwsh_run``'s schema: there is no script, no session
    state, and no background adoption, because a caller of this tool is
    asking for a bounded, contained *process*, not a shell session.
    """

    argv: list[str] = Field(
        ...,
        min_length=1,
        description="Executable and arguments. No shell is involved; each item is one argument.",
    )
    cwd: str = Field(
        ...,
        min_length=1,
        description="Working directory for the child process.",
    )
    timeout_seconds: int = Field(
        default=300,
        ge=1,
        le=3600,
        description="Hard timeout; the process tree is killed, never backgrounded.",
    )


async def execute(ctx: ToolExecutionContext) -> ToolResult:
    """Run one argv contained and report the verified containment facts."""
    try:
        params = Parameters.model_validate(ctx.parameters or {})
    except Exception as exc:  # pylint: disable=broad-except
        return ToolResult(tool_id=TOOL_ID, error=f"Invalid parameters: {exc}")

    cwd = Path(params.cwd)
    if not cwd.is_dir():
        return ToolResult(
            tool_id=TOOL_ID,
            error=f"cwd does not exist or is not a directory: {params.cwd}",
        )
    if not argv_containment_available():
        return ToolResult(
            tool_id=TOOL_ID,
            error=(
                "contained argv execution is unavailable on this host: the Job "
                "Object containment primitive requires Windows. Running the argv "
                "unsandboxed would break the caller's containment guarantee."
            ),
            output_json={"sandboxed": False, "contained": False, "tier": "unavailable"},
        )

    try:
        result = await run_argv_contained(
            list(params.argv),
            cwd=cwd,
            timeout_seconds=params.timeout_seconds,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return ToolResult(tool_id=TOOL_ID, error=f"contained argv run failed: {exc}")

    payload: dict[str, Any] = result.as_output_json()
    if not result.contained:
        return ToolResult(
            tool_id=TOOL_ID,
            error=(
                "contained argv run could not verify Job Object assignment; the "
                "process tree was not contained, so the result is not trustworthy."
            ),
            output_json=payload,
        )
    return ToolResult(
        tool_id=TOOL_ID,
        output_text=result.stdout,
        output_json=payload,
    )
