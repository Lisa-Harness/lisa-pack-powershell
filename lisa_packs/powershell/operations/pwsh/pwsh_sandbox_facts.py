"""Pwsh sandbox-facts prewarm operation (shell_pwsh mode pre-turn).

Runs before every shell_pwsh-mode model call (bound via the mode's
``pre_turn_operation_ids``). It resolves — creating if needed — the pwsh
session for this context identity, which both primes the session and
publishes the per-session containment fact to
``<data_dir>/run/<session_key>/sandbox-facts.json``.

That pre-warm matters: without it, the first ``pwsh_run`` call would hit
the approval gate *before* any session existed, so the policy engine's
containment check would read a missing fact and prompt even though the
script would have run contained. Resolving here closes that inversion. The
pack only reports the fact; the host approval engine owns the decision.
"""

from __future__ import annotations

import json

from kernel.models import (
    OperationExecutionContext,
    OperationResult,
    ToolExecutionContext,
)

from lisa_packs.powershell.probe import probe_capabilities
from lisa_packs.powershell.session import (
    SANDBOX_FACTS_DIRNAME,
    resolve_or_create_session,
)

__all__ = ["execute"]


async def execute(ctx: OperationExecutionContext) -> OperationResult:
    """Resolve the pwsh session and report its containment state."""
    tool_ctx = ToolExecutionContext(
        tool_id="pwsh_run",
        workspace_id=ctx.workspace_id,
        user_id=ctx.user_id,
        user_slug=ctx.user_slug,
        surface_type=ctx.surface_type,
        surface_id=ctx.surface_id,
        memory_scope=ctx.memory_scope,
        mode_id=ctx.mode_id,
        query=ctx.query,
        session_plan_digest=ctx.session_plan_digest,
        data_dir=ctx.data_dir,
        pack_config=ctx.pack_config,
        execution_floor_for=ctx.execution_floor_for,
    )
    probe = await probe_capabilities()
    session_contained = probe.pwsh_available and probe.job_object_ok
    session = resolve_or_create_session(tool_ctx, contained=session_contained)
    fact_path = session.data_dir / "run" / session.session_key / SANDBOX_FACTS_DIRNAME
    containment = "contained" if session_contained else "none"
    reasons: list[str] = []
    try:
        fact = json.loads(fact_path.read_text(encoding="utf-8"))
        containment = str(fact.get("containment") or containment)
        raw_reasons = fact.get("reasons")
        if isinstance(raw_reasons, list):
            reasons = [str(r) for r in raw_reasons]
    except (OSError, json.JSONDecodeError):
        pass
    return OperationResult(
        output_text=f"pwsh session ready ({containment})",
        output_json={
            "containment": containment,
            "reasons": reasons,
            "contained": containment in ("contained", "deliberate_bare"),
            "session_key": session.session_key,
            "pwsh_version": probe.pwsh_version,
        },
    )
