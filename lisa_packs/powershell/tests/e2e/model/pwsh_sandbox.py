"""Scripted model for the powershell pack's sandbox e2e scenario.

Drives the real shell_pwsh tool surface with zero credentials. The session
starts in ``default`` mode, where the kernel injects a routing hint toward
``shell_pwsh``; the model follows it with ``transition_stage`` (production
handoff path), then calls the approval-gated ``pwsh_run`` (the scenario's
approval policy approves it), then reports the containment stamp from the
tool's result JSON — which a real Job-Object pwsh child produced.
Everything below the model — mode routing, handoff, tool surface,
approval pause/continue, sandbox capability resolution, dispatch,
receipts, persistence — is production code.

See ``e2etest.scripted`` for the ScriptTurn/Reply contract.
"""

from __future__ import annotations

from e2etest.scripted import Reply, ScriptError, ScriptTurn


def auxiliary(turn: ScriptTurn) -> Reply:
    """Tool-less requests (classifiers, distillers, titles): empty answers."""
    if turn.request.response_format is not None:
        return Reply.text("{}")
    return Reply.text("")


def respond(turn: ScriptTurn) -> Reply:
    if "pwsh_run" in turn.tool_names:
        return _pwsh_turn(turn)
    if "transition_stage" in turn.tool_names and turn.count("pwsh_run") == 0:
        return Reply.call("transition_stage", target_stage_id="shell_pwsh")
    raise ScriptError(f"pwsh_run not offered; tools={sorted(turn.tool_names)}")


def _pwsh_turn(turn: ScriptTurn) -> Reply:
    if turn.count("pwsh_run") == 0:
        return Reply.call(
            "pwsh_run",
            command="Write-Output $PSVersionTable.PSVersion.ToString()",
            timeout_seconds=60,
        )
    last = turn.last("pwsh_run")
    if last is None:
        raise ScriptError("pwsh_run never returned")
    if last.failed:
        raise ScriptError(f"pwsh_run failed: {last.text[:200]}")
    data = last.data
    contained = bool(data.get("contained"))
    tier = str(data.get("tier", ""))
    if not contained or tier not in ("basic", "contained"):
        raise ScriptError(
            f"pwsh_run did not prove containment: contained={contained!r} tier={tier!r}"
        )
    return Reply.text(
        f"Contained run confirmed: the pwsh child reported tier {tier!r} "
        f"(contained={contained!r}) from a Job-Object execution."
    )
