"""Session management tests: state file, jobs, containment fact."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kernel.capability_binding import ExecutionFloorView
from kernel.models import ToolExecutionContext

from lisa_packs.powershell.session import (
    _reset_sessions,
    ps_quote,
    resolve_or_create_session,
)


def _ctx(tmp_path: Path) -> ToolExecutionContext:
    return ToolExecutionContext(
        tool_id="pwsh_run",
        data_dir=str(tmp_path),
        mode_id="shell_pwsh",
        query="test",
    )


TEST_RC = 7


def test_ps_quote_escapes_single_quotes() -> None:
    assert ps_quote("it's") == "'it''s'"
    assert ps_quote("plain") == "'plain'"


def test_session_created_and_cached(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    session = resolve_or_create_session(ctx)
    again = resolve_or_create_session(ctx)
    assert session is again
    assert session.session_key


def test_state_file_records_cwd_and_vars(tmp_path: Path) -> None:
    _reset_sessions()
    session = resolve_or_create_session(_ctx(tmp_path))
    session.record_post_run_state(cwd="C:\\some\\path", variables={"MYVAR": "value 'with' quote"})
    content = session.priming.state_path.read_text(encoding="utf-8-sig")
    assert "Set-Location -LiteralPath 'C:\\some\\path'" in content
    assert "$MYVAR = 'value ''with'' quote'" in content


def test_state_policy_can_drop_cwd(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    ctx = ctx.model_copy(update={"pack_config": {"session_state": {"cwd": False}}})
    session = resolve_or_create_session(ctx)
    session.record_post_run_state(cwd="C:\\x", variables={})
    content = session.priming.state_path.read_text(encoding="utf-8-sig")
    assert "Set-Location" not in content


def test_apply_cwd_replaces_only_location_line(tmp_path: Path) -> None:
    _reset_sessions()
    session = resolve_or_create_session(_ctx(tmp_path))
    session.record_post_run_state(cwd="C:\\old", variables={"A": "1"})
    session.apply_cwd("C:\\new")
    content = session.priming.state_path.read_text(encoding="utf-8-sig")
    assert "Set-Location -LiteralPath 'C:\\new'" in content
    assert "C:\\old" not in content
    assert "$A = '1'" in content


def test_job_registry_roundtrip(tmp_path: Path) -> None:
    _reset_sessions()
    session = resolve_or_create_session(_ctx(tmp_path))
    session.register_job("jabc", {"command": "dummy"})
    _log, _rc, status = session.job_artifacts("jabc")
    status_payload = json.loads(status.read_text(encoding="utf-8"))
    assert status_payload["state"] == "running"
    session.complete_job("jabc", rc=TEST_RC, killed=False)
    status_payload = json.loads(status.read_text(encoding="utf-8"))
    assert status_payload["state"] == "done"
    assert status_payload["rc"] == TEST_RC
    assert "jabc" not in session.jobs


def test_containment_fact_published(tmp_path: Path) -> None:
    _reset_sessions()
    session = resolve_or_create_session(_ctx(tmp_path))
    fact_path = session.data_dir / "run" / session.session_key / "sandbox-facts.json"
    assert fact_path.is_file()
    fact = json.loads(fact_path.read_text(encoding="utf-8"))
    assert fact["tool_id"] == "pwsh_run"
    assert fact["containment"] in ("contained", "none", "deliberate_bare")


def _bare_floor() -> Any:
    """A floor double with execution='bare'."""
    return ExecutionFloorView(
        execution="bare", persistence=None, paths={}, network=None, device=None, ipc=None
    )


def test_deliberate_bare_stamp(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    ctx = ctx.model_copy(update={"execution_floor_for": lambda _tool_id: _bare_floor()})
    session = resolve_or_create_session(ctx)
    fact_path = session.data_dir / "run" / session.session_key / "sandbox-facts.json"
    fact = json.loads(fact_path.read_text(encoding="utf-8"))
    assert fact["containment"] == "deliberate_bare"


def test_contained_property_updates_in_place(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    session = resolve_or_create_session(ctx, contained=False)
    assert session.contained is False
    again = resolve_or_create_session(ctx, contained=True)
    assert session is again and session.contained is True
