"""Unit tests for the composed argv backend tool (no pwsh required)."""

from __future__ import annotations

from pathlib import Path

import pytest
from kernel.capability_binding import ExecutionFloorView
from kernel.models import ToolExecutionContext

from lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run import (
    Parameters,
    _covering_grant,
    _build_child_argv,
    _writable_grants,
)


def _ctx(floor: ExecutionFloorView | None, parameters: dict) -> ToolExecutionContext:
    return ToolExecutionContext(
        tool_id="pwsh_argv_run",
        parameters=parameters,
        execution_floor_for=(lambda _tool_id: floor) if floor is not None else None,
    )


def test_parameters_reject_empty_argv() -> None:
    with pytest.raises(ValueError):
        Parameters.model_validate({"argv": [], "cwd": "C:\\wt"})


def test_covering_grant_picks_nearest_rw_root() -> None:
    grants = {"C:\\Code": "rw", "C:\\Code\\worktrees": "rw", "C:\\Code\\ro": "ro"}
    grant = _covering_grant(Path("C:\\Code\\worktrees\\wt"), grants)
    assert grant == "C:\\Code\\worktrees"


def test_covering_grant_none_outside_or_under_ro() -> None:
    grants = {"C:\\Code": "rw", "C:\\Other": "ro"}
    assert _covering_grant(Path("C:\\Elsewhere\\wt"), grants) is None
    assert _covering_grant(Path("C:\\Other\\wt"), grants) is None


def test_writable_grants_resolves_floor_paths() -> None:
    floor = ExecutionFloorView(
        execution="sandbox",
        persistence="direct-write",
        paths={"C:\\Code": "rw"},
    )
    grants = _writable_grants(floor)
    assert grants == {"C:\\Code": "rw"}


def test_writable_grants_empty_without_floor() -> None:
    assert _writable_grants(None) == {}


def test_child_argv_quotes_each_word_once() -> None:
    argv = _build_child_argv(["pnpm", "run", "build's script"], "C:\\My Code\\wt")
    assert argv[0].endswith("pwsh") or "pwsh" in argv[0]
    script = argv[-1]
    assert "''" in script  # embedded single quote doubled inside the literal
    assert script.startswith("Set-Location -LiteralPath 'C:\\My Code\\wt'")
    assert script.endswith("& 'pnpm' 'run' 'build''s script'")


def test_child_argv_never_merges_words() -> None:
    argv = _build_child_argv(["echo", "a b", "c;d"], "C:\\wt")
    script = argv[-1]
    assert "'a b'" in script
    assert "'c;d'" in script


@pytest.mark.asyncio
async def test_execute_refuses_cwd_outside_floor(tmp_path: Path) -> None:
    from lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run import execute

    outside = tmp_path / "elsewhere"
    outside.mkdir()
    floor = ExecutionFloorView(
        execution="sandbox",
        persistence="direct-write",
        paths={str(tmp_path / "granted"): "rw"},
    )
    ctx = _ctx(
        floor,
        {"argv": ["pwsh", "-c", "1"], "cwd": str(outside)},
    )
    result = await execute(ctx)
    assert result.error
    assert "rw grant" in result.error
    assert result.output_json["sandboxed"] is False


@pytest.mark.asyncio
async def test_execute_refuses_missing_cwd_without_floor(tmp_path: Path) -> None:
    from lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run import execute

    ctx = _ctx(None, {"argv": ["git", "status"], "cwd": str(tmp_path / "no-such-dir")})
    result = await execute(ctx)
    assert result.error
    assert "not an existing directory" in result.error
    assert result.output_json["sandboxed"] is False


@pytest.mark.asyncio
async def test_execute_reports_invalid_parameters() -> None:
    from lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run import execute

    ctx = _ctx(None, {"cwd": "C:\\wt"})
    result = await execute(ctx)
    assert result.error
    assert "Invalid parameters" in result.error
