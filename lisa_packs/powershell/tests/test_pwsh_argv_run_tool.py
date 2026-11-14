"""Tool-boundary tests for ``pwsh_argv_run`` (no live pwsh/Job Object needed).

The tool is the runner surface a composing pack dispatches to, so what matters
here is the *fail-closed* shapes: no shell, a real cwd requirement, a refused
host without Job Objects, and a result the tool cannot prove.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from kernel.models import ToolExecutionContext

from lisa_packs.powershell.run_argv import ArgvRunResult
from lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run import TOOL_ID, execute


def _ctx(tmp_path: Path, parameters: dict[str, Any]) -> ToolExecutionContext:
    return ToolExecutionContext(
        tool_id=TOOL_ID,
        parameters=parameters,
        data_dir=str(tmp_path),
        mode_id="coding_execute",
        pack_config={},
    )


@pytest.mark.asyncio
async def test_rejects_a_missing_cwd(tmp_path: Path) -> None:
    result = await execute(
        _ctx(tmp_path, {"argv": ["git", "status"], "cwd": str(tmp_path / "gone")})
    )
    assert "cwd does not exist" in result.error


@pytest.mark.asyncio
async def test_fails_closed_when_job_objects_are_unavailable(tmp_path: Path) -> None:
    with patch(
        "lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run.argv_containment_available",
        return_value=False,
    ):
        result = await execute(_ctx(tmp_path, {"argv": ["git", "status"], "cwd": str(tmp_path)}))
    assert "requires Windows" in result.error
    assert result.output_json["sandboxed"] is False


@pytest.mark.asyncio
async def test_reports_an_unproven_run_as_an_error(tmp_path: Path) -> None:
    # The primitive returned without Job Object assignment: the tool must not
    # present that as a usable result.
    unproven = ArgvRunResult(
        return_code=0,
        stdout="ok",
        stderr="",
        contained=False,
        cwd=str(tmp_path),
        writable_paths=(str(tmp_path),),
        tier="basic",
    )
    with (
        patch(
            "lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run.argv_containment_available",
            return_value=True,
        ),
        patch(
            "lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run.run_argv_contained",
            return_value=unproven,
        ),
    ):
        result = await execute(_ctx(tmp_path, {"argv": ["git", "status"], "cwd": str(tmp_path)}))
    assert "could not verify Job Object assignment" in result.error
    assert result.output_json["sandboxed"] is False


@pytest.mark.asyncio
async def test_returns_verified_evidence_for_a_contained_run(tmp_path: Path) -> None:
    contained = ArgvRunResult(
        return_code=0,
        stdout="clean\n",
        stderr="",
        contained=True,
        cwd=str(tmp_path),
        writable_paths=(str(tmp_path),),
        tier="basic",
    )
    with (
        patch(
            "lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run.argv_containment_available",
            return_value=True,
        ),
        patch(
            "lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run.run_argv_contained",
            return_value=contained,
        ),
    ):
        result = await execute(_ctx(tmp_path, {"argv": ["git", "status"], "cwd": str(tmp_path)}))
    assert result.error == ""
    assert result.output_text == "clean\n"
    assert result.output_json["sandboxed"] is True
    assert result.output_json["persistence"] == "direct-write"
    assert result.output_json["writable_paths"] == [str(tmp_path)]


@pytest.mark.asyncio
async def test_parameters_have_no_shell_surface(tmp_path: Path) -> None:
    # A caller passes argv items; extra keys are rejected rather than ignored,
    # so a "command" string can never sneak in as a shell path.
    result = await execute(_ctx(tmp_path, {"command": "git status", "cwd": str(tmp_path)}))
    assert "Invalid parameters" in result.error
