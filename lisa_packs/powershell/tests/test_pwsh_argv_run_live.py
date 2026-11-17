"""Live tests for the composed argv backend (real pwsh + Job Object)."""

from __future__ import annotations

from pathlib import Path

import pytest
from kernel.capability_binding import ExecutionFloorView
from kernel.models import ToolExecutionContext

pytestmark = pytest.mark.live


def _ctx(
    tmp_path: Path,
    floor: ExecutionFloorView | None,
    parameters: dict,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        tool_id="pwsh_argv_run",
        parameters=parameters,
        execution_floor_for=(lambda _tool_id: floor) if floor is not None else None,
    )


def _floor(tmp_path: Path) -> ExecutionFloorView:
    return ExecutionFloorView(
        execution="sandbox",
        persistence="direct-write",
        paths={str(tmp_path): "rw"},
    )


@pytest.mark.asyncio
async def test_live_run_argv_in_granted_cwd(tmp_path: Path) -> None:
    from lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run import execute

    result = await execute(
        _ctx(
            tmp_path,
            _floor(tmp_path),
            {
                "argv": ["pwsh", "-NoProfile", "-Command", "Write-Output 'argv-ok'"],
                "cwd": str(tmp_path),
                "timeout_seconds": 60,
            },
        )
    )
    assert result.error == "", result.output_json
    assert result.output_json["sandboxed"] is True
    assert result.output_json["tier"] == "basic"
    assert result.output_json["persistence"] == "direct-write"
    assert "argv-ok" in result.output_text


@pytest.mark.asyncio
async def test_live_child_writes_are_real(tmp_path: Path) -> None:
    from lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run import execute

    target = tmp_path / "marker.txt"
    result = await execute(
        _ctx(
            tmp_path,
            _floor(tmp_path),
            {
                "argv": [
                    "pwsh",
                    "-NoProfile",
                    "-Command",
                    f"Set-Content -Path 'marker.txt' -Value 'direct' -Encoding utf8",
                ],
                "cwd": str(tmp_path),
                "timeout_seconds": 60,
            },
        )
    )
    assert result.error == "", result.output_json
    assert target.is_file()
    assert "direct" in target.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_live_job_object_kills_tree_on_timeout(tmp_path: Path) -> None:
    """The child tree cannot outlive the call: kill-on-close via termination."""
    from lisa_packs.powershell.tools.pwsh_argv_run.pwsh_argv_run import execute

    result = await execute(
        _ctx(
            tmp_path,
            _floor(tmp_path),
            {
                "argv": [
                    "pwsh",
                    "-NoProfile",
                    "-Command",
                    "Start-Sleep -Seconds 60",
                ],
                "cwd": str(tmp_path),
                "timeout_seconds": 3,
            },
        )
    )
    assert result.output_json["timed_out"] is True
    assert result.output_json["sandboxed"] is True
