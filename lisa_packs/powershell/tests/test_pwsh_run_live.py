"""Live wrapper tests: real pwsh children (marked ``live``).

Run with ``pytest -m live``. Exercises: bare full-language execution, state
carry, and Job Object kill semantics against the real host.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from kernel.models import ToolExecutionContext

from lisa_packs.powershell.executor import run_in_session
from lisa_packs.powershell.probe import probe_capabilities
from lisa_packs.powershell.session import PwshSession


def _ctx(tmp_path: Path, contained: bool) -> ToolExecutionContext:
    return ToolExecutionContext(
        tool_id="pwsh_run",
        data_dir=str(tmp_path),
        mode_id="shell_pwsh",
        query="live",
    )


pytestmark = pytest.mark.live


def _session(tmp_path: Path, contained: bool) -> PwshSession:
    """Resolve a session for tests (identity key stable per tmp_path)."""
    from lisa_packs.powershell.session import resolve_or_create_session

    ctx = _ctx(tmp_path, contained)
    ctx = ctx.model_copy(update={"user_id": f"live-{int(contained)}"})
    return resolve_or_create_session(ctx, contained=contained)


@pytest.mark.asyncio
async def test_live_bare_hello(tmp_path: Path) -> None:
    session = _session(tmp_path, contained=False)
    result = await run_in_session(
        _ctx(tmp_path, contained=False),
        session,
        "Write-Output 'hello-live'",
        timeout_seconds=30,
    )
    assert result["return_code"] == 0
    assert "hello-live" in result["stdout"]


@pytest.mark.asyncio
async def test_live_state_carry_cwd(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, contained=False)
    session = _session(tmp_path, contained=False)
    first = await run_in_session(
        ctx,
        session,
        "Set-Location $env:TEMP; Get-Location | Select-Object -ExpandProperty Path",
        timeout_seconds=30,
    )
    assert first["return_code"] == 0
    assert first.get("cwd")
    second = await run_in_session(
        ctx,
        session,
        "Get-Location | Select-Object -ExpandProperty Path",
        timeout_seconds=30,
    )
    assert second["return_code"] == 0
    assert second.get("cwd") == first.get("cwd")


@pytest.mark.asyncio
async def test_live_var_carry(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, contained=False)
    session = _session(tmp_path, contained=False)
    await run_in_session(ctx, session, "$LISA_TEST_VAR = 'carries'", timeout_seconds=30)
    out = await run_in_session(ctx, session, "Write-Output $LISA_TEST_VAR", timeout_seconds=30)
    assert "carries" in out["stdout"]


@pytest.mark.asyncio
async def test_live_contained_clm_blocks_dotnet(tmp_path: Path) -> None:
    probe = await probe_capabilities()
    if not probe.contained_runnable:
        pytest.skip("CLM engine unavailable on this host")
    ctx = _ctx(tmp_path, contained=True)
    session = _session(tmp_path, contained=True)
    result = await run_in_session(
        ctx,
        session,
        "try { [Environment]::GetFolderPath('ProgramFiles'); Write-Output 'LEAKED' } "
        "catch { Write-Output 'CLM-BLOCKED' }",
        timeout_seconds=60,
    )
    assert "CLM-BLOCKED" in result["stdout"]
    assert "LEAKED" not in result["stdout"]


@pytest.mark.asyncio
async def test_live_job_object_kills_tree(tmp_path: Path) -> None:
    probe = await probe_capabilities()
    if not probe.basic_runnable:
        pytest.skip("Job Object API unavailable")
    from lisa_packs.powershell.winjob import (
        assign_process_to_job,
        close_job,
        create_contained_job,
        job_processes,
        terminate_job,
    )

    job = create_contained_job(max_processes=4, memory_mb=512)
    assert job
    try:
        proc = await asyncio.create_subprocess_exec(
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 30",
        )
        assert assign_process_to_job(job, proc.pid)
        pids = job_processes(job)
        assert proc.pid in pids
        terminate_job(job)
        await asyncio.wait_for(proc.wait(), timeout=10)
        assert proc.returncode not in (0, None)
    finally:
        close_job(job)
