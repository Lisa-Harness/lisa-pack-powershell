"""Tool-boundary tests with mocked subprocesses (no live pwsh needed)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from kernel.models import ToolExecutionContext

from lisa_packs.powershell import executor as executor_mod
from lisa_packs.powershell.session import (
    _SESSIONS,
    _reset_sessions,
    resolve_or_create_session,
)
from lisa_packs.powershell.tools.pwsh_run.pwsh_run import TOOL_ID, execute

FakeRun = Callable[..., Awaitable[dict[str, Any]]]


def _ctx(tmp_path: Path) -> ToolExecutionContext:
    return ToolExecutionContext(
        tool_id=TOOL_ID,
        data_dir=str(tmp_path),
        mode_id="shell_pwsh",
        query="test",
        pack_config={},
    )


def _current_sentinel() -> str:
    """The cached session's sentinel (parse keys on it, not a constant)."""
    (session,) = _SESSIONS.values()
    assert isinstance(session.sentinel, str)
    return session.sentinel


def _fake_auto_bg(fake_run: FakeRun) -> Callable[..., Awaitable[dict[str, Any]]]:
    """Adapt a _fake_run into a _run_process_with_auto_bg signature."""

    async def _auto_bg(
        ctx: ToolExecutionContext,
        session: object,
        command: str,
        argv: list[str],
        *,
        timeout_seconds: int,
        spill_dir: Path,
    ) -> dict[str, Any]:
        return await fake_run(argv, timeout_seconds=timeout_seconds, spill_dir=spill_dir)

    return _auto_bg


def _fake_stdout(body: str, *, rc: int = 0, cwd: str = "C:\\tmp") -> bytes:
    sentinel = _current_sentinel()
    return (f"{body}\n{sentinel}state=cwd={cwd}\n{sentinel}rc={rc}\n").encode()


def _proc_payload(stdout_raw: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "stdout_raw": stdout_raw,
        "stderr": "",
        "stdout_path": "",
        "stderr_path": "",
        "stdout_bytes": len(stdout_raw),
        "stderr_bytes": 0,
        "timed_out": False,
        "truncated": False,
        "process_rc": 0,
    }
    base.update(over)
    return base


def _fake_run_from(payload: dict[str, Any]) -> FakeRun:
    async def _fake_run(
        argv: list[str],
        *,
        timeout_seconds: int,
        spill_dir: Path,
        ctx: ToolExecutionContext | None = None,
        sentinel: str = "",
    ) -> dict[str, Any]:
        return payload

    return _fake_run


@pytest.mark.asyncio
async def test_execute_happy_path(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    resolve_or_create_session(ctx, contained=False)
    payload = _proc_payload(_fake_stdout("hi from pwsh").decode("utf-8"))
    with (
        patch.object(executor_mod, "pwsh_exe", lambda: "pwsh"),
        patch.object(executor_mod, "_run_process", _fake_run_from(payload)),
        patch.object(
            executor_mod, "_run_process_with_auto_bg", _fake_auto_bg(_fake_run_from(payload))
        ),
    ):
        result = await execute(
            ctx.model_copy(update={"parameters": {"command": "Write-Output hi"}})
        )
    assert result.error == ""
    assert "hi from pwsh" in result.output_text
    assert result.output_json["return_code"] == 0


@pytest.mark.asyncio
async def test_execute_invalid_params(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    result = await execute(ctx.model_copy(update={"parameters": {}}))
    assert "Invalid parameters" in result.error


@pytest.mark.asyncio
async def test_command_error_rc1(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    resolve_or_create_session(ctx, contained=False)
    payload = _proc_payload(
        _fake_stdout("", rc=1).decode("utf-8"),
        stderr="boom",
        stderr_bytes=4,
        process_rc=1,
    )
    with (
        patch.object(executor_mod, "pwsh_exe", lambda: "pwsh"),
        patch.object(executor_mod, "_run_process", _fake_run_from(payload)),
        patch.object(
            executor_mod, "_run_process_with_auto_bg", _fake_auto_bg(_fake_run_from(payload))
        ),
    ):
        result = await execute(ctx.model_copy(update={"parameters": {"command": "throw 'x'"}}))
    assert result.output_json["return_code"] == 1


@pytest.mark.asyncio
async def test_state_carries_between_calls(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    session = resolve_or_create_session(ctx, contained=False)
    payload = _proc_payload(_fake_stdout("x", cwd="C:\\moved").decode("utf-8"))
    with (
        patch.object(executor_mod, "pwsh_exe", lambda: "pwsh"),
        patch.object(executor_mod, "_run_process", _fake_run_from(payload)),
        patch.object(
            executor_mod, "_run_process_with_auto_bg", _fake_auto_bg(_fake_run_from(payload))
        ),
    ):
        await execute(ctx.model_copy(update={"parameters": {"command": "Set-Location C:\\moved"}}))
    state_content = session.priming.state_path.read_text(encoding="utf-8-sig")
    assert "C:\\moved" in state_content


@pytest.mark.asyncio
async def test_batch_agrees_on_cwd(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    resolve_or_create_session(ctx, contained=False)
    payload = _proc_payload(_fake_stdout("x", cwd="C:\\agreed").decode("utf-8"))
    with (
        patch.object(executor_mod, "pwsh_exe", lambda: "pwsh"),
        patch.object(executor_mod, "_run_process", _fake_run_from(payload)),
        patch.object(
            executor_mod, "_run_process_with_auto_bg", _fake_auto_bg(_fake_run_from(payload))
        ),
    ):
        result = await execute(ctx.model_copy(update={"parameters": {"commands": ["a", "b"]}}))
    assert result.output_json["batch"] is True
    assert result.output_json["return_code"] == 0
    assert "cwd adopted" in result.output_json["shaping_note"]


@pytest.mark.asyncio
async def test_batch_disagrees_keeps_session(tmp_path: Path) -> None:
    _reset_sessions()
    ctx = _ctx(tmp_path)
    resolve_or_create_session(ctx, contained=False)
    calls = {"n": 0}

    async def _fake_run(
        argv: list[str],
        *,
        timeout_seconds: int,
        spill_dir: Path,
        ctx: ToolExecutionContext | None = None,
        sentinel: str = "",
    ) -> dict[str, Any]:
        calls["n"] += 1
        cwd = "C:\\one" if calls["n"] == 1 else "C:\\two"
        return _proc_payload(_fake_stdout("x", cwd=cwd).decode("utf-8"))

    with (
        patch.object(executor_mod, "pwsh_exe", lambda: "pwsh"),
        patch.object(executor_mod, "_run_process", _fake_run),
        patch.object(executor_mod, "_run_process_with_auto_bg", _fake_auto_bg(_fake_run)),
    ):
        result = await execute(ctx.model_copy(update={"parameters": {"commands": ["a", "b"]}}))
    assert "cwd/variables unchanged" in result.output_json["shaping_note"]
