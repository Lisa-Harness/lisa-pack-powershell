"""Bounded command execution in a primed pwsh session.

Builds a wrapper argv per call (state replay -> user script -> sentinel
state-capture block), runs it with drained/truncated output, parses the
sentinel-tagged results, and tees everything to the per-session audit log.
Containment composes in: the wrapper child is Job-Object contained, and
``contained`` sessions additionally wrap the user script in a nested
ConstrainedLanguage runspace inside the wrapper (see the ``%%CLM%%``
branch of ``content/profile/wrapper.ps1.tmpl``).
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import secrets
import shlex
from pathlib import Path
from typing import Any

from kernel.models import ToolExecutionContext

from lisa_packs.powershell.probe import pwsh_exe
from lisa_packs.powershell.session import PwshSession, ps_quote

__all__ = [
    "MAX_BATCH_COMMANDS",
    "MAX_OUTPUT_BYTES",
    "build_wrapper_argv",
    "is_auto_background_guarded",
    "normalize_benign_rc",
    "parse_output",
    "run_batch_in_session",
    "run_in_session",
    "shape_empty_output",
]

MAX_OUTPUT_BYTES = 512_000
MAX_SPILL_BYTES = 64 * 1024 * 1024
MAX_BATCH_COMMANDS = 8

#: Strong references to in-flight job-done publish tasks (RUF006).
_PENDING_JOB_EVENTS: set[asyncio.Task[None]] = set()

_RC_MARKER = re.compile(r"^(?P<sentinel>.+?)rc=(?P<rc>-?\d+)$")
_STATE_CWD = re.compile(r"^(?P<sentinel>.+?)state=cwd=(?P<cwd>.*)$")
_STATE_VAR = re.compile(
    r"^(?P<sentinel>.+?)statevar (?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$"
)
_OUT_OBJ = re.compile(r"^(?P<sentinel>.+?)obj (?P<json>.*)$")
_OUT_TEXT = re.compile(r"^(?P<sentinel>.+?)text (?P<text>.*)$")
_OUT_ERR = re.compile(r"^(?P<sentinel>.+?)err (?P<err>.*)$")

#: Cmdlets whose exit code 1 is an informational answer, not a failure.
BENIGN_RC1_CMDLETS = frozenset(
    {
        "Select-String",
        "Test-Path",
        "Compare-Object",
        "Get-WinEvent",
        "Wait-Job",
        "Receive-Job",
    }
)


def render_wrapper(
    *,
    sentinel: str,
    state_path: Path,
    user_script_path: Path,
    capture_variables: bool,
    clm: bool,
    wait_ms: int,
) -> str:
    """Render ``wrapper.ps1.tmpl`` with per-call substitutions."""
    from lisa_packs.powershell import get_content_root

    template_path = get_content_root() / "content" / "profile" / "wrapper.ps1.tmpl"
    if not template_path.is_file():
        raise RuntimeError(f"powershell pack missing wrapper template: {template_path}")
    body = template_path.read_text(encoding="utf-8")
    return (
        body.replace("%%SENTINEL%%", sentinel)
        .replace("%%STATE_FILE%%", str(state_path))
        .replace("%%USER_SCRIPT%%", str(user_script_path))
        .replace("%%WAIT_MS%%", str(max(wait_ms, 1000)))
        .replace("%%CAPTURE_VARS%%", "true" if capture_variables else "false")
        .replace("%%CLM%%", "1" if clm else "0")
    )


def build_wrapper_argv(
    *,
    pwsh_exe: str,
    user_script: str,
    state_path: Path | None,
    sentinel: str,
    spill_dir: Path,
    capture_variables: bool,
    clm: bool,
    wait_ms: int,
) -> list[str]:
    """Write the user script + rendered wrapper; return the child argv."""
    spill_dir.mkdir(parents=True, exist_ok=True)
    user_path = spill_dir / f"user-{secrets.token_hex(4)}.ps1"
    user_path.write_text(user_script, encoding="utf-8-sig")
    wrapper_path = spill_dir / f"wrap-{secrets.token_hex(4)}.ps1"
    wrapper_path.write_text(
        render_wrapper(
            sentinel=sentinel,
            state_path=state_path or Path("__unused__"),
            user_script_path=user_path,
            capture_variables=capture_variables,
            clm=clm,
            wait_ms=wait_ms,
        ),
        encoding="utf-8-sig",
    )
    return [
        pwsh_exe,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(wrapper_path),
    ]


class ParsedOutput:
    """Structured parse of one command's raw stdout."""

    __slots__ = ("body", "errors", "return_code", "state")

    def __init__(
        self,
        *,
        body: str,
        return_code: int | None,
        state: dict[str, Any] | None = None,
    ) -> None:
        self.body = body
        self.return_code = return_code
        self.state: dict[str, Any] = state or {}
        self.errors: list[str] = []


def parse_output(raw: str, sentinel: str) -> ParsedOutput:
    """Strip sentinel and split wrapper output into body/state/errors.

    Wrapper contract — sentinel-tagged lines are:
    - ``<sentinel>obj <json>``     one pipeline object (JSON)
    - ``<sentinel>text <line>``    one rendered output line
    - ``<sentinel>err <line>``     one error record
    - ``<sentinel>state=cwd=<path>``
    - ``<sentinel>statevar NAME=<value>``
    - ``<sentinel>rc=<int>``       final exit status
    ``body`` re-renders the object/text lines (JSON objects inline);
    ``state`` carries cwd + named-variable delta; ``errors`` carries err
    lines separately so stdout stays clean.
    """
    parts = _split_wrapper_lines(raw, sentinel)
    state: dict[str, Any] = {}
    if parts["cwd"]:
        state["cwd"] = parts["cwd"]
    if parts["variables"]:
        state["variables"] = parts["variables"]
    parsed = ParsedOutput(
        body="\n".join(parts["body"]).strip("\n"), return_code=parts["rc"], state=state
    )
    parsed.errors = parts["errors"]
    return parsed


def _split_wrapper_lines(raw: str, sentinel: str) -> dict[str, Any]:
    """One pass over wrapper lines accumulating all parse buckets."""
    rc: int | None = None
    cwd = ""
    variables: dict[str, str] = {}
    body_lines: list[str] = []
    errors: list[str] = []
    for line in raw.splitlines():
        kind, value = _classify_tagged(line, sentinel)
        if kind == "rc":
            with contextlib.suppress(ValueError):
                rc = int(value)
        elif kind == "cwd":
            cwd = value.strip("'")
        elif kind == "var":
            name, _, val = value.partition("=")
            variables[name] = val
        elif kind == "machinery":
            continue
        elif kind in ("obj", "text"):
            body_lines.append(value)
        elif kind == "err":
            errors.append(value)
        else:
            body_lines.append(line)
    return {
        "rc": rc,
        "cwd": cwd,
        "variables": variables,
        "body": body_lines,
        "errors": errors,
    }


def _classify_tagged(line: str, sentinel: str) -> tuple[str, str]:
    """Return (kind, value) for one wrapper line; kind '' = plain body line."""
    if sentinel not in line:
        return "", ""
    for pattern, kind, value_group in (
        (_RC_MARKER, "rc", "rc"),
        (_STATE_CWD, "cwd", "cwd"),
        (_STATE_VAR, "var", "name"),
        (_OUT_OBJ, "obj", "json"),
        (_OUT_TEXT, "text", "text"),
        (_OUT_ERR, "err", "err"),
    ):
        match = pattern.match(line)
        if match:
            if kind == "var":
                return kind, f"{match.group('name')}={match.group('value')}"
            return kind, str(match.groupdict().get(value_group, ""))
    return "machinery", ""


def shape_empty_output(stdout: str, stderr: str, return_code: int) -> str:
    """Explicit message for a silent success (never a hang)."""
    if return_code == 0 and not stdout.strip() and not stderr.strip():
        return "(your command ran successfully and produced no output)"
    return stdout


def normalize_benign_rc(command: str, return_code: int) -> str | None:
    """Note text when rc=1 is informational for this command."""
    if return_code != 1:
        return None
    stripped = command.strip()
    first = stripped.split(maxsplit=1)[0] if stripped else ""
    if first in BENIGN_RC1_CMDLETS:
        return (
            f"exit 1 from {first!r} is informational here (e.g. no matches), "
            "not a failure; read the output for the answer."
        )
    return None


def is_auto_background_guarded(command: str) -> bool:
    """True when a command must never be auto-backgrounded on timeout."""
    stripped = command.strip()
    if stripped.lower().startswith("start-sleep"):
        return True
    try:
        tokens = shlex.split(stripped, posix=False)
    except ValueError:
        tokens = stripped.split()
    return any(token.lower().strip("'\"") in ("git", "msiexec") for token in tokens)


def _append_log(log_path: Path, command: str, result: dict[str, Any]) -> None:
    """Append command + output to the user-visible audit log."""
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"PS> {command}\n")
            out = result.get("stdout", "")
            if out:
                handle.write(out + ("" if str(out).endswith("\n") else "\n"))
            err = result.get("stderr", "")
            if err:
                handle.write("[stderr] " + str(err).replace("\n", "\n[stderr] ") + "\n")
            handle.write(
                f"[rc={result.get('return_code')} timed_out={result.get('timed_out')} "
                f"contained={result.get('contained')}]\n"
            )
    except OSError:
        # Logging must never fail the tool call.
        return


async def _drain(
    stream: asyncio.StreamReader,
    spill_path: Path,
    *,
    inline_limit: int = MAX_OUTPUT_BYTES,
    spill_limit: int = MAX_SPILL_BYTES,
) -> dict[str, Any]:
    """Drain a stream fully to ``spill_path`` while retaining an inline head."""
    inline = bytearray()
    overflowed = False
    total = 0
    spill_path.parent.mkdir(parents=True, exist_ok=True)
    with spill_path.open("wb") as handle:
        while chunk := await stream.read(8192):
            total += len(chunk)
            if total <= spill_limit:
                handle.write(chunk)
            else:
                overflowed = True
            inline_remaining = inline_limit - len(inline)
            if inline_remaining > 0:
                inline.extend(chunk[:inline_remaining])
    if total > inline_limit:
        overflowed = True
    return {
        "inline": inline.decode("utf-8", errors="replace"),
        "output_path": str(spill_path),
        "output_bytes": total,
        "truncated": overflowed or len(inline) >= inline_limit,
    }


async def _run_process(
    argv: list[str],
    *,
    timeout_seconds: int | None,
    spill_dir: Path,
    ctx: ToolExecutionContext | None = None,
    sentinel: str = "",
) -> dict[str, Any]:
    """Run the wrapper argv, draining + spilling both streams."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    spill_dir.mkdir(parents=True, exist_ok=True)
    stamp = secrets.token_hex(4)
    stdout_path = spill_dir / f"stdout-{stamp}.log"
    stderr_path = spill_dir / f"stderr-{stamp}.log"
    stdout_task = asyncio.create_task(_drain(proc.stdout, stdout_path))
    stderr_task = asyncio.create_task(_drain(proc.stderr, stderr_path))
    timed_out = False
    try:
        if timeout_seconds is None:
            await proc.wait()
        else:
            await asyncio.wait_for(proc.wait(), timeout=timeout_seconds)
    except TimeoutError:
        timed_out = True
        proc.kill()
    stdout = await stdout_task
    stderr = await stderr_task
    return {
        "stdout_raw": stdout["inline"],
        "stderr": stderr["inline"],
        "stdout_path": stdout["output_path"],
        "stderr_path": stderr["output_path"],
        "stdout_bytes": stdout["output_bytes"],
        "stderr_bytes": stderr["output_bytes"],
        "timed_out": timed_out,
        "truncated": stdout["truncated"] or stderr["truncated"],
        "process_rc": proc.returncode,
    }


def _publish_job_done(
    ctx: ToolExecutionContext,
    *,
    job_id: str,
    rc: int | None,
    killed: bool,
    log_path: Path,
    command: str,
) -> None:
    """Best-effort job completion event on the session event bus."""
    bus = getattr(ctx, "event_bus", None)
    if bus is None or not hasattr(bus, "publish"):
        return
    payload: dict[str, Any] = {
        "job_id": job_id,
        "rc": rc,
        "killed": killed,
        "log_path": str(log_path),
        "command": command[:200],
    }

    async def _pub() -> None:
        with contextlib.suppress(Exception):
            await bus.publish("lisa.pwsh.job_done", payload)

    with contextlib.suppress(Exception):
        task = asyncio.create_task(_pub())
        _PENDING_JOB_EVENTS.add(task)
        task.add_done_callback(_PENDING_JOB_EVENTS.discard)


async def _run_background_command(
    ctx: ToolExecutionContext,
    session: PwshSession,
    *,
    command: str,
    argv: list[str],
    log_path: Path,
    rc_path: Path,
    job_id: str,
) -> None:
    """Run one backgrounded command to completion, teeing output to log_path."""
    rc = -1
    killed = False
    try:
        proc = await _run_process(
            argv,
            timeout_seconds=None,
            spill_dir=log_path.parent,
            ctx=ctx,
            sentinel=session.sentinel,
        )
        stdout_raw = proc["stdout_raw"]
        stderr = proc["stderr"]
        raw_rc = proc.get("process_rc")
        if raw_rc is None:
            parsed = parse_output(stdout_raw, session.sentinel)
            rc = parsed.return_code if parsed.return_code is not None else -1
        else:
            rc = int(raw_rc)
        _write_log_entry(
            log_path,
            command,
            stdout_raw,
            stderr,
            f"[rc={rc} timed_out={proc['timed_out']} job={job_id}]",
        )
        with contextlib.suppress(OSError):
            rc_path.write_text(str(rc), encoding="utf-8")
    except Exception as exc:
        _write_log_entry(log_path, command, "", "", f"[pwsh-job error] {exc}")
        with contextlib.suppress(OSError):
            rc_path.write_text(str(rc), encoding="utf-8")
    finally:
        session.complete_job(job_id, rc=rc, killed=killed)
        _publish_job_done(
            ctx, job_id=job_id, rc=rc, killed=killed, log_path=log_path, command=command
        )


def _write_log_entry(
    log_path: Path,
    command: str,
    stdout_raw: str,
    stderr: str,
    tail_line: str,
) -> None:
    """One audit-log entry block; failures are swallowed."""
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"PS> {command}\n")
            if stdout_raw:
                handle.write(stdout_raw + "\n")
            if stderr:
                handle.write("[stderr] " + stderr.replace("\n", "\n[stderr] ") + "\n")
            handle.write(tail_line + "\n")
    except OSError:
        return


async def _run_process_with_auto_bg(
    ctx: ToolExecutionContext,
    session: PwshSession,
    command: str,
    argv: list[str],
    *,
    timeout_seconds: int,
    spill_dir: Path,
) -> dict[str, Any]:
    """Foreground run that auto-backgrounds on timeout instead of killing."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stdout is not None and proc.stderr is not None
    stamp = secrets.token_hex(4)
    stdout_path = spill_dir / f"stdout-{stamp}.log"
    stderr_path = spill_dir / f"stderr-{stamp}.log"
    stdout_task = asyncio.create_task(_drain(proc.stdout, stdout_path))
    stderr_task = asyncio.create_task(_drain(proc.stderr, stderr_path))
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_seconds)
    except TimeoutError:
        return await _adopt_as_job(
            ctx,
            session,
            command=command,
            proc=proc,
            stdout_task=stdout_task,
            stderr_task=stderr_task,
            timeout_seconds=timeout_seconds,
        )
    stdout = await stdout_task
    stderr = await stderr_task
    return {
        "stdout_raw": stdout["inline"],
        "stderr": stderr["inline"],
        "stdout_path": stdout["output_path"],
        "stderr_path": stderr["output_path"],
        "stdout_bytes": stdout["output_bytes"],
        "stderr_bytes": stderr["output_bytes"],
        "timed_out": False,
        "truncated": stdout["truncated"] or stderr["truncated"],
        "process_rc": proc.returncode,
    }


async def _adopt_as_job(
    ctx: ToolExecutionContext,
    session: PwshSession,
    *,
    command: str,
    proc: asyncio.subprocess.Process,
    stdout_task: asyncio.Task[dict[str, Any]],
    stderr_task: asyncio.Task[dict[str, Any]],
    timeout_seconds: int,
) -> dict[str, Any]:
    """Register the still-running child as a background job; return descriptor."""
    job_id = f"j{secrets.token_hex(6)}"
    log_path, rc_path, status_path = session.job_artifacts(job_id)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    async def _collect() -> None:
        await proc.wait()
        stdout = await stdout_task
        stderr = await stderr_task
        rc = proc.returncode if proc.returncode is not None else -1
        _write_log_entry(
            log_path,
            command,
            stdout["inline"],
            stderr["inline"],
            f"[rc={rc} auto_backgrounded=1 job={job_id}]",
        )
        with contextlib.suppress(OSError):
            rc_path.write_text(str(rc), encoding="utf-8")
        session.complete_job(job_id, rc=rc, killed=False)
        _publish_job_done(
            ctx, job_id=job_id, rc=rc, killed=False, log_path=log_path, command=command
        )

    collector = asyncio.create_task(_collect(), name=f"lisa-pwsh-job-{job_id}")
    session.register_job(job_id, {"task": collector})
    return {
        "backgrounded": True,
        "auto_backgrounded_on_timeout": True,
        "job_id": job_id,
        "log_path": str(log_path),
        "rc_path": str(rc_path),
        "status_path": str(status_path),
        "timeout_seconds": timeout_seconds,
        "command": command,
        "contained": session.contained,
        "background_jobs": session.jobs_summary(),
    }


def _start_background_job(
    ctx: ToolExecutionContext, session: PwshSession, command: str, argv: list[str]
) -> dict[str, Any]:
    """Spawn a host-side background job; return its descriptor."""
    job_id = f"j{secrets.token_hex(6)}"
    log_path, rc_path, status_path = session.job_artifacts(job_id)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    task = asyncio.create_task(
        _run_background_command(
            ctx,
            session,
            command=command,
            argv=argv,
            log_path=log_path,
            rc_path=rc_path,
            job_id=job_id,
        ),
        name=f"lisa-pwsh-job-{job_id}",
    )
    session.register_job(job_id, {"task": task})
    return {
        "backgrounded": True,
        "job_id": job_id,
        "log_path": str(log_path),
        "rc_path": str(rc_path),
        "status_path": str(status_path),
        "status": "running",
        "command": command,
        "contained": session.contained,
        "background_jobs": session.jobs_summary(),
    }


async def _run_foreground(
    ctx: ToolExecutionContext,
    session: PwshSession,
    *,
    command: str,
    argv: list[str],
    timeout_seconds: int,
    spill_dir: Path,
) -> dict[str, Any]:
    """Guard-aware foreground run; auto-backgrounds unless guarded."""
    if is_auto_background_guarded(command):
        return await _run_process(
            argv,
            timeout_seconds=timeout_seconds,
            spill_dir=spill_dir,
            ctx=ctx,
            sentinel=session.sentinel,
        )
    return await _run_process_with_auto_bg(
        ctx, session, command, argv, timeout_seconds=timeout_seconds, spill_dir=spill_dir
    )


def _foreground_result(
    session: PwshSession, command: str, proc: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse + shape one finished foreground run; return (state, result)."""
    parsed = parse_output(proc["stdout_raw"], session.sentinel)
    rc = parsed.return_code
    if rc is None:
        rc = proc.get("process_rc")
    result: dict[str, Any] = {
        "stdout": parsed.body,
        "stderr": proc["stderr"],
        "return_code": rc if rc is not None else 0,
        "timed_out": proc["timed_out"],
        "truncated": proc["truncated"],
        "contained": session.contained,
    }
    if parsed.errors:
        result["errors"] = parsed.errors
    if proc.get("truncated"):
        for spill_key in ("stdout_path", "stderr_path", "stdout_bytes", "stderr_bytes"):
            result[spill_key] = proc[spill_key]
    _shape_result(result, command)
    return parsed.state, result


def _shape_result(result: dict[str, Any], command: str) -> None:
    """Apply the empty-output and benign-rc1 shaping notes."""
    if result["stdout"] == "":
        shaped = shape_empty_output("", result.get("stderr", ""), result["return_code"])
        if shaped:
            result["note"] = shaped
    benign = normalize_benign_rc(command, result["return_code"])
    if benign:
        result["note"] = f"{result.get('note', '')} {benign}".strip()


def _record_and_log(
    session: PwshSession,
    command: str,
    state: dict[str, Any],
    result: dict[str, Any],
    *,
    record_state: bool,
) -> None:
    """Persist the state delta (policy-permitted) and append the audit log."""
    cwd = state.get("cwd", "")
    if record_state:
        session.record_post_run_state(cwd=cwd, variables=state.get("variables") or {})
    if cwd:
        result["cwd"] = cwd
    jobs = session.jobs_summary()
    if jobs:
        result["background_jobs"] = jobs
    _append_log(session.log_path, command, result)


async def run_in_session(
    ctx: ToolExecutionContext,
    session: PwshSession,
    command: str,
    *,
    timeout_seconds: int,
    run_in_background: bool = False,
    record_state: bool = True,
) -> dict[str, Any]:
    """Run a script block in the session.

    Contained sessions wrap the user script in a nested CLM runspace inside
    the wrapper child; bare sessions run it at full language. Both paths
    auto-background on timeout.
    """
    spill_dir = session.jobs_dir
    spill_dir.mkdir(parents=True, exist_ok=True)
    argv = build_wrapper_argv(
        pwsh_exe=pwsh_exe(),
        user_script=command,
        state_path=session.priming.state_path,
        sentinel=session.sentinel,
        spill_dir=spill_dir,
        capture_variables=session._state_policy["variables"],
        clm=session.contained,
        wait_ms=timeout_seconds * 1000,
    )
    if run_in_background:
        return _start_background_job(ctx, session, command, argv)
    try:
        proc = await _run_foreground(
            ctx,
            session,
            command=command,
            argv=argv,
            timeout_seconds=timeout_seconds,
            spill_dir=spill_dir,
        )
    except Exception as exc:
        return {"error": f"pwsh execution failed: {exc}", "contained": session.contained}
    if proc.get("backgrounded"):
        return proc
    state, result = _foreground_result(session, command, proc)
    _record_and_log(session, command, state, result, record_state=record_state)
    return result


async def run_batch_in_session(
    ctx: ToolExecutionContext,
    session: PwshSession,
    commands: list[str],
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Run ``commands`` as independent children against a state snapshot.

    Children run sequentially (the simplest safe default); variable deltas
    are discarded, cwd adopted only when every child agrees. Commands must
    be pre-quoted with :func:`ps_quote`-style literals by the caller? No —
    the caller passes raw script text; each child writes its own user file.
    """
    if not commands:
        return {"error": "commands must be a non-empty list"}
    if len(commands) > MAX_BATCH_COMMANDS:
        return {"error": f"commands is capped at {MAX_BATCH_COMMANDS} (got {len(commands)})"}

    results = [
        await _batch_child(ctx, session, index, command, timeout_seconds)
        for index, command in enumerate(commands)
    ]
    return _batch_envelope(session, results)


async def _batch_child(
    ctx: ToolExecutionContext,
    session: PwshSession,
    index: int,
    command: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    """One batch child: run against the shared state snapshot."""
    item = await run_in_session(
        ctx, session, command, timeout_seconds=timeout_seconds, record_state=False
    )
    item["index"] = index
    item["command"] = command
    return item


def _batch_envelope(session: PwshSession, results: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble the batch result; adopt an agreed cwd."""
    cwds = [str(item["cwd"]) for item in results if item.get("cwd")]
    notes: list[str] = []
    if cwds and len(set(cwds)) == 1:
        session.apply_cwd(cwds[0])
        notes.append(
            f"cwd adopted ({cwds[0]}) because every command agreed; "
            "variable deltas from the batch were discarded"
        )
    else:
        notes.append(
            "session cwd/variables unchanged (batch ran against a snapshot; "
            "variable deltas discarded" + ("" if not cwds else "; child cwds disagreed") + ")"
        )
    return {
        "batch": True,
        "when": "serial",
        "results": results,
        "contained": session.contained,
        "note": " ".join(notes),
        "stdout": "",
        "stderr": "",
        "return_code": max((item.get("return_code") or 0) for item in results) if results else 0,
        "timed_out": any(bool(item.get("timed_out")) for item in results),
        "truncated": any(bool(item.get("truncated")) for item in results),
    }


def _unused_ps_quote() -> str:
    return ps_quote("keeps the import referenced for re-exports")
