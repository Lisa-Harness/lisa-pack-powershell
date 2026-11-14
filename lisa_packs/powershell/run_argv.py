"""Run one explicit argv under the powershell pack's containment.

The bash pack on POSIX composes through bubblewrap for contained argv
execution; Windows has no bwrap, so this module is the equivalent
*containment primitive* for an argv: it spawns the process inside a Job
Object (kill-on-close, optional caps) and reports the same facts a consumer's
guarantee depends on.

Why this is not ``pwsh_run``: ``pwsh_run`` is the model-facing *shell* — it
takes PowerShell script text, carries session state across calls, and
auto-backgrounds work that outlives the model's wait. A contained *argv*
runner has the opposite contract: no shell text at all (so no quoting layer
can reinterpret an argument), no session state, and a hard timeout that
kills instead of adopting. Folding the two together would force a durable
workflow's checks through shell re-parsing and a detached job.

Containment evidence is the point: :class:`ArgvRunResult` reports whether the
child was actually assigned to its Job Object, and the tool (and the runner
declaration built on it) refuses to report success without that evidence, so
a consumer can treat "returned a result" as "this ran contained".
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lisa_packs.powershell.winjob import (
    assign_process_to_job,
    close_job,
    create_contained_job,
    job_object_available,
    terminate_job,
)

__all__ = [
    "ArgvRunResult",
    "argv_containment_available",
    "run_argv_contained",
]

#: Upper bound on reaping and draining once a child tree has been killed.
_KILL_GRACE_SECONDS = 5.0
#: Output retained inline per stream; the rest is dropped, not buffered.
_MAX_OUTPUT_BYTES = 512_000


@dataclass(frozen=True, slots=True)
class ArgvRunResult:
    """One finished contained argv run, with its containment evidence."""

    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_truncated: bool = False
    #: True only when the child was assigned to its Job Object *and* ran in
    #: the requested cwd. Consumers read this before trusting the result.
    contained: bool = False
    cwd: str = ""
    #: Roots this primitive can write: the cwd the consumer asked for. A Job
    #: Object governs process lifetime, not file persistence, so this list is
    #: the caller's own grant rather than a bind list.
    writable_paths: tuple[str, ...] = ()
    tier: str = ""

    def as_output_json(self) -> dict[str, Any]:
        """Render the containment-evidence block a consumer verifies."""
        return {
            "return_code": self.return_code,
            "stderr": self.stderr,
            "sandboxed": self.contained,
            "contained": self.contained,
            "tier": self.tier,
            "persistence": "direct-write",
            "cwd": self.cwd,
            "writable_paths": list(self.writable_paths),
            "timed_out": self.timed_out,
            "truncated": self.output_truncated,
        }


def argv_containment_available() -> bool:
    """True when this host can contain an argv child (Job Object + Windows)."""
    return os.name == "nt" and job_object_available()


class _Capture:
    """Bytes drained from one stream, kept even if the drain is cancelled."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.overflowed = False

    async def drain(self, stream: asyncio.StreamReader) -> None:
        while chunk := await stream.read(65536):
            room = self.limit - len(self.data)
            if room > 0:
                self.data += chunk[:room]
            if len(chunk) > room:
                self.overflowed = True

    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")


def _kill_tree(process: asyncio.subprocess.Process, job_handle: int) -> None:
    """Kill the contained tree; the job owns descendants when one exists."""
    if job_handle:
        with contextlib.suppress(Exception):
            terminate_job(job_handle)
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            process.kill()


async def run_argv_contained(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int = _MAX_OUTPUT_BYTES,
) -> ArgvRunResult:
    """Spawn ``argv`` in ``cwd`` inside a Job Object and bound its output.

    No shell is involved: the argv is passed to ``create_subprocess_exec``
    verbatim, so an argument containing spaces, quotes, or PowerShell syntax
    reaches the child as the exact single argument the caller built. The
    child leads a new process group (POSIX) and is assigned to a kill-on-close
    Job Object (Windows) before it can spawn descendants.
    """
    if not argv or not argv[0]:
        raise ValueError("A non-empty executable argument vector is required.")
    if not argv_containment_available():
        raise RuntimeError(
            "argv containment is unavailable on this host: the powershell pack's "
            "Job Object primitive requires Windows, and the job API could not be "
            "opened. Running the argv on the host would break the containment "
            "guarantee this runner exists to provide."
        )

    job_handle = create_contained_job(kill_on_close=True, no_breakaway=True)
    process = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(cwd),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=os.name != "nt",
    )
    # Assignment happens after spawn (there is no create-in-job flag in the
    # public API); kill-on-close still covers the tree from this point on.
    assigned = assign_process_to_job(job_handle, process.pid) if job_handle else False
    assert process.stdout is not None
    assert process.stderr is not None
    stdout, stderr = _Capture(max_output_bytes), _Capture(max_output_bytes)
    drains = asyncio.gather(stdout.drain(process.stdout), stderr.drain(process.stderr))
    timed_out = False
    try:
        async with asyncio.timeout(timeout_seconds):
            await process.wait()
    except TimeoutError:
        timed_out = True
    except BaseException:
        _kill_tree(process, job_handle)
        drains.cancel()
        close_job(job_handle)
        raise
    _kill_tree(process, job_handle)
    with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(_KILL_GRACE_SECONDS):
            await asyncio.gather(drains, process.wait())
    drains.cancel()
    close_job(job_handle)
    return ArgvRunResult(
        return_code=process.returncode if process.returncode is not None else -1,
        stdout=stdout.text(),
        stderr=stderr.text(),
        timed_out=timed_out,
        output_truncated=stdout.overflowed or stderr.overflowed,
        contained=assigned,
        cwd=str(cwd),
        writable_paths=(str(cwd),),
        tier="basic",
    )
