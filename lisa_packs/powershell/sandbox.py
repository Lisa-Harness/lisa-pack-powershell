"""The powershell pack's sandbox-capability implementation declaration.

Linux hosts contain commands with bubblewrap (``lisa-pack-bwrap``); a Windows
host has no bubblewrap, so this pack is the sandbox implementation there: Job
Objects (kill-on-close process tree, optional caps) plus ConstrainedLanguage
runspaces for the shell, and Job Objects for a bare argv.

Two halves, mirroring bwrap's declaration:

- ``validate_floor`` — the single loud validator for the *merged* floor. Job
  Objects govern process lifetime, not the filesystem, so this implementation
  can enforce far less than bubblewrap's floor vocabulary. It therefore
  *rejects* axes it cannot enforce (network/device/ipc isolation, tmpfs
  budgets, non-``rw`` path access) instead of accepting a posture it would
  silently ignore — a session asking for network denial on Windows gets a
  load-time error naming the axis, not a quiet weaker sandbox.
- ``runner`` — the execution surface a composing pack (``lisa-pack-coding``)
  dispatches contained argv runs through, so that pack never names
  ``pwsh_argv_run`` itself.

Registration is host-gated: on a host with no Job Object API (Linux, macOS)
the declaration returns ``None`` and discovery skips it, so installing this
pack next to bwrap never creates an ambiguous sandbox owner.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernel.sandbox_floor import (
    SandboxExecutionEnvelope,
    SandboxRunnerContractError,
    SandboxRunRequest,
    SandboxRunResult,
)

from lisa_packs.powershell.run_argv import argv_containment_available

#: The argv-in, contained-result-out tool this pack contributes.
RUNNER_TOOL_ID = "pwsh_argv_run"

#: Floor axes this implementation can enforce, with the values it accepts.
#: Everything else is rejected by :func:`_validate_floor`.
_ENFORCEABLE_SCALARS: dict[str, frozenset[str]] = {
    # ``sandbox`` is the posture consumers requiring containment ask for;
    # ``bare`` is a deliberate host-execution policy the shell and argv paths
    # already honour (``resolve_effective_tier`` / Job Object assignment).
    "execution": frozenset({"sandbox", "bare"}),
    # Job Objects do not capture or discard filesystem writes.
    "persistence": frozenset({"direct-write"}),
}


def _validate_floor(floor: Mapping[str, Any]) -> None:
    """Reject floor values this implementation cannot enforce.

    Raises:
        ValueError: The merged floor asks for a posture Job Objects cannot
            provide. The message names the axis and the reason so the operator
            can fix the session policy rather than discover a weaker sandbox
            mid-turn.
    """
    for axis, allowed in _ENFORCEABLE_SCALARS.items():
        if axis not in floor:
            continue
        value = floor[axis]
        if value not in allowed:
            raise ValueError(
                f"the powershell pack's Job Object sandbox cannot enforce "
                f"{axis}={value!r}; it supports "
                + ", ".join(repr(item) for item in sorted(allowed))
                + ". Remove the axis from this session's sandbox floor or select a "
                "sandbox implementation that can enforce it."
            )
    for axis in ("network", "device", "ipc", "tmpfs_budget_bytes", "timeout_ceiling_seconds"):
        if axis in floor:
            raise ValueError(
                f"the powershell pack's Job Object sandbox cannot enforce "
                f"{axis!r}: there is no namespace or budget primitive on Windows. "
                "Remove the axis from this session's sandbox floor or select an "
                "implementation that can enforce it."
            )
    paths = floor.get("paths")
    if paths is None:
        return
    if not isinstance(paths, Mapping):
        raise ValueError("sandbox floor 'paths' must be a mapping of path -> access.")
    unsupported = sorted(f"{path}={access}" for path, access in paths.items() if access != "rw")
    if unsupported:
        raise ValueError(
            "the powershell pack's Job Object sandbox cannot enforce path access "
            "other than 'rw' (it has no bind-mount equivalent): "
            + ", ".join(unsupported)
            + ". Remove those entries or select an implementation that can enforce them."
        )


class PwshRunner:
    """Run a neutral request through ``pwsh_argv_run`` and verify the result.

    A Job Object cannot bind paths, so this runner attests what it *does*
    know: the child ran in the requested directory, inside an assigned job,
    with no shell in between. Path grants are taken from the request because
    the caller's own grant *is* the grant on Windows — the Job Object merely
    guarantees the process tree dies with the job.
    """

    tool_id = RUNNER_TOOL_ID
    #: The result reports ``writable_paths`` (the cwd it actually ran in), so a
    #: caller can require its own target in that list.
    path_attestation = "result"

    def build_request(
        self,
        request: SandboxRunRequest,
        *,
        floor: Any = None,
    ) -> Mapping[str, Any]:
        """Translate a neutral request into ``pwsh_argv_run`` parameters.

        Requests the Windows primitive cannot honour are rejected here rather
        than silently dropped: a consumer asking for ``ephemeral`` writes or a
        read-only bind would otherwise believe it got a posture it does not
        have.
        """
        if request.persistence != "direct-write":
            raise SandboxRunnerContractError(
                "the powershell pack's Job Object sandbox can only run with "
                f"persistence 'direct-write'; {request.persistence!r} is not "
                "enforceable on Windows."
            )
        unsupported_paths = sorted(path for path, access in request.paths.items() if access != "rw")
        if unsupported_paths:
            raise SandboxRunnerContractError(
                "the powershell pack's Job Object sandbox cannot enforce "
                "non-'rw' path access: " + ", ".join(unsupported_paths)
            )
        for axis in ("network", "device", "ipc"):
            value = getattr(request, axis, None)
            if value is not None:
                raise SandboxRunnerContractError(
                    "the powershell pack's Job Object sandbox cannot enforce "
                    f"{axis}={value!r}: there is no namespace primitive on Windows."
                )
        return {
            "argv": list(request.argv),
            "cwd": request.cwd,
            "timeout_seconds": request.timeout_seconds,
        }

    def interpret_result(
        self,
        request: SandboxRunRequest,
        envelope: SandboxExecutionEnvelope,
    ) -> SandboxRunResult:
        """Require containment evidence, then normalize the run result."""
        payload = dict(envelope.output_json or {})
        if envelope.error:
            raise SandboxRunnerContractError(f"powershell sandbox failed: {envelope.error}")
        if payload.get("sandboxed") is not True:
            raise SandboxRunnerContractError(
                "the powershell runner did not prove containment "
                f"(sandboxed={payload.get('sandboxed')!r}); refusing to accept the run."
            )
        if str(payload.get("cwd") or "") != request.cwd:
            raise SandboxRunnerContractError(
                f"the argv ran in {payload.get('cwd')!r}, not {request.cwd!r}."
            )
        writable = payload.get("writable_paths")
        if not isinstance(writable, list) or request.cwd not in writable:
            raise SandboxRunnerContractError(
                "the powershell runner did not report the target directory as "
                f"writable (writable: {writable!r})."
            )
        if type(payload.get("return_code")) is not int:
            raise SandboxRunnerContractError(
                "the powershell runner returned no exit status; the run cannot be trusted."
            )
        return SandboxRunResult(
            return_code=int(payload["return_code"]),
            stdout=envelope.output_text or "",
            stderr=str(payload.get("stderr", "")),
            timed_out=bool(payload.get("timed_out", False)),
            output_truncated=bool(payload.get("truncated", False)),
        )


def describe_sandbox() -> Mapping[str, Any] | None:
    """Return this pack's sandbox declaration, or ``None`` off Windows.

    ``None`` is the documented "not applicable on this host" answer: the pack
    still loads (its shell mode has other containment fallbacks), but it never
    competes with bubblewrap for sandbox ownership on a host where Job Objects
    do not exist.
    """
    if not argv_containment_available():
        return None
    return {
        "pack_name": "lisa-pack-powershell",
        "validate_floor": _validate_floor,
        "runner": PwshRunner(),
    }


__all__ = ["RUNNER_TOOL_ID", "PwshRunner", "describe_sandbox"]
