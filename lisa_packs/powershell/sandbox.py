"""The powershell pack's sandbox-capability implementation declaration.

Linux hosts contain commands with bubblewrap (``lisa-pack-bwrap``); a Windows
host has no bubblewrap, so this pack is the sandbox implementation there.
It pairs ``run_argv.py`` — the Job-Object containment primitive for a bare
argv (create_subprocess_exec, kill-on-close, output caps) — with the
:func:`describe_sandbox` declaration the kernel's sandbox capability loads.

Two halves, mirroring bwrap's declaration:

- ``validate_floor`` — the single loud validator for the *merged* floor.
  Job Objects govern process lifetime, not the filesystem or network, so
  this implementation enforces less than bubblewrap's floor vocabulary. It
  accepts exactly the values its primitives can honor and *rejects* what it
  cannot (``network: deny``, device/ipc isolation, non-``rw`` path access)
  instead of accepting a posture it would silently ignore — a session
  asking for network denial on Windows fails at load naming the axis, not
  quietly with a weaker sandbox mid-turn. ``network: allow`` passes: it
  names the Windows reality, so a session shared with bwrap validates on
  both platforms.
- ``runner`` — the execution surface a composing pack (``lisa-pack-coding``)
  dispatches contained argv runs through, so that pack never names
  ``pwsh_argv_run`` itself. The runner forwards the floor's granted axes
  (``network``) explicitly and requires the tool's containment evidence
  before accepting a run.

The runner is provider-neutral on the consumer side: a consumer builds a
:class:`kernel.sandbox_floor.SandboxRunRequest` and never names the tool;
the session's ``providers.capabilities.sandbox`` selection resolves this
declaration, and the runtime materializes the merged floor into this pack's
binding configuration so the runner and ``ctx.execution_floor_for`` see one
identical floor.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from kernel.sandbox_floor import (
    SandboxExecutionEnvelope,
    SandboxRunnerContractError,
    SandboxRunRequest,
    SandboxRunResult,
)

from lisa_packs.powershell.containment import PolicyError
from lisa_packs.powershell.run_argv import argv_containment_available

__all__ = [
    "RUNNER_TOOL_ID",
    "PwshRunner",
    "describe_sandbox",
    "validate_floor",
]

logger = logging.getLogger(__name__)

#: The argv-in, contained-result-out tool this pack contributes.
RUNNER_TOOL_ID = "pwsh_argv_run"

#: What this implementation's results can attest about requested paths:
#: the result reports the writable roots the run actually had.
_PATH_ATTESTATION = "result"

#: Floor axis values this implementation can enforce. Keys mirror bwrap's
#: so one session plan validates on both platforms; values are the subset a
#: Windows Job Object can honestly grant.
_EXECUTION_VALUES = ("bare", "sandbox", "sandboxed", "contained")
_PERSISTENCE_VALUES = ("direct-write", "direct")
_NETWORK_VALUES = ("allow",)
_ACCESS_VALUES = ("rw",)


def validate_floor(floor: Mapping[str, Any]) -> None:
    """Reject a floor this implementation cannot enforce, naming the axis.

    The runtime applies this to the *merged* floor (authored floor plus
    pack contributions), so a session authored for bwrap that carries an
    axis Windows cannot honor fails at load with the fix in the message —
    never silently at first contained run. ``network: allow`` is accepted:
    it needs no enforcement on Windows, where interfaces stay reachable,
    and denial is the load-time rejection below.
    """
    for axis, allowed in (
        ("execution", _EXECUTION_VALUES),
        ("persistence", _PERSISTENCE_VALUES),
        ("network", _NETWORK_VALUES),
    ):
        value = floor.get(axis)
        if value is None:
            continue
        if not isinstance(value, str) or value not in allowed:
            raise PolicyError(axis, str(value), "one of " + "/".join(allowed))
    paths = floor.get("paths")
    if paths is not None:
        if not isinstance(paths, Mapping):
            raise PolicyError("paths", type(paths).__name__, "a mapping of path -> rw")
        for path, access in paths.items():
            if access not in _ACCESS_VALUES:
                raise PolicyError(
                    f"paths[{path}]",
                    str(access),
                    "rw only (Windows Job-Object sandbox: the filesystem stays "
                    "real, so ro/capture/hidden grants cannot be enforced)",
                )
    ceiling = floor.get("timeout_ceiling_seconds")
    if ceiling is not None and (
        not isinstance(ceiling, int) or isinstance(ceiling, bool) or ceiling < 1
    ):
        raise PolicyError(
            "timeout_ceiling_seconds",
            str(ceiling),
            "a positive integer number of seconds",
        )
    for bwrap_only in ("device", "ipc", "tmpfs_budget_bytes"):
        if floor.get(bwrap_only) is not None:
            raise PolicyError(
                bwrap_only,
                str(floor[bwrap_only]),
                "unset (bwrap-only axis: Job Objects have no namespace or "
                "budget primitive on Windows)",
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
        "validate_floor": validate_floor,
        "runner": PwshRunner(),
    }


class PwshRunner:
    """Run a neutral request through ``pwsh_argv_run`` and verify the result.

    The consumer side of :class:`kernel.sandbox_floor.SandboxRunner`:
    :meth:`build_request` maps a :class:`SandboxRunRequest` onto the tool's
    parameters (refusing postures the Windows primitive cannot honor, so a
    consumer never believes it got a weaker sandbox than it asked for), and
    :meth:`interpret_result` proves the run was contained before accepting
    it. A Job Object cannot bind paths, so the runner attests what the
    result *does* prove: the child ran in the requested directory, inside an
    assigned job, at a contained tier.
    """

    tool_id = RUNNER_TOOL_ID
    #: The result reports ``writable_paths`` (the cwd it actually ran in), so
    #: a caller can require its own target in that list.
    path_attestation = _PATH_ATTESTATION

    def build_request(
        self,
        request: SandboxRunRequest,
        *,
        floor: Any = None,
    ) -> Mapping[str, Any]:
        """Translate a neutral request into ``pwsh_argv_run`` parameters."""
        if request.persistence is not None and request.persistence != "direct-write":
            raise SandboxRunnerContractError(
                "the powershell pack's Job Object sandbox can only run with "
                f"persistence 'direct-write'; {request.persistence!r} is not "
                "enforceable on Windows."
            )
        unsupported_paths = sorted(
            path for path, access in request.paths.items() if access != "rw"
        )
        if unsupported_paths:
            raise SandboxRunnerContractError(
                "the powershell pack's Job Object sandbox cannot enforce "
                "non-'rw' path access: " + ", ".join(unsupported_paths)
            )
        for axis in ("device", "ipc"):
            value = getattr(request, axis, None)
            if value is not None:
                raise SandboxRunnerContractError(
                    "the powershell pack's Job Object sandbox cannot enforce "
                    f"{axis}={value!r}: there is no namespace primitive on Windows."
                )
        parameters: dict[str, Any] = {
            "argv": list(request.argv),
            "cwd": request.cwd,
            "timeout_seconds": request.timeout_seconds,
        }
        # Granted axes are forwarded explicitly: the tool attests the network
        # posture it ran with, so the evidence block stays honest.
        if request.network is not None:
            parameters["network"] = request.network
        return parameters

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
        if payload.get("tier") not in ("basic", "contained"):
            raise SandboxRunnerContractError(
                f"the powershell runner ran at tier {payload.get('tier')!r}, "
                "which is not a contained posture; refusing to accept the run."
            )
        persistence = str(payload.get("persistence") or "direct-write")
        if request.persistence is not None and persistence != request.persistence:
            raise SandboxRunnerContractError(
                f"the powershell runner persisted as {persistence!r}, not the "
                f"requested {request.persistence!r}."
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
