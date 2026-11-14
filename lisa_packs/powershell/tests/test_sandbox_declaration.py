"""Tests for the powershell pack's sandbox implementation declaration.

Two things are load-bearing and tested here:

1. The declaration *opts out* on a host without Job Objects, so installing
   this pack next to bubblewrap never makes sandbox ownership ambiguous.
2. The floor validator *rejects* axes Job Objects cannot enforce. Accepting
   them would let a session believe it asked for network denial it does not
   have.
"""

from __future__ import annotations

import pytest
from kernel.sandbox_floor import (
    SandboxExecutionEnvelope,
    SandboxRunnerContractError,
    SandboxRunRequest,
)

from lisa_packs.powershell import sandbox as declaration
from lisa_packs.powershell.sandbox import PwshRunner, describe_sandbox


def test_declaration_opts_out_without_job_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(declaration, "argv_containment_available", lambda: False)
    assert describe_sandbox() is None


def test_declaration_names_the_pack_and_exposes_runner_with_job_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(declaration, "argv_containment_available", lambda: True)
    declared = describe_sandbox()
    assert declared is not None
    assert declared["pack_name"] == "lisa-pack-powershell"
    assert callable(declared["validate_floor"])
    runner = declared["runner"]
    assert runner.tool_id == "pwsh_argv_run"
    assert runner.path_attestation == "result"


def test_validator_accepts_what_job_objects_can_enforce() -> None:
    declaration._validate_floor(
        {"execution": "sandbox", "persistence": "direct-write", "paths": {"/wt": "rw"}}
    )


@pytest.mark.parametrize(
    "floor",
    [
        {"network": "deny"},
        {"device": "minimal"},
        {"ipc": "unshared"},
        {"tmpfs_budget_bytes": 1024},
        {"timeout_ceiling_seconds": 60},
        {"paths": {"/wt": "ro"}},
        {"paths": {"/wt": "capture"}},
        {"persistence": "overlay"},
        {"persistence": "ephemeral"},
        {"execution": "contained"},
    ],
)
def test_validator_rejects_inexpressible_axes(floor: dict) -> None:
    with pytest.raises(ValueError):
        declaration._validate_floor(floor)


def test_runner_request_is_argv_cwd_and_timeout_only() -> None:
    parameters = PwshRunner().build_request(
        SandboxRunRequest(argv=("git", "status"), cwd="/wt", timeout_seconds=60)
    )
    assert parameters == {"argv": ["git", "status"], "cwd": "/wt", "timeout_seconds": 60}


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"persistence": "ephemeral"},
        {"paths": {"/wt": "ro"}},
        {"network": "deny"},
    ],
)
def test_runner_rejects_requests_it_cannot_enforce(
    request_kwargs: dict,
) -> None:
    # Silently dropping these would hand the caller a weaker posture than it
    # asked for, which is the failure this contract exists to prevent.
    ask = SandboxRunRequest(argv=("x",), cwd="/wt", timeout_seconds=1, **request_kwargs)
    with pytest.raises(SandboxRunnerContractError):
        PwshRunner().build_request(ask)


def test_runner_accepts_a_verified_result() -> None:
    request = SandboxRunRequest(argv=("git", "status"), cwd="/wt", timeout_seconds=60)
    result = PwshRunner().interpret_result(
        request,
        SandboxExecutionEnvelope(
            output_text="clean\n",
            output_json={
                "sandboxed": True,
                "contained": True,
                "tier": "basic",
                "persistence": "direct-write",
                "cwd": "/wt",
                "writable_paths": ["/wt"],
                "return_code": 0,
            },
        ),
    )
    assert result.return_code == 0
    assert result.stdout == "clean\n"


@pytest.mark.parametrize(
    "payload",
    [
        {"sandboxed": False, "cwd": "/wt", "writable_paths": ["/wt"], "return_code": 0},
        {"sandboxed": True, "cwd": "/other", "writable_paths": ["/other"], "return_code": 0},
        {"sandboxed": True, "cwd": "/wt", "writable_paths": [], "return_code": 0},
        {"sandboxed": True, "cwd": "/wt", "writable_paths": ["/wt"], "return_code": "0"},
    ],
)
def test_runner_rejects_unverified_results(payload: dict) -> None:
    request = SandboxRunRequest(argv=("x",), cwd="/wt", timeout_seconds=60)
    with pytest.raises(SandboxRunnerContractError):
        PwshRunner().interpret_result(request, SandboxExecutionEnvelope(output_json=payload))


def test_runner_rejects_a_failed_dispatch() -> None:
    request = SandboxRunRequest(argv=("x",), cwd="/wt", timeout_seconds=60)
    with pytest.raises(SandboxRunnerContractError, match="sandbox failed"):
        PwshRunner().interpret_result(
            request, SandboxExecutionEnvelope(error="job object unavailable")
        )
