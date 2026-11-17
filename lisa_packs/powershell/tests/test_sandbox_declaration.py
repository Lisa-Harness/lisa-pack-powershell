"""Tests for the powershell pack's sandbox implementation declaration.

Three things are load-bearing and tested here:

1. The declaration *opts out* on a host without Job Objects, so installing
   this pack next to bubblewrap never makes sandbox ownership ambiguous.
2. The floor validator accepts exactly the values Windows can honor —
   including ``network: allow`` (the 2026-11-17 branding-session incident:
   a session authored for cross-platform use that carries the axis fails at
   load on a validator that rejects every ``network`` value) — and rejects
   what the primitives cannot enforce.
3. The runner refuses requests or results whose containment it cannot
   prove, so a consumer never accepts a weaker posture than it asked for.
"""

from __future__ import annotations

import pytest
from kernel.sandbox_floor import (
    SandboxExecutionEnvelope,
    SandboxRunner,
    SandboxRunnerContractError,
    SandboxRunRequest,
)
from lisa_packs.powershell.containment import PolicyError

from lisa_packs.powershell import sandbox as declaration
from lisa_packs.powershell.sandbox import RUNNER_TOOL_ID, PwshRunner, describe_sandbox


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
    assert runner.tool_id == RUNNER_TOOL_ID == "pwsh_argv_run"
    assert runner.path_attestation == "result"
    assert isinstance(runner, SandboxRunner)


def test_validator_accepts_a_cross_platform_workflow_floor() -> None:
    declaration.validate_floor(
        {
            "execution": "sandbox",
            "persistence": "direct-write",
            "network": "allow",
            "paths": {"C:\\Code\\worktrees": "rw"},
        }
    )


def test_validator_accepts_what_job_objects_can_enforce() -> None:
    declaration.validate_floor(
        {"execution": "sandbox", "persistence": "direct-write", "paths": {"/wt": "rw"}}
    )


def test_validator_accepts_empty_floor() -> None:
    declaration.validate_floor({})


def test_validator_accepts_integer_timeout_ceiling() -> None:
    declaration.validate_floor({"timeout_ceiling_seconds": 3600})


@pytest.mark.parametrize(
    "floor",
    [
        {"network": "deny"},
        {"device": "minimal"},
        {"ipc": "unshared"},
        {"tmpfs_budget_bytes": 1024},
        {"timeout_ceiling_seconds": 0},
        {"timeout_ceiling_seconds": "soon"},
        {"paths": {"/wt": "ro"}},
        {"paths": {"/wt": "capture"}},
        {"persistence": "overlay"},
        {"persistence": "ephemeral"},
    ],
)
def test_validator_rejects_inexpressible_axes(floor: dict) -> None:
    with pytest.raises(PolicyError):
        declaration.validate_floor(floor)


def test_runner_forwards_a_granted_network_axis() -> None:
    parameters = PwshRunner().build_request(
        SandboxRunRequest(
            argv=("git", "status"),
            cwd="/wt",
            timeout_seconds=60,
            network="allow",
        )
    )
    assert parameters["network"] == "allow"


def test_runner_request_translates_the_neutral_request() -> None:
    parameters = PwshRunner().build_request(
        SandboxRunRequest(argv=("git", "status"), cwd="/wt", timeout_seconds=60)
    )
    assert parameters == {"argv": ["git", "status"], "cwd": "/wt", "timeout_seconds": 60}


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"persistence": "ephemeral"},
        {"paths": {"/wt": "ro"}},
        {"device": "minimal"},
        {"ipc": "unshared"},
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
        {"sandboxed": True, "cwd": "/wt", "writable_paths": ["/wt"], "tier": "bare"},
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
