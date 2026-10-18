"""Containment policy tests: floor join, tightening-only overrides."""

from __future__ import annotations

from typing import Any

import pytest
from kernel.capability_binding import ExecutionFloorView

from lisa_packs.powershell.containment import (
    PolicyError,
    resolve_effective_tier,
    tightening_requested,
)


def _floor(execution: str | None) -> ExecutionFloorView:
    return ExecutionFloorView(
        execution=execution,
        persistence=None,
        paths={},
        network=None,
        device=None,
        ipc=None,
    )


def test_missing_floor_maps_to_contained() -> None:
    assert resolve_effective_tier(None, None, None) == "contained"


def test_bare_floor_yields_bare_without_request() -> None:
    assert resolve_effective_tier(_floor("bare"), None, None) == "bare"


def test_bare_floor_tightens_on_override() -> None:
    overrides: dict[str, Any] = {"memory_mb": 512}
    assert resolve_effective_tier(_floor("bare"), None, overrides) == "basic"


def test_bare_floor_tightens_on_tier_request() -> None:
    assert resolve_effective_tier(_floor("bare"), "contained", None) == "contained"


def test_sandbox_floor_maps_to_contained() -> None:
    assert resolve_effective_tier(_floor("sandbox"), None, None) == "contained"


def test_loosen_request_below_floor_raises_policy_error() -> None:
    with pytest.raises(PolicyError):
        resolve_effective_tier(_floor("sandbox"), "bare", None)


def test_unknown_tier_raises_policy_error() -> None:
    with pytest.raises(PolicyError):
        resolve_effective_tier(_floor("bare"), "nonexistent", None)


def test_tightening_requested_axes() -> None:
    assert tightening_requested({"tier": "basic"}) is True
    assert tightening_requested({"memory_mb": 512}) is True
    assert tightening_requested({"unrelated": 1}) is True
    assert tightening_requested({}) is False
    assert tightening_requested(None) is False
