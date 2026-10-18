"""Containment policy + mechanics for the powershell pack.

The harness (user) sets a deterministic containment FLOOR via
``ctx.execution_floor_for("pwsh_run")``; the model may only *tighten*
per call, never loosen below the floor. Windows has no bwrap, so
containment is layered from two verified primitives:

- **Job Objects** (win32): process-tree kill-on-close plus resource caps —
  the process-tree equivalent of bwrap's ``--die-with-parent`` + cgroups.
- **ConstrainedLanguage mode**: an in-process pwsh runspace whose language
  mode blocks .NET method invocation, ``Add-Type``, and P/Invoke while
  still allowing the core cmdlet surface — a shell-language boundary with
  no bwrap analogue.

Tiers (loosest -> tightest):
    bare < basic (job object) < contained (job object + CLM) < readonly

``basic`` runs an external ``pwsh -File`` child inside a job object: real
processes, killable, resource-capped, but full language. ``contained`` runs
the pwsh engine *inside this host process* on a CLM InitialSessionState —
the same verified enforcement surface the probe measured. A floor of
``readonly`` still resolves to ``contained`` execution plus a read-only
session policy (cwd carry only); it is advisory at the pack layer.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from kernel.capability_binding import ExecutionFloorView

__all__ = [
    "ContainmentTier",
    "PolicyError",
    "ProbeView",
    "resolve_effective_tier",
    "tightening_requested",
]

logger = logging.getLogger(__name__)

#: Ordered tier lattice (loosest -> tightest).
_TIER_ORDER: dict[str, int] = {
    "bare": 0,
    "basic": 1,
    "contained": 2,
    "readonly": 3,
}


def ContainmentTier(value: str) -> str:
    """Validate and return a tier name (plain string to keep JSON simple)."""
    if value not in _TIER_ORDER:
        raise PolicyError("tier", value, "one of " + "/".join(_TIER_ORDER))
    return value


class PolicyError(ValueError):
    """A request asked to loosen containment below the harness floor."""

    def __init__(self, axis: str, attempted: str, floor: str) -> None:
        self.axis = axis
        self.attempted = attempted
        self.floor = floor
        super().__init__(
            f"Refused: '{axis}' cannot be loosened to {attempted!r} - the harness "
            f"floor for this session is {floor!r}. Ask the user to raise the floor "
            "in the sandbox policy configuration."
        )


def _tier_level(value: str) -> int:
    try:
        return _TIER_ORDER[value]
    except KeyError:
        raise PolicyError("tier", value, "one of " + "/".join(_TIER_ORDER)) from None


def tightening_requested(overrides: Mapping[str, Any] | None) -> bool:
    """True when the model asked for containment above a bare floor.

    Any recognized tighten axis in ``overrides`` — or a bare non-empty
    ``overrides`` with unstructured content — counts. Model parameters are
    untrusted: this never WEAKENS the floor, it only chooses between two
    postures the floor already permits.
    """
    if not isinstance(overrides, Mapping) or not overrides:
        return False
    recognized = {"tier", "process_count", "memory_mb", "kill_on_close"}
    return any(key in overrides for key in recognized) or bool(overrides)


def _floor_tier(floor: ExecutionFloorView | None) -> str:
    """Map the floor's execution axis onto the pack's tier lattice.

    Only an explicit ``bare`` floor permits host execution. A missing floor
    is never evidence of consent to run bare — it maps to ``contained``.
    """
    if floor is None:
        return "contained"
    execution = (floor.execution or "").strip()
    if execution == "bare":
        return "bare"
    if execution in ("sandbox", "sandboxed", "contained"):
        return "contained"
    # Unrecognized execution axis: fail closed to contained.
    return "contained"


def resolve_effective_tier(
    floor: ExecutionFloorView | None,
    requested_tier: str | None,
    overrides: Mapping[str, Any] | None = None,
) -> str:
    """Join the floor with the model's per-call request.

    Returns the effective tier name. An explicit request to loosen below
    the floor raises :class:`PolicyError` (never silently clamped). Under a
    bare floor, any tightening request opts the call into ``basic``; no
    request means the floor's posture stands.
    """
    floor_tier = _floor_tier(floor)
    if requested_tier:
        req_level = _tier_level(requested_tier)
        floor_level = _tier_level(floor_tier)
        if req_level < floor_level:
            raise PolicyError("tier", requested_tier, floor_tier)
        return requested_tier
    if floor_tier == "bare" and tightening_requested(overrides):
        return "basic"
    return floor_tier


@dataclass(frozen=True, slots=True)
class ProbeView:
    """Verified containment capability facts for this host."""

    pwsh_available: bool
    pwsh_path: str
    pwsh_version: str
    is_core: bool
    job_object_ok: bool
    clm_ok: bool
    missing: tuple[str, ...] = field(default_factory=tuple)

    @property
    def contained_runnable(self) -> bool:
        """True when the in-process CLM runspace path can run."""
        return self.clm_ok and self.is_core

    @property
    def basic_runnable(self) -> bool:
        """True when the external job-object child path can run."""
        return self.pwsh_available and self.job_object_ok
