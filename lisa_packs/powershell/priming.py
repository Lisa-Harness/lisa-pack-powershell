"""Render the Lisa state/profile files for one pwsh session.

No rc template is needed: pwsh children run with ``-NoProfile`` for
determinism, and per-session state (cwd + named variables) replays through
the state file the wrapper dot-sources. The priming layer owns those paths
and the per-session sentinel used by the output parser.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["SessionPriming"]


@dataclass(frozen=True, slots=True)
class SessionPriming:
    """Path + sentinel ownership for one session."""

    data_dir: Path
    session_key: str
    _sentinel: str = field(default="", init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_sentinel",
            f"LISAPWSH_{self.session_key[:8]}_{secrets.token_hex(4)}>> ",
        )

    @property
    def run_dir(self) -> Path:
        return self.data_dir / "run" / self.session_key

    @property
    def log_path(self) -> Path:
        """Audit log: command + output lines, one entry per call."""
        return self.run_dir / f"pwsh-{self.session_key}.log"

    @property
    def state_path(self) -> Path:
        """Replayed at the top of each wrapper invocation."""
        return self.run_dir / "profile" / f"state-{self.session_key}.ps1"

    @property
    def sentinel(self) -> str:
        """Per-session output marker: unique, never user-visible text."""
        return self._sentinel
