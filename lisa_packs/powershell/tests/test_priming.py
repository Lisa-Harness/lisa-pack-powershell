"""Priming tests: session paths and sentinel uniqueness."""

from __future__ import annotations

from pathlib import Path

from lisa_packs.powershell.priming import SessionPriming


def test_priming_paths_live_under_run(tmp_path: Path) -> None:
    priming = SessionPriming(data_dir=tmp_path, session_key="key1")
    assert str(priming.log_path).startswith(str(tmp_path / "run" / "key1"))
    assert priming.state_path.parent.name == "profile"


def test_sentinel_unique_across_sessions(tmp_path: Path) -> None:
    a = SessionPriming(data_dir=tmp_path, session_key="key1")
    b = SessionPriming(data_dir=tmp_path, session_key="key1")
    assert a.sentinel != b.sentinel
    assert a.sentinel.endswith(">> ")
