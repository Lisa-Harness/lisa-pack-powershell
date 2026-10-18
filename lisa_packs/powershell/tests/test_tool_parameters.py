"""Parameter validation tests for the pwsh_run tool."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lisa_packs.powershell.tools.pwsh_run.pwsh_run import Parameters


def test_command_xor_commands() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        Parameters.model_validate({})
    with pytest.raises(ValidationError, match="exactly one"):
        Parameters.model_validate({"command": "a", "commands": ["b"]})
    assert Parameters.model_validate({"command": "Get-Date"}).command == "Get-Date"
    assert Parameters.model_validate({"commands": ["a"]}).commands == ["a"]


def test_run_in_background_invalid_with_commands() -> None:
    with pytest.raises(ValidationError, match="run_in_background"):
        Parameters.model_validate({"commands": ["a"], "run_in_background": True})


def test_commands_cap() -> None:
    with pytest.raises(ValidationError, match="capped"):
        Parameters.model_validate({"commands": ["a"] * 9})


def test_commands_items_nonempty() -> None:
    with pytest.raises(ValidationError, match="non-empty"):
        Parameters.model_validate({"commands": ["", "b"]})


def test_default_timeout_and_tier() -> None:
    params = Parameters.model_validate({"command": "x"})
    assert params.timeout_seconds == Parameters.model_fields["timeout_seconds"].default
    assert params.tier is None
    assert params.overrides == {}
