"""Executor unit tests: parser, shaping, batch schedule."""

from __future__ import annotations

from lisa_packs.powershell.executor import (
    MAX_BATCH_COMMANDS,
    is_auto_background_guarded,
    normalize_benign_rc,
    parse_output,
    shape_empty_output,
)

_EXPECTED_BATCH_CAP = 8
_SENTINEL = "LISAPWSHTEST>> "


def test_parse_output_extracts_rc_and_state() -> None:
    raw = (
        "hello\n"
        f'{_SENTINEL}obj {{"Name": "Code"}}\n'
        f"{_SENTINEL}text plain\n"
        f"{_SENTINEL}state=cwd=C:\\new\\path\n"
        f"{_SENTINEL}statevar MYVAR=val\n"
        f"{_SENTINEL}err oops\n"
        f"{_SENTINEL}rc=0\n"
    )
    parsed = parse_output(raw, _SENTINEL)
    assert "hello" in parsed.body
    assert '{"Name": "Code"}' in parsed.body
    assert "plain" in parsed.body
    assert parsed.return_code == 0
    assert parsed.state["cwd"] == "C:\\new\\path"
    assert parsed.state["variables"] == {"MYVAR": "val"}
    assert parsed.errors == ["oops"]


def test_parse_output_strips_all_machinery() -> None:
    raw = f"{_SENTINEL}obj {{}}\n{_SENTINEL}err boom\n{_SENTINEL}rc=1\n"
    parsed = parse_output(raw, _SENTINEL)
    assert parsed.body == "{}"
    assert parsed.return_code == 1
    assert parsed.errors == ["boom"]
    assert parsed.state == {}


def test_parse_output_rc_none_when_missing() -> None:
    parsed = parse_output("plain output", _SENTINEL)
    assert parsed.return_code is None
    assert parsed.body == "plain output"


def test_shape_empty_output() -> None:
    note = shape_empty_output("", "", 0)
    assert "no output" in note
    assert shape_empty_output("data", "", 0) == "data"


def test_benign_rc1_cmdlets() -> None:
    assert normalize_benign_rc("Select-String -Pattern x foo.txt", 1) is not None
    assert normalize_benign_rc("Get-Date", 1) is None
    assert normalize_benign_rc("Get-Date", 2) is None


def test_auto_background_guards() -> None:
    assert is_auto_background_guarded("Start-Sleep 5")
    assert is_auto_background_guarded("git status")
    assert not is_auto_background_guarded("Get-ChildItem")


def test_batch_cap_constant() -> None:
    assert MAX_BATCH_COMMANDS == _EXPECTED_BATCH_CAP
