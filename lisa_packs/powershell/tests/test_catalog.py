"""Catalog discovery test for the powershell pack."""

from __future__ import annotations

import json

from sdk.content._catalog import (
    build_mode_catalog_json,
    build_operation_catalog_json,
    build_tool_catalog_json,
    resolve_mode_roots,
    resolve_operation_roots,
    resolve_tool_roots,
)

from lisa_packs.powershell import get_content_root


def test_pwsh_run_tool_discovered() -> None:
    roots = resolve_tool_roots([get_content_root()])
    assert roots, "No tools/ directory found in powershell pack"

    catalog = json.loads(build_tool_catalog_json(roots))

    assert "pwsh_run" in catalog
    tool = catalog["pwsh_run"]
    assert tool["tool_id"] == "pwsh_run"
    assert tool["pack_id"] == "lisa-pack-powershell"
    assert tool["effect"] == "execute"
    assert tool["approval_required"] is True
    assert tool["exportable"] is True
    assert tool["module_path"] == "lisa_packs.powershell.tools.pwsh_run.pwsh_run"
    assert "background" in tool["description"].lower() or "batch" in tool["description"].lower()


def test_shell_pwsh_mode_routable() -> None:
    """Frontmatter is load-bearing: command_pattern + routable must survive edits."""
    roots = resolve_mode_roots([get_content_root()])
    assert roots, "No modes/ directory found in powershell pack"
    catalog = json.loads(build_mode_catalog_json(roots))
    assert "shell_pwsh" in catalog
    mode = catalog["shell_pwsh"]
    assert mode["routable"] is True
    assert mode["command_pattern"].startswith("^(?:/)?(?:pwsh|powershell)")
    assert "pwsh_run" in mode["allowed_tool_ids"]
    assert "pwsh_sandbox_facts" in mode["pre_turn_operation_ids"]


def test_pwsh_sandbox_facts_operation_discovered() -> None:
    ops = resolve_operation_roots([get_content_root()])
    assert ops, "No operations/ directory found in powershell pack"
    catalog = json.loads(build_operation_catalog_json(ops))
    assert "pwsh_sandbox_facts" in catalog
    op = catalog["pwsh_sandbox_facts"]
    assert op["effect"] == "read"
    assert op["approval_required"] is False


def _declared_timeout_ceiling(tool_id: str) -> int:
    catalog = json.loads(build_tool_catalog_json(resolve_tool_roots([get_content_root()])))
    return int(catalog[tool_id]["timeout_seconds"])


def test_pwsh_run_declares_itself_self_bounding() -> None:
    """``pwsh_run`` must disable the kernel wrapper (``timeout_seconds: 0``).

    Mirrors the bash pack's 2026-10-05 regression: a positive wrapper bound
    cancels a slow call before job adoption can run. pwsh_run self-bounds
    (model timeout parameter + job adoption), so the declared ceiling must
    be 0 with stream_output kept true.
    """
    assert _declared_timeout_ceiling("pwsh_run") == 0
    catalog = json.loads(build_tool_catalog_json(resolve_tool_roots([get_content_root()])))
    assert catalog["pwsh_run"]["stream_output"] is True
