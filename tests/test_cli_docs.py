"""
Detect documentation / CLI command-inventory drift.

The authoritative command list is generated from the Typer app, not from
hand-written counts in documentation.
"""

from __future__ import annotations

from pathlib import Path

from zhubin.cli.app import iter_cli_command_paths

_DOCS = [
    Path("README.md"),
    Path("AGENTS.md"),
    Path("docs/ARCHITECTURE.md"),
    Path("docs/SECURITY.md"),
]


def test_command_inventory_matches_implementation() -> None:
    commands = iter_cli_command_paths()
    # Every implemented command must appear at least once in README.
    readme = Path("README.md").read_text()
    missing = [c for c in commands if f"zhubin {c}" not in readme and f"`{c}`" not in readme]
    # Top-level commands are documented as `zhubin <name>`.
    still_missing = [c for c in missing if f"zhubin {c}" not in readme]
    assert still_missing == [], f"README.md missing commands: {still_missing}"


def test_no_phantom_commands_in_readme() -> None:
    commands = set(iter_cli_command_paths())
    # A documented command that is not implemented would be a user-facing bug.
    # Check the Device Management / Groups / top-level headings' code fences.
    documented = {
        "init",
        "add",
        "edit",
        "delete",
        "cp",
        "show",
        "list",
        "find",
        "group create",
        "group list",
        "group rotate",
        "device init",
        "device list",
        "device authorize",
        "device revoke",
        "device fingerprint",
        "device show",
        "status",
        "sync",
        "lock",
        "unlock",
        "web",
    }
    unimplemented = sorted(documented - commands)
    extra_undocumented = sorted(commands - documented)
    assert unimplemented == [], f"Documented but not implemented: {unimplemented}"
    assert extra_undocumented == [], (
        f"Implemented but not in expected inventory: {extra_undocumented}"
    )


def test_help_lists_subcommands() -> None:
    from typer.testing import CliRunner

    from zhubin.cli.app import app

    runner = CliRunner()
    root = runner.invoke(app, ["--help"])
    assert root.exit_code == 0
    for name in ("init", "add", "group", "device", "status", "sync", "lock", "unlock", "web"):
        assert name in root.stdout

    group = runner.invoke(app, ["group", "--help"])
    assert group.exit_code == 0
    for name in ("create", "list", "rotate"):
        assert name in group.stdout

    device = runner.invoke(app, ["device", "--help"])
    assert device.exit_code == 0
    for name in ("init", "list", "authorize", "revoke", "fingerprint", "show"):
        assert name in device.stdout


def test_add_help_exposes_field_options_but_not_password_flag() -> None:
    from typer.testing import CliRunner

    from zhubin.cli.app import app

    runner = CliRunner()
    result = runner.invoke(app, ["add", "--help"])
    assert result.exit_code == 0
    assert "--username" in result.stdout
    assert "--url" in result.stdout
    assert "--notes" in result.stdout
    assert "--password-stdin" in result.stdout
    # Passwords must never be accepted as CLI arguments (shell history / ps).
    assert "--password" not in result.stdout.replace("--password-stdin", "")


def test_docs_do_not_claim_age_equivalence() -> None:
    for path in _DOCS:
        if not path.exists():
            continue
        text = path.read_text().lower()
        assert "semantically equivalent to age" not in text
        assert "protocol-equivalent to age" not in text or "not" in text
