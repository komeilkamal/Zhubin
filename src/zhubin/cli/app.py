"""
Zhubin CLI — main Typer application.

All commands are registered here from sub-modules.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console

from zhubin.cli.completion import complete_cp_field, complete_group_name, complete_secret_path
from zhubin.cli.device import app as device_app
from zhubin.cli.git import app as git_app
from zhubin.cli.group import app as group_app

if TYPE_CHECKING:
    from zhubin.vault.vault import VaultService

# Sub-apps

app = typer.Typer(
    name="zhubin",
    help="Zhubin — secure, Git-backed password manager.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.add_typer(group_app, name="group")
app.add_typer(device_app, name="device")

# Register git commands at top level
for _cmd in git_app.registered_commands:
    app.registered_commands.append(_cmd)

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Helpers shared across CLI modules
# ---------------------------------------------------------------------------

_VAULT_PATH_ENV = "ZHUBIN_VAULT"
_DEFAULT_VAULT = Path.cwd()


def get_vault_path() -> Path:
    """Return vault path from env or current directory."""
    import os

    env = os.environ.get(_VAULT_PATH_ENV)
    return Path(env) if env else _DEFAULT_VAULT


def get_service(
    vault_path: Path | None = None,
    *,
    require_unlock: bool = True,
) -> VaultService:
    """
    Return an unlocked VaultService for the current session.

    If the vault is locked, prompt for the passphrase.
    """
    from zhubin.crypto.identity import identity_exists, load_device_identity
    from zhubin.storage.filesystem import assert_vault
    from zhubin.vault.vault import VaultService

    vp = vault_path or get_vault_path()

    try:
        assert_vault(vp)
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    if not require_unlock:
        return VaultService(vp)

    if not identity_exists():
        err_console.print(
            "[bold red]Error:[/bold red] No device identity found. "
            "Run [cyan]zhubin init[/cyan] first."
        )
        raise typer.Exit(1)

    # Try keyring first (no passphrase needed)
    try:
        identity = load_device_identity()
        return VaultService(vp, identity)
    except Exception:
        pass

    # Prompt for passphrase
    passphrase = typer.prompt("Vault passphrase", hide_input=True)
    try:
        identity = load_device_identity(passphrase)
    except Exception as exc:
        err_console.print(f"[bold red]Authentication failed:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    return VaultService(vp, identity)


# ---------------------------------------------------------------------------
# Top-level commands
# ---------------------------------------------------------------------------


@app.command()
def init(
    vault_path: Annotated[
        Path | None,
        typer.Option("--vault", "-v", help="Vault directory (default: current dir)"),
    ] = None,
    device_name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Human-readable device name"),
    ] = None,
) -> None:
    """
    Initialise a new Zhubin vault and local device identity.

    [bold]This command is safe to run in an existing directory.[/bold]
    It will not overwrite an existing vault or private key.
    """
    import platform as plat

    from zhubin.crypto.identity import (
        create_device_identity,
        identity_exists,
        save_device_identity,
        save_device_meta,
    )
    from zhubin.storage.filesystem import init_vault
    from zhubin.vault.models import DeviceRecord

    vp = vault_path or get_vault_path()

    # Vault init
    try:
        init_vault(vp)
        console.print(f"[green]✓[/green] Vault initialised at [cyan]{vp}[/cyan]")
    except Exception as exc:
        if "already exists" in str(exc):
            console.print(f"[yellow]✓[/yellow] Vault already exists at [cyan]{vp}[/cyan]")
        else:
            err_console.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1) from exc

    # Device identity
    if identity_exists():
        console.print(
            "[yellow]✓[/yellow] Device identity already exists — skipping key generation."
        )
    else:
        if device_name is None:
            device_name = typer.prompt(
                "Device name",
                default=plat.node() or "my-device",
            )
        passphrase = typer.prompt(
            "Vault passphrase (protects private key)",
            hide_input=True,
            confirmation_prompt=True,
        )
        identity = create_device_identity()
        save_device_identity(identity, passphrase)
        save_device_meta(identity, device_name)

        # Register device in vault
        try:
            from zhubin.storage.filesystem import save_device

            dr = DeviceRecord(
                id=identity.device_id,
                name=device_name,
                public_key=identity.public_key_b64,
                hostname=plat.node(),
                platform=plat.system(),
            )
            save_device(vp, dr)
            console.print(f"[green]✓[/green] Device [bold]{device_name}[/bold] registered.")
        except Exception as exc:
            console.print(f"[yellow]⚠[/yellow] Could not register device in vault: {exc}")

        from zhubin.crypto.identity import format_fingerprint_display

        console.print(
            f"[green]✓[/green] Private key stored securely. "
            f"[dim](Device ID: {identity.device_id})[/dim]"
        )
        console.print("[bold]Public Key Fingerprint[/bold] (SHA-256):")
        console.print(f"  [cyan]{format_fingerprint_display(identity.fingerprint)}[/cyan]")

    console.print(
        "\n[bold green]Vault ready.[/bold green] Next steps:\n"
        "  [cyan]zhubin group create personal[/cyan]\n"
        "  [cyan]zhubin add personal/github[/cyan]\n"
    )


@app.command(name="add")
def add_secret(
    path: Annotated[
        str,
        typer.Argument(
            help="group/path format, e.g. personal/github or own/ilo/bank/s",
            autocompletion=complete_secret_path,
        ),
    ],
    username: Annotated[
        str | None,
        typer.Option("--username", "-u", help="Username (prompted if omitted)"),
    ] = None,
    url: Annotated[
        str | None,
        typer.Option("--url", help="URL (prompted if omitted)"),
    ] = None,
    notes: Annotated[
        str | None,
        typer.Option("--notes", help="Notes (prompted if omitted)"),
    ] = None,
    password_stdin: Annotated[
        bool,
        typer.Option(
            "--password-stdin",
            help="Read password from stdin (do not pass passwords on the command line)",
        ),
    ] = False,
) -> None:
    """Add a new secret. Non-password fields may be set via options; password is prompted."""
    from zhubin.vault.models import SecretPayload

    group_name, secret_name = _parse_path(path)
    svc = get_service()

    if password_stdin:
        # Read password first; do not prompt for other fields (prompts would
        # consume the same stdin stream). Omitted options default to empty.
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            err_console.print("[bold red]Error:[/bold red] password is required (stdin was empty).")
            raise typer.Exit(1)
        if username is None:
            username = ""
        if url is None:
            url = ""
        if notes is None:
            notes = ""
    else:
        if username is None:
            username = typer.prompt("Username", default="")
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=False)
        if url is None:
            url = typer.prompt("URL", default="")
        if notes is None:
            notes = typer.prompt("Notes", default="")

    payload = SecretPayload(username=username, password=password, url=url, notes=notes)
    try:
        svc.add_secret(group_name, secret_name, payload)
        console.print(f"[green]✓[/green] Secret [bold]{path}[/bold] added.")
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command(name="edit")
def edit_secret(
    path: Annotated[
        str,
        typer.Argument(help="group/path", autocompletion=complete_secret_path),
    ],
) -> None:
    """Edit an existing secret interactively."""
    from zhubin.vault.models import SecretPayload

    group_name, secret_name = _parse_path(path)
    svc = get_service()

    try:
        existing = svc.get_secret(group_name, secret_name)
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    console.print("[dim]Press Enter to keep the current value.[/dim]")
    username = typer.prompt("Username", default=existing.username)
    password = _prompt_password_edit(existing.password)
    url = typer.prompt("URL", default=existing.url)
    notes = typer.prompt("Notes", default=existing.notes)

    payload = SecretPayload(username=username, password=password, url=url, notes=notes)
    try:
        svc.edit_secret(group_name, secret_name, payload)
        console.print(f"[green]✓[/green] Secret [bold]{path}[/bold] updated.")
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command(name="delete")
def delete_secret(
    path: Annotated[
        str,
        typer.Argument(help="group/path", autocompletion=complete_secret_path),
    ],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
) -> None:
    """Delete a secret permanently."""
    group_name, secret_name = _parse_path(path)
    svc = get_service()

    if not yes:
        typer.confirm(f"Delete '{path}'?", abort=True)

    try:
        svc.delete_secret(group_name, secret_name)
        console.print(f"[green]✓[/green] Secret [bold]{path}[/bold] deleted.")
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command(name="cp")
def copy_secret(
    path: Annotated[
        str,
        typer.Argument(help="group/path", autocompletion=complete_secret_path),
    ],
    field: Annotated[
        str,
        typer.Argument(
            help="Field to copy: password (default), username, url",
            autocompletion=complete_cp_field,
        ),
    ] = "password",
    timeout: Annotated[
        int | None,
        typer.Option("--timeout", "-t", help="Clipboard clear timeout in seconds"),
    ] = None,
) -> None:
    """Copy a secret field to the clipboard (default: password)."""
    from zhubin.clipboard.clipboard import ClipboardError, copy
    from zhubin.config import load_config

    group_name, secret_name = _parse_path(path)
    svc = get_service()

    try:
        payload = svc.get_secret(group_name, secret_name)
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    field_map = {
        "password": payload.password,
        "username": payload.username,
        "url": payload.url,
    }
    if field not in field_map:
        err_console.print(
            f"[bold red]Error:[/bold red] Unknown field '{field}'. "
            "Valid fields: password, username, url."
        )
        raise typer.Exit(1)

    value = field_map[field]
    if not value:
        err_console.print(f"[yellow]⚠[/yellow] Field '{field}' is empty.")
        raise typer.Exit(1)

    cfg = load_config(get_vault_path())
    t = timeout if timeout is not None else cfg.clipboard_timeout

    try:
        copy(value, timeout=t)
    except ClipboardError as exc:
        err_console.print(f"[bold red]Clipboard error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    console.print(
        f"[green]✓[/green] [bold]{field.capitalize()}[/bold] copied to clipboard.\n"
        f"  [dim]Clipboard will be cleared in {t} seconds.[/dim]"
    )


@app.command(name="show")
def show_secret(
    path: Annotated[
        str,
        typer.Argument(help="group/path", autocompletion=complete_secret_path),
    ],
) -> None:
    """Display a secret's fields (password is shown — use cp for safer access)."""
    from rich.table import Table

    group_name, secret_name = _parse_path(path)
    svc = get_service()

    try:
        payload = svc.get_secret(group_name, secret_name)
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    table = Table(title=f"[bold]{path}[/bold]", show_header=False, box=None)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value")

    if payload.username:
        table.add_row("Username", payload.username)
    if payload.password:
        table.add_row("Password", f"[yellow]{payload.password}[/yellow]")
    if payload.url:
        table.add_row("URL", payload.url)
    if payload.notes:
        table.add_row("Notes", payload.notes)

    console.print(table)


@app.command(name="list")
def list_all(
    group: Annotated[
        str | None,
        typer.Option(
            "--group",
            "-g",
            help="Filter by group",
            autocompletion=complete_group_name,
        ),
    ] = None,
) -> None:
    """List all secrets in the vault."""
    from rich.tree import Tree

    svc = get_service()

    try:
        groups = svc.list_groups()
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    if not groups:
        console.print("[dim]No groups found. Create one with 'zhubin group create <name>'.[/dim]")
        return

    tree = Tree("[bold]Vault[/bold]")
    for g in groups:
        if group and g.name != group:
            continue
        secrets = svc.list_secrets(g.name)
        branch = tree.add(f"[cyan]{g.name}[/cyan] [dim]({len(secrets)} secrets)[/dim]")
        _add_nested_secret_tree(branch, secrets)

    console.print(tree)


@app.command(name="find")
def find_secrets(
    query: Annotated[str, typer.Argument(help="Search query (case-insensitive)")],
) -> None:
    """Search secrets by group or name."""
    from rich.table import Table

    svc = get_service()

    try:
        results = svc.find_secrets(query)
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    if not results:
        console.print(f"[dim]No secrets matching '{query}'.[/dim]")
        return

    table = Table(title=f"Results for '{query}'")
    table.add_column("Group", style="cyan")
    table.add_column("Secret")
    for group_name, secret_name in results:
        table.add_row(group_name, secret_name)

    console.print(table)


@app.command(name="status")
def status() -> None:
    """Show vault and Git status."""
    from rich.panel import Panel
    from rich.table import Table

    from zhubin.storage.git import get_status

    vp = get_vault_path()

    table = Table(show_header=False, box=None)
    table.add_column("Key", style="cyan")
    table.add_column("Value")

    table.add_row("Vault path", str(vp))

    git_st = get_status(vp)
    table.add_row("Git branch", git_st.branch)
    if git_st.has_remote:
        table.add_row("Remote", git_st.remote or "—")
        table.add_row("Ahead", str(git_st.ahead))
        table.add_row("Behind", str(git_st.behind))
    else:
        table.add_row("Remote", "[dim]not configured[/dim]")

    if git_st.uncommitted:
        table.add_row(
            "Uncommitted",
            f"[yellow]{len(git_st.uncommitted)} file(s)[/yellow]",
        )
    else:
        table.add_row("Uncommitted", "[green]clean[/green]")

    if git_st.has_conflicts:
        table.add_row("Conflicts", "[bold red]YES — resolve before syncing[/bold red]")
    if git_st.detached:
        table.add_row("HEAD", "[bold red]detached — sync refused[/bold red]")
    if git_st.merge_in_progress:
        table.add_row("Merge", "[bold red]in progress[/bold red]")
    if not git_st.git_available:
        table.add_row("Git", "[bold red]executable not found[/bold red]")
    elif not git_st.initialized:
        table.add_row("Git", "[dim]repository not initialised[/dim]")

    console.print(Panel(table, title="[bold]Zhubin Status[/bold]"))


@app.command(name="sync")
def sync(
    message: Annotated[
        str,
        typer.Option("--message", "-m", help="Commit message"),
    ] = "zhubin: sync vault",
    no_push: Annotated[bool, typer.Option("--no-push", help="Only pull + commit")] = False,
) -> None:
    """Synchronise the vault with the remote Git repository."""
    vp = get_vault_path()
    try:
        from zhubin.storage.git import sync as git_sync

        results = git_sync(vp, message, push_after=not no_push)
        console.print("[green]✓[/green] Pull:", results.get("pull", ""))
        console.print("[green]✓[/green] Commit:", results.get("commit", ""))
        if not no_push:
            console.print("[green]✓[/green] Push:", results.get("push", ""))
    except Exception as exc:
        err_console.print(f"[bold red]Sync error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command(name="lock")
def lock_vault() -> None:
    """Lock the vault (clears in-memory keys and session tokens)."""
    from zhubin.crypto import keyring_store

    keyring_store.clear_session("web_session")
    console.print("[green]✓[/green] Vault locked.")


@app.command(name="unlock")
def unlock_vault() -> None:
    """Unlock the vault by loading the device identity."""
    get_service()
    console.print("[green]✓[/green] Vault unlocked.")


@app.command(name="web")
def web_ui(
    host: Annotated[
        str, typer.Option("--host", help="Bind host (default: 127.0.0.1)")
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Port (default: 8787)")] = 8787,
    open_browser: Annotated[bool, typer.Option("--open/--no-open", help="Open browser")] = True,
) -> None:
    """Start the local Web UI."""
    import uvicorn

    from zhubin.config import load_config

    if host not in ("127.0.0.1", "localhost", "::1"):
        err_console.print(
            "[bold red]Security warning:[/bold red] "
            "The Web UI is designed for localhost only. "
            f"Binding to '{host}' exposes it to the network."
        )
        if not typer.confirm("Continue anyway?"):
            raise typer.Exit(0)

    cfg = load_config(get_vault_path())
    _host = host or cfg.web_host
    _port = port or cfg.web_port

    console.print(f"[green]✓[/green] Starting Web UI at [link]http://{_host}:{_port}[/link]")

    if open_browser:
        import threading
        import webbrowser

        def _open() -> None:
            import time

            time.sleep(1.2)
            webbrowser.open(f"http://{_host}:{_port}")

        threading.Thread(target=_open, daemon=True).start()

    from zhubin.web.app import create_app

    vault_path = get_vault_path()
    web_app = create_app(
        vault_path,
        allowed_hosts=[_host, "127.0.0.1", "localhost", "::1"],
    )
    uvicorn.run(web_app, host=_host, port=_port, log_level="warning")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_path(path: str) -> tuple[str, str]:
    """Parse 'group/path' into (group, secret path). Nested secret folders are allowed."""
    parts = path.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        err_console.print(
            f"[bold red]Error:[/bold red] Invalid path '{path}'. "
            "Expected format: [bold]group/path[/bold] "
            "(e.g. personal/github or own/ilo/bank/s)"
        )
        raise typer.Exit(1)
    return parts[0], parts[1]


def _add_nested_secret_tree(branch: object, names: list[str]) -> None:
    """Render slash-separated secret names as nested Rich tree folders."""
    from rich.tree import Tree

    class _Node:
        def __init__(self) -> None:
            self.folders: dict[str, _Node] = {}
            self.leaves: list[str] = []

    root = _Node()
    for name in names:
        parts = name.split("/")
        node = root
        for part in parts[:-1]:
            node = node.folders.setdefault(part, _Node())
        node.leaves.append(parts[-1])

    def render(tree_node: Tree, node: _Node) -> None:
        keys = sorted(set(node.folders) | set(node.leaves))
        for key in keys:
            if key in node.leaves:
                tree_node.add(f"[white]{key}[/white]")
            if key in node.folders:
                sub = tree_node.add(f"[dim]{key}/[/dim]")
                render(sub, node.folders[key])

    assert isinstance(branch, Tree)
    render(branch, root)


def _prompt_password_edit(current: str) -> str:
    """Prompt for a new password, keeping the current if blank."""
    new = typer.prompt("Password (blank=keep current)", hide_input=True, default="")
    return new if new else current


def main() -> None:
    app()


def iter_cli_command_paths() -> list[str]:
    """
    Return the authoritative list of user-facing command paths.

    Examples: ``init``, ``group create``, ``device authorize``.
    Used to detect documentation/CLI drift.
    """
    paths: list[str] = []
    for cmd in app.registered_commands:
        name = cmd.name or (cmd.callback.__name__ if cmd.callback else "")
        if name:
            paths.append(name)
    for group_name, typer_app in (
        ("group", group_app),
        ("device", device_app),
    ):
        for cmd in typer_app.registered_commands:
            name = cmd.name or (cmd.callback.__name__ if cmd.callback else "")
            if name:
                paths.append(f"{group_name} {name}")
    return sorted(paths)
