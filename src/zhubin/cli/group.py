"""
Group management CLI commands.
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from zhubin.cli.completion import complete_group_name

app = typer.Typer(help="Manage secret groups.", no_args_is_help=True)
console = Console()
err_console = Console(stderr=True)


@app.command(name="create")
def create_group(
    name: Annotated[str, typer.Argument(help="Group name (alphanumeric, hyphen, underscore)")],
) -> None:
    """Create a new secret group and generate its encryption key."""
    from zhubin.cli.app import get_service

    svc = get_service()
    try:
        group = svc.create_group(name)
        console.print(
            f"[green]✓[/green] Group [bold]{name}[/bold] created. [dim](ID: {group.id})[/dim]"
        )
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command(name="list")
def list_groups() -> None:
    """List all groups in the vault."""
    from zhubin.cli.app import get_service

    svc = get_service(require_unlock=False)
    try:
        groups = svc.list_groups()
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    if not groups:
        console.print("[dim]No groups yet. Create one with 'zhubin group create <name>'.[/dim]")
        return

    table = Table(title="Groups")
    table.add_column("Name", style="cyan")
    table.add_column("Devices")
    table.add_column("Created")
    for g in groups:
        table.add_row(
            g.name,
            str(len(g.device_keys)),
            g.created_at.strftime("%Y-%m-%d"),
        )
    console.print(table)


@app.command(name="delete")
def delete_group(
    name: Annotated[
        str,
        typer.Argument(help="Group name", autocompletion=complete_group_name),
    ],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
) -> None:
    """Delete a group and all secrets in it."""
    from zhubin.cli.app import get_service

    svc = get_service(require_unlock=False)
    try:
        if not any(g.name == name for g in svc.list_groups()):
            err_console.print(f"[bold red]Error:[/bold red] Group '{name}' not found.")
            raise typer.Exit(1)
        count = len(svc.list_secrets(name))
    except typer.Exit:
        raise
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    if not yes:
        typer.confirm(
            f"Delete group '{name}' and all {count} secret(s)? This cannot be undone.",
            abort=True,
        )

    try:
        deleted = svc.delete_group(name)
        console.print(
            f"[green]✓[/green] Group [bold]{name}[/bold] deleted ({deleted} secret(s) removed)."
        )
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command(name="rotate")
def rotate_group(
    name: Annotated[
        str,
        typer.Argument(help="Group name", autocompletion=complete_group_name),
    ],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
) -> None:
    """
    Rotate the group encryption key.

    Generates a new key, re-encrypts all secrets in memory, and wraps
    the new key for all currently authorized devices.

    [bold yellow]Note:[/bold yellow] Old group keys remain in Git history.
    Only forward secrecy is guaranteed after rotation.
    """
    from zhubin.cli.app import get_service

    if not yes:
        typer.confirm(
            f"Rotate encryption key for group '{name}'? All secrets will be re-encrypted.",
            abort=True,
        )

    svc = get_service()
    try:
        with console.status(f"Rotating key for group [bold]{name}[/bold]..."):
            group = svc.rotate_group_key(name)
        console.print(
            f"[green]✓[/green] Group [bold]{name}[/bold] key rotated. "
            f"{len(group.device_keys)} device(s) updated."
        )
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc
