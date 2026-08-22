"""
Device management CLI commands.
"""

from __future__ import annotations

import contextlib
import platform as plat
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(help="Manage devices and authorization.", no_args_is_help=True)
console = Console()
err_console = Console(stderr=True)


def _print_fingerprint(fingerprint: str) -> None:
    from zhubin.crypto.identity import format_fingerprint_display

    console.print("[bold]Public Key Fingerprint[/bold] (SHA-256):")
    console.print(f"  [cyan]{format_fingerprint_display(fingerprint)}[/cyan]")


@app.command(name="init")
def device_init(
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Device name"),
    ] = None,
) -> None:
    """
    Initialise a device identity without reinitialising the vault.

    Use this when cloning an existing vault onto a new device.
    After running this command, compare fingerprints, then ask an authorized
    device owner to run [cyan]zhubin device authorize <your-device-name>[/cyan].
    """
    from zhubin.cli.app import get_vault_path
    from zhubin.crypto.identity import (
        create_device_identity,
        identity_exists,
        save_device_identity,
        save_device_meta,
    )
    from zhubin.storage.filesystem import assert_vault, save_device
    from zhubin.vault.models import DeviceRecord

    vp = get_vault_path()
    try:
        assert_vault(vp)
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    if identity_exists():
        err_console.print(
            "[bold red]Error:[/bold red] Device identity already exists. "
            "Use 'zhubin device fingerprint' to display this device's fingerprint."
        )
        raise typer.Exit(1)

    if name is None:
        name = typer.prompt("Device name", default=plat.node() or "new-device")

    passphrase = typer.prompt(
        "Vault passphrase (protects private key)",
        hide_input=True,
        confirmation_prompt=True,
    )

    identity = create_device_identity()
    save_device_identity(identity, passphrase)
    save_device_meta(identity, name)

    dr = DeviceRecord(
        id=identity.device_id,
        name=name,
        public_key=identity.public_key_b64,
        hostname=plat.node(),
        platform=plat.system(),
    )
    save_device(vp, dr)

    console.print(f"[green]✓[/green] Device [bold]{name}[/bold] identity created.")
    console.print(f"  [dim]Device ID: {identity.device_id}[/dim]")
    _print_fingerprint(identity.fingerprint)
    console.print(
        "\nCompare this fingerprint on a trusted device with:\n"
        f"  [cyan]zhubin device fingerprint {name}[/cyan]\n"
        "or:\n"
        f"  [cyan]zhubin device show {name}[/cyan]\n"
        "Then ask an authorized device to run:\n"
        f"  [cyan]zhubin device authorize {name}[/cyan]"
    )


@app.command(name="list")
def list_devices() -> None:
    """List all registered devices."""
    from zhubin.cli.app import get_service

    svc = get_service(require_unlock=False)
    try:
        devices = svc.list_devices()
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    if not devices:
        console.print("[dim]No devices registered.[/dim]")
        return

    from zhubin.crypto.identity import identity_exists, load_device_meta

    my_id = None
    if identity_exists():
        try:
            meta = load_device_meta()
            my_id = meta.get("id")
        except Exception:
            pass

    table = Table(title="Devices")
    table.add_column("Name", style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Fingerprint (SHA-256)", style="green")
    table.add_column("Status")
    table.add_column("Created")

    for d in devices:
        status = "[red]revoked[/red]" if d.revoked else "[green]active[/green]"
        name_str = f"[bold]{d.name}[/bold] [dim](this device)[/dim]" if d.id == my_id else d.name
        fp = d.fingerprint()
        fp_short = ":".join(fp.split(":")[:8]) + ":…"
        table.add_row(
            name_str,
            d.id[:8] + "...",
            fp_short,
            status,
            d.created_at.strftime("%Y-%m-%d"),
        )
    console.print(table)
    console.print("[dim]Use 'zhubin device show <name>' to display the full fingerprint.[/dim]")


@app.command(name="fingerprint")
def device_fingerprint(
    device_name: Annotated[
        str | None,
        typer.Argument(help="Device name (default: this device)"),
    ] = None,
) -> None:
    """
    Display the SHA-256 public-key fingerprint of this device or a named device.

    Compare fingerprints out-of-band during onboarding.  A matching name in
    Git is not proof of identity — only a matching fingerprint is.
    """
    from zhubin.cli.app import get_service, get_vault_path
    from zhubin.crypto.identity import identity_exists, load_device_identity, load_device_meta
    from zhubin.storage.filesystem import load_device

    if device_name is None:
        if not identity_exists():
            err_console.print("[bold red]Error:[/bold red] No local device identity found.")
            raise typer.Exit(1)
        try:
            identity = load_device_identity()
            meta = load_device_meta()
            name = str(meta.get("name") or "this device")
            fp = identity.fingerprint
        except Exception:
            passphrase = typer.prompt("Vault passphrase", hide_input=True)
            try:
                identity = load_device_identity(passphrase)
                meta = load_device_meta()
                name = str(meta.get("name") or "this device")
                fp = identity.fingerprint
            except Exception as exc:
                err_console.print(f"[bold red]Error:[/bold red] {exc}")
                raise typer.Exit(1) from exc
        console.print(f"Device: [bold]{name}[/bold] [dim](this device)[/dim]")
        _print_fingerprint(fp)
        return

    vp = get_vault_path()
    try:
        # Listing does not require unlock; the fingerprint is public.
        svc = get_service(require_unlock=False)
        target = next((d for d in svc.list_devices() if d.name == device_name), None)
        if target is None:
            target = load_device(vp, device_name)
        console.print(f"Device: [bold]{target.name}[/bold]")
        _print_fingerprint(target.fingerprint())
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command(name="show")
def show_device(
    device_name: Annotated[str, typer.Argument(help="Device name")],
) -> None:
    """Show public details and the full fingerprint of a registered device."""
    from zhubin.cli.app import get_service
    from zhubin.crypto.identity import format_fingerprint_display, identity_exists, load_device_meta

    svc = get_service(require_unlock=False)
    target = next((d for d in svc.list_devices() if d.name == device_name), None)
    if target is None:
        err_console.print(f"[bold red]Error:[/bold red] Device '{device_name}' not found.")
        raise typer.Exit(1)

    my_id = None
    if identity_exists():
        with contextlib.suppress(Exception):
            my_id = load_device_meta().get("id")

    status = "revoked" if target.revoked else "active"
    groups = [g.name for g in svc.list_groups() if target.id in g.device_keys]
    body = (
        f"[bold]Device:[/bold] {target.name}"
        + (" [dim](this device)[/dim]" if target.id == my_id else "")
        + f"\n[bold]ID:[/bold] {target.id}"
        + f"\n[bold]Status:[/bold] {status}"
        + f"\n[bold]Platform:[/bold] {target.platform or '—'}"
        + f"\n[bold]Hostname:[/bold] {target.hostname or '—'}"
        + "\n[bold]Public Key Fingerprint[/bold] (SHA-256):\n"
        + f"[cyan]{format_fingerprint_display(target.fingerprint())}[/cyan]"
        + "\n[bold]Currently authorized for:[/bold] "
        + (", ".join(groups) if groups else "(none)")
    )
    console.print(Panel(body, title="Device"))


@app.command(name="authorize")
def authorize_device(
    device_name: Annotated[str, typer.Argument(help="Device name to authorize")],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip fingerprint confirmation (insecure)"),
    ] = False,
) -> None:
    """
    Authorize a device to access all groups this device can access.

    The Git repository is untrusted.  A device file in Git is not proof of
    identity — compare the displayed fingerprint with the value shown on the
    target device ([cyan]zhubin device fingerprint[/cyan]) before confirming.
    """
    from zhubin.cli.app import get_service
    from zhubin.crypto.identity import format_fingerprint_display
    from zhubin.vault.models import DeviceRecord

    svc = get_service()
    try:
        preview = svc.preview_authorize(device_name)
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    device = preview["device"]
    if not isinstance(device, DeviceRecord):
        err_console.print(f"[bold red]Error:[/bold red] Device '{device_name}' not found.")
        raise typer.Exit(1)
    fingerprint = str(preview["fingerprint"])
    groups = [str(g) for g in preview["groups"]]

    group_lines = "\n".join(f"  - {g}" for g in groups) if groups else "  (none)"
    console.print(
        Panel(
            f"[bold]You are about to authorize:[/bold]\n\n"
            f"  Device: [cyan]{device.name}[/cyan]\n"
            f"  Fingerprint:\n[green]{format_fingerprint_display(fingerprint)}[/green]\n\n"
            f"This device will receive access to:\n{group_lines}\n\n"
            "[yellow]The Git repository is untrusted.[/yellow] Compare this fingerprint "
            "with [cyan]zhubin device fingerprint[/cyan] on the target device.",
            title="Authorize device",
        )
    )

    if not yes:
        typer.confirm("Authorize this device and wrap group keys?", abort=True)

    try:
        authorized = svc.authorize_device(device_name)
        console.print(
            f"[green]✓[/green] Device [bold]{device_name}[/bold] "
            f"authorized for {len(authorized)} group(s)."
        )
        console.print("[dim]Commit and push the vault so the new device can pull its key.[/dim]")
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc


@app.command(name="revoke")
def revoke_device(
    device_name: Annotated[str, typer.Argument(help="Device name to revoke")],
    yes: Annotated[bool, typer.Option("--yes", "-y")] = False,
    rotate: Annotated[
        bool | None,
        typer.Option("--rotate/--no-rotate", help="Rotate group keys after revocation"),
    ] = None,
) -> None:
    """
    Revoke a device's access.

    [bold yellow]Warning:[/bold yellow] Revocation removes the device from current
    authorization metadata and prevents future group keys from being issued to
    it, but does NOT invalidate historical wrapped group keys already present
    in Git history.  Rotation is required if the device may be compromised.
    """
    from zhubin.cli.app import get_service, get_vault_path

    svc = get_service()
    vp = get_vault_path()

    target_device = next((d for d in svc.list_devices() if d.name == device_name), None)
    if target_device is None:
        err_console.print(f"[bold red]Error:[/bold red] Device '{device_name}' not found.")
        raise typer.Exit(1)

    from zhubin.storage.filesystem import list_groups as _list_groups

    affected = [g.name for g in _list_groups(vp) if target_device.id in g.device_keys]

    if not yes:
        typer.confirm(f"Revoke device '{device_name}'?", abort=True)

    if affected:
        console.print(
            f"\n[bold]Device revoked (pending write).[/bold]\n"
            f"The following groups were accessible by [bold]{device_name}[/bold]:\n"
            + "\n".join(f"  - [cyan]{g}[/cyan]" for g in affected)
            + "\n\nBecause Git history may still contain Group Keys encrypted for this "
            "device, [bold]rotation is required[/bold] if the device may be compromised."
        )
        if rotate is None:
            rotate = typer.confirm("\nRotate affected groups now?", default=True)
    elif rotate is None:
        rotate = False

    do_rotate = bool(rotate) and bool(affected)

    try:
        with console.status(f"Revoking device [bold]{device_name}[/bold]..."):
            svc.revoke_device(device_name, rotate_groups=do_rotate)
        console.print(f"[green]✓[/green] Device [bold]{device_name}[/bold] revoked.")
        if do_rotate:
            console.print("[green]✓[/green] Affected group keys rotated.")
        else:
            console.print(
                "[yellow]⚠[/yellow] Historical wrapped keys in Git history remain valid "
                "until the affected groups are rotated ([cyan]zhubin group rotate[/cyan])."
            )
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from exc
