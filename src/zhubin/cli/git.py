"""
Git CLI commands (registered directly on the main app).
"""

from __future__ import annotations

import typer
from rich.console import Console

app = typer.Typer(help="Git operations.")
console = Console()
err_console = Console(stderr=True)
