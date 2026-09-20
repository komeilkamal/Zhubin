"""
Shell Tab completion for vault group and secret names.

Completers read on-disk names only. They never unlock the vault, decrypt
secrets, or prompt for a passphrase — Tab would hang if they did.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_CP_FIELDS = ("password", "username", "url")

# Typer's bash completion script plus nospace when a match ends with "/".
_BASH_SOURCE_NOSPACE = """
%(complete_func)s() {
    local IFS=$'\\n'
    COMPREPLY=( $( env COMP_WORDS="${COMP_WORDS[*]}" \\
                   COMP_CWORD=$COMP_CWORD \\
                   %(autocomplete_var)s=complete_bash $1 ) )
    for __zhubin_c in "${COMPREPLY[@]}"; do
        if [[ "$__zhubin_c" == */ ]]; then
            compopt -o nospace 2>/dev/null
            break
        fi
    done
    return 0
}

complete -o default -F %(complete_func)s %(prog_name)s
"""


def complete_secret_path(incomplete: str) -> list[str]:
    """
    Complete ``group/secret`` paths one segment at a time, like directories.

    Groups are offered with a trailing ``/`` so the next Tab continues into
    secrets. Nested secret folders also keep a trailing ``/``; leaf secrets
    do not, so the shell can insert a space.
    """
    vault = _vault_path()
    if vault is None:
        return []

    from zhubin.storage.filesystem import list_groups, list_secrets

    try:
        groups = [g.name for g in list_groups(vault)]
    except Exception:
        return []

    if "/" not in incomplete:
        return [f"{name}/" for name in groups if name.startswith(incomplete)]

    group, rest = incomplete.split("/", 1)
    if group not in groups:
        return []

    try:
        names = list_secrets(vault, group)
    except Exception:
        return []

    return [f"{group}/{item}" for item in _next_path_segments(rest, names)]


def complete_group_name(incomplete: str) -> list[str]:
    """Complete an existing group name (no trailing slash)."""
    vault = _vault_path()
    if vault is None:
        return []

    from zhubin.storage.filesystem import list_groups

    try:
        return [g.name for g in list_groups(vault) if g.name.startswith(incomplete)]
    except Exception:
        return []


def complete_cp_field(incomplete: str) -> list[str]:
    """Complete the ``cp`` field argument: password, username, or url."""
    return [field for field in _CP_FIELDS if field.startswith(incomplete)]


def _vault_path() -> Path | None:
    """Return the vault path if it exists, otherwise ``None``. Never prompts."""
    try:
        from zhubin.cli.app import get_vault_path
        from zhubin.storage.filesystem import assert_vault

        vault = get_vault_path()
        assert_vault(vault)
    except Exception:
        return None
    return vault


def _next_path_segments(prefix: str, names: list[str]) -> list[str]:
    """
    Return the next path segment of *names* matching *prefix*.

    Folders include a trailing ``/``; leaf secrets do not. Duplicates from
    several secrets sharing a folder prefix are collapsed.
    """
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if not name.startswith(prefix):
            continue
        rest = name[len(prefix) :]
        if rest == "":
            candidate = name
        else:
            slash = rest.find("/")
            candidate = name if slash == -1 else name[: len(prefix) + slash + 1]
        if candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out


def _zsh_quote(value: str) -> str:
    """Return *value* as a zsh single-quoted word."""
    return "'" + value.replace("'", "'\\''") + "'"


def _zsh_compadd_script(values: list[str]) -> str:
    """
    Build a zsh snippet that completes *values*.

    Folder matches (trailing ``/``) use an empty suffix so the shell does
    not insert a space; the next Tab can continue into that path. Leaf
    matches keep the default space suffix.
    """
    folders = [_zsh_quote(v) for v in values if v.endswith("/")]
    leaves = [_zsh_quote(v) for v in values if not v.endswith("/")]
    parts: list[str] = []
    if folders:
        parts.append("compadd -U -S '' -- " + " ".join(folders))
    if leaves:
        parts.append("compadd -U -- " + " ".join(leaves))
    return "; ".join(parts) if parts else "_files"


def _patch_typer_shell_complete() -> None:
    """Replace Typer's zsh ``_arguments`` completion so folders get no space."""
    try:
        from typer._completion_classes import BashComplete, ZshComplete
    except ImportError:
        return

    def complete(self: Any) -> str:
        args, incomplete = self.get_completion_args()
        items = self.get_completions(args, incomplete)
        return _zsh_compadd_script([str(item.value) for item in items])

    ZshComplete.complete = complete  # type: ignore[method-assign]
    BashComplete.source_template = _BASH_SOURCE_NOSPACE


_patch_typer_shell_complete()
