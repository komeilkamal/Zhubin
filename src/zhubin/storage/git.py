"""
Git integration for Zhubin.

Uses the system ``git`` executable via safe subprocess invocation.
Never invokes a shell.

Design principles
-----------------
* Git authentication is handled entirely by the user's existing setup
  (SSH keys, credential helpers, etc.).
* Zhubin never handles passwords or tokens for Git.
* Conflict resolution that could silently lose secrets is refused.
* All staging is limited to known vault paths.
* Encrypted objects are treated as binary (see ``.gitattributes``); Git
  will conflict rather than auto-merge concurrent writes.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import NamedTuple

from zhubin.exceptions import GitConflictError, GitError, GitUnsafeStateError
from zhubin.storage.filesystem import ensure_gitattributes


class GitStatus(NamedTuple):
    branch: str
    remote: str | None
    has_remote: bool
    uncommitted: list[str]
    ahead: int
    behind: int
    has_conflicts: bool
    detached: bool
    merge_in_progress: bool
    rebase_in_progress: bool
    git_available: bool
    initialized: bool
    untracked: list[str]


def _run(
    args: list[str],
    cwd: Path,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a git command safely (never via a shell, never interpolate secrets)."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found. Please install Git.") from exc

    if check and result.returncode != 0:
        # Do not include the full command line when it might be huge; args
        # never contain secret values (only paths and git flags).
        stderr = (result.stderr or "").strip()
        raise GitError(f"git {args[0]} failed (exit {result.returncode}): {stderr}")
    return result


def git_available() -> bool:
    """Return True if a ``git`` executable can be invoked."""
    try:
        result = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def is_git_repo(path: Path) -> bool:
    """Return True if *path* is inside a Git repository."""
    try:
        result = _run(["rev-parse", "--git-dir"], path, check=False)
    except GitError:
        return False
    return result.returncode == 0


def current_branch(path: Path) -> str:
    result = _run(["branch", "--show-current"], path)
    return result.stdout.strip() or "HEAD"


def _git_dir(path: Path) -> Path:
    result = _run(["rev-parse", "--git-dir"], path)
    raw = Path(result.stdout.strip())
    return raw if raw.is_absolute() else (path / raw)


def _porcelain_conflicts(lines: list[str]) -> bool:
    return any(line[:2] in ("UU", "AA", "DD", "AU", "UA", "DU", "UD") for line in lines)


def get_status(vault_path: Path) -> GitStatus:
    """Return structured Git status for *vault_path*."""
    if not git_available():
        return GitStatus(
            branch="(git unavailable)",
            remote=None,
            has_remote=False,
            uncommitted=[],
            ahead=0,
            behind=0,
            has_conflicts=False,
            detached=False,
            merge_in_progress=False,
            rebase_in_progress=False,
            git_available=False,
            initialized=False,
            untracked=[],
        )

    if not is_git_repo(vault_path):
        return GitStatus(
            branch="(no git)",
            remote=None,
            has_remote=False,
            uncommitted=[],
            ahead=0,
            behind=0,
            has_conflicts=False,
            detached=False,
            merge_in_progress=False,
            rebase_in_progress=False,
            git_available=True,
            initialized=False,
            untracked=[],
        )

    branch = current_branch(vault_path)
    detached = branch in ("HEAD", "") or _run(
        ["rev-parse", "--abbrev-ref", "HEAD"], vault_path, check=False
    ).stdout.strip() in ("HEAD", "")

    git_dir = _git_dir(vault_path)
    merge_in_progress = (git_dir / "MERGE_HEAD").exists()
    rebase_in_progress = (
        (git_dir / "REBASE_HEAD").exists()
        or (git_dir / "rebase-merge").exists()
        or (git_dir / "rebase-apply").exists()
    )

    remote_result = _run(
        ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        vault_path,
        check=False,
    )
    remote = remote_result.stdout.strip() if remote_result.returncode == 0 else None

    ahead = behind = 0
    if remote:
        rev_result = _run(
            ["rev-list", "--left-right", "--count", f"{remote}...HEAD"],
            vault_path,
            check=False,
        )
        if rev_result.returncode == 0:
            parts = rev_result.stdout.strip().split()
            if len(parts) == 2:
                behind, ahead = int(parts[0]), int(parts[1])

    status_result = _run(["status", "--porcelain"], vault_path)
    porcelain = [line for line in status_result.stdout.splitlines() if line.strip()]
    uncommitted = [line.strip() for line in porcelain]
    untracked = [line[3:].strip() for line in porcelain if line.startswith("??")]
    has_conflicts = _porcelain_conflicts(porcelain) or _has_conflict_markers(vault_path)

    return GitStatus(
        branch=branch,
        remote=remote,
        has_remote=bool(remote),
        uncommitted=uncommitted,
        ahead=ahead,
        behind=behind,
        has_conflicts=has_conflicts,
        detached=detached,
        merge_in_progress=merge_in_progress,
        rebase_in_progress=rebase_in_progress,
        git_available=True,
        initialized=True,
        untracked=untracked,
    )


def _has_conflict_markers(vault_path: Path) -> bool:
    for path in vault_path.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in {".json", ".secret", ".yaml"} and path.name not in {
            "config.yaml",
            "group.json",
        }:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"<<<<<<<" in data or b">>>>>>>" in data:
            return True
    return False


def _verify_vault_integrity_after_pull(vault_path: Path) -> None:
    """Refuse to continue if a merge produced conflict markers or invalid JSON."""
    for path in vault_path.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix not in {".json", ".secret"}:
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise GitError(f"Unable to read vault file {path.name} after pull.") from exc
        if b"<<<<<<< " in data or b">>>>>>> " in data:
            raise GitConflictError(
                f"Unresolved conflict in {path.relative_to(vault_path)}. "
                "Zhubin will not auto-resolve encrypted objects. Resolve manually."
            )
        try:
            json.loads(data)
        except json.JSONDecodeError as exc:
            raise GitConflictError(
                f"Vault file {path.relative_to(vault_path)} is not valid JSON after "
                "the pull. A silent merge would risk losing secrets; resolve manually."
            ) from exc


def assert_safe_to_sync(vault_path: Path) -> GitStatus:
    """Raise if the repository is not in a state that is safe to mutate via sync."""
    if not git_available():
        raise GitError("git executable not found. Please install Git.")

    status = get_status(vault_path)

    if not status.initialized:
        raise GitUnsafeStateError(
            "This directory is not a Git repository. Initialise Git before syncing."
        )
    if status.detached:
        raise GitUnsafeStateError("Refusing to sync on a detached HEAD. Check out a branch first.")
    if status.merge_in_progress:
        raise GitUnsafeStateError(
            "A merge is already in progress. Resolve or abort it before syncing."
        )
    if status.rebase_in_progress:
        raise GitUnsafeStateError(
            "A rebase is already in progress. Resolve or abort it before syncing."
        )
    if status.has_conflicts:
        raise GitConflictError(
            "There are existing merge conflicts in the repository. "
            "Resolve them manually before syncing. Zhubin will not choose ours or theirs."
        )
    if not status.has_remote:
        raise GitError(
            "No remote tracking branch configured. "
            "Add a remote with 'git remote add origin <url>' and set upstream first."
        )
    return status


def stage_vault(vault_path: Path) -> None:
    """Stage all changes inside the vault directory (never outside it)."""
    _run(["add", "--", str(vault_path)], vault_path)


def commit(vault_path: Path, message: str) -> str:
    """Commit staged changes.  Returns the new commit hash."""
    result = _run(["commit", "--message", message], vault_path)
    for line in result.stdout.splitlines():
        if line.startswith("["):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].rstrip("]")
    return ""


def pull(vault_path: Path) -> str:
    """Pull from the remote tracking branch.  Raises GitConflictError on conflict."""
    # Never pass -X ours / -X theirs.  Never auto-commit through --no-edit if a
    # conflict occurs — git itself will refuse to complete the merge.
    result = _run(["pull", "--no-rebase", "--no-edit"], vault_path, check=False)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        lowered = output.lower()
        conflicted = (
            "conflict" in lowered
            or "merge conflict" in lowered
            or "not possible to fast-forward" in lowered
        )
        if conflicted:
            raise GitConflictError(
                "Git merge conflict detected.\n"
                "Zhubin will not automatically choose ours or theirs.\n"
                "Please resolve conflicts manually, then run 'zhubin sync' again."
            )
        unreachable = (
            "could not resolve host" in lowered
            or "unable to access" in lowered
            or "network" in lowered
        )
        if unreachable:
            raise GitError("Remote is unavailable. Check your network and try again.")
        raise GitError(f"git pull failed:\n{(result.stderr or '').strip()}")

    porcelain_lines = [
        line
        for line in _run(["status", "--porcelain"], vault_path).stdout.splitlines()
        if line.strip()
    ]
    if _porcelain_conflicts(porcelain_lines) or _has_conflict_markers(vault_path):
        raise GitConflictError(
            "Git merge conflict detected after pull. "
            "Zhubin will not auto-resolve encrypted objects. Resolve manually."
        )

    _verify_vault_integrity_after_pull(vault_path)
    return result.stdout.strip()


def push(vault_path: Path) -> str:
    """Push to the remote tracking branch.  Never force-pushes."""
    result = _run(["push"], vault_path, check=False)
    if result.returncode != 0:
        stderr = (result.stderr or "") + (result.stdout or "")
        lowered = stderr.lower()
        if "non-fast-forward" in lowered or "rejected" in lowered:
            raise GitError(
                "Push rejected because the remote has new commits. "
                "Zhubin will not force-push. Run 'zhubin sync' again after the remote "
                "is reachable; resolve any conflicts manually if they appear."
            )
        if "could not resolve host" in lowered or "unable to access" in lowered:
            raise GitError("Remote is unavailable. Check your network and try again.")
        raise GitError(f"git push failed:\n{(result.stderr or '').strip()}")
    return result.stdout.strip()


def sync(
    vault_path: Path,
    commit_message: str = "zhubin: sync vault",
    *,
    push_after: bool = True,
) -> dict[str, str]:
    """
    Perform a safe pull → stage → commit → push sequence.

    Returns a dict with keys: pull, commit, push.
    Raises GitConflictError if conflicts are detected (never auto-resolves).
    Raises GitUnsafeStateError if the repository is detached, merging, or
    otherwise unsafe to mutate.
    """
    ensure_gitattributes(vault_path)
    assert_safe_to_sync(vault_path)

    results: dict[str, str] = {}
    results["pull"] = pull(vault_path)

    # Re-check after pull: a merge may have started and stopped on conflicts.
    post = get_status(vault_path)
    if post.has_conflicts or post.merge_in_progress:
        raise GitConflictError(
            "Pull produced unresolved conflicts. "
            "Zhubin will not auto-resolve encrypted objects. Resolve them manually."
        )

    stage_vault(vault_path)
    rechk = _run(["status", "--porcelain"], vault_path)
    if rechk.stdout.strip():
        results["commit"] = commit(vault_path, commit_message)
    else:
        results["commit"] = "(nothing to commit)"

    if push_after:
        results["push"] = push(vault_path)
    else:
        results["push"] = "(skipped)"

    return results
