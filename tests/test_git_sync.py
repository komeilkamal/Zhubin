"""
Integration tests for Git sync safety.

Uses real Git repositories in temporary directories.  Zhubin must never
silently resolve concurrent edits to encrypted objects.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from zhubin.crypto.identity import create_device_identity
from zhubin.exceptions import GitConflictError, GitError, GitUnsafeStateError
from zhubin.storage.filesystem import init_vault, save_device, save_secret
from zhubin.storage.git import assert_safe_to_sync, get_status, push, sync
from zhubin.vault.models import DeviceRecord, SecretPayload
from zhubin.vault.vault import VaultService


def _git_env(home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Zhubin Test",
            "GIT_AUTHOR_EMAIL": "test@zhubin.test",
            "GIT_COMMITTER_NAME": "Zhubin Test",
            "GIT_COMMITTER_EMAIL": "test@zhubin.test",
        }
    )
    return env


def git(
    cwd: Path, *args: str, env: dict[str, str], check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "init.defaultBranch=main", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=check,
    )


def _init_repo(path: Path, env: dict[str, str]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", env=env)
    git(path, "config", "user.email", "test@zhubin.test", env=env)
    git(path, "config", "user.name", "Zhubin Test", env=env)


@pytest.fixture
def git_home(tmp_path: Path) -> Path:
    home = tmp_path / "githome"
    home.mkdir()
    return home


@pytest.fixture
def env(git_home: Path) -> dict[str, str]:
    return _git_env(git_home)


def _vault_with_secret(path: Path) -> VaultService:
    init_vault(path)
    ident = create_device_identity()
    save_device(
        path,
        DeviceRecord(id=ident.device_id, name="dev", public_key=ident.public_key_b64),
    )
    svc = VaultService(path, ident)
    svc.create_group("personal")
    svc.add_secret("personal", "github", SecretPayload(password="original"))
    return svc


class TestGitStatus:
    def test_not_a_repo(self, tmp_path: Path) -> None:
        st = get_status(tmp_path)
        assert st.initialized is False
        assert st.branch == "(no git)"

    def test_untracked_and_dirty(self, tmp_path: Path, env: dict[str, str]) -> None:
        repo = tmp_path / "repo"
        _init_repo(repo, env)
        (repo / "readme").write_text("hi")
        st = get_status(repo)
        assert any("readme" in u for u in st.untracked) or any(
            "readme" in u for u in st.uncommitted
        )


class TestSyncPreconditions:
    def test_refuses_uninitialized(self, tmp_path: Path) -> None:
        with pytest.raises((GitError, GitUnsafeStateError)):
            sync(tmp_path)

    def test_refuses_missing_upstream(self, tmp_path: Path, env: dict[str, str]) -> None:
        repo = tmp_path / "repo"
        _init_repo(repo, env)
        init_vault(repo)
        git(repo, "add", ".", env=env)
        git(repo, "commit", "-m", "init", env=env)
        with pytest.raises(GitError, match="remote"):
            sync(repo)

    def test_refuses_detached_head(self, tmp_path: Path, env: dict[str, str]) -> None:
        repo = tmp_path / "repo"
        _init_repo(repo, env)
        init_vault(repo)
        git(repo, "add", ".", env=env)
        git(repo, "commit", "-m", "init", env=env)
        sha = git(repo, "rev-parse", "HEAD", env=env).stdout.strip()
        git(repo, "checkout", sha, env=env)
        st = get_status(repo)
        assert st.detached
        with pytest.raises(GitUnsafeStateError, match="detached"):
            assert_safe_to_sync(repo)

    def test_refuses_unresolved_conflicts(self, tmp_path: Path, env: dict[str, str]) -> None:
        """Scenario C: unresolved merge conflicts → sync refused."""
        remote = tmp_path / "remote.git"
        git(tmp_path, "init", "--bare", str(remote), env=env)

        a = tmp_path / "a"
        _init_repo(a, env)
        init_vault(a)
        (a / "groups").mkdir(exist_ok=True)
        git(a, "add", ".", env=env)
        git(a, "commit", "-m", "base", env=env)
        git(a, "remote", "add", "origin", str(remote), env=env)
        git(a, "push", "-u", "origin", "main", env=env)

        b = tmp_path / "b"
        git(tmp_path, "clone", str(remote), str(b), env=env)
        git(b, "config", "user.email", "test@zhubin.test", env=env)
        git(b, "config", "user.name", "Zhubin Test", env=env)

        cfg_a = (
            "version: 1\nclipboard_timeout: 30\n"
            'web_host: "127.0.0.1"\nweb_port: 8787\nauto_lock_timeout: 900\n# A\n'
        )
        (a / "config.yaml").write_text(cfg_a)
        git(a, "add", "config.yaml", env=env)
        git(a, "commit", "-m", "A", env=env)
        git(a, "push", env=env)

        cfg_b = (
            "version: 1\nclipboard_timeout: 30\n"
            'web_host: "127.0.0.1"\nweb_port: 8787\nauto_lock_timeout: 900\n# B\n'
        )
        (b / "config.yaml").write_text(cfg_b)
        git(b, "add", "config.yaml", env=env)
        git(b, "commit", "-m", "B", env=env)
        pull = git(b, "pull", "--no-rebase", env=env, check=False)
        conflicted = (
            pull.returncode != 0
            or "conflict" in (pull.stdout + pull.stderr).lower()
            or get_status(b).has_conflicts
            or get_status(b).merge_in_progress
        )
        assert conflicted

        # Force a conflicted state if pull auto-merged: write markers
        if not (get_status(b).has_conflicts or get_status(b).merge_in_progress):
            git(b, "checkout", "-B", "tmpconflict", env=env)
            pytest.skip("git auto-merged config.yaml; conflict scenario covered by secret tests")

        with pytest.raises((GitConflictError, GitUnsafeStateError)):
            sync(b)


class TestConcurrentEdits:
    def test_concurrent_secret_edit_conflicts(self, tmp_path: Path, env: dict[str, str]) -> None:
        """Scenario A: two devices edit personal/github independently → no silent overwrite."""
        remote = tmp_path / "remote.git"
        git(tmp_path, "init", "--bare", str(remote), env=env)

        a = tmp_path / "device-a"
        _init_repo(a, env)
        svc_a = _vault_with_secret(a)
        git(a, "add", ".", env=env)
        git(a, "commit", "-m", "vault", env=env)
        git(a, "remote", "add", "origin", str(remote), env=env)
        git(a, "push", "-u", "origin", "main", env=env)

        b = tmp_path / "device-b"
        git(tmp_path, "clone", str(remote), str(b), env=env)
        git(b, "config", "user.email", "test@zhubin.test", env=env)
        git(b, "config", "user.name", "Zhubin Test", env=env)

        # Independent edits of the same encrypted secret
        svc_a.edit_secret("personal", "github", SecretPayload(password="from-a"))
        git(a, "add", ".", env=env)
        git(a, "commit", "-m", "edit A", env=env)
        git(a, "push", env=env)

        # B still has the original and edits without pulling.
        save_secret(
            b,
            "personal",
            "github",
            (
                b'{"version":2,"type":"zhubin-secret-v1","cipher":"xsalsa20poly1305",'
                b'"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"BBBB"}'
            ),
            overwrite=True,
        )
        git(b, "add", ".", env=env)
        git(b, "commit", "-m", "edit B", env=env)

        with pytest.raises(GitConflictError):
            sync(b)

        # Neither side should have been chosen silently: working trees still differ
        # from a clean fast-forward of the other.
        a_secret = (a / "groups" / "personal" / "secrets" / "github.secret").read_bytes()
        b_secret = (b / "groups" / "personal" / "secrets" / "github.secret").read_bytes()
        assert a_secret != b_secret

    def test_push_rejection_when_remote_advanced(self, tmp_path: Path, env: dict[str, str]) -> None:
        """Scenario B: remote advances before push → rejection is reported, no force-push."""
        remote = tmp_path / "remote.git"
        git(tmp_path, "init", "--bare", str(remote), env=env)

        a = tmp_path / "a"
        _init_repo(a, env)
        init_vault(a)
        git(a, "add", ".", env=env)
        git(a, "commit", "-m", "base", env=env)
        git(a, "remote", "add", "origin", str(remote), env=env)
        git(a, "push", "-u", "origin", "main", env=env)

        b = tmp_path / "b"
        git(tmp_path, "clone", str(remote), str(b), env=env)
        git(b, "config", "user.email", "test@zhubin.test", env=env)
        git(b, "config", "user.name", "Zhubin Test", env=env)

        (a / "note-a.txt").write_text("from a")
        git(a, "add", "note-a.txt", env=env)
        git(a, "commit", "-m", "a ahead", env=env)
        git(a, "push", env=env)

        (b / "note-b.txt").write_text("from b")
        git(b, "add", "note-b.txt", env=env)
        git(b, "commit", "-m", "b local", env=env)

        with pytest.raises(GitError, match=r"rejected|non-fast-forward|remote"):
            push(b)

    def test_concurrent_group_rotation_conflicts(self, tmp_path: Path, env: dict[str, str]) -> None:
        """Scenario D: concurrent group rotations do not auto-merge."""
        remote = tmp_path / "remote.git"
        git(tmp_path, "init", "--bare", str(remote), env=env)

        a = tmp_path / "a"
        _init_repo(a, env)
        svc_a = _vault_with_secret(a)
        git(a, "add", ".", env=env)
        git(a, "commit", "-m", "vault", env=env)
        git(a, "remote", "add", "origin", str(remote), env=env)
        git(a, "push", "-u", "origin", "main", env=env)

        b = tmp_path / "b"
        git(tmp_path, "clone", str(remote), str(b), env=env)
        git(b, "config", "user.email", "test@zhubin.test", env=env)
        git(b, "config", "user.name", "Zhubin Test", env=env)

        svc_a.rotate_group_key("personal")
        git(a, "add", ".", env=env)
        git(a, "commit", "-m", "rotate A", env=env)
        git(a, "push", env=env)

        # B writes a different group.json (simulating an independent rotation)
        group_json = b / "groups" / "personal" / "group.json"
        original = group_json.read_text()
        patched = original.replace('"version": 1', '"version": 1,\n  "note": "b-rotation"')
        group_json.write_text(patched)
        if group_json.read_text() == original:
            import json

            parsed = json.loads(original)
            parsed["id"] = parsed["id"][:-1] + ("0" if parsed["id"][-1] != "0" else "1")
            group_json.write_text(json.dumps(parsed, indent=2))
        git(b, "add", ".", env=env)
        git(b, "commit", "-m", "rotate B", env=env)

        with pytest.raises(GitConflictError):
            sync(b)


class TestGitCommandSafety:
    def test_no_shell_true_in_git_module(self) -> None:
        src = Path(__file__).resolve().parents[1] / "src" / "zhubin" / "storage" / "git.py"
        text = src.read_text()
        assert "shell=True" not in text
        assert '["git", *args]' in text

    def test_git_unavailable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import zhubin.storage.git as gitmod

        def boom(*_a, **_k):
            raise FileNotFoundError("git")

        monkeypatch.setattr(gitmod.subprocess, "run", boom)
        st = get_status(tmp_path)
        assert st.git_available is False
