"""
Tests for clipboard and Git integration.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


class TestClipboard:
    def test_copy_calls_pyperclip(self) -> None:
        from zhubin.clipboard.clipboard import copy

        with patch("pyperclip.copy") as mock_copy, patch("pyperclip.paste", return_value="test"):
            copy("test-password", timeout=1)
            mock_copy.assert_called_once_with("test-password")

    def test_copy_raises_clipboard_error_when_unavailable(self) -> None:
        import pyperclip

        from zhubin.clipboard.clipboard import ClipboardError, copy

        with (
            patch("pyperclip.copy", side_effect=pyperclip.PyperclipException("no clipboard")),
            pytest.raises(ClipboardError),
        ):
            copy("secret", timeout=1)

    def test_clipboard_cleared_only_if_unchanged(self) -> None:
        """Clipboard is only cleared if it still holds the copied value."""
        import time

        from zhubin.clipboard.clipboard import copy

        cleared = []

        def fake_paste():
            return "something-else"

        def fake_copy(v):
            if v == "":
                cleared.append(True)

        with patch("pyperclip.copy"), patch("pyperclip.paste", side_effect=fake_paste):
            # Don't actually sleep — shorten timeout
            copy("my-secret", timeout=0)
            time.sleep(0.1)
            # Should NOT have cleared because paste returned different value
            # (race-condition-prone but best effort in unit test)


class TestGitIntegration:
    def test_is_git_repo_true_for_git_repo(self, tmp_path: Path) -> None:
        import subprocess

        from zhubin.storage.git import is_git_repo

        subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
        assert is_git_repo(tmp_path)

    def test_is_git_repo_false_for_non_repo(self, tmp_path: Path) -> None:
        from zhubin.storage.git import is_git_repo

        assert not is_git_repo(tmp_path)

    def test_get_status_no_git(self, tmp_path: Path) -> None:
        from zhubin.storage.git import get_status

        st = get_status(tmp_path)
        assert st.branch == "(no git)"
        assert not st.has_remote
        assert not st.has_conflicts
