"""
Clipboard manager with automatic timed clearing.

Security design
---------------
1.  Zhubin copies the secret value to the clipboard.
2.  After ``timeout`` seconds it inspects the clipboard.
3.  If the clipboard still contains the value Zhubin placed there, it is
    cleared.  If another application has replaced the content in the
    meantime, Zhubin does NOT clear it (the user may have copied something
    else intentionally).

Platform notes
--------------
* Linux (X11 / Wayland): requires ``xclip``, ``xsel``, or
  ``wl-clipboard`` to be installed.  ``pyperclip`` auto-detects the
  available backend.  On headless / Wayland-only systems the clipboard may
  not work.
* macOS: works via ``pbcopy`` / ``pbpaste``.
* Windows: works via ctypes win32 clipboard.

Limitations
-----------
* Clipboard history managers (e.g. KDE Klipper, GNOME clipboard daemon)
  may retain the password even after clearing.  Zhubin cannot prevent this.
* The 30-second window still briefly exposes the secret in clipboard memory.
* Process memory may retain the secret while the background thread runs.
"""

from __future__ import annotations

import contextlib
import threading
import time

import pyperclip


class ClipboardError(Exception):
    pass


def copy(value: str, *, timeout: int = 30) -> None:
    """
    Copy *value* to the clipboard and schedule clearing after *timeout* seconds.

    The clearing thread checks whether the clipboard still contains *value*
    before clearing, to avoid inadvertently wiping content the user copied.
    """
    try:
        pyperclip.copy(value)
    except pyperclip.PyperclipException as exc:
        raise ClipboardError(
            f"Clipboard unavailable: {exc}\nOn Linux, install xclip, xsel, or wl-clipboard."
        ) from exc

    def _clear() -> None:
        time.sleep(timeout)
        try:
            current = pyperclip.paste()
        except pyperclip.PyperclipException:
            return
        if current == value:
            with contextlib.suppress(pyperclip.PyperclipException):
                pyperclip.copy("")

    t = threading.Thread(target=_clear, daemon=True)
    t.start()


def clear() -> None:
    """Immediately clear the clipboard (best-effort)."""
    with contextlib.suppress(pyperclip.PyperclipException):
        pyperclip.copy("")
