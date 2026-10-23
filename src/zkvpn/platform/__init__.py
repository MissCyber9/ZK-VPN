"""Operating-system abstraction for ZK-VPN.

Everything that differs between Linux, macOS and Windows lives behind this package:
well-known directories (:mod:`.paths`), private-file handling (:mod:`.fsperm`) and
graceful shutdown (:mod:`.process`). The network plumbing (interfaces, routes,
firewall, DNS) is selected per system by :mod:`zkvpn.platform.net`.

Functions take an optional ``system_name`` so the logic of *every* system can be
unit-tested from any runner.
"""

import sys

LINUX, MACOS, WINDOWS = "linux", "macos", "windows"
SYSTEMS = (LINUX, MACOS, WINDOWS)


class UnsupportedPlatform(RuntimeError):
    """The operating system has no ZK-VPN support."""


def system(platform_name: str = None) -> str:
    """Return ``"linux"``, ``"macos"`` or ``"windows"`` (``sys.platform`` by default)."""
    name = platform_name or sys.platform
    if name.startswith("linux"):
        return LINUX
    if name == "darwin":
        return MACOS
    if name in ("win32", "cygwin", "msys"):
        return WINDOWS
    raise UnsupportedPlatform(f"Unsupported operating system: {name!r} (supported: Linux, macOS, Windows)")


def is_windows() -> bool:
    return system() == WINDOWS


__all__ = ["system", "is_windows", "UnsupportedPlatform", "LINUX", "MACOS", "WINDOWS", "SYSTEMS"]
