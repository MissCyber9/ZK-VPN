"""Environment diagnostics that work on every operating system (``zkvpn doctor``)."""

import ctypes
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional

from zkvpn.platform import WINDOWS, system
from zkvpn.platform.net import backend
from zkvpn.zk import toolchain

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass
class Check:
    name: str
    status: str            # OK / WARN / FAIL
    detail: str
    hint: str = ""


def is_privileged(system_name: Optional[str] = None) -> bool:
    """Root on POSIX, elevated Administrator on Windows."""
    if system(system_name) == WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _tool_version(cmd: List[str]) -> Optional[str]:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or out.stderr).strip().splitlines()
    return text[0] if text else "available"


def run_checks(which: Callable[[str], Optional[str]] = shutil.which) -> List[Check]:
    """The checks, in order. ``FAIL`` = the portable core cannot work; ``WARN`` = a feature is missing."""
    checks: List[Check] = []

    be = backend
    checks.append(Check("Operating system", OK if be.features else FAIL,
                        f"{be.name} ({sys.platform}); features: {', '.join(sorted(be.features)) or 'none'}",
                        "" if be.features else "Supported: Linux, macOS, Windows"))
    if be.notes:
        checks.append(Check("Backend status", WARN if "experimental" in be.notes else OK, be.notes))

    py_ok = sys.version_info >= (3, 9)
    checks.append(Check("Python", OK if py_ok else FAIL, sys.version.split()[0],
                        "" if py_ok else "Python 3.9 or newer is required"))

    try:
        node_dir = toolchain.node_executable()
        checks.append(Check("Node.js", OK, _tool_version([node_dir, "--version"]) or node_dir))
    except toolchain.ToolchainError as e:
        checks.append(Check("Node.js", FAIL, str(e), "Install Node.js 18+ from https://nodejs.org"))

    checks.append(Check("ZK keys", OK if toolchain.is_built() else FAIL,
                        str(toolchain.default_workspace() / "build"),
                        "" if toolchain.is_built() else "Run: zkvpn zk setup"))

    wg = which("wg")
    wg_hint = {"linux": "apt install wireguard-tools / dnf install wireguard-tools",
               "macos": "brew install wireguard-tools wireguard-go",
               "windows": "winget install WireGuard.WireGuard"}.get(system() if be.features else "linux", "")
    checks.append(Check("WireGuard tools (wg)", OK if wg else WARN,
                        _tool_version([wg, "--version"]) if wg else "not found", "" if wg else wg_hint))

    priv = is_privileged() if be.features else False
    checks.append(Check("Privileges", OK if priv else WARN,
                        "administrator/root" if priv else "not elevated",
                        "" if priv else "Creating tunnels and routes needs root (sudo) or an elevated terminal"))
    return checks
