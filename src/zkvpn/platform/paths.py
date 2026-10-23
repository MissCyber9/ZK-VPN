"""Well-known directories per operating system.

Each location can be overridden with an environment variable, which is also how the
tests and containers relocate everything.

======================  ==============================  ==============================  ===================================
purpose                 Linux                           macOS                           Windows
======================  ==============================  ==============================  ===================================
service configuration   /etc/zkvpn                      /usr/local/etc/zkvpn            %PROGRAMDATA%\\zkvpn
runtime state (RAM)     /run/zkvpn                      /var/run/zkvpn                  %PROGRAMDATA%\\zkvpn\\run
user data (ZK files)    $XDG_DATA_HOME/zkvpn            ~/Library/Application Support   %LOCALAPPDATA%\\zkvpn
WireGuard configs       /etc/wireguard                  /usr/local/etc/wireguard        %PROGRAMDATA%\\zkvpn\\wireguard
======================  ==============================  ==============================  ===================================
"""

import os
from pathlib import Path
from typing import Mapping, Optional

from zkvpn.platform import LINUX, MACOS, WINDOWS, system as _system


def _env(env: Optional[Mapping[str, str]]) -> Mapping[str, str]:
    return os.environ if env is None else env


def _program_data(env) -> Path:
    return Path(env.get("PROGRAMDATA") or r"C:\ProgramData")


def config_dir(system_name: str = None, env: Mapping[str, str] = None) -> Path:
    env = _env(env)
    if env.get("ZKVPN_CONFIG_DIR"):
        return Path(env["ZKVPN_CONFIG_DIR"])
    s = _system(system_name)
    if s == WINDOWS:
        return _program_data(env) / "zkvpn"
    return Path("/usr/local/etc/zkvpn") if s == MACOS else Path("/etc/zkvpn")


def env_file(system_name: str = None, env: Mapping[str, str] = None) -> Path:
    return config_dir(system_name, env) / ".env"


def state_dir(system_name: str = None, env: Mapping[str, str] = None) -> Path:
    env = _env(env)
    if env.get("ZKVPN_STATE_DIR"):
        return Path(env["ZKVPN_STATE_DIR"])
    s = _system(system_name)
    if s == WINDOWS:
        return _program_data(env) / "zkvpn" / "run"
    return Path("/var/run/zkvpn") if s == MACOS else Path("/run/zkvpn")


def data_dir(system_name: str = None, env: Mapping[str, str] = None, home: Path = None) -> Path:
    env = _env(env)
    if env.get("ZKVPN_DATA_DIR"):
        return Path(env["ZKVPN_DATA_DIR"])
    s = _system(system_name)
    home = home or Path.home()
    if s == WINDOWS:
        return Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local") / "zkvpn"
    if s == MACOS:
        return home / "Library" / "Application Support" / "zkvpn"
    return Path(env.get("XDG_DATA_HOME") or home / ".local" / "share") / "zkvpn"


def zk_dir(system_name: str = None, env: Mapping[str, str] = None) -> Path:
    """Workspace of the ZK toolchain (Node project + built circuit keys)."""
    env = _env(env)
    if env.get("ZKVPN_ZK_DIR"):
        return Path(env["ZKVPN_ZK_DIR"])
    return data_dir(system_name, env) / "zk"


def wireguard_config_dir(system_name: str = None, env: Mapping[str, str] = None) -> Path:
    s = _system(system_name)
    if s == WINDOWS:
        return _program_data(_env(env)) / "zkvpn" / "wireguard"
    return Path("/usr/local/etc/wireguard") if s == MACOS else Path("/etc/wireguard")
