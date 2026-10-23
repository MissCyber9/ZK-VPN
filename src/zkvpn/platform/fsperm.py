"""Owner-only files, on POSIX and on Windows.

POSIX: mode ``0600``. Windows ignores POSIX modes, so access is restricted with an ACL
(``icacls``): inheritance removed, full control for the current user only.
Used for secrets: the ZK identity and the configuration file.
"""

import os
import stat
import subprocess
from pathlib import Path
from typing import Optional, Union

from zkvpn.platform import WINDOWS, system as _system

# Principals allowed to appear in a "private" Windows ACL besides the owner
_WINDOWS_TRUSTED = {"NT AUTHORITY\\SYSTEM", "BUILTIN\\ADMINISTRATORS", "NT SERVICE\\TRUSTEDINSTALLER",
                    "NT AUTHORITY\\OWNER RIGHTS", "OWNER RIGHTS", "CREATOR OWNER"}


def _windows_user() -> str:
    out = subprocess.run(["whoami"], capture_output=True, text=True, check=True).stdout.strip()
    return out


def _icacls_principals(output: str, path: str) -> set:
    """Principals named in ``icacls <path>`` output (``DOMAIN\\user:(F)`` entries)."""
    principals = set()
    for line in output.splitlines():
        line = line.replace(path, "", 1).strip() if path in line else line.strip()
        if ":(" in line:
            principals.add(line.split(":(", 1)[0].strip().upper())
    return principals


def restrict_to_owner(path: Union[str, Path], system_name: str = None, *,
                      allow_system: bool = False) -> None:
    """Make ``path`` readable and writable by its owner only.

    ``allow_system`` also grants the Windows SYSTEM account (needed when a service running
    as SYSTEM, such as the WireGuard tunnel service, must read the file).
    """
    path = str(path)
    if _system(system_name) == WINDOWS:
        user = _windows_user()
        grants = ["/grant:r", f"{user}:(F)"]
        if allow_system:
            grants += ["/grant:r", "NT AUTHORITY\\SYSTEM:(F)"]
        # /reset drops every explicit entry (e.g. one a careless user added for Everyone);
        # /inheritance:r then drops the inherited ones
        subprocess.run(["icacls", path, "/reset"], capture_output=True, check=True)
        subprocess.run(["icacls", path, "/inheritance:r", *grants], capture_output=True, check=True)
    else:
        os.chmod(path, 0o600)


def is_private(path: Union[str, Path], system_name: str = None) -> bool:
    """True when nobody but the owner (and, on Windows, system accounts) can access ``path``."""
    path = str(path)
    if _system(system_name) == WINDOWS:
        out = subprocess.run(["icacls", path], capture_output=True, text=True, check=True).stdout
        # compare account names only: `whoami` may omit the domain that icacls prints
        allowed = {p.split("\\")[-1] for p in _WINDOWS_TRUSTED} | {_windows_user().upper().split("\\")[-1]}
        return {p.split("\\")[-1] for p in _icacls_principals(out, path)} <= allowed
    return not (stat.S_IMODE(os.stat(path).st_mode) & 0o077)


def write_private_file(path: Union[str, Path], data: Union[str, bytes], *,
                       exclusive: bool = False, system_name: str = None,
                       allow_system: bool = False) -> None:
    """Write ``data`` to an owner-only file. ``exclusive`` refuses to overwrite an existing file."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY                    # Windows: no newline translation
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode("utf-8") if isinstance(data, str) else data)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    restrict_to_owner(path, system_name, allow_system=allow_system)


def replace_private_file(path: Union[str, Path], data: Union[str, bytes]) -> None:
    """Atomically replace ``path`` with an owner-only file (temp file + rename)."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    write_private_file(tmp, data, exclusive=True)
    os.replace(tmp, path)


def ensure_private_dir(path: Union[str, Path], system_name: str = None) -> Path:
    """Create a directory only the owner can use."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if _system(system_name) == WINDOWS:
        user = _windows_user()
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"],
                       capture_output=True, check=True)
    else:
        os.chmod(path, 0o700)
    return path
