"""Small async process runner shared by the macOS and Windows backends."""

import asyncio
import re
from typing import Optional, Tuple

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._ -]{1,64}$")


async def run(*cmd: str, input_text: Optional[str] = None, timeout: float = 30.0,
              env: Optional[dict] = None) -> Tuple[int, str, str]:
    """Run a program; returns ``(returncode, stdout, stderr)``. A missing program gives 127."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input_text.encode() if input_text is not None else None), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, "", f"{cmd[0]}: timed out"
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


async def powershell(script: str, timeout: float = 60.0) -> Tuple[int, str, str]:
    """Run a PowerShell snippet (Windows)."""
    return await run("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                     "-Command", script, timeout=timeout)


def ps_quote(value: str) -> str:
    """Single-quote a value for PowerShell (single quotes are doubled)."""
    return "'" + str(value).replace("'", "''") + "'"


def check_name(value: str) -> str:
    """Interface/service names end up in shell-adjacent commands: allow only plain names."""
    if not _SAFE_NAME.match(value or ""):
        raise ValueError(f"Unsafe name: {value!r}")
    return value
