"""Client ZK identity: a secret field element stored in an owner-only file."""

import os
import stat
from pathlib import Path
from typing import Optional

from zkvpn.zk.auth import FIELD_PRIME, SessionProver, generate_identity


def save_identity(path: str, sk: Optional[int] = None) -> int:
    """Write a (new) secret key to ``path`` with mode 0600; refuses to overwrite."""
    sk = generate_identity() if sk is None else sk
    # O_EXCL: never clobber an existing identity (that would lose the account)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(str(sk) + "\n")
    return sk


def load_identity(path: str) -> int:
    """Read a secret key; refuses files readable by group/others."""
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"{path} is accessible by other users (mode {oct(mode)}); run: chmod 600 {path}")
    sk = int(Path(path).read_text().strip())
    if not 0 < sk < FIELD_PRIME:
        raise ValueError("Invalid identity file")
    return sk


async def public_identity(sk: int, prover: Optional[SessionProver] = None) -> str:
    """The public identity (``pk``) for ``sk``, as listed in authorized_identities."""
    prover = prover or SessionProver()
    proof = await prover.prove(sk, "identity", "identity")
    return str(proof.pk)
