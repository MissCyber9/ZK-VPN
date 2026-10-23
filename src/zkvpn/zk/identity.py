"""Client ZK identity: a secret field element stored in an owner-only file."""

from pathlib import Path
from typing import Optional

from zkvpn.platform.fsperm import is_private, write_private_file
from zkvpn.zk.auth import FIELD_PRIME, SessionProver, generate_identity


def save_identity(path: str, sk: Optional[int] = None) -> int:
    """Write a (new) secret key to ``path`` with mode 0600; refuses to overwrite."""
    sk = generate_identity() if sk is None else sk
    # exclusive: never clobber an existing identity (that would lose the account)
    write_private_file(path, str(sk) + "\n", exclusive=True)
    return sk


def load_identity(path: str) -> int:
    """Read a secret key; refuses files readable by group/others."""
    if not is_private(path):
        raise PermissionError(
            f"{path} is accessible by other users; restrict it to your account "
            "(Linux/macOS: chmod 600; Windows: icacls <file> /inheritance:r /grant:r %USERNAME%:F)")
    sk = int(Path(path).read_text().strip())
    if not 0 < sk < FIELD_PRIME:
        raise ValueError("Invalid identity file")
    return sk


async def public_identity(sk: int, prover: Optional[SessionProver] = None) -> str:
    """The public identity (``pk``) for ``sk``, as listed in authorized_identities."""
    prover = prover or SessionProver()
    proof = await prover.prove(sk, "identity", "identity")
    return str(proof.pk)
