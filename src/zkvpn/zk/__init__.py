"""Real Groth16 zero-knowledge session authentication for ZK-VPN."""

from zkvpn.zk.snark import SnarkBackend, SnarkError
from zkvpn.zk.auth import (
    SessionProof,
    SessionProver,
    SessionVerifier,
    VerifyResult,
    bind_challenge,
    generate_identity,
)

__all__ = [
    "SnarkBackend", "SnarkError", "SessionProof", "SessionProver",
    "SessionVerifier", "VerifyResult", "bind_challenge", "generate_identity",
]
