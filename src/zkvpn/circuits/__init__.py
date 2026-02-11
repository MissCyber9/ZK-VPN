"""ZK-VPN circuits package.

Provides zero-knowledge proof generation and verification for no-logging guarantees.
"""

from zkvpn.circuits.prover import ZKProver, prover, Proof
from zkvpn.circuits.verifier import ZKVerifier, verifier, VerificationResult
from zkvpn.circuits.compiler import CircuitCompiler, compiler

__all__ = [
    "ZKProver", "prover", "Proof",
    "ZKVerifier", "verifier", "VerificationResult",
    "CircuitCompiler", "compiler"
]
