"""Thin async wrapper around snarkjs (Groth16) through the node scripts in ``zk/``.

Secrets are passed on stdin; nothing sensitive is written to disk.
"""

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Tuple

from zkvpn.core.config import settings


class SnarkError(RuntimeError):
    """Proof generation / verification infrastructure error (not 'invalid proof')."""


class SnarkBackend:
    """Generate and verify Groth16 proofs for the ``session_auth`` circuit."""

    def __init__(self, zk_dir: str = None, timeout: float = None):
        self.zk_dir = Path(zk_dir or settings.zk_dir).resolve()
        self.timeout = timeout or settings.proof_generation_timeout * 15

    @property
    def available(self) -> bool:
        """True when node and the built circuit artifacts are present."""
        build = self.zk_dir / "build"
        return bool(
            shutil.which("node")
            and (self.zk_dir / "node_modules" / "snarkjs").is_dir()
            and all((build / f).is_file()
                    for f in ("session_auth.wasm", "session_auth.zkey", "vkey.json"))
        )

    async def _run(self, script: str, payload: Dict[str, Any]) -> bytes:
        if not self.available:
            raise SnarkError(
                f"ZK artifacts missing in {self.zk_dir}; run `zkvpn zk setup`"
            )
        proc = await asyncio.create_subprocess_exec(
            "node", str(self.zk_dir / script),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(json.dumps(payload).encode()), self.timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise SnarkError(f"{script} timed out")
        if proc.returncode != 0:
            raise SnarkError(err.decode(errors="replace").strip()[:500])
        return out

    async def prove(self, inputs: Dict[str, str]) -> Tuple[Dict[str, Any], List[str]]:
        """Return ``(proof, public_signals)``; raises SnarkError if constraints fail."""
        out = await self._run("prove.js", {"input": inputs})
        data = json.loads(out)
        return data["proof"], [str(s) for s in data["publicSignals"]]

    async def verify(self, proof: Dict[str, Any], public_signals: List[str]) -> bool:
        """Cryptographically verify a proof against the circuit's verification key."""
        try:
            out = await self._run(
                "verify.js", {"proof": proof, "publicSignals": public_signals}
            )
        except SnarkError as e:
            # Malformed proofs make snarkjs throw; that is "invalid", not an outage.
            if "missing in" in str(e) or "timed out" in str(e):
                raise
            return False
        return out.strip() == b"true"
