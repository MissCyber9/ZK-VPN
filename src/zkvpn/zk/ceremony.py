"""Multi-party trusted-setup ceremony for the ``session_auth`` Groth16 circuit.

Why: with the single-party development setup, whoever kept the setup entropy ("toxic waste")
can forge proofs. In a ceremony every participant adds their own entropy; the keys are safe as
long as AT LEAST ONE participant destroyed theirs.

    Phase 1 (circuit independent)  a PUBLIC Powers-of-Tau file from a large ceremony, e.g. the
                                   Hermez ``powersOfTau28_hez_final_12.ptau``.
    Phase 2 (this circuit)         the steps below.

Flow (coordinator = whoever runs init/beacon/finalize; participants only run ``contribute``)::

    coordinator$ zkvpn zk ceremony init powersOfTau28_hez_final_12.ptau
    participant$ zkvpn zk ceremony contribute ceremony/zkey_0000.zkey ceremony/zkey_0001.zkey "Alice"
    participant$ zkvpn zk ceremony contribute ceremony/zkey_0001.zkey ceremony/zkey_0002.zkey "Bob"
    coordinator$ zkvpn zk ceremony beacon ceremony/zkey_0002.zkey ceremony/zkey_final.zkey <public-hex>
    anyone$      zkvpn zk ceremony verify ceremony/zkey_final.zkey    # recompiles, checks the WHOLE chain
    coordinator$ zkvpn zk ceremony finalize ceremony/zkey_final.zkey  # installs the keys

Each participant passes ONLY the ``.zkey`` file to the next one and keeps nothing.
``<public-hex>``: a value unpredictable before the last contribution (e.g. the hash of a Bitcoin
block mined after the contributions closed); publish which one.

``init --dev`` builds a LOCAL single-party phase 1 for tests. Never use it in production.
"""

import hashlib
import re
import shutil
from pathlib import Path
from typing import Dict, Optional

from zkvpn.zk import toolchain
from zkvpn.zk.toolchain import CIRCUIT, ToolchainError, entropy, snarkjs

DEFAULT_DIR = Path("ceremony")


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _manifest(ceremony: Path) -> Dict[str, str]:
    try:
        lines = (ceremony / "MANIFEST.txt").read_text().splitlines()
    except OSError:
        return {}
    return dict(line.split("=", 1) for line in lines if "=" in line)


def init(ceremony: Path = DEFAULT_DIR, ptau: Optional[Path] = None, dev: bool = False,
         zk_dir: Optional[Path] = None, ptau_power: int = 12) -> Path:
    """Start a ceremony: verify (or, for tests, create) phase 1 and make ``zkey_0000``."""
    ceremony = Path(ceremony)
    zk_dir = toolchain.prepare_workspace(zk_dir)
    if (ceremony / "zkey_0000.zkey").exists():
        raise ToolchainError(f"{ceremony} is already initialised (remove it to restart)")
    ceremony.mkdir(parents=True, exist_ok=True)

    if ptau:
        ptau = Path(ptau)
        if not ptau.is_file():
            raise ToolchainError(f"no such file: {ptau}")
        snarkjs(zk_dir, "powersoftau", "verify", ptau)          # fails loudly on a bad phase 1
        shutil.copyfile(ptau, ceremony / "ptau.ptau")
    elif dev:
        p0, p1 = ceremony / "p0.ptau", ceremony / "p1.ptau"
        snarkjs(zk_dir, "powersoftau", "new", "bn128", ptau_power, p0)
        snarkjs(zk_dir, "powersoftau", "contribute", p0, p1, "--name=dev", f"-e={entropy()}")
        snarkjs(zk_dir, "powersoftau", "prepare", "phase2", p1, ceremony / "ptau.ptau")
        p0.unlink()
        p1.unlink()
    else:
        raise ToolchainError("usage: init <public-phase1.ptau>  |  init --dev (tests only)")

    with toolchain.workdir(zk_dir, "ceremony-") as work:
        compiled = toolchain.compile_circuit(zk_dir, work)
        shutil.copyfile(compiled / "session_auth.r1cs", ceremony / "session_auth.r1cs")
    snarkjs(zk_dir, "groth16", "setup", ceremony / "session_auth.r1cs", ceremony / "ptau.ptau",
            ceremony / "zkey_0000.zkey")
    (ceremony / "MANIFEST.txt").write_text(
        f"circuit_sha256={sha256(CIRCUIT)}\n"
        f"r1cs_sha256={sha256(ceremony / 'session_auth.r1cs')}\n"
        f"ptau_sha256={sha256(ceremony / 'ptau.ptau')}\n")
    return ceremony


def contribute(zkey_in: Path, zkey_out: Path, name: str, zk_dir: Optional[Path] = None) -> str:
    """Add one participant's entropy. Returns the output's sha256 (publish it)."""
    zkey_in, zkey_out = Path(zkey_in), Path(zkey_out)
    if not zkey_in.is_file():
        raise ToolchainError(f"no such file: {zkey_in}")
    if zkey_out.exists():
        raise ToolchainError(f"{zkey_out} exists")
    zk_dir = toolchain.prepare_workspace(zk_dir)
    snarkjs(zk_dir, "zkey", "contribute", zkey_in, zkey_out, f"--name={name}", f"-e={entropy()}")
    return sha256(zkey_out)


def beacon(zkey_in: Path, zkey_out: Path, public_hex: str, zk_dir: Optional[Path] = None) -> str:
    """Apply the public random beacon (final step)."""
    if not re.fullmatch(r"[0-9a-fA-F]{16,}", public_hex):
        raise ToolchainError("beacon must be a hex string of at least 16 digits")
    zk_dir = toolchain.prepare_workspace(zk_dir)
    snarkjs(zk_dir, "zkey", "beacon", zkey_in, zkey_out, public_hex, 10, "-n=Final beacon")
    return sha256(zkey_out)


def verify(zkey: Path, ceremony: Path = DEFAULT_DIR, zk_dir: Optional[Path] = None) -> str:
    """Recompile the circuit from source and check the WHOLE contribution chain. Returns snarkjs' report."""
    ceremony, zkey = Path(ceremony), Path(zkey)
    if not (ceremony / "ptau.ptau").is_file():
        raise ToolchainError(f"missing {ceremony / 'ptau.ptau'} (the phase-1 file used by init)")
    zk_dir = toolchain.prepare_workspace(zk_dir)
    with toolchain.workdir(zk_dir, "verify-") as work:
        # We verify against THIS circuit source, not against a file someone sent us.
        r1cs = toolchain.compile_circuit(zk_dir, work) / "session_auth.r1cs"
        expected = _manifest(ceremony).get("r1cs_sha256")
        if expected and expected != sha256(r1cs):
            raise ToolchainError("circuit source does not match the ceremony manifest")
        try:
            return snarkjs(zk_dir, "zkey", "verify", r1cs, ceremony / "ptau.ptau", zkey)
        except ToolchainError as e:
            raise ToolchainError(f"ZKEY VERIFICATION FAILED\n{e}")


def finalize(zkey: Path, ceremony: Path = DEFAULT_DIR, zk_dir: Optional[Path] = None,
             build_dir: Optional[Path] = None) -> Path:
    """Verify, then install the keys (wasm, zkey, verification key, CEREMONY.txt) into the workspace."""
    ceremony, zkey = Path(ceremony), Path(zkey)
    zk_dir = toolchain.prepare_workspace(zk_dir)
    verify(zkey, ceremony, zk_dir)
    build = Path(build_dir or (zk_dir / "build"))
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True)
    with toolchain.workdir(zk_dir, "final-") as work:
        compiled = toolchain.compile_circuit(zk_dir, work)
        shutil.copyfile(compiled / "session_auth_js" / "session_auth.wasm", build / "session_auth.wasm")
    shutil.copyfile(zkey, build / "session_auth.zkey")
    snarkjs(zk_dir, "zkey", "export", "verificationkey", zkey, build / "vkey.json")
    (build / "CEREMONY.txt").write_text(
        "ceremony=multi-party\n" + (ceremony / "MANIFEST.txt").read_text()
        + f"zkey_sha256={sha256(zkey)}\nvkey_sha256={sha256(build / 'vkey.json')}\n")
    return build
