"""Build the ZK toolchain and keys without any shell: Node.js + the pinned npm packages.

Works the same on Linux, macOS and Windows. ``circom2`` (circom compiled to WebAssembly) and
``snarkjs`` are called through ``node`` directly, so no ``.cmd``/``.sh`` shims are involved.

The development keys come from a SINGLE-PARTY setup: whoever ran it can forge proofs. For
production use the multi-party ceremony (:mod:`zkvpn.zk.ceremony`).
"""

import contextlib
import json
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence

from zkvpn.platform import paths as platform_paths

NODE_ASSETS = Path(__file__).resolve().parent / "node"
ASSET_FILES = ("package.json", "package-lock.json", "prove.js", "verify.js")
CIRCUIT = Path(__file__).resolve().parent.parent / "circuits" / "session_auth.circom"
MIN_NODE = 18


class ToolchainError(RuntimeError):
    """A build step failed (message ends with the tool's own error output)."""


def default_workspace() -> Path:
    return platform_paths.zk_dir()


def entropy() -> str:
    """Fresh randomness for one contribution (never stored)."""
    return secrets.token_hex(64)


@contextlib.contextmanager
def workdir(zk_dir: Path, prefix: str = "tmp-"):
    """Scratch directory INSIDE the workspace (circom2 only sees paths below its working directory)."""
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=zk_dir))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _run(cmd: Sequence[str], cwd: Optional[Path] = None) -> str:
    try:
        result = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise ToolchainError(f"{cmd[0]} not found: {e}")
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).strip().splitlines()[-8:]
        raise ToolchainError(f"{Path(str(cmd[0])).name} failed ({result.returncode}):\n" + "\n".join(tail))
    return result.stdout


def node_executable() -> str:
    node = shutil.which("node")
    if not node:
        raise ToolchainError("Node.js is required (>= 18): https://nodejs.org")
    major = int(_run([node, "-p", "process.versions.node.split('.')[0]"]).strip())
    if major < MIN_NODE:
        raise ToolchainError(f"Node.js >= {MIN_NODE} is required (found {major})")
    return node


def prepare_workspace(zk_dir: Optional[Path] = None) -> Path:
    """Create the workspace (Node project from the package) and install the pinned dependencies."""
    zk_dir = Path(zk_dir or default_workspace())
    node_executable()
    npm = shutil.which("npm")
    if not npm:
        raise ToolchainError("npm is required (it ships with Node.js)")
    zk_dir.mkdir(parents=True, exist_ok=True)
    for name in ASSET_FILES:
        shutil.copyfile(NODE_ASSETS / name, zk_dir / name)
    _run([npm, "ci", "--no-audit", "--no-fund", "--silent"], cwd=zk_dir)
    return zk_dir


def _js_bin(zk_dir: Path, package: str) -> List[str]:
    """Command line running an installed package's CLI through node."""
    meta = json.loads((zk_dir / "node_modules" / package / "package.json").read_text())
    bin_field = meta["bin"]
    script = bin_field if isinstance(bin_field, str) else bin_field[package]
    return [node_executable(), str(zk_dir / "node_modules" / package / script)]


def snarkjs(zk_dir: Path, *args) -> str:
    return _run(_js_bin(zk_dir, "snarkjs") + [str(a) for a in args])


def compile_circuit(zk_dir: Path, out_dir: Path) -> Path:
    """Compile ``session_auth.circom``; returns the directory holding the .r1cs and the wasm.

    ``circom2`` runs in a WebAssembly sandbox that can only see paths below its working
    directory, so the circuit is copied into the workspace and everything is relative to it.
    ``out_dir`` must be inside the workspace (see :func:`workdir`).
    """
    zk_dir, out_dir = Path(zk_dir).resolve(), Path(out_dir).resolve()
    src_dir = zk_dir / "circuits"
    src_dir.mkdir(exist_ok=True)
    shutil.copyfile(CIRCUIT, src_dir / CIRCUIT.name)
    out_dir.mkdir(parents=True, exist_ok=True)
    _run(_js_bin(zk_dir, "circom2") + [f"circuits/{CIRCUIT.name}", "--r1cs", "--wasm", "-l", "node_modules",
                                      "-o", out_dir.relative_to(zk_dir).as_posix()], cwd=zk_dir)
    return out_dir


def is_built(zk_dir: Optional[Path] = None) -> bool:
    build = Path(zk_dir or default_workspace()) / "build"
    return all((build / f).is_file() for f in ("session_auth.wasm", "session_auth.zkey", "vkey.json"))


def build_dev_keys(zk_dir: Optional[Path] = None, ptau_power: int = 12) -> Path:
    """Single-party development setup: compile, powers of tau, Groth16 keys. Returns ``<zk_dir>/build``."""
    zk_dir = prepare_workspace(zk_dir)
    build = zk_dir / "build"
    if build.exists():
        shutil.rmtree(build)
    with workdir(zk_dir, "build-") as work:
        compiled = compile_circuit(zk_dir, work)
        p = lambda name: work / name
        snarkjs(zk_dir, "powersoftau", "new", "bn128", ptau_power, p("pot_0.ptau"))
        snarkjs(zk_dir, "powersoftau", "contribute", p("pot_0.ptau"), p("pot_1.ptau"),
                "--name=zkvpn-dev", f"-e={entropy()}")
        snarkjs(zk_dir, "powersoftau", "prepare", "phase2", p("pot_1.ptau"), p("pot_final.ptau"))
        snarkjs(zk_dir, "groth16", "setup", compiled / "session_auth.r1cs", p("pot_final.ptau"), p("s_0.zkey"))
        snarkjs(zk_dir, "zkey", "contribute", p("s_0.zkey"), p("session_auth.zkey"),
                "--name=zkvpn-dev", f"-e={entropy()}")
        build.mkdir(parents=True)
        snarkjs(zk_dir, "zkey", "export", "verificationkey", p("session_auth.zkey"), build / "vkey.json")
        shutil.copyfile(p("session_auth.zkey"), build / "session_auth.zkey")
        shutil.copyfile(compiled / "session_auth_js" / "session_auth.wasm", build / "session_auth.wasm")
    return build
