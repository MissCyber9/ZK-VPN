"""The installed package (not the source tree) must contain everything the CLI needs.

`pip install -e .` hides missing files because it imports from the source tree; a normal
`pip install .` does not. These tests look at what really ships.
"""

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "zkvpn"


def test_every_package_directory_has_an_init():
    """setuptools.find_packages() silently skips directories without __init__.py."""
    missing = [str(d.relative_to(SRC.parent)) for d in SRC.rglob("*")
               if d.is_dir() and d.name not in ("__pycache__", "node") and any(d.glob("*.py"))
               and not (d / "__init__.py").exists()]
    assert not missing, f"directories with code but no __init__.py (not packaged!): {missing}"


@pytest.fixture(scope="module")
def wheel(tmp_path_factory):
    out = tmp_path_factory.mktemp("wheel")
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps",
                    "-w", str(out), str(ROOT)], check=True, capture_output=True)
    return zipfile.ZipFile(next(out.glob("*.whl")))


def test_wheel_contains_every_module_and_data_file(wheel):
    names = set(wheel.namelist())
    for py in SRC.rglob("*.py"):
        assert f"zkvpn/{py.relative_to(SRC).as_posix()}" in names, f"{py} is not in the wheel"
    for data in ("circuits/session_auth.circom", "zk/node/package.json", "zk/node/package-lock.json",
                 "zk/node/prove.js", "zk/node/verify.js"):
        assert f"zkvpn/{data}" in names, f"{data} is not in the wheel"


def test_wheel_contains_no_tests_secrets_or_personal_files(wheel):
    bad = [n for n in wheel.namelist()
           if n.startswith(("tests/", "ceremony/", "zk/")) or n.endswith((".env", ".key", ".zkey", ".ptau", ".pem"))]
    assert not bad, bad


def test_wheel_declares_its_entry_point_and_license(wheel):
    meta = next(n for n in wheel.namelist() if n.endswith("entry_points.txt"))
    assert "zkvpn=zkvpn.cli.main:main" in wheel.read(meta).decode().replace(" ", "")
    info = next(n for n in wheel.namelist() if n.endswith("METADATA"))
    assert "MIT" in wheel.read(info).decode()
