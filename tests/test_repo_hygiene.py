"""Guards that keep the PUBLIC repository free of secrets and personal information.

They look at every tracked file and, when the full history is available, at every commit
identity. A failure here means something private is about to be published.
"""

import fnmatch
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    not shutil.which("git") or not (ROOT / ".git").exists(), reason="needs a git checkout")

# files that must never be tracked (editor/OS metadata, build output, key material, local config)
FORBIDDEN_FILES = [
    "*:Zone.Identifier", ".coverage", "*.egg-info/*", "*.pyc", "__pycache__/*", "node_modules/*",
    "*.pem", "*.key", "*.zkey", "*.ptau", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "*.conf.dpapi",
    ".env", ".env.*", "current_deps.txt", "*.bundle", ".DS_Store", "Thumbs.db",
]
ALLOWED_FILES = [".env.example"]

# commit identities allowed in the history
ALLOWED_IDENTITIES = re.compile(
    r"^(.+ <\d+\+[\w-]+@users\.noreply\.github\.com>|.+ <noreply@github\.com>|.+ <noreply@anthropic\.com>)$")

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
OK_EMAIL = re.compile(r"(@users\.noreply\.github\.com|@example\.(com|org)|noreply@(anthropic|github)\.com)$")
HOME_PATH = re.compile(r"(/home/(?!user\b|runner\b)[a-z][\w.-]*/|/Users/(?!runner\b|me\b|Shared\b)[A-Za-z][\w.-]*/"
                       r"|[A-Za-z]:\\Users\\(?!me\b|runneradmin\b|Public\b|runner\b)[\w.-]+\\)")
SECRETS = [
    re.compile(r"ghp_[A-Za-z0-9]{30,}"), re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"sk-(ant-)?[A-Za-z0-9_-]{30,}"), re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"), re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"(?i)(private[_-]?key|PrivateKey)\s*[=:]\s*[\"']?[A-Za-z0-9+/]{43}=[\"']?"),   # a real WireGuard key
]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def tracked():
    return [f for f in git("ls-files").splitlines() if (ROOT / f).is_file()]


def text_of(path):
    data = (ROOT / path).read_bytes()
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", "replace")


def test_no_forbidden_file_is_tracked():
    bad = [f for f in tracked()
           if any(fnmatch.fnmatch(f, p) or fnmatch.fnmatch(Path(f).name, p) for p in FORBIDDEN_FILES)
           and f not in ALLOWED_FILES]
    assert not bad, f"private or generated files are tracked: {bad}"


def test_no_personal_email_or_home_directory_in_tracked_files():
    problems = []
    for f in tracked():
        text = text_of(f)
        if text is None or f == "tests/test_repo_hygiene.py":
            continue
        for m in EMAIL.finditer(text):
            if not OK_EMAIL.search(m.group(0)) and "package-lock" not in f:
                problems.append(f"{f}: e-mail {m.group(0)}")
        for m in HOME_PATH.finditer(text):
            problems.append(f"{f}: home directory {m.group(0)}")
    assert not problems, "\n".join(problems)


def test_no_secret_in_tracked_files():
    problems = []
    for f in tracked():
        text = text_of(f)
        if text is None or f == "tests/test_repo_hygiene.py" or f.endswith("package-lock.json"):
            continue
        for pattern in SECRETS:
            for m in pattern.finditer(text):
                problems.append(f"{f}: matches {pattern.pattern[:40]}…")
    assert not problems, "\n".join(problems)


def test_every_commit_uses_a_noreply_identity():
    if git("rev-parse", "--is-shallow-repository").strip() == "true":
        pytest.skip("shallow clone: the full history is needed")
    identities = set(git("log", "--all", "--format=%an <%ae>%n%cn <%ce>").split("\n")) - {""}
    bad = sorted(i for i in identities if not ALLOWED_IDENTITIES.match(i))
    assert not bad, f"commit identities that expose a personal address: {bad}"


def test_no_personal_data_in_commit_messages():
    if git("rev-parse", "--is-shallow-repository").strip() == "true":
        pytest.skip("shallow clone: the full history is needed")
    messages = git("log", "--all", "--format=%B")
    leaks = [m.group(0) for m in EMAIL.finditer(messages) if not OK_EMAIL.search(m.group(0))]
    assert not leaks, leaks
    assert "claude.ai/code/session" not in messages
