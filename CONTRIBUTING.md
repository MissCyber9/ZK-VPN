# Contributing

## Set up
```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt -e .
zkvpn doctor            # what is missing on this machine?
zkvpn zk setup          # build the (development) proving keys, needs Node.js >= 18
pytest                  # portable tests: any OS
```
Other suites, each in CI:

| Suite | Command | Needs |
|---|---|---|
| real network on Linux (namespaces, WireGuard, iptables) | `sudo -E env "PATH=$PATH" pytest -m e2e tests/e2e` | Linux, root |
| installer + systemd service per distribution | `tests/distro/run.sh ubuntu:24.04 --e2e` | Docker |
| Docker image | `tests/docker/smoke.sh` | Docker |
| multi-party ceremony | `pytest -m slow tests/test_ceremony.py` | Node.js |
| real WireGuard interfaces | `pytest -m netsmoke tests/netsmoke` | macOS/Windows, admin, WireGuard |

## Keep the repository free of personal data and secrets
This repository is public, and Git history is permanent. `tests/test_repo_hygiene.py` fails when a
tracked file or a commit contains a personal e-mail address, a home-directory path, a credential,
key material or editor/OS metadata. Before your first commit:

```bash
# use GitHub's private address, never your real one
git config user.name  "Your Name or handle"
git config user.email "<id>+<username>@users.noreply.github.com"   # GitHub → Settings → Emails
```
and tick **GitHub → Settings → Emails → "Block command line pushes that expose my email"**.

Never commit: `.env` (use `.env.example` as a template), `*.key`, `*.pem`, `*.zkey`, `*.ptau`,
identity files, `ceremony/` directories, `.coverage`, `*:Zone.Identifier`, build output.
If something private is committed by mistake, tell the maintainer *before* pushing: removing it
afterwards needs a history rewrite.

## Conventions
* Network behaviour is verified against the real thing (see the suites above), not only mocked.
* A protection is only considered tested if the test fails when the protection is removed.
* Platform-specific code goes behind `zkvpn.platform` (see `platform/net`); the core stays portable.
