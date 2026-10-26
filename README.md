# ZK-VPN

A WireGuard VPN driven from Python, whose **client admission** relies on real zero-knowledge
proofs (Groth16, circom + snarkjs): the client proves that it knows the secret key of an
identity, for a server challenge bound to its WireGuard key, without revealing it.

> ⚠️ **Status: unaudited prototype.** The proving keys produced by `zkvpn zk setup` come from a
> **single-party** setup (development only). This project does **not** prove that a server keeps
> no logs: no zero-knowledge proof can. See [docs/AUDIT.md](docs/AUDIT.md) and
> [SECURITY.md](SECURITY.md).

## Supported systems

| | Client | Server | What is verified |
|---|---|---|---|
| **Linux** (Debian/Ubuntu, Fedora/RHEL) | yes | yes | end to end (WireGuard, routes, kill-switch, DNS, NAT) on a virtual network and under systemd; CI on Ubuntu, Debian and Fedora |
| **Docker** | yes | yes | image built and tested in CI (`tests/docker/smoke.sh`) |
| **macOS** | yes | no | unit tests + real WireGuard (interface, keys, peer, handshake) in CI; routes, `pf` firewall and DNS are **not applied in CI** |
| **Windows** | yes | no | same (WireGuard service, `netsh`, PowerShell) |
| Other | degraded | no | the core (proofs, protocol, CLI) works; networking is refused cleanly |

The core (ZK proofs, admission protocol, CLI, configuration) is the same everywhere; only the
network layer (`zkvpn.platform.net`) differs per system. Run `zkvpn doctor` to see what is
missing on your machine.

## Installation

Requirements: Python ≥ 3.9, Node.js ≥ 18 (to compile the circuit), WireGuard (kernel module,
`wireguard-go`, or WireGuard for Windows) and the system's networking tools.

```bash
pipx install .            # or: python -m venv .venv && . .venv/bin/activate && pip install .
zkvpn doctor              # check the machine
zkvpn zk setup            # compile the circuit, build DEVELOPMENT keys (~1 min)
```

Keys, identity and configuration are created in your user directories (overridable with
`ZKVPN_*` variables), never inside the repository.

### Linux server (systemd)
```bash
sudo ./scripts/install.sh
sudo systemctl enable --now zkvpn
```
A dedicated system user (`zkvpn`) with only `CAP_NET_ADMIN`/`CAP_NET_RAW`; the firewall is
modified only if one is already active.

### Docker
```bash
docker compose up --build        # server; the proving keys are built into the image
```
The image contains no identity and no WireGuard key: provide `ZKVPN_PRIVATE_KEY` at run time.

## Usage
```bash
# Server (needs network privileges): prints its WireGuard public key
ZKVPN_AUTHORIZED_IDENTITIES=<pk1>,<pk2> zkvpn serve

# Client: create an identity, give the printed public key to the operator, connect
zkvpn identity new
zkvpn connect -e <ip>:51820 -k <server WireGuard key>
zkvpn status
zkvpn disconnect
```
An empty allow-list admits **any** valid identity: set `ZKVPN_AUTHORIZED_IDENTITIES` in
production. For real proving keys, run a multi-party ceremony:
`zkvpn zk ceremony init | contribute | beacon | verify | finalize`.

## Development and tests
```bash
pip install -r requirements-dev.txt -e .
zkvpn zk setup
pytest                                        # unit tests, any OS
pytest -m slow tests/test_ceremony.py         # full ceremony
sudo -E env "PATH=$PATH" pytest -m e2e tests/e2e    # Linux, root: virtual network
tests/distro/run.sh ubuntu:24.04 --e2e        # installer + real systemd service (Docker)
```
CI (`.github/workflows/ci.yml`) runs all of this on Linux, macOS and Windows.

## Public repository: what is never in it
Contributions use GitHub's `noreply` address. Tests (`tests/test_repo_hygiene.py`) and a history scan (gitleaks)
check this on every push. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License
[MIT](LICENSE)
