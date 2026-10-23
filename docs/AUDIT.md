# Audit and verification status

This project started as a mock-up (simulated proofs, a service that could not start, an unusable
CLI). This document records what was found, what was fixed, how each point was verified, and what
is still open. It does not replace an independent audit (see [SECURITY.md](../SECURITY.md)).

## What was wrong at the start
- **The "ZK" part was simulated**: the proof was a SHA-256 of the inputs and the verifier accepted
  any forged proof. Replaced by a real Groth16 circuit (`src/zkvpn/circuits/session_auth.circom`,
  Poseidon, 32-bit freshness checks) with real proving and verification (`src/zkvpn/zk/`).
- The WireGuard private key was not a valid key; the systemd unit could not run (no
  `CAP_NET_ADMIN`, read-only devices); the DNS firewall commands were never awaited; the
  kill-switch did not exist; `config set` allowed variable injection through newlines;
  peer keys and endpoints reached `wg set` unvalidated; the CLI crashed on `--help`.
- `pip install .` produced a package without `zkvpn.core`, so the installed CLI could not start.

## What exists now, and how it is verified

| Area | State | Verification |
|---|---|---|
| Admission proofs | Groth16 proof of knowledge of the secret behind `pk = Poseidon(sk)`, bound to a single-use server nonce and the client's WireGuard key, with a freshness window | unit tests with real proofs; forged, replayed and expired proofs rejected |
| Admission protocol | TCP, JSON lines, size / time / per-IP / global limits, generic failure reply | unit tests, end-to-end |
| Tunnel | WireGuard through the kernel module or `wireguard-go`; client routes all traffic (`/1` routes + pinned server route) | end-to-end on Linux, real WireGuard in CI on macOS and Windows |
| Kill-switch | dedicated `iptables`/`ip6tables` chain (macOS: `pf` anchor, Windows: firewall rules), fail-closed | Linux: leak test with a control experiment; macOS/Windows: unit tests only |
| DNS protection | systemd-resolved / resolvconf / `resolv.conf` backends, plain DNS and DoT blocked outside the tunnel, state restored by `disconnect` | Linux end-to-end (file backend); others unit-tested |
| Server | NAT + forwarding, clients isolated from each other, exact teardown on exit | Linux end-to-end with two simultaneous clients |
| Installer / service | dedicated user, minimal privileges, Debian and RHEL families | real systemd service on Ubuntu 24.04, Debian 12, Fedora 41 (CI) |
| Docker image | no secret inside, server starts with the supplied key, client container reaches the server through the tunnel | CI (`tests/docker/smoke.sh`) |
| Trusted setup | `zkvpn zk ceremony`: public phase 1, independent contributions, public beacon, full-chain verification | 3 contributors + beacon, tampering and wrong-ceremony rejection, proofs from the old single-party key rejected |
| Portability | per-OS paths, owner-only files (POSIX modes / Windows ACLs), network backend per system | unit tests on Linux, macOS, Windows; real WireGuard on macOS and Windows |
| Repository privacy | no personal e-mail, machine path, key material or secret in files or history | `tests/test_repo_hygiene.py`, gitleaks in CI |

Tests were validated by **mutation**: removing client isolation, the port-53 block or the DNS
restoration makes the corresponding test fail.

## Defects found only by running the real thing (all fixed)
- the client installed no route, so traffic did not enter the tunnel;
- the server had no NAT and no forwarding rules;
- the admission waited for the proof too short a time and held a concurrency slot while waiting
  (slowloris): separate timeouts, per-IP and global limits;
- `zkvpn connect` returned exit code 0 on failure;
- no fallback when the WireGuard kernel module is missing (containers, VMs);
- a client sharing a machine with a server configuration inherited the server's private key, so
  both had the same public key and WireGuard silently ignored the peer;
- the systemd unit could not start (`/dev/net/tun` mode, `/run/wireguard` not creatable,
  unreadable `wireguard-go` errors);
- `disconnect` could never restore DNS (backup kept in another process's memory);
- Windows: circuit compilation failed, console output crashed on code page 1252, and
  `restrict_to_owner` left an explicit "Everyone" ACL entry in place (fixed with `icacls /reset`,
  with a regression test).

## Design decision
Chaining each proof to the previous one (`prev_tag`) is not enforced by default
(`enforce_chain=False`): it made reconnection impossible (the client does not keep the last tag and
the server loses its state on restart), while replay is already prevented by single-use challenges
bound to the WireGuard key.

## Known limits (open)
1. **No real ceremony has been held.** Keys from `zkvpn zk setup` are single-party: whoever kept the
   entropy can forge proofs. Run `zkvpn zk ceremony` with independent participants for any real use.
2. **macOS and Windows**: routes, firewall and DNS changes are covered by unit tests but not applied
   in CI (doing so would cut the runner off the network). The server role is Linux/Docker only.
3. **IPv6** end-to-end tests exist but are skipped on kernels without IPv6 (CI runners run them);
   `resolvectl`/`resolvconf` commands are unit-tested only.
4. **Physical networks** were not tested; Linux tests use namespaces and virtual interfaces.
5. **The admission channel is plain TCP** carrying public data only; a network attacker can block or
   slow it. Verification costs about 0.7 s of CPU, bounded by connection limits.
6. **An empty allow-list admits any valid identity.** Set `ZKVPN_AUTHORIZED_IDENTITIES` in production.
7. **Identity files are not encrypted** (owner-only permissions).
8. **There is no external audit.** Do not use this project to protect real users.
