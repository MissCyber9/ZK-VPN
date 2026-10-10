# Security

**Status: prototype, never audited. Do not use it to protect real users.**

## Reporting a vulnerability
Please open a private security advisory on GitHub (Security → Report a vulnerability) rather than a
public issue. Include the version/commit, what you did, and what you expected.

## What the system claims (and does not)
| Claim | Mechanism |
|---|---|
| Only holders of an authorised identity can join | Groth16 proof of knowledge of the secret behind `pk = Poseidon(sk)`, checked against `ZKVPN_AUTHORIZED_IDENTITIES` (`src/zkvpn/zk/auth.py`) |
| A proof cannot be replayed or moved to another WireGuard key | Single-use server nonce; the circuit's public `challenge` is `SHA-256(nonce, wireguard_public_key) mod p` |
| Proofs are fresh | `timestamp ≤ current_time ≤ timestamp + 300` enforced in the circuit; `current_time` checked against the server clock (±30 s) |
| Client traffic does not leak if the tunnel dies | Kill-switch chain (`iptables`/`ip6tables`), `/1` routes, pinned server route |
| Clients cannot reach each other | `ZKVPN_FWD` drops forwarding between tunnel peers |

**It does not prove that a server keeps no logs.** No zero-knowledge proof can: a server can always log
what it sees. Anonymity towards the *server operator* is not provided either: the operator sees client
traffic and WireGuard public keys. The admission channel is plain TCP carrying only public data; a
network attacker can block it but not forge an admission.

## Trust assumptions
1. **Trusted setup.** `scripts/setup_circuits.sh` is a *single-party* setup: whoever ran it can forge
   proofs. For production use `scripts/ceremony.sh` (public phase 1, several independent contributors,
   public random beacon). Keys are sound if **at least one** contributor destroyed their entropy.
2. **Server WireGuard key** must be pinned by clients out of band; it authenticates the server.
3. **Open registration.** With an empty `ZKVPN_AUTHORIZED_IDENTITIES` any valid identity is admitted.
4. **Identity files** are protected by file permissions only (0600).

## What is tested
* Unit tests (`pytest`): proofs, protocol, parsers, rule construction, CLI.
* Real-network tests (`pytest -m e2e`, Linux namespaces + real WireGuard/iptables): address hiding,
  refusal of unauthorised/unproven clients, kill-switch leak test with a control experiment, DNS through
  the tunnel and restoration, client isolation, clean teardown. Mutation checks confirm these tests fail
  when the protection is removed.
* Installer/service tests (`tests/distro/run.sh`): install on a distribution, real systemd unit,
  real client against it.
* Ceremony tests (`pytest -m slow`): contribution chain, beacon, tamper and wrong-ceremony rejection.

Not covered by automated tests: IPv6 on kernels without IPv6 (tests skip), physical networks, DoH,
resource exhaustion beyond the connection limits, side channels, the circom/snarkjs toolchain itself.

## Suggested scope for an external audit
1. `src/zkvpn/circuits/session_auth.circom`: soundness (range checks on 32-bit timestamps, field-size
   assumptions on `challenge`, under-constrained signals).
2. `src/zkvpn/zk/auth.py`, `protocol/admission.py`: challenge lifecycle, parsing of untrusted JSON,
   denial-of-service limits (verification costs ~0.7 s of CPU).
3. `protocol/killswitch.py`, `routing.py`, `dns.py`: rule ordering, race windows while enabling or
   disabling, behaviour across crashes.
4. `scripts/install.sh` and the systemd unit: privileges (`CAP_NET_ADMIN`), file permissions, the
   `curl | bash` path.
5. The ceremony procedure (`scripts/ceremony.sh`) with real, independent participants.
