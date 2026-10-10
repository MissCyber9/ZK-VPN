# ZK-VPN (prototype)

Prototype de VPN WireGuard piloté en Python, avec une couche de « preuves » destinée
à devenir un jour de vraies preuves zero-knowledge.

> ⚠️ **Statut : maquette, non utilisable en production.**
> L'**admission des clients** utilise de vraies preuves Groth16 (`zkvpn.zk`), mais la
> cérémonie de setup est locale et mono-partie (développement uniquement).
> Les modules `zkvpn.circuits.*` (prover/verifier/no_logging) sont des **stubs simulés**
> qui peuvent être forgés. Ce projet **ne prouve pas** l'absence de logs : aucune preuve ZK
> ne le peut. Voir [AUDIT.md](AUDIT.md).

## Ce qui existe
- Gestion d'une interface WireGuard via `wg` / `ip` (`src/zkvpn/protocol/wireguard.py`, `tunnel.py`)
- Protection DNS basique via `iptables` / `resolv.conf` (`protocol/dns.py`)
- Stockage en mémoire avec TTL pour sessions, preuves et clés (`core/memory.py`)
- Configuration par variables d'environnement `ZKVPN_*` (`core/config.py`)
- CLI `zkvpn` (click / rich)
- **Authentification ZK de session** (Groth16, circom + snarkjs) : le client prouve qu'il
  connaît la clé secrète de son identité, pour un challenge du serveur **lié à sa clé
  WireGuard**, avec horodatage frais et chaînage anti-rejeu (`zk/`, `src/zkvpn/zk/`,
  `circuits/session_auth.circom`). Le serveur refuse les clients sans preuve valide
  (`ZKVPN_REQUIRE_CLIENT_PROOF`, `ZKVPN_AUTHORIZED_IDENTITIES`).
- **Kill-switch** iptables/ip6tables (bloque tout hors tunnel, DoT/DoH inclus), activé à la connexion client
- Stubs de preuve « no-logging » **simulés** (`circuits/prover.py`, `verifier.py`, `no_logging.py`)

## Ce qui n'existe pas (encore)
- Transport réseau des preuves entre pairs (l'API `issue_challenge` / `add_client(proof=...)` existe, pas le protocole)
- Cérémonie de confiance multipartite pour les clés de preuve
- Réseau P2P, système de réputation, interface web

## Installation (développement)
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt -e .
scripts/setup_circuits.sh   # Node >= 18 : compile le circuit, génère les clés (~1 min)
pytest                      # les tests ZK sont ignorés si les artefacts manquent
```

L'installeur système (`scripts/install.sh`, Ubuntu/Debian, root) est expérimental :
lisez-le avant de l'exécuter.

## Licence
Aucune licence n'est encore définie.
