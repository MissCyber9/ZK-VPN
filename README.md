# ZK-VPN (prototype)

Prototype de VPN WireGuard piloté en Python, avec une couche de « preuves » destinée
à devenir un jour de vraies preuves zero-knowledge.

> ⚠️ **Statut : maquette, non utilisable en production.**
> Les « preuves ZK » actuelles sont **simulées** (hash SHA-256 et structures factices) :
> elles ne prouvent rien cryptographiquement et peuvent être forgées.
> Ce projet **ne garantit pas** l'absence de logs. Voir [AUDIT.md](AUDIT.md).

## Ce qui existe
- Gestion d'une interface WireGuard via `wg` / `ip` (`src/zkvpn/protocol/wireguard.py`, `tunnel.py`)
- Protection DNS basique via `iptables` / `resolv.conf` (`protocol/dns.py`)
- Stockage en mémoire avec TTL pour sessions, preuves et clés (`core/memory.py`)
- Configuration par variables d'environnement `ZKVPN_*` (`core/config.py`)
- CLI `zkvpn` (click / rich)
- Preuve « no-logging » **simulée** (`circuits/`) ; un circuit circom d'esquisse
  (`no_logging.circom`) existe mais **ne compile pas** encore

## Ce qui n'existe pas (encore)
- Vrai système de preuve (SNARK) et vérification entre pairs
- Réseau P2P, système de réputation, interface web
- Kill-switch réseau complet

## Installation (développement)
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt -e .
pytest
```

L'installeur système (`scripts/install.sh`, Ubuntu/Debian, root) est expérimental :
lisez-le avant de l'exécuter.

## Licence
Aucune licence n'est encore définie.
