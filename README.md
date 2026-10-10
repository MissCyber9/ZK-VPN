# ZK-VPN (prototype)

Prototype de VPN WireGuard piloté en Python, avec une couche de « preuves » destinée
à devenir un jour de vraies preuves zero-knowledge.

> ⚠️ **Statut : maquette, non auditée, non utilisable en production.**
> L'**admission des clients** repose sur de vraies preuves Groth16 (`zkvpn.zk`), mais la
> cérémonie de setup est locale et mono-partie (développement uniquement).
> Ce projet **ne prouve pas** l'absence de logs : aucune preuve ZK ne le peut. Voir [AUDIT.md](AUDIT.md).

## Ce qui existe
- Gestion d'une interface WireGuard via `wg` / `ip` (`protocol/wireguard.py`, `tunnel.py`)
- **Authentification ZK de session** (Groth16, circom + snarkjs) : le client prouve qu'il
  connaît la clé secrète de son identité, pour un challenge du serveur **lié à sa clé
  WireGuard**, avec horodatage frais (`circuits/session_auth.circom`, `src/zkvpn/zk/`)
- **Protocole d'admission** TCP (`protocol/admission.py`) : hello → challenge → preuve → IP attribuée.
  Le serveur refuse les clients sans preuve valide (`ZKVPN_REQUIRE_CLIENT_PROOF`,
  `ZKVPN_AUTHORIZED_IDENTITIES`, `ZKVPN_ADMISSION_PORT`)
- **Routage client** (tout le trafic dans le tunnel, route épinglée vers le serveur) et **NAT serveur** (clients isolés les uns des autres)
- **Kill-switch** iptables/ip6tables (bloque tout hors tunnel, DoT/DoH inclus), activé à la connexion client
- Protection DNS basique (`protocol/dns.py`)
- Stockage en mémoire avec TTL (`core/memory.py`), configuration `ZKVPN_*` (`core/config.py`)
- CLI `zkvpn` : `serve`, `connect`, `disconnect`, `status`, `identity`, `config`, `peer`, `test`

## Ce qui n'existe pas (encore)
- Cérémonie de confiance multipartite pour les clés de preuve
- Chiffrement/authentification du canal d'admission (il ne transporte que des données publiques ;
  le serveur est authentifié par sa clé WireGuard, à épingler hors bande)
- Réseau P2P, système de réputation, interface web
- Tests sur machine physique / sous systemd (le kill-switch, le NAT et le routage sont en revanche vérifiés sur réseau virtuel, voir `tests/e2e`)

## Utilisation
```bash
# Serveur (root) : écoute WireGuard + admission, liste blanche optionnelle
ZKVPN_AUTHORIZED_IDENTITIES=<pk1>,<pk2> zkvpn serve

# Client : créer une identité, donner la clé publique affichée à l'opérateur, se connecter
zkvpn identity new ~/.zkvpn-identity          # fichier 0600, jamais écrasé
zkvpn connect -e <ip>:51820 -k <clé WireGuard du serveur> -i ~/.zkvpn-identity
```

## Installation (développement)
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt -e .
scripts/setup_circuits.sh   # Node >= 18 : compile le circuit, génère les clés (~1 min)
pytest                      # tests unitaires ; les tests ZK sont ignorés si les artefacts manquent

# Tests de bout en bout sur un vrai réseau virtuel (namespaces Linux, root requis) :
# vrai WireGuard (noyau ou wireguard-go), vraies règles iptables, vraies preuves
sudo -E env "PATH=$PATH" pytest -m e2e tests/e2e
```

L'installeur système (`scripts/install.sh`, Ubuntu/Debian, root) est expérimental :
lisez-le avant de l'exécuter.

## Licence
[MIT](LICENSE)
