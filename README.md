# ZK-VPN

VPN WireGuard piloté en Python, dont l'**admission des clients** repose sur de vraies preuves
zero-knowledge (Groth16, circom + snarkjs) : le client prouve qu'il connaît la clé secrète d'une
identité, pour un challenge du serveur lié à sa clé WireGuard, sans la révéler.

> ⚠️ **Statut : prototype non audité.** Les clés de preuve produites par `zkvpn zk setup` viennent
> d'un setup **mono-partie** (développement). Ce projet **ne prouve pas** l'absence de logs :
> aucune preuve ZK ne le peut. Voir [docs/AUDIT.md](docs/AUDIT.md) et [SECURITY.md](SECURITY.md).

## Systèmes pris en charge

| | Client | Serveur | Ce qui est vérifié |
|---|---|---|---|
| **Linux** (Debian/Ubuntu, Fedora/RHEL) | oui | oui | de bout en bout (WireGuard, routes, kill-switch, DNS, NAT) sur réseau virtuel et sous systemd ; CI Ubuntu, Debian, Fedora |
| **Docker** | oui | oui | image construite et testée (voir `tests/docker/smoke.sh`) |
| **macOS** | oui | non | tests unitaires + vrai WireGuard (interface, clés, pair, handshake) en CI ; routes, pare-feu `pf` et DNS **non appliqués en CI** |
| **Windows** | oui | non | idem (service WireGuard, `netsh`, PowerShell) |
| Autre | dégradé | non | le cœur (preuves, protocole, CLI) fonctionne ; le réseau est refusé proprement |

Le cœur (preuves ZK, protocole d'admission, CLI, configuration) est le même partout ; seule la
couche réseau (`zkvpn.platform.net`) change d'un système à l'autre. Lancez `zkvpn doctor` pour
savoir ce qui manque sur votre machine.

## Installation

Prérequis : Python ≥ 3.9, Node ≥ 18 (compilation du circuit), WireGuard (module noyau,
`wireguard-go`, ou WireGuard pour Windows) et les outils réseau du système.

```bash
pipx install .            # ou : python -m venv .venv && . .venv/bin/activate && pip install .
zkvpn doctor              # état de la machine
zkvpn zk setup            # compile le circuit, génère les clés de DÉVELOPPEMENT (~1 min)
```

Les clés, l'identité et la configuration sont créées chez vous (dossiers utilisateur du système,
modifiables par `ZKVPN_*`), jamais dans le dépôt.

### Serveur Linux (systemd)
```bash
sudo ./scripts/install.sh
sudo systemctl enable --now zkvpn
```
Utilisateur système dédié (`zkvpn`), seulement `CAP_NET_ADMIN`/`CAP_NET_RAW`, pare-feu modifié
uniquement s'il est déjà actif.

### Docker
```bash
docker compose up --build        # serveur ; les clés de preuve sont construites dans l'image
```
L'image ne contient ni identité ni clé WireGuard : fournissez `ZKVPN_PRIVATE_KEY` à l'exécution.

## Utilisation
```bash
# Serveur (privilèges réseau) : affiche sa clé publique WireGuard
ZKVPN_AUTHORIZED_IDENTITIES=<pk1>,<pk2> zkvpn serve

# Client : créer une identité, donner la clé publique affichée à l'opérateur, se connecter
zkvpn identity new
zkvpn connect -e <ip>:51820 -k <clé WireGuard du serveur>
zkvpn status
zkvpn disconnect
```
Une liste blanche vide admet **toute** identité valide : renseignez `ZKVPN_AUTHORIZED_IDENTITIES`
en production. Pour de vraies clés de preuve, faites une cérémonie multipartite :
`zkvpn zk ceremony init | contribute | beacon | verify | finalize`.

## Développement et tests
```bash
pip install -r requirements-dev.txt -e .
zkvpn zk setup
pytest                                        # unitaires, tous systèmes
pytest -m slow tests/test_ceremony.py         # cérémonie complète
sudo -E env "PATH=$PATH" pytest -m e2e tests/e2e          # Linux, root : réseau virtuel
tests/distro/run.sh ubuntu:24.04 --e2e        # installeur + service systemd réel (Docker)
```
La CI (`.github/workflows/ci.yml`) exécute tout cela sur Linux, macOS et Windows.

## Dépôt public : ce qui n'y est jamais
Aucune clé, identité, `.env`, adresse e-mail personnelle ou chemin de machine. Les contributions
utilisent l'adresse `noreply` de GitHub. Des tests (`tests/test_repo_hygiene.py`) et un scan
d'historique (gitleaks) le vérifient à chaque push. Voir [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence
[MIT](LICENSE)
