# Audit ZK-VPN

Audit par lecture du code (tests non exécutés : pytest absent de l'environnement).

## Critique : la partie ZK est simulée
- `prover.py` : la « preuve » est un `sha256(commitment + validity + random)`. Aucun SNARK, aucun circuit exécuté.
- `verifier.py` : vérifie `public_inputs["is_valid"] == 1` et `sha256(proof_data) == proof_hash`, or `Proof.__post_init__` recalcule toujours ce hash. N'importe qui peut forger une preuve valide.
- Le cache de vérification accepte toute preuve dont le hash est dans `proof_store`.
- `no_logging.circom` ne compile pas (signal `bits[512]` inutilisé, sorties de `Sha256` assignées à la main, `Bits2Num` non inclus, hash 256 bits dans un élément de champ ~254 bits).
- Même corrigé, le circuit ne prouve qu'un horodatage récent : une preuve ZK ne peut pas garantir l'absence de logs.
- Les preuves ne sont jamais envoyées ni vérifiées par un pair ; `connect()` ne vérifie rien.
- README : « réputation », « P2P », « interface web » n'existent pas dans le code.

## Sécurité
1. `config.py` génère une « clé privée » `token_urlsafe(32)` qui n'est pas une clé WireGuard valide.
2. `install.sh` écrit la clé privée dans `/etc/zkvpn/.env` ; `dns.py` écrit dans `resolv.conf`. Contredit « jamais sur disque ».
3. Service systemd en `User=nobody` sans `CAP_NET_ADMIN`, avec `PrivateDevices=yes` et `ProtectSystem=strict` : ne peut pas fonctionner.
4. `dns.py` : commandes `iptables` lancées sans `await proc.wait()` ; seul le port 53 est bloqué (pas DoT/DoH) ; pas de kill-switch.
5. `WireGuardPeer` : `allowed_ips` par défaut `0.0.0.0/0, ::/0`.
6. `install.sh` désactive puis réactive UFW avec seulement ssh et 51820.
7. `config set` ne valide ni clé ni valeur (injection de variable via retour à la ligne) et affiche la valeur.
8. Pas de validation des clés publiques/endpoints passés à `wg set` (une valeur commençant par `-` peut être lue comme option).
9. Logs DEBUG : préfixes de clés et de pairs.

## Bugs et fiabilité
- `wireguard.py` : `subprocess.run` bloquant dans des coroutines ; parsing de `wg show` cassé sur IPv6 ; type `any` ; exceptions avalées de façon incohérente ; instance globale créée à l'import.
- `tunnel.py` : `disconnect` supprime l'interface côté serveur aussi ; IP serveur et `/24` codés en dur.
- `prover.py` : `get_event_loop()` déprécié, `_proof_cache` non borné.
- `memory.py` : pas d'effacement mémoire réel, `except:` nus.
- `core/test_config.py` est dans le paquet de production.
- Tests `test_basic.py` : attrapent `ImportError` et ne peuvent pas échouer ; conflit `tests/test_circuits.py` / `tests/test_circuits/`.
- Pas de CI, pas de fichier LICENSE.

## Corrigé (commits successifs)
**Packaging et hygiène**
- `setup.py` n'était pas parsable (bloc orphelin) : réécrit, entry points inexistants retirés.
- `requirements.txt` corrigé (dépendances réellement importées) ; `requirements-dev.txt` ajouté.
- `install.sh` : chemin de clone, `requirements.txt`, caractère non ASCII, fins de ligne CRLF des scripts.
- Fichiers parasites retirés (`egg-info`, `*:Zone.Identifier`, `.TXT`, `current_deps.txt`) ; `.gitignore` complété.

**Bugs trouvés en exécutant les tests (58 passent, contre 38 erreurs au départ)**
- `memory_guard` (`@contextmanager` utilisé sur des méthodes `async`) ne protégeait rien : il se terminait avant l'`await`. Réécrit en garde sync/async.
- La validation anti-traversée de chemin de `config.py` ne rejetait rien (`normpath` supprimait les `..` avant le contrôle).
- `pytest.ini` ajouté (`asyncio_mode=auto`) : la fixture async `autouse` ne s'exécutait pas.
- `tests/test_basic.py` et `test_circuits.py` avalaient toutes les exceptions (un test appelait une méthode inexistante et « passait ») : réécrits avec de vrais `assert`.
- `test_config.py` déplacé hors du paquet de production, tests de régression ajoutés.

**Durcissement**
- `dns.py` : les commandes `iptables`/`ip6tables` sont maintenant attendues (`await proc.wait()`).
- `wireguard.py` : validation des clés publiques, endpoints et `allowed_ips` avant `wg set` ; type `Any` corrigé.
- `config.py` : plus de fausse « clé privée WireGuard » générée ; la clé vient de `wg genkey`.
- `install.sh` : comparaison de version Python sans `bc`, UFW n'est plus désactivé/réinitialisé, unité systemd avec `CAP_NET_ADMIN`/`CAP_NET_RAW` (non testée sous systemd).
- README réécrit : statut maquette, pas de promesse « no logging ».

## État final des points de l'audit
| Point | État |
|---|---|
| Vrai SNARK | **Fait** : `circuits/session_auth.circom` (Groth16/bn128, Poseidon), `src/zkvpn/zk/`. Prouve la connaissance de la clé secrète d'une identité, pour un challenge lié à la clé WireGuard, avec fraîcheur. Ne prouve **pas** l'absence de logs. |
| Transport des preuves | **Fait** : `protocol/admission.py` (TCP, JSON par lignes, challenge à usage unique, limites de taille/temps/concurrence, réponse d'échec générique). |
| `connect()` sur le vrai prover | **Fait** : `connect(..., identity_sk=...)` s'authentifie auprès du serveur qui attribue l'IP ; échec fermé si refusé. |
| Stubs simulés | **Supprimés** (`circuits/prover|verifier|no_logging|compiler` et leurs tests) : plus aucun vérificateur falsifiable dans le paquet. |
| Kill-switch | **Fait** (`protocol/killswitch.py`), activé par `connect()`, échec fermé. |
| `wireguard.py` | **Fait** : non bloquant, parseur `wg show` corrigé, clé configurée réellement utilisée. |
| `config set` | **Fait**. |
| Pydantic v2, CI, licence MIT | **Faits**. |

**Bugs supplémentaires trouvés et corrigés en testant le vrai CLI** : `zkvpn --help` et `zkvpn status` plantaient (commandes enregistrées comme fonctions), les sous-commandes `async` des groupes n'étaient jamais attendues, `connect` démarrait le serveur deux fois, `test zk` appelait un argument inexistant, le service systemd lançait une commande `node` qui n'existe pas (remplacée par `zkvpn serve`), et la clé privée générée par l'installeur n'était pas celle utilisée par le serveur.

**Décision de conception** : le chaînage `prev_tag` n'est plus imposé par défaut (`enforce_chain=False`). Il rendait toute reconnexion impossible (le client ne conserve pas le dernier tag, le serveur perd son état au redémarrage) alors que le rejeu est déjà empêché par les challenges à usage unique liés à la clé WireGuard.

## Vérification en conditions réelles (`tests/e2e`)
Banc d'essai en namespaces Linux (client, serveur, routeur « FAI », site web) avec de **vrais** processus `zkvpn serve` / `zkvpn connect`, un vrai WireGuard (module noyau ou `wireguard-go`), de vraies règles iptables et de vraies preuves Groth16. Les 8 scénarios passent :

| Scénario | Ce qui est vérifié |
|---|---|
| Client avec identité autorisée | Le site web voit l'adresse du **serveur**, pas celle du client ; aucun paquet ne contourne le tunnel (compteur sur le routeur FAI). |
| Client sans preuve | Le serveur ne l'admet pas : rien ne passe et rien ne fuit. |
| Identité hors liste blanche | Connexion refusée, aucune règle ni route laissée, le client garde son chemin normal. |
| Tunnel qui meurt (processus tué) | Avec kill-switch : le site n'est pas joignable et **0 paquet** ne part hors tunnel. |
| Même panne **sans** kill-switch (témoin) | Le trafic fuit en clair : prouve que le test précédent sait détecter une fuite. |
| `disconnect` | Routes, règles, interface supprimées ; chemin direct rétabli. |
| Règles serveur | NAT + isolation client-à-client présents ; **aucune règle résiduelle** après SIGTERM. |

**Défauts de logique que seul ce banc pouvait révéler** (tous corrigés) :
- le client n'installait **aucune route** : le trafic ne passait pas par le tunnel malgré `allowed_ips=0.0.0.0/0` ;
- le serveur n'avait **ni NAT ni règles de forward** : un client ne pouvait pas atteindre Internet via lui ;
- l'admission attendait la preuve 2 à 10 s alors qu'elle prend 1 à 4 s (bien plus sur téléphone), et retenait un slot de concurrence pendant l'attente (slowloris) : timeouts séparés (hello 5 s / preuve 30 s), limites par IP et globales, sémaphore limité à la vérification ;
- `zkvpn connect` renvoyait le code 0 même en cas d'échec ;
- pas de repli quand le module noyau WireGuard est absent (conteneurs, VM) : repli sur `wireguard-go`.

## Solutions apportées aux points restants (et ce qui est réellement vérifié)

| Point | Solution | Vérifié ? |
|---|---|---|
| Cérémonie mono-partie | `scripts/ceremony.sh` : phase 1 publique, contributions indépendantes, balise publique, `verify` qui recompile le circuit et revérifie toute la chaîne, `finalize`. | **Oui** (3 contributeurs + balise, clé falsifiée rejetée, clé d'une autre cérémonie rejetée, preuves valides avec les nouvelles clés, preuve faite avec l'ancienne clé mono-partie rejetée). La phase 1 du test est locale (`--dev`) : **la vraie cérémonie exige de vraies personnes indépendantes** et un fichier Powers of Tau public. |
| Installeur / unité systemd | `install.sh` indépendant de la distribution (famille Debian : apt ; famille RHEL : dnf), utilisateur système dédié `zkvpn`, un seul changement système (`ip_forward`), pare-feu seulement s'il est déjà actif. | **Ubuntu 24.04 : oui, de bout en bout** (`tests/distro/run.sh`, systemd PID 1 dans un conteneur à réseau isolé). **Debian 12 et Fedora 41 : non exécutés** ici (miroirs de paquets bloqués par la politique réseau de l'environnement) ; ils sont dans la matrice CI. |
| Protection DNS | Backends `systemd-resolved` / `resolvconf` / `resolv.conf`, état persistant dans `/run/zkvpn` (le `disconnect` est un autre processus), DoT bloqué. | **Oui** sur réseau virtuel (backend `file`) ; les commandes `resolvectl` et `resolvconf` ne sont vérifiées que par tests unitaires. |
| Plusieurs clients | Isolation client-à-client par `ZKVPN_FWD`. | **Oui** (2 clients simultanés, le serveur joint les deux, ils ne se joignent pas). |
| IPv6 | Routes `::/1` + kill-switch `ip6tables`. | **Non vérifié ici** : le noyau de ce bac à sable n'a pas l'IPv6. Les tests existent et s'exécuteront en CI. |
| Audit externe | `SECURITY.md` : périmètre, hypothèses de confiance, ce qui est testé, plan d'audit. | Ne remplace pas un audit. |

Les tests ont été validés par **mutation** : supprimer l'isolation, le blocage DNS port 53 ou la restauration de `resolv.conf` fait échouer le test concerné.

**Défauts supplémentaires trouvés par ces bancs (tous corrigés)** :
- le client héritait de la clé privée du serveur quand les deux configurations coexistent sur la machine : même clé publique, et WireGuard ignore **silencieusement** le pair ;
- l'unité systemd ne démarrait pas : `/dev/net/tun` inaccessible (`0600` en conteneur), `/run/wireguard` non créable par l'utilisateur du service, erreurs de `wireguard-go` illisibles ;
- `disconnect` ne pouvait jamais restaurer le DNS (sauvegarde gardée en mémoire d'un autre processus) ;
- `main.py` plantait si `/etc/zkvpn/.env` (0600 root) n'était pas lisible par l'utilisateur du service ;
- `ceremony.sh verify` laissait un `trap RETURN` qui cassait `finalize`.

## Limites connues (non résolues)
1. **Aucune cérémonie réelle n'a eu lieu** : les clés livrées par `setup_circuits.sh` sont mono-partie. Tant qu'une cérémonie multipartite n'est pas faite avec des participants indépendants, quiconque a gardé l'entropie peut forger des preuves.
2. **Debian, Fedora, IPv6, `resolvectl`/`resolvconf`** : code écrit et testé unitairement, pas exécuté en conditions réelles ici.
3. **Machine physique** : tout a été testé sur réseau virtuel (namespaces + `wireguard-go`), pas avec le module noyau WireGuard ni sur une vraie carte réseau.
4. **Canal d'admission en clair** : données publiques uniquement, mais un attaquant réseau peut le bloquer ou le ralentir ; la vérification coûte ~0,7 s de CPU (bornée par des limites de connexions et un sémaphore).
5. **Liste blanche vide = toute identité valide est admise** (inscription ouverte). Renseigner `ZKVPN_AUTHORIZED_IDENTITIES` en production.
6. **Identité** : le fichier secret n'est pas chiffré (permissions 0600 seulement).
7. **Pas d'audit externe** : ne pas utiliser pour protéger des utilisateurs réels.
