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

## Limites connues (non résolues)
1. **Cérémonie de confiance mono-partie** : quiconque a gardé l'entropie du setup local peut forger des preuves. Production : cérémonie multipartite (phase 1 publique + phase 2 dédiée).
2. **Aucun test sur machine réelle** du kill-switch (iptables), de l'unité systemd, de `install.sh` de bout en bout : seuls la construction des règles, le rollback, la syntaxe shell et le protocole d'admission (TCP réel, preuves réelles) sont testés.
3. **Canal d'admission en clair** : il ne transporte que des données publiques, mais un attaquant réseau peut bloquer ou ralentir l'admission (déni de service), et la vérification de preuve coûte du CPU (borné par un sémaphore de 8).
4. **Liste blanche vide = toute identité valide est admise** (inscription ouverte, sybil possible). Renseigner `ZKVPN_AUTHORIZED_IDENTITIES` en production.
5. **Identité** : le fichier secret n'est pas chiffré (protégé seulement par les permissions 0600).
6. Pas d'audit externe : ne pas utiliser pour protéger des utilisateurs réels.
