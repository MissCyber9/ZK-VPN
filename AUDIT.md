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

## Corrigé dans ce commit (packaging et hygiène)
- `setup.py` n'était pas parsable (bloc orphelin) : réécrit ; entry points inexistants retirés ; auteur/URL corrigés.
- `requirements.txt` : ajout de `pydantic`, `pydantic-settings`, `numpy`, `humanize`, `pyperclip` ; retrait de `asyncio` et des dépendances inutilisées ; tests déplacés dans `requirements-dev.txt`.
- `install.sh` : chemin de clone (`zk-vpn-prototype/src` → `src`), `requirements.txt`, caractère non ASCII dans `tr`, fins de ligne CRLF (scripts non exécutables) ; README pointe vers `scripts/install.sh`.
- Retrait du dépôt de `egg-info`, `*:Zone.Identifier`, `Nouveau document texte.TXT`, `current_deps.txt` ; `.gitignore` complété.

## Reste à faire (par priorité)
1. Reformuler README (« no logging »/« ZK-SNARKs ») tant que la preuve est simulée.
2. Vrai SNARK (circom + snarkjs), circuit corrigé, vérification intégrée à l'établissement de session.
3. Durcissement réseau : kill-switch, `await` des commandes, capabilities systemd, validation des entrées, comparaison de versions Python dans `install.sh` (`bc` échoue sur `3.10`).
4. Tests fiables + CI, licence.
