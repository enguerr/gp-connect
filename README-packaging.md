# GP Connect - Packaging & Release

## Installation complète (recommandé)

```bash
./install.sh
```

Le script installe les dépendances runtime et de build, construit le `.deb`
dans `dist/`, puis l'installe via `apt`.

| Commande | Effet |
|----------|--------|
| `./install.sh` | dépendances + build + installation |
| `./install.sh --deps` | paquets système uniquement |
| `./install.sh --build` | dépendances + `.deb` |
| `./install.sh --install` | installe le `.deb` déjà présent dans `dist/` |
| `./install.sh --local` | copie dans `~/.local` sans paquet |

## Build seul

Prérequis : `./install.sh --deps` (git, dpkg-deb, OpenConnect, GTK, …).

```bash
./build_deb.sh          # version lue dans APP_VERSION
./build_deb.sh 3.5.1    # version forcée
```

Le paquet est généré dans `dist/gp-connect_<version>_<arch>.deb`.
`gp-saml-gui` est cloné une fois dans `build/gp-saml-gui-src/` (dossier ignoré par git).

## Installation manuelle du `.deb`

```bash
sudo apt install ./dist/gp-connect_<version>_<arch>.deb
```

## Désinstallation

Paquet Debian :

```bash
gp-connect-uninstall
# ou
sudo apt remove --purge gp-connect
```

Installation `--local` :

```bash
./uninstall.sh
```

## Publication (release)

1. Mettre à jour `APP_VERSION` dans `gp_connect.py`
2. `./install.sh --build`
3. Vérifier installation / désinstallation sur une machine de test
4. Publier le `.deb` de `dist/` (pas le dossier `build/`)
5. Checksum :

```bash
cd dist
sha256sum gp-connect_*.deb > SHA256SUMS
```
