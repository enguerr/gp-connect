# GP Connect - Packaging & Release

Ce document explique comment produire un paquet Debian publiable et comment désinstaller proprement.

## Prérequis

- Ubuntu/Debian avec `dpkg-deb`
- Dépendances projet déjà présentes (voir `install.sh`)

## Build du package `.deb`

Depuis la racine du projet:

```bash
cd gp-connect
./build_deb.sh
```

Le paquet est généré dans:

```bash
dist/gp-connect_<version>_<arch>.deb
```

Pour forcer une version:

```bash
./build_deb.sh 1.0.1
```

## Installation du `.deb`

```bash
sudo apt install ./dist/gp-connect_<version>_<arch>.deb
```

## Désinstallation

### Si installé via `.deb`

```bash
gp-connect-uninstall
```

ou:

```bash
sudo apt remove --purge gp-connect
```

### Si installé via `install.sh` (mode local utilisateur)

```bash
./uninstall.sh
```

## Publication (release)

Workflow conseillé:

1. Mettre à jour `APP_VERSION` dans `gp_connect.py`
2. Générer le package: `./build_deb.sh`
3. Vérifier installation/désinstallation sur une machine de test
4. Publier le `.deb` du dossier `dist/`
5. Publier un checksum:

```bash
cd dist
sha256sum gp-connect_*.deb > SHA256SUMS
```
