#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  GP Connect — Script d'installation pour Ubuntu/GNOME
# ─────────────────────────────────────────────────────────────────────────────
set -e

APP_NAME="gp-connect"
APP_ID="com.gpconnect.app"

APP_DIR="$HOME/.local/share/$APP_NAME"
BIN_DIR="$HOME/.local/bin"
APP_DIR_APPS="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${GREEN}✔${NC}  $*"; }
warning() { echo -e "${YELLOW}⚠${NC}  $*"; }
error()   { echo -e "${RED}✘${NC}  $*"; exit 1; }
step()    { echo -e "\n${YELLOW}▶${NC}  $*"; }

# Vrai si le paquet Debian est installé (état "ii")
deb_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null \
        | grep -q "^install ok installed$"
}

# Installe via apt uniquement si le paquet n'est pas déjà présent.
# Usage : ensure_apt <pkg> [<pkg2>...]
ensure_apt() {
    local missing=()
    for p in "$@"; do
        deb_installed "$p" || missing+=("$p")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        warning "Paquets manquants : ${missing[*]} — installation…"
        sudo apt-get install -y "${missing[@]}"
    fi
}

# Installe le premier paquet d'une liste de candidats qui existe dans apt.
# Utile pour libwebkit2gtk-4.1-0 (Ubuntu 24.04+) vs 4.0-37 (anciennes).
# Usage : ensure_apt_any <pkg-preferred> [<pkg-fallback>...]
ensure_apt_any() {
    for p in "$@"; do
        if deb_installed "$p"; then return 0; fi
    done
    for p in "$@"; do
        if apt-cache show "$p" >/dev/null 2>&1; then
            warning "Installation de $p…"
            sudo apt-get install -y "$p" && return 0
        fi
    done
    warning "Aucun candidat installable parmi : $*"
    return 1
}

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║        GP Connect — Installation             ║"
echo "║   Client VPN GlobalProtect pour GNOME        ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Vérifications préalables ───────────────────────────────────────────────
step "Vérification des dépendances…"

# Python 3
if ! command -v python3 &>/dev/null; then
    error "Python 3 requis. Installez-le avec : sudo apt install python3"
fi
info "Python 3 : $(python3 --version)"

# Rafraîchir l'index apt (mode silencieux, échec non bloquant)
sudo apt-get update -qq >/dev/null 2>&1 || true

# openconnect + vpnc-scripts (binaire VPN)
ensure_apt openconnect vpnc-scripts
info "openconnect : $(openconnect --version 2>&1 | head -1)"

# GTK3 + PyGObject + Cairo bindings
# python3-gi-cairo est OBLIGATOIRE : sans lui GTK3 lève en boucle :
#   TypeError: Couldn't find foreign struct converter for 'cairo.Context'
ensure_apt python3-gi python3-gi-cairo python3-cairo gir1.2-gtk-3.0
info "GTK3 + Cairo bindings : OK"

# WebKit2GTK (fenêtre SAML intégrée)
# Ubuntu 24.04+ : 4.1 ; <= 22.04 : 4.0
if ! deb_installed gir1.2-webkit2-4.1 && ! deb_installed gir1.2-webkit2-4.0; then
    ensure_apt_any gir1.2-webkit2-4.1 gir1.2-webkit2-4.0 || \
        warning "WebKit2GTK indisponible — la WebView SAML intégrée sera désactivée"
fi
if ! deb_installed libwebkit2gtk-4.1-0 && ! deb_installed libwebkit2gtk-4.0-37; then
    ensure_apt_any libwebkit2gtk-4.1-0 libwebkit2gtk-4.0-37 || true
fi
info "WebKit2GTK : OK"

# AppIndicator (tray GNOME) — optionnel mais recommandé
ensure_apt gir1.2-ayatanaappindicator3-0.1
info "AppIndicator : OK"

# requests (HTTP)
ensure_apt python3-requests
info "Dépendances Python : OK"

# gp-saml-gui (utile uniquement en fallback ; le .deb le bundle dans /usr/share)
if ! command -v gp-saml-gui &>/dev/null; then
    warning "gp-saml-gui non trouvé dans PATH (optionnel pour install.sh local)."
    warning "Pour l'installer : pipx install \"git+https://github.com/dlenski/gp-saml-gui\" --system-site-packages"
else
    info "gp-saml-gui : $(gp-saml-gui --version 2>&1 | head -1 || echo 'présent')"
fi

# vpnc-script (chemin attendu par openconnect)
if [ ! -f /usr/share/vpnc-scripts/vpnc-script ]; then
    warning "vpnc-script introuvable dans /usr/share/vpnc-scripts/"
fi
info "vpnc-scripts : OK"

# ── 2. Patch gp-saml-gui ──────────────────────────────────────────────────────
step "Application du patch gp-saml-gui (support PAN-OS 10+)…"

GP_SAML_SRC=$(python3 -c "
import sys
paths = [
    '$HOME/.local/share/pipx/venvs/gp-saml-gui/lib/python3.13/site-packages/gp_saml_gui.py',
    '$HOME/.local/share/pipx/venvs/gp-saml-gui/lib/python3.12/site-packages/gp_saml_gui.py',
    '$HOME/.local/share/pipx/venvs/gp-saml-gui/lib/python3.11/site-packages/gp_saml_gui.py',
]
import os
for p in paths:
    if os.path.exists(p):
        print(p)
        break
" 2>/dev/null)

if [ -n "$GP_SAML_SRC" ] && [ -f "$GP_SAML_SRC" ]; then
    # Vérifier si le patch a déjà été appliqué
    if ! grep -q "_check_browser_cookies" "$GP_SAML_SRC"; then
        warning "Patch gp-saml-gui non appliqué. Veuillez exécuter le patch manuellement."
        warning "Le patch est nécessaire pour les serveurs PAN-OS 10+ (GP_SESSION_CK)."
    else
        info "gp-saml-gui déjà patché ✔"
    fi
else
    warning "Impossible de localiser gp_saml_gui.py"
fi

# ── 3. Création des dossiers ──────────────────────────────────────────────────
step "Création des dossiers…"
mkdir -p "$APP_DIR" "$BIN_DIR" "$APP_DIR_APPS" "$ICON_DIR"
info "Dossiers créés"

# ── 4. Installation des fichiers ──────────────────────────────────────────────
step "Copie des fichiers de l'application…"

cp "$SCRIPT_DIR/gp_connect.py" "$APP_DIR/gp_connect.py"
chmod +x "$APP_DIR/gp_connect.py"
info "Application copiée → $APP_DIR/gp_connect.py"

# Script HIP (rapport de conformité)
if [ -f "$SCRIPT_DIR/hipreport.py" ]; then
    cp "$SCRIPT_DIR/hipreport.py" "$APP_DIR/hipreport.py"
    chmod +x "$APP_DIR/hipreport.py"
    info "Script HIP copié → $APP_DIR/hipreport.py"
else
    warning "hipreport.py non trouvé dans $SCRIPT_DIR — rapport HIP désactivé"
fi

# Icône
if [ -f "$SCRIPT_DIR/data/$APP_ID.svg" ]; then
    cp "$SCRIPT_DIR/data/$APP_ID.svg" "$ICON_DIR/$APP_ID.svg"
    info "Icône copiée → $ICON_DIR/$APP_ID.svg"
    gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor/" 2>/dev/null || true
fi

# ── 5. Lanceur shell ──────────────────────────────────────────────────────────
step "Création du lanceur…"
cat > "$BIN_DIR/$APP_NAME" << LAUNCHER
#!/usr/bin/env bash
exec python3 "\$HOME/.local/share/$APP_NAME/gp_connect.py" "\$@"
LAUNCHER
chmod +x "$BIN_DIR/$APP_NAME"
info "Lanceur créé → $BIN_DIR/$APP_NAME"

# ── 6. Fichier .desktop ───────────────────────────────────────────────────────
step "Création du fichier .desktop…"
cat > "$APP_DIR_APPS/$APP_ID.desktop" << DESKTOP
[Desktop Entry]
Type=Application
Version=1.0
Name=GP Connect
Comment=Client VPN GlobalProtect pour GNOME (OpenConnect + SAML)
Exec=$BIN_DIR/$APP_NAME
Icon=$APP_ID
Categories=Network;VPN;
Keywords=GlobalProtect;VPN;Palo Alto;OpenConnect;SAML;SSO;
StartupNotify=true
StartupWMClass=gp-connect
DESKTOP

update-desktop-database "$APP_DIR_APPS" 2>/dev/null || true
info "Fichier .desktop créé"

# ── 7. Épinglage dans le dock GNOME ───────────────────────────────────────────
step "Mise à jour du dock GNOME…"
if command -v gsettings &>/dev/null; then
    FAVORITES=$(gsettings get org.gnome.shell favorite-apps 2>/dev/null || echo "[]")

    if echo "$FAVORITES" | grep -q "$APP_ID.desktop"; then
        info "Déjà épinglé dans le dock"
    else
        # Remplacer gp-saml-gui.desktop si présent, sinon ajouter
        if echo "$FAVORITES" | grep -q "gp-saml-gui.desktop"; then
            NEW_FAV=$(echo "$FAVORITES" | sed "s|'gp-saml-gui.desktop'|'$APP_ID.desktop'|")
        else
            NEW_FAV=$(echo "$FAVORITES" | sed "s|]|, '$APP_ID.desktop']|")
        fi
        gsettings set org.gnome.shell favorite-apps "$NEW_FAV"
        info "Application épinglée dans le dock"
    fi
else
    warning "gsettings non disponible — épinglage manuel requis"
fi

# ── 8. Résumé ─────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║         ✅  Installation terminée !          ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  Lancer l'application :"
echo "    • Via le dock GNOME : icône 'GP Connect'"
echo "    • En ligne de commande : gp-connect"
echo ""
echo "  Configuration initiale :"
echo "    1. Ouvrir GP Connect"
echo "    2. Cliquer sur ⚙ Paramètres"
echo "    3. Renseigner le serveur VPN (ex: vpn.company.com)"
echo "    4. Cliquer sur 'Se connecter'"
echo ""
