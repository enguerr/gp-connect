#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  GP Connect — Installation (dépendances + paquet .deb)
# ─────────────────────────────────────────────────────────────────────────────
#  Usage :
#    ./install.sh              installe les dépendances, construit et installe le .deb
#    ./install.sh --deps       dépendances système uniquement
#    ./install.sh --build      dépendances + construction du .deb
#    ./install.sh --install    installe le .deb déjà présent dans dist/
#    ./install.sh --local      copie utilisateur (~/.local) sans paquet
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

APP_NAME="gp-connect"
APP_ID="com.gpconnect.app"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${GREEN}✔${NC}  $*"; }
warning() { echo -e "${YELLOW}⚠${NC}  $*"; }
error()   { echo -e "${RED}✘${NC}  $*" >&2; exit 1; }
step()    { echo -e "\n${YELLOW}▶${NC}  $*"; }

usage() {
    cat <<'EOF'
Usage: ./install.sh [option]

  (aucune)      Installe les dépendances, construit le .deb et l'installe
  --deps        Installe uniquement les paquets système (runtime + build)
  --build       Dépendances + construction du .deb (sans l'installer)
  --install     Installe le .deb déjà généré dans dist/
  --local       Installation utilisateur (~/.local) sans paquet Debian
  --help        Affiche cette aide
EOF
}

MODE="all"
for arg in "$@"; do
    case "$arg" in
        --deps)    MODE="deps" ;;
        --build)   MODE="build" ;;
        --install) MODE="install" ;;
        --local)   MODE="local" ;;
        --help|-h) usage; exit 0 ;;
        *) error "Option inconnue : $arg (voir --help)" ;;
    esac
done

need_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    fi
    if ! command -v sudo >/dev/null 2>&1; then
        error "sudo est requis pour installer les paquets."
    fi
}

as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

deb_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null \
        | grep -q "^install ok installed$"
}

ensure_apt() {
    local missing=()
    local p
    for p in "$@"; do
        deb_installed "$p" || missing+=("$p")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        warning "Paquets manquants : ${missing[*]} — installation…"
        as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
    fi
}

ensure_apt_any() {
    local p
    for p in "$@"; do
        if deb_installed "$p"; then
            return 0
        fi
    done
    for p in "$@"; do
        if apt-cache show "$p" >/dev/null 2>&1; then
            warning "Installation de $p…"
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$p"
            return 0
        fi
    done
    warning "Aucun candidat installable parmi : $*"
    return 1
}

app_version() {
    python3 - <<'PY'
import re
from pathlib import Path
txt = Path('gp_connect.py').read_text(encoding='utf-8', errors='ignore')
m = re.search(r"APP_VERSION\s*=\s*'([^']+)'", txt)
print(m.group(1) if m else "0.0.0")
PY
}

latest_deb() {
    local f
    f="$(ls -1t dist/${APP_NAME}_*.deb 2>/dev/null | head -1 || true)"
    [ -n "$f" ] || return 1
    printf '%s' "$f"
}

install_runtime_deps() {
    step "Installation des dépendances d'exécution…"

    if ! command -v python3 >/dev/null 2>&1; then
        ensure_apt python3
    fi
    info "Python 3 : $(python3 --version)"

    ensure_apt \
        python3 \
        python3-gi \
        python3-gi-cairo \
        python3-cairo \
        python3-requests \
        python3-urllib3 \
        gir1.2-gtk-3.0 \
        gir1.2-ayatanaappindicator3-0.1 \
        gir1.2-secret-1 \
        openconnect \
        vpnc-scripts \
        iproute2 \
        procps \
        xdg-utils \
        ca-certificates

    ensure_apt_any pkexec policykit-1 || \
        warning "pkexec absent — la règle sudoers devra être créée à la main"
    ensure_apt_any bind9-dnsutils dnsutils || \
        warning "dig/host absents — la détection LAN utilisera le fallback UDP"

    if ! deb_installed gir1.2-webkit2-4.1 && ! deb_installed gir1.2-webkit2-4.0; then
        ensure_apt_any gir1.2-webkit2-4.1 gir1.2-webkit2-4.0 || \
            warning "WebKit2GTK indisponible — la WebView SAML sera désactivée"
    fi
    if ! deb_installed libwebkit2gtk-4.1-0 && ! deb_installed libwebkit2gtk-4.0-37; then
        ensure_apt_any libwebkit2gtk-4.1-0 libwebkit2gtk-4.0-37 || true
    fi

    if [ ! -f /usr/share/vpnc-scripts/vpnc-script ]; then
        warning "vpnc-script introuvable dans /usr/share/vpnc-scripts/"
    fi
    info "Dépendances d'exécution : OK"
}

install_build_deps() {
    step "Installation des dépendances de construction…"
    ensure_apt git ca-certificates dpkg-dev
    command -v dpkg-deb >/dev/null 2>&1 || error "dpkg-deb introuvable."
    command -v git >/dev/null 2>&1 || error "git introuvable."
    info "Dépendances de construction : OK"
}

refresh_apt() {
    step "Mise à jour de l'index apt…"
    as_root apt-get update -qq >/dev/null 2>&1 || \
        warning "apt-get update a échoué — on continue avec le cache local"
}

build_package() {
    step "Construction du paquet Debian…"
    "$SCRIPT_DIR/build_deb.sh"
    local deb
    deb="$(latest_deb)" || error "Aucun .deb généré dans dist/"
    info "Paquet : $deb"
}

install_package() {
    local deb
    deb="$(latest_deb)" || error \
        "Aucun .deb dans dist/. Lancez d'abord : ./install.sh --build"
    step "Installation de $deb…"
    as_root apt-get install -y "./$deb"
    info "GP Connect $(app_version) installé"
}

install_local() {
    local app_dir bin_dir apps_dir icon_dir
    app_dir="$HOME/.local/share/$APP_NAME"
    bin_dir="$HOME/.local/bin"
    apps_dir="$HOME/.local/share/applications"
    icon_dir="$HOME/.local/share/icons/hicolor/scalable/apps"

    step "Installation locale (sans paquet)…"
    mkdir -p "$app_dir" "$bin_dir" "$apps_dir" "$icon_dir"

    install -m 0755 "$SCRIPT_DIR/gp_connect.py" "$app_dir/gp_connect.py"
    install -m 0755 "$SCRIPT_DIR/hipreport.py" "$app_dir/hipreport.py"
    if [ -f "$SCRIPT_DIR/data/$APP_ID.svg" ]; then
        install -m 0644 "$SCRIPT_DIR/data/$APP_ID.svg" "$icon_dir/$APP_ID.svg"
        gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor/" 2>/dev/null || true
    fi

    # Fallback SAML : bundle local de gp-saml-gui
    if [ ! -f "$app_dir/vendor/gp-saml-gui/gp_saml_gui.py" ]; then
        mkdir -p "$app_dir/vendor/gp-saml-gui"
        if [ -f "$SCRIPT_DIR/build/gp-saml-gui-src/gp_saml_gui.py" ]; then
            cp "$SCRIPT_DIR/build/gp-saml-gui-src/gp_saml_gui.py" \
               "$app_dir/vendor/gp-saml-gui/"
        elif command -v git >/dev/null 2>&1; then
            git clone --depth 1 https://github.com/dlenski/gp-saml-gui.git \
                "$app_dir/vendor/gp-saml-gui-src"
            cp "$app_dir/vendor/gp-saml-gui-src/gp_saml_gui.py" \
               "$app_dir/vendor/gp-saml-gui/"
            rm -rf "$app_dir/vendor/gp-saml-gui-src"
        fi
        if [ -f "$app_dir/vendor/gp-saml-gui/gp_saml_gui.py" ]; then
            cat > "$app_dir/vendor/gp-saml-gui/gp-saml-gui" <<EOF
#!/usr/bin/env bash
exec python3 -c "import os,sys; sys.path.insert(0, '$app_dir/vendor/gp-saml-gui'); from gp_saml_gui import main; raise SystemExit(main())" "\$@"
EOF
            chmod 0755 "$app_dir/vendor/gp-saml-gui/gp-saml-gui"
        fi
    fi

    cat > "$bin_dir/$APP_NAME" <<LAUNCHER
#!/usr/bin/env bash
exec python3 "\$HOME/.local/share/$APP_NAME/gp_connect.py" "\$@"
LAUNCHER
    chmod +x "$bin_dir/$APP_NAME"

    cat > "$apps_dir/$APP_ID.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Version=1.0
Name=GP Connect
Comment=Client VPN GlobalProtect pour GNOME (OpenConnect + SAML)
Exec=$bin_dir/$APP_NAME
Icon=$APP_ID
Categories=Network;VPN;
Keywords=GlobalProtect;VPN;Palo Alto;OpenConnect;SAML;SSO;
StartupNotify=true
StartupWMClass=gp-connect
DESKTOP
    update-desktop-database "$apps_dir" 2>/dev/null || true
    info "Installé dans $app_dir — lanceur : $bin_dir/$APP_NAME"
}

print_done() {
    echo ""
    echo "╔══════════════════════════════════════════════╗"
    echo "║         Installation terminée                ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""
    echo "  Lancer :  gp-connect"
    echo "  ou via le menu d'applications : GP Connect VPN"
    echo ""
    echo "  1. Ouvrir GP Connect"
    echo "  2. Cliquer sur ⚙ Paramètres"
    echo "  3. Renseigner le serveur VPN (ex. vpn.company.com)"
    echo "  4. Autoriser openconnect sans mot de passe si demandé"
    echo "  5. Se connecter"
    echo ""
}

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║        GP Connect — Installation             ║"
echo "║   Client VPN GlobalProtect pour GNOME        ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

need_sudo
refresh_apt

case "$MODE" in
    deps)
        install_runtime_deps
        install_build_deps
        info "Dépendances installées."
        ;;
    build)
        install_runtime_deps
        install_build_deps
        build_package
        ;;
    install)
        install_runtime_deps
        install_package
        print_done
        ;;
    local)
        install_runtime_deps
        install_build_deps
        install_local
        print_done
        ;;
    all)
        install_runtime_deps
        install_build_deps
        build_package
        install_package
        print_done
        ;;
esac
