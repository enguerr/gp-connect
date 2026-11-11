#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP_NAME="gp-connect"
APP_ID="com.gpconnect.app"
PKG_NAME="gp-connect"
ARCH="$(dpkg --print-architecture)"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(python3 - <<'PY'
import re
from pathlib import Path
txt = Path('gp_connect.py').read_text(encoding='utf-8', errors='ignore')
m = re.search(r"APP_VERSION\s*=\s*'([^']+)'", txt)
print(m.group(1) if m else "1.0.0")
PY
)"
fi

for cmd in python3 git dpkg-deb install; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "✘ $cmd est requis. Lancez : ./install.sh --deps" >&2
    exit 1
  }
done

BUILD_DIR="$SCRIPT_DIR/build/deb"
VENDOR_SRC="$SCRIPT_DIR/build/gp-saml-gui-src"
PKG_ROOT="$BUILD_DIR/${PKG_NAME}_${VERSION}_${ARCH}"
DIST_DIR="$SCRIPT_DIR/dist"
VENDOR_DST="$PKG_ROOT/usr/share/$APP_NAME/vendor/gp-saml-gui"

echo "==> Build .deb ${PKG_NAME} ${VERSION} (${ARCH})"
rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT/DEBIAN" \
         "$PKG_ROOT/usr/bin" \
         "$PKG_ROOT/usr/share/$APP_NAME" \
         "$VENDOR_DST" \
         "$PKG_ROOT/usr/share/applications" \
         "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps"

install -m 0755 gp_connect.py "$PKG_ROOT/usr/share/$APP_NAME/gp_connect.py"
install -m 0755 hipreport.py "$PKG_ROOT/usr/share/$APP_NAME/hipreport.py"
install -m 0644 "data/${APP_ID}.svg" \
  "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps/${APP_ID}.svg"

# Bundle gp-saml-gui (fallback SAML si WebKit2 crash). Cache dans build/.
if [ ! -f "$VENDOR_SRC/gp_saml_gui.py" ]; then
  echo "==> Téléchargement de gp-saml-gui…"
  rm -rf "$VENDOR_SRC"
  git clone --depth 1 https://github.com/dlenski/gp-saml-gui.git "$VENDOR_SRC"
fi
install -m 0644 "$VENDOR_SRC/gp_saml_gui.py" "$VENDOR_DST/gp_saml_gui.py"
if [ -f "$VENDOR_SRC/LICENSE" ]; then
  install -m 0644 "$VENDOR_SRC/LICENSE" "$VENDOR_DST/LICENSE"
fi

cat > "$VENDOR_DST/gp-saml-gui" <<'EOF'
#!/usr/bin/env bash
exec python3 -c "import os,sys; sys.path.insert(0, '/usr/share/gp-connect/vendor/gp-saml-gui'); from gp_saml_gui import main; raise SystemExit(main())" "$@"
EOF
chmod 0755 "$VENDOR_DST/gp-saml-gui"

cat > "$PKG_ROOT/usr/bin/$APP_NAME" <<'EOF'
#!/usr/bin/env bash
exec python3 /usr/share/gp-connect/gp_connect.py "$@"
EOF
chmod 0755 "$PKG_ROOT/usr/bin/$APP_NAME"

cat > "$PKG_ROOT/usr/bin/gp-connect-uninstall" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--help" ]; then
  echo "Usage: gp-connect-uninstall"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
  exec sudo "$0" "$@"
fi
apt-get remove --purge -y gp-connect || dpkg -r gp-connect || true
rm -f /etc/sudoers.d/gp-connect || true
echo "GP Connect désinstallé."
EOF
chmod 0755 "$PKG_ROOT/usr/bin/gp-connect-uninstall"

cat > "$PKG_ROOT/usr/share/applications/${APP_ID}.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=GP Connect VPN
Comment=Client VPN GlobalProtect pour GNOME (OpenConnect + SAML)
Exec=/usr/bin/${APP_NAME}
Icon=${APP_ID}
Categories=Network;VPN;
Keywords=GlobalProtect;VPN;Palo Alto;OpenConnect;SAML;SSO;
StartupNotify=true
StartupWMClass=gp-connect
Terminal=false
EOF

cat > "$PKG_ROOT/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: GP Connect contributors <noreply@example.com>
Depends: python3, python3-gi, python3-gi-cairo, python3-cairo, python3-requests, python3-urllib3, gir1.2-gtk-3.0, gir1.2-webkit2-4.1 | gir1.2-webkit2-4.0, gir1.2-ayatanaappindicator3-0.1, gir1.2-secret-1, openconnect, vpnc-scripts, iproute2, procps, xdg-utils, pkexec | policykit-1, ca-certificates, bind9-dnsutils | dnsutils
Description: Client VPN GlobalProtect pour GNOME (OpenConnect + SAML)
 Application GTK3 pour se connecter aux VPN Palo Alto GlobalProtect avec SSO/SAML.
EOF

cat > "$PKG_ROOT/DEBIAN/postinst" <<'EOF'
#!/usr/bin/env bash
set -e
update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true

deb_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "^install ok installed$"
}
for p in python3-gi python3-gi-cairo python3-cairo gir1.2-gtk-3.0 openconnect; do
  if ! deb_installed "$p"; then
    echo "⚠ Dépendance manquante : $p" >&2
    echo "   Exécutez : sudo apt-get install -f" >&2
  fi
done
if ! deb_installed gir1.2-webkit2-4.1 && ! deb_installed gir1.2-webkit2-4.0; then
  echo "⚠ WebKit2GTK absent — la WebView SAML intégrée sera désactivée." >&2
  echo "   Pour l'activer : sudo apt-get install gir1.2-webkit2-4.1" >&2
fi

TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] && [ -n "${PKEXEC_UID:-}" ]; then
  TARGET_USER="$(getent passwd "$PKEXEC_UID" | cut -d: -f1 || true)"
fi
if [ -n "$TARGET_USER" ]; then
  USER_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6 || true)"
  if [ -n "$USER_HOME" ] && [ -f "$USER_HOME/.local/bin/gp-connect" ]; then
    if grep -q "\.local/share/gp-connect/gp_connect.py" "$USER_HOME/.local/bin/gp-connect"; then
      mv "$USER_HOME/.local/bin/gp-connect" "$USER_HOME/.local/bin/gp-connect.local-disabled-by-deb" || true
      echo "Ancien lanceur local désactivé: $USER_HOME/.local/bin/gp-connect.local-disabled-by-deb"
    fi
  fi
  if [ -f "$USER_HOME/.local/share/applications/com.gpconnect.app.desktop" ]; then
    if grep -q "\.local/bin/gp-connect" "$USER_HOME/.local/share/applications/com.gpconnect.app.desktop"; then
      mv "$USER_HOME/.local/share/applications/com.gpconnect.app.desktop" \
         "$USER_HOME/.local/share/applications/com.gpconnect.app.desktop.local-disabled-by-deb" || true
      echo "Ancien desktop local désactivé: $USER_HOME/.local/share/applications/com.gpconnect.app.desktop.local-disabled-by-deb"
    fi
  fi
fi

echo "GP Connect installé."
EOF
chmod 0755 "$PKG_ROOT/DEBIAN/postinst"

cat > "$PKG_ROOT/DEBIAN/postrm" <<'EOF'
#!/usr/bin/env bash
set -e
if [ "$1" = "purge" ]; then
  rm -f /etc/sudoers.d/gp-connect || true
fi
update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true
EOF
chmod 0755 "$PKG_ROOT/DEBIAN/postrm"

mkdir -p "$DIST_DIR"
dpkg-deb --build --root-owner-group "$PKG_ROOT" >/dev/null
mv "$PKG_ROOT.deb" "$DIST_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

echo "✅ Package créé : $DIST_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
