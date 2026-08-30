#!/usr/bin/env bash
set -euo pipefail

APP_NAME="gp-connect"
APP_ID="com.gpconnect.app"

APP_DIR="$HOME/.local/share/$APP_NAME"
BIN_FILE="$HOME/.local/bin/$APP_NAME"
DESKTOP_FILE="$HOME/.local/share/applications/$APP_ID.desktop"
ICON_FILE="$HOME/.local/share/icons/hicolor/scalable/apps/$APP_ID.svg"
SUDOERS_FILE="/etc/sudoers.d/gp-connect"

echo "==> Désinstallation locale de GP Connect"

rm -f "$BIN_FILE"
rm -f "$DESKTOP_FILE"
rm -f "$ICON_FILE"
rm -rf "$APP_DIR"

# Retirer du dock GNOME si présent
if command -v gsettings >/dev/null 2>&1; then
  FAVS="$(gsettings get org.gnome.shell favorite-apps 2>/dev/null || echo "[]")"
  if echo "$FAVS" | grep -q "$APP_ID.desktop"; then
    NEW_FAVS="$(echo "$FAVS" | sed "s|'$APP_ID.desktop', ||; s|, '$APP_ID.desktop'||; s|'$APP_ID.desktop'||")"
    gsettings set org.gnome.shell favorite-apps "$NEW_FAVS" || true
  fi
fi

# Supprimer la règle sudoers créée par GP Connect (optionnel)
if [ -f "$SUDOERS_FILE" ]; then
  echo "==> Suppression de la règle sudoers ($SUDOERS_FILE)"
  if command -v pkexec >/dev/null 2>&1; then
    pkexec rm -f "$SUDOERS_FILE" || true
  else
    echo "pkexec absent. Supprimez manuellement avec : sudo rm -f $SUDOERS_FILE"
  fi
fi

echo "✅ Désinstallation terminée."
