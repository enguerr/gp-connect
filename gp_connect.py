#!/usr/bin/env python3
"""
GP Connect - Client VPN GlobalProtect pour Ubuntu/GNOME
Version 1.9.0

Application GTK3 qui intègre :
- Authentification SAML/SSO via gp-saml-gui (patché)
- Sélection de gateway
- Connexion via openconnect
- Gestion d'état et logs
"""

APP_ID      = 'com.gpconnect.app'
APP_VERSION = '3.5.1'

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Gio, Gdk, Pango
try:
    gi.require_version('AyatanaAppIndicator3', '0.1')
    from gi.repository import AyatanaAppIndicator3 as AppIndicator3
    HAS_APPINDICATOR = True
except Exception:
    try:
        gi.require_version('AppIndicator3', '0.1')
        from gi.repository import AppIndicator3  # type: ignore
        HAS_APPINDICATOR = True
    except Exception:
        AppIndicator3 = None
        HAS_APPINDICATOR = False

WebKit2 = None
HAS_WEBKIT2 = False
_webkit2_checked = False


def _ensure_webkit2():
    """Charge WebKit2 à la demande (évite les crashs SIGABRT au démarrage)."""
    global WebKit2, HAS_WEBKIT2, _webkit2_checked
    if _webkit2_checked:
        return HAS_WEBKIT2
    _webkit2_checked = True
    try:
        gi.require_version('WebKit2', '4.1')
        from gi.repository import WebKit2 as _W2
        WebKit2 = _W2
        HAS_WEBKIT2 = True
    except Exception:
        try:
            gi.require_version('WebKit2', '4.0')
            from gi.repository import WebKit2 as _W2
            WebKit2 = _W2
            HAS_WEBKIT2 = True
        except Exception:
            pass
    return HAS_WEBKIT2

import collections
import configparser
import ipaddress
import json
import time as _time_mod
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import requests
import stat
import xml.etree.ElementTree as ET
from base64 import b64decode
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote, quote
from pathlib import Path

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────

_bundled_gp_saml = Path('/usr/share/gp-connect/vendor/gp-saml-gui/gp-saml-gui')
_bundled_dev_gp_saml = (Path(__file__).resolve().parent /
                        'vendor/gp-saml-gui/gp-saml-gui')
GP_SAML_GUI = (
    os.environ.get('GP_SAML_GUI')
    or (str(_bundled_gp_saml) if _bundled_gp_saml.exists() else None)
    or (str(_bundled_dev_gp_saml) if _bundled_dev_gp_saml.exists() else None)
    or shutil.which('gp-saml-gui')
)

def resolve_gp_saml_gui():
    """Résout dynamiquement le binaire gp-saml-gui.

    Priorité:
      1) variable d'env GP_SAML_GUI (si chemin existant/exécutable)
      2) binaire bundle du paquet (/usr/share/gp-connect/vendor/...)
      3) binaire bundle local (dev)
      4) binaire dans PATH
    """
    cand = os.environ.get('GP_SAML_GUI')
    if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    for bundled in (_bundled_gp_saml, _bundled_dev_gp_saml):
        if bundled.is_file() and os.access(str(bundled), os.X_OK):
            return str(bundled)
    p = shutil.which('gp-saml-gui')
    if p:
        return p
    return ''

CONFIG_DIR  = Path.home() / '.config' / 'gp-connect'
CONFIG_FILE = CONFIG_DIR / 'config.json'
# Nom conservé pour la compat avec anciennes installations ; le contenu
# est un JSON (chmod 0600). Le keyring libsecret (GNOME Keyring/KWallet)
# est désormais le stockage PRINCIPAL — le fichier ne sert que de cache
# local de survie en cas d'indisponibilité du keyring (ex. session sans
# unlock automatique).
_TOKEN_FILE  = CONFIG_DIR / '.session.enc'
_TOKEN_SCHEMA = 'com.gpconnect.session'
# Durée de vie max d'un token réutilisable côté serveur (~23 h).
# Au-delà, on considère le refresh token comme expiré et on force SAML.
_TOKEN_MAX_AGE = 82800
# Durée de vie d'un access one-shot type prelogin-cookie : très courte,
# 15 min côté PAN-OS. Sert juste à éviter de tenter un cookie déjà périmé
# au démarrage suivant immédiat.
_ACCESS_MAX_AGE = 900
# Champs de cookies considérés comme RÉUTILISABLES (peuvent servir de
# refresh token car le serveur les accepte plusieurs fois) :
_REFRESH_FIELDS = ('portal-userauthcookie', 'authcookie')
# Champs ONE-SHOT (consommés à la première utilisation par openconnect) :
_ONESHOT_FIELDS = ('prelogin-cookie', 'portal-prelogonuserauthcookie')

# ─────────────────────────────────────────────
#  Secure token storage
#
#  Stockage multi-serveurs :
#    { "v": 2, "sessions": { "<server>": { "cookie_field":..., ... } } }
#
#  Emplacements :
#    • ~/.config/gp-connect/.session.enc   (JSON, chmod 0600 — principal)
#    • libsecret / GNOME Keyring / KWallet (chiffré par l'OS — fallback)
#    • ~/.config/gp-connect/.vpn_state.json (état tunnel, survie aux MAJ)
# ─────────────────────────────────────────────


_DMI_UUID_CACHE = None  # mémorisation après 1er accès réussi


def _get_dmi_machine_uuid():
    """Retourne l'UUID DMI/SMBIOS de la machine (host-id Palo Alto).

    Format attendu : 4c4c4544-004a-5710-8053-c8c04f383734
    Priorité :
      1. /sys/class/dmi/id/product_uuid    (root requis)
      2. sudo -n cat /sys/class/dmi/...     (non-bloquant, OK si NOPASSWD)
      3. dmidecode -s system-uuid           (root requis)
      4. /etc/machine-id reformaté         (stable, accessible non-root)
      5. /var/lib/dbus/machine-id
      6. UUID aléatoire                     (dernier recours, instable)
    """
    global _DMI_UUID_CACHE
    if _DMI_UUID_CACHE:
        return _DMI_UUID_CACHE
    import uuid as _uuid

    def _valid(s):
        s = (s or '').strip().lower()
        return s if (len(s) == 36 and s.count('-') == 4) else None

    # 1) Lecture directe
    try:
        with open('/sys/class/dmi/id/product_uuid') as f:
            v = _valid(f.read())
        if v:
            _DMI_UUID_CACHE = v
            return v
    except Exception:
        pass

    # 2) sudo -n cat — ne bloque pas si pas d'autorisation
    try:
        out = subprocess.check_output(
            ['sudo', '-n', 'cat', '/sys/class/dmi/id/product_uuid'],
            text=True, stderr=subprocess.DEVNULL, timeout=3)
        v = _valid(out)
        if v:
            _DMI_UUID_CACHE = v
            return v
    except Exception:
        pass

    # 3) dmidecode
    for cmd in (['dmidecode', '-s', 'system-uuid'],
                ['sudo', '-n', 'dmidecode', '-s', 'system-uuid']):
        try:
            out = subprocess.check_output(
                cmd, text=True, stderr=subprocess.DEVNULL, timeout=3)
            v = _valid(out)
            if v:
                _DMI_UUID_CACHE = v
                return v
        except Exception:
            pass

    # 4-5) machine-id (32 hex sans tirets → reformaté)
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path) as f:
                mid = f.read().strip().lower()
            if len(mid) == 32:
                v = (f'{mid[:8]}-{mid[8:12]}-{mid[12:16]}'
                     f'-{mid[16:20]}-{mid[20:]}')
                _DMI_UUID_CACHE = v
                return v
            v = _valid(mid)
            if v:
                _DMI_UUID_CACHE = v
                return v
        except Exception:
            pass

    # 6) Dernier recours (non mis en cache — change à chaque appel)
    return str(_uuid.uuid4())


def _read_token_file():
    """Retourne le document complet du fichier token (dict) ou None."""
    if not _TOKEN_FILE.is_file():
        return None
    try:
        raw = _TOKEN_FILE.read_text().strip()
        if not raw:
            return None
        doc = json.loads(raw)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    # Migration ancien format (mono-serveur, dict plat avec 'server')
    if 'sessions' not in doc and 'server' in doc:
        doc = {'v': 2, 'sessions': {doc['server']: doc}}
    return doc


def _write_token_file(doc, log_fn=None):
    _log = log_fn or (lambda m: None)
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # Écriture atomique pour éviter corruption en cas de crash
        tmp = _TOKEN_FILE.with_suffix(_TOKEN_FILE.suffix + '.tmp')
        with open(tmp, 'w') as f:
            json.dump(doc, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, _TOKEN_FILE)
        return True
    except Exception as e:
        _log(f'  [Token] Écriture fichier erreur : {e}')
        return False


def _keyring_store_sync(server, payload_json, log_fn=None):
    """Stocke le token dans le keyring libsecret de façon synchrone.

    Retourne True si l'écriture a réussi, False sinon. Synchrone car le
    keyring est désormais le stockage canonique : on veut savoir tout de
    suite si on tombe sur un fallback fichier.
    """
    _log = log_fn or (lambda m: None)
    try:
        gi.require_version('Secret', '1')
        from gi.repository import Secret
        schema = Secret.Schema.new(
            _TOKEN_SCHEMA,
            Secret.SchemaFlags.NONE,
            {'server': Secret.SchemaAttributeType.STRING})
        Secret.password_store_sync(
            schema, {'server': server},
            Secret.COLLECTION_DEFAULT,
            f'GP Connect - {server}',
            payload_json, None)
        _log(f'  [Token] Keyring OK ({server})')
        return True
    except Exception as e:
        _log(f'  [Token] Keyring indisponible ({e})')
        return False


def _keyring_store_async(server, payload_json, log_fn=None):
    """Variante non-bloquante (legacy) : utilise un thread."""
    threading.Thread(
        target=_keyring_store_sync,
        args=(server, payload_json),
        kwargs={'log_fn': log_fn},
        daemon=True,
    ).start()


def _keyring_lookup(server, log_fn=None):
    _log = log_fn or (lambda m: None)
    try:
        gi.require_version('Secret', '1')
        from gi.repository import Secret
        schema = Secret.Schema.new(
            _TOKEN_SCHEMA,
            Secret.SchemaFlags.NONE,
            {'server': Secret.SchemaAttributeType.STRING})
        attrs = {'server': server} if server else {}
        raw = Secret.password_lookup_sync(schema, attrs, None)
        return raw
    except Exception as e:
        _log(f'  [Token] Keyring lecture indisponible ({e})')
        return None


def _keyring_clear(server=None, log_fn=None):
    _log = log_fn or (lambda m: None)
    try:
        gi.require_version('Secret', '1')
        from gi.repository import Secret
        schema = Secret.Schema.new(
            _TOKEN_SCHEMA,
            Secret.SchemaFlags.NONE,
            {'server': Secret.SchemaAttributeType.STRING})
        attrs = {'server': server} if server else {}
        Secret.password_clear_sync(schema, attrs, None)
    except Exception as e:
        _log(f'  [Token] Keyring clear indisponible ({e})')


def _save_session_token(server, data, log_fn=None):
    """Sauvegarde les éléments de connexion d'un serveur.

    Écrit deux copies pour la robustesse :
      • keyring libsecret (GNOME Keyring / KWallet) — STOCKAGE PRINCIPAL,
        chiffré par l'OS, déverrouillé à l'ouverture de session.
      • fichier `~/.config/gp-connect/.session.enc` (chmod 600) — cache
        local de secours si le keyring est indisponible.

    `data` doit contenir au minimum `cookie_field` + `cookie_value`. Les
    tokens RÉUTILISABLES (portal-userauthcookie / authcookie) sont
    automatiquement promus en slot `refresh_*` afin de pouvoir renouveler
    un access token consommé sans repasser par SAML.

    Une entrée existante est mergée (les anciens `refresh_*` sont
    préservés si la nouvelle save n'en apporte pas).
    """
    import sys as _sys
    _log = log_fn or (lambda m: None)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    now = _time_mod.time()

    # Lire l'éventuelle entrée précédente pour préserver le refresh.
    prev = _load_session_token_raw(server, log_fn=_log) or {}

    cf = data.get('cookie_field')
    cv = data.get('cookie_value')

    # Refus catégorique de sauvegarder un cookie ONE-SHOT seul : il sera
    # invalide à la prochaine ouverture de l'app (consommé une fois ou
    # à expirer rapidement). On ne le persiste que s'il vient accompagné
    # d'un refresh utilisable. Sinon, on conserve l'entrée existante
    # (qui contient peut-être encore un refresh valide).
    has_explicit_refresh = bool(
        data.get('refresh_field') and data.get('refresh_value'))
    if cf in _ONESHOT_FIELDS and not has_explicit_refresh \
            and not prev.get('refresh_value'):
        _log(f'  [Token] SKIP save : cookie one-shot ({cf}) sans refresh '
             f'→ pas de persistance (servirait à rien)')
        return

    entry = {
        **prev,
        'server':       server,
        'ts':           now,
        'access_ts':    now,
        **data,
    }

    # Auto-promotion : si le cookie qu'on sauvegarde est réutilisable, il
    # devient (aussi) le refresh token pour les prochaines connexions.
    if cf in _REFRESH_FIELDS and cv:
        entry['refresh_field'] = cf
        entry['refresh_value'] = cv
        entry['refresh_ts']    = now
    elif has_explicit_refresh:
        # Permettre à l'appelant de fournir explicitement un refresh
        # différent (ex. portal-userauthcookie obtenu via getconfig
        # alors que l'access actuel est un prelogin-cookie).
        entry['refresh_ts'] = now

    entry_json = json.dumps(entry)

    _log(f'  [Token] SAVE server={server} access={cf} '
         f'has_refresh={bool(entry.get("refresh_value"))} '
         f'len={len(entry_json)}')
    print(f'[GP-TOKEN-SAVE] field={cf} server={server} '
          f'refresh={bool(entry.get("refresh_value"))}', file=_sys.stderr)

    # 1) Keyring (principal — synchrone pour garantir la persistance avant
    #    qu'un crash éventuel ne perde le token).
    keyring_ok = _keyring_store_sync(server, entry_json, log_fn=_log)

    # 2) Fichier : cache de secours. Mêmes données.
    doc = _read_token_file() or {'v': 2, 'sessions': {}}
    if 'sessions' not in doc or not isinstance(doc.get('sessions'), dict):
        doc['sessions'] = {}
    doc['sessions'][server] = entry
    doc['v'] = 2
    if _write_token_file(doc, log_fn=_log):
        _log(f'  [Token] Cache fichier OK : {_TOKEN_FILE} '
             f'({len(doc["sessions"])} serveur(s))')

    if not keyring_ok:
        _log('  [Token] ⚠ Keyring indisponible — fallback fichier uniquement')


def _save_vpn_state(server, iface='', client_ip='', pid=None):
    """Sauvegarde l'etat du tunnel actif pour reprise apres redemarrage app."""
    state_file = CONFIG_DIR / '.vpn_state.json'
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({
        'server': server,
        'iface': iface,
        'client_ip': client_ip,
        'pid': pid,
        'ts': _time_mod.time(),
    })
    with open(state_file, 'w') as f:
        f.write(payload)
    os.chmod(state_file, 0o600)


def _load_vpn_state():
    """Charge l'etat du tunnel sauvegarde. Retourne dict ou None."""
    state_file = CONFIG_DIR / '.vpn_state.json'
    if not state_file.is_file():
        return None
    try:
        with open(state_file) as f:
            data = json.loads(f.read())
        age = _time_mod.time() - data.get('ts', 0)
        if age > 86400:
            return None
        return data
    except Exception:
        return None


def _clear_vpn_state():
    """Supprime l'etat du tunnel sauvegarde."""
    state_file = CONFIG_DIR / '.vpn_state.json'
    try:
        state_file.unlink(missing_ok=True)
    except Exception:
        pass


def _load_session_token_raw(server=None, log_fn=None):
    """Charge la session brute (sans contrôle d'âge).

    Cherche d'abord dans le keyring GNOME (canonique), puis dans le
    fichier cache. Retourne le dict tel que sauvegardé, ou None.
    """
    _log = log_fn or (lambda m: None)
    data = None

    # 1) Keyring (canonique)
    if server:
        raw = _keyring_lookup(server, log_fn=_log)
        if raw:
            try:
                data = json.loads(raw)
                _log(f'  [Token] Keyring : session trouvée pour {server}')
            except Exception as e:
                _log(f'  [Token] Keyring : JSON invalide ({e})')

    # 2) Fichier (cache de secours)
    if not data:
        doc = _read_token_file()
        if doc is not None:
            sessions = doc.get('sessions', {}) if isinstance(doc, dict) else {}
            if server and server in sessions:
                data = sessions[server]
                _log(f'  [Token] Cache fichier : session trouvée pour {server}')
            elif not server and sessions:
                data = max(sessions.values(),
                           key=lambda e: e.get('ts', 0))
                if data:
                    _log(f'  [Token] Cache fichier : session la plus récente '
                         f'({data.get("server")})')
            else:
                _log(f'  [Token] Cache fichier : aucune session pour '
                     f'{server or "*"}')
        else:
            _log(f'  [Token] Cache fichier absent : {_TOKEN_FILE}')

        # Rétro-cycle : si on l'a trouvé via le fichier mais pas dans le
        # keyring, ré-injecter dans le keyring (rattrapage migration).
        if data and server:
            try:
                _keyring_store_sync(server, json.dumps(data), log_fn=_log)
                _log('  [Token] Re-synchronisé fichier → keyring')
            except Exception:
                pass

    if server and data and data.get('server') != server:
        _log(f'  [Token] Serveur mismatch : {data.get("server")} != {server}')
        return None

    return data


def _access_is_fresh(data):
    """True si l'access token (cookie_field/cookie_value) est encore utilisable."""
    if not data:
        return False
    cf = data.get('cookie_field')
    cv = data.get('cookie_value')
    if not cf or not cv:
        return False
    age = _time_mod.time() - data.get('access_ts', data.get('ts', 0))
    # Les access ONE-SHOT ont une fenêtre très courte côté serveur.
    if cf in _ONESHOT_FIELDS:
        return age <= _ACCESS_MAX_AGE
    # Les réutilisables (portal-userauthcookie / authcookie) → 23 h.
    return age <= _TOKEN_MAX_AGE


def _refresh_is_fresh(data):
    """True si le refresh token (portal-userauthcookie/authcookie) est utilisable."""
    if not data:
        return False
    rf = data.get('refresh_field')
    rv = data.get('refresh_value')
    if not rf or not rv:
        return False
    age = _time_mod.time() - data.get('refresh_ts', 0)
    return age <= _TOKEN_MAX_AGE


def _load_session_token(server=None, log_fn=None):
    """Charge un token réutilisable pour un serveur (keyring puis fichier).

    Retourne :
      - None         si aucune session ni refresh utilisable
      - dict         contenant au minimum cookie_field/cookie_value
                     valides au moment de l'appel
    Si l'access est consommé/périmé mais qu'un refresh frais est
    disponible, le refresh est promu comme nouveau cookie d'accès dans
    le dict retourné, afin que les appelants puissent réutiliser sans
    se soucier de la distinction.
    """
    _log = log_fn or (lambda m: None)

    data = _load_session_token_raw(server, log_fn=_log)
    if not data:
        _log('  [Token] Aucune session trouvée — auth SAML requise')
        return None

    access_ok  = _access_is_fresh(data)
    refresh_ok = _refresh_is_fresh(data)

    _log(f'  [Token] État session : access={data.get("cookie_field")} '
         f'(fresh={access_ok}) refresh={data.get("refresh_field") or "—"} '
         f'(fresh={refresh_ok}) mode={data.get("conn_mode","")} '
         f'user={data.get("username","")}')

    if access_ok:
        return data

    if refresh_ok:
        _log('  [Token] Access expiré/consommé — promotion du refresh token '
             f'({data.get("refresh_field")}) en access')
        promoted = dict(data)
        promoted['cookie_field'] = data['refresh_field']
        promoted['cookie_value'] = data['refresh_value']
        promoted['access_ts']    = data.get('refresh_ts', _time_mod.time())
        return promoted

    _log('  [Token] Access ET refresh expirés → nouvelle auth SAML requise')
    return None


def _clear_session_token(server=None, log_fn=None):
    """Supprime les tokens (d'un serveur donné, ou tous si None).

    Supprime aussi `.vpn_state.json` si on purge entièrement.
    """
    _log = log_fn or (lambda m: None)
    # Fichier
    if server:
        doc = _read_token_file()
        if doc and isinstance(doc.get('sessions'), dict):
            doc['sessions'].pop(server, None)
            if doc['sessions']:
                _write_token_file(doc, log_fn=_log)
                _log(f'  [Token] Fichier : session {server} supprimée')
            else:
                try:
                    _TOKEN_FILE.unlink(missing_ok=True)
                    _log('  [Token] Fichier supprimé (plus aucune session)')
                except Exception:
                    pass
    else:
        for f in (_TOKEN_FILE, CONFIG_DIR / '.vpn_state.json'):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
        _log('  [Token] Fichier + état VPN supprimés')

    # Keyring
    _keyring_clear(server, log_fn=_log)

def _resolve_hip_script_builtin():
    """Trouve hipreport.py selon le mode d'installation.

    Priorité :
      1. À côté de gp_connect.py (cas .deb : /usr/share/gp-connect/, ou dev)
      2. /usr/share/gp-connect/hipreport.py (install système .deb)
      3. ~/.local/share/gp-connect/hipreport.py (install locale via install.sh)
      4. Variable d'env GP_HIP_SCRIPT (override)
    """
    env = os.environ.get('GP_HIP_SCRIPT', '').strip()
    if env and os.path.isfile(env):
        return env
    candidates = [
        str(Path(__file__).resolve().parent / 'hipreport.py'),
        '/usr/share/gp-connect/hipreport.py',
        str(Path.home() / '.local/share/gp-connect/hipreport.py'),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    # Retourne le chemin local par défaut même s'il n'existe pas
    # (sera signalé par "script introuvable" dans le log applicatif).
    return candidates[0]


HIP_SCRIPT_BUILTIN = _resolve_hip_script_builtin()

DEFAULT_CONFIG = {
    'server':            '',
    'clientos':          'Linux',
    'user_agent':        'PAN GlobalProtect',
    'preferred_gateway': '',
    'verify_ssl':        True,
    'last_username':     '',
    # HIP (Host Information Profile)
    'hip_enabled':       True,
    'hip_mode':          'fake',       # 'builtin' | 'custom' | 'fake'
    'hip_script':        '',          # chemin script personnalisé
    # HIP mode fake – valeurs simulées (modifiables dans les réglages)
    'hip_fake_hostname':            '',
    'hip_fake_firewall':            True,
    'hip_fake_firewall_name':       'UFW',
    'hip_fake_antivirus':           True,
    'hip_fake_antivirus_vendor':    'Trend Micro, Inc.',
    'hip_fake_antivirus_name':      'Trend Micro Deep Security Agent',
    'hip_fake_antivirus_version':   '20.0.0.0000',
    'hip_fake_antivirus_real_time': True,
    'hip_fake_encryption':          True,
    'hip_fake_mdm':                 True,
    'hip_fake_mdm_name':            'Microsoft Intune',
    'hip_fake_backup':              False,
    'hip_fake_backup_name':         'timeshift',
    # Diagnostic HIP : si True, hipreport.py fait un POST direct au gateway
    # en plus de openconnect, pour capturer le body de la réponse PAN-OS
    # (utile en cas de "no HIP profile assigned" pour voir les erreurs).
    'hip_verify_post':              False,
    # TLS
    'allow_insecure_crypto': False,   # --allow-insecure-crypto (legacy TLS)
    # Mode de connexion
    # 'auto'    : détection automatique du réseau et du type de déploiement :
    #             - sur le LAN (portail résout en IP privée) → internal
    #             - hors LAN, déploiement cloud (Prisma)     → portal
    #             - hors LAN, déploiement on-prem            → gateway
    # 'portal'  : portail interactif (cloud gateways)
    # 'gateway' : passerelle directe sans getconfig (on-prem)
    # 'internal': passerelle interne sans tunnel (user-ID + HIP)
    'connection_mode': 'auto',
    # DNS
    'force_vpn_dns': True,  # force resolvectl domain <tun> ~.
    'vpn_dns_servers': '',  # fallback DNS (ex: '10.0.0.1,10.0.0.2')
    'vpn_dns_suffixes': '', # domaines (ex: 'corp.local,internal.lan')
    'learned_vpn_dns': {},  # auto-appris par serveur
    # UI
    'minimize_to_tray': True,  # fermer la fenêtre => réduire en zone notif
    # Modes mémorisés par serveur (auto-détection on-prem hors LAN)
    # ex. {'vpn.company.com': 'gateway'} — jamais 'internal' (décidé via DNS)
    'server_modes': {},
    # OS mémorisé par serveur (auto-détection cloud Prisma Access)
    # ex. {'vpn.company.com': 'Windows'}
    'server_os': {},
    # Internal Host Detection mémorisée par serveur (récupérée via getconfig)
    # ex. {'vpn.company.com': {'ip': '10.1.2.3', 'host': 'ihd.corp.local'}}
    # Conservée pour diagnostic ; la détection LAN repose uniquement sur la
    # résolution DNS du portail (IP privée = interne, sinon = externe).
    'server_ihd': {},
    # Type de déploiement mémorisé (cloud Prisma Access vs on-prem)
    # ex. {'vpn.company.com': 'cloud'} ou 'onprem'
    'server_deployment': {},
}

UA_PRESETS_BY_OS = {
    'Linux': {
        'Chrome (Ubuntu)':
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
        'Firefox (Ubuntu)':
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) '
            'Gecko/20100101 Firefox/147.0',
        'Edge (Linux)':
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0',
        'PAN GlobalProtect':
            'PAN GlobalProtect',
    },
    'Mac': {
        'Safari (macOS)':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) '
            'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15',
        'Chrome (macOS)':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
        'Firefox (macOS)':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:147.0) '
            'Gecko/20100101 Firefox/147.0',
        'PAN GlobalProtect':
            'PAN GlobalProtect',
    },
    'Windows': {
        'Chrome (Win11)':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
        'Edge (Win11)':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0',
        'Firefox (Win11)':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) '
            'Gecko/20100101 Firefox/147.0',
        'PAN GlobalProtect':
            'PAN GlobalProtect',
    },
}
# Flat compat (ancienne structure)
UA_PRESETS = {}
for _os, _presets in UA_PRESETS_BY_OS.items():
    UA_PRESETS.update(_presets)


class Config:
    def __init__(self):
        self.data = DEFAULT_CONFIG.copy()
        self._load()

    def _load(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    self.data.update(json.load(f))
            except Exception:
                pass

    def save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.data, f, indent=2)

    def reload(self):
        """Relit le fichier de config depuis le disque (changements externes)."""
        self._load()

    def get(self, key, default=None):
        return self.data.get(key, default if default is not None else DEFAULT_CONFIG.get(key, ''))

    def set(self, key, value):
        self.data[key] = value
        self.save()


# ─────────────────────────────────────────────
#  Helpers VPN
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
#  Gestion sudoers (openconnect sans mot de passe)
# ─────────────────────────────────────────────

SUDOERS_FILE = '/etc/sudoers.d/gp-connect'

def can_sudo_openconnect():
    """Vérifie si openconnect peut être lancé via sudo sans mot de passe."""
    oc = shutil.which('openconnect') or '/usr/sbin/openconnect'
    try:
        r = subprocess.run(
            ['sudo', '-n', oc, '--version'],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False

def _detect_dns_tool():
    """Detecte l'outil DNS disponible sur le systeme.

    Retourne ('resolvectl', path) ou ('systemd-resolve', path) ou ('resolvconf', path)
    ou ('nmcli', path) ou (None, None).
    """
    for tool in ('resolvectl', 'systemd-resolve', 'resolvconf', 'nmcli'):
        path = shutil.which(tool)
        if path:
            return tool, path
    return None, None


def can_sudo_resolvectl():
    """Vérifie si l'outil DNS peut être lancé via sudo sans mot de passe."""
    tool, path = _detect_dns_tool()
    if not path or tool == 'nmcli':
        return tool == 'nmcli'
    try:
        r = subprocess.run(
            ['sudo', '-n', path, 'status'] if tool in ('resolvectl', 'systemd-resolve')
            else ['sudo', '-n', path, '--version'],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False

def can_sudo_all_required():
    """Vérifie toutes les permissions sudo non-interactives requises."""
    return can_sudo_openconnect() and can_sudo_resolvectl()

def setup_sudoers_rule():
    """Crée /etc/sudoers.d/gp-connect via pkexec (dialogue GNOME)."""
    username = os.environ.get('USER', os.environ.get('LOGNAME', ''))
    oc       = shutil.which('openconnect') or '/usr/sbin/openconnect'
    pkill    = shutil.which('pkill') or '/usr/bin/pkill'
    dns_cmds = []
    for t in ('resolvectl', 'systemd-resolve', 'resolvconf'):
        p = shutil.which(t)
        if p:
            dns_cmds.append(p)
    if not dns_cmds:
        dns_cmds.append('/usr/bin/resolvectl')
    cmds = ', '.join([oc, pkill] + dns_cmds)
    rule     = f'{username} ALL=(ALL) NOPASSWD: {cmds}\n'
    helper   = f'''#!/bin/bash
printf '{rule}' > {SUDOERS_FILE}
chmod 440 {SUDOERS_FILE}
'''
    # Écriture dans un script temporaire
    import tempfile, stat
    with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False) as f:
        f.write(helper)
        tmp = f.name
    os.chmod(tmp, stat.S_IRWXU)
    try:
        r = subprocess.run(['pkexec', 'bash', tmp],
                           capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

def remove_sudoers_rule():
    """Supprime /etc/sudoers.d/gp-connect via pkexec."""
    helper = f'''#!/bin/bash
rm -f {SUDOERS_FILE}
'''
    import tempfile, stat
    with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False) as f:
        f.write(helper)
        tmp = f.name
    os.chmod(tmp, stat.S_IRWXU)
    try:
        r = subprocess.run(['pkexec', 'bash', tmp],
                           capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _make_session(verify=True, allow_insecure=False):
    """Crée une session requests avec les options SSL appropriées.

    Quand allow_insecure=True, reproduit le TLSAdapter de gp-saml-gui :
    SECLEVEL=1, ciphers faibles autorisés, legacy renegotiation.
    """
    import ssl as _ssl
    import urllib3
    from requests.adapters import HTTPAdapter

    s = requests.Session()
    s.headers['User-Agent'] = 'PAN GlobalProtect'

    if allow_insecure:
        class _GPTLSAdapter(HTTPAdapter):
            def __init__(self, _verify=True, **kw):
                self._verify = _verify
                super().__init__(**kw)

            def init_poolmanager(self, connections, maxsize, block=False,
                                 **kw):
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
                ctx.options |= 1 << 2   # OP_LEGACY_SERVER_CONNECT
                if not self._verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                self.poolmanager = urllib3.PoolManager(
                    num_pools=connections, maxsize=maxsize,
                    block=block, ssl_context=ctx)

        s.mount('https://', _GPTLSAdapter(_verify=verify))

    return s


CLIENTOS_OS_MAP = {
    'Windows': 'win',
    'Linux':   'linux-64',
    'Mac':     'mac-intel',
}
OS_TO_CLIENTOS = {v: k for k, v in CLIENTOS_OS_MAP.items()}

CLIENTOS_CLOUD_PRIORITY = ['Linux', 'Windows', 'Mac']

CLOUD_DEFAULT_UA = {
    'Linux':   'PAN GlobalProtect',
    'Windows': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0'),
    'Mac':     ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'),
}

# UA utilisé par la WebView SAML (doit être un vrai navigateur pour que
# la page Microsoft SSO affiche les champs de saisie correctement).
WEBVIEW_UA = {
    'Linux':   ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'),
    'Windows': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'),
    'Mac':     ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'),
}


def probe_prelogin(server, verify=True, allow_insecure=False,
                   clientos='Linux'):
    """Interroge prelogin.esp pour détecter les caractéristiques du portail.

    Retourne un dict avec :
      - 'is_cloud'    : True si saml-default-browser=yes (Prisma Access)
      - 'saml_method' : 'REDIRECT' | 'POST' | None
      - 'status'      : 'Success' | 'Error' | None
      - 'region'      : ex. 'DE' | None
    """
    try:
        s = _make_session(verify=verify, allow_insecure=allow_insecure)
        r = s.post(
            f'https://{server}/global-protect/prelogin.esp',
            verify=verify,
            data={'tmp': 'tmp', 'clientVer': '4100', 'clientos': clientos},
            timeout=10,
        )
        xml_root = ET.fromstring(r.content)
        status_el = xml_root.find('status')
        sdb_el    = xml_root.find('saml-default-browser')
        sam_el    = xml_root.find('saml-auth-method')
        reg_el    = xml_root.find('region')
        return {
            'is_cloud':    (sdb_el is not None and
                            (sdb_el.text or '').lower() == 'yes'),
            'saml_method': sam_el.text if sam_el is not None else None,
            'status':      status_el.text if status_el is not None else None,
            'region':      reg_el.text if reg_el is not None else None,
        }
    except Exception:
        return {'is_cloud': False, 'saml_method': None,
                'status': None, 'region': None}


def diagnose_connection(server, clientos='Linux', verify=True,
                        allow_insecure=False, log_fn=None):
    """Diagnostic complet de la connexion GP : DNS, TLS, prelogin portal/gateway."""
    _log = log_fn or print

    _log(f'=== Diagnostic GP Connect → {server} ===')
    _log(f'  clientos={clientos}  verify_ssl={verify}  '
         f'allow_insecure={allow_insecure}')

    # 1. DNS
    _log('\n--- Résolution DNS ---')
    try:
        import socket
        addrs = socket.getaddrinfo(server, 443, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
        ips = sorted({a[4][0] for a in addrs})
        _log(f'  ✔ {server} → {", ".join(ips)}')
    except Exception as e:
        _log(f'  ✘ DNS échoué : {e}')
        _log('  → Vérifiez votre réseau et /etc/resolv.conf')
        return

    # 2. TLS
    _log('\n--- Connectivité HTTPS ---')
    for mode_label, insecure in [('standard', False),
                                  ('insecure-crypto', True)]:
        try:
            s = _make_session(verify=verify, allow_insecure=insecure)
            r = s.get(f'https://{server}/', verify=verify, timeout=10,
                      allow_redirects=False)
            _log(f'  ✔ TLS ({mode_label}) : HTTP {r.status_code}')
            break
        except Exception as e:
            err = str(e)
            if len(err) > 120:
                err = err[:120] + '…'
            _log(f'  ✘ TLS ({mode_label}) : {err}')

    # 3. Prelogin sur les deux endpoints
    if2path = {'portal': 'global-protect/prelogin.esp',
               'gateway': 'ssl-vpn/prelogin.esp'}

    for iface, path in if2path.items():
        _log(f'\n--- Prelogin {iface} ({path}) ---')
        endpoint = f'https://{server}/{path}'
        try:
            s = _make_session(verify=verify, allow_insecure=allow_insecure)
            r = s.post(endpoint, verify=verify, timeout=10,
                       data={'tmp': 'tmp', 'kerberos-support': 'yes',
                             'ipv6-support': 'yes', 'clientVer': '4100',
                             'clientos': clientos})
            _log(f'  HTTP {r.status_code}  ({len(r.content)} octets)')

            if r.status_code == 404:
                _log(f'  ✘ Endpoint {iface} non disponible (404)')
                continue
            if r.status_code >= 400:
                _log(f'  ✘ Erreur HTTP {r.status_code}')
                continue

            try:
                xml_root = ET.fromstring(r.content)
            except ET.ParseError as e:
                _log(f'  ✘ Réponse non-XML : {e}')
                _log(f'    Début : {r.text[:150]}')
                continue

            status = xml_root.findtext('status') or '?'
            sam = xml_root.findtext('saml-auth-method') or '—'
            sr = xml_root.find('saml-request')
            sdb = xml_root.findtext('saml-default-browser') or '—'
            region = xml_root.findtext('region') or '—'
            msg = xml_root.findtext('msg') or ''

            _log(f'  status={status}  saml-method={sam}  '
                 f'saml-default-browser={sdb}  region={region}')
            if sr is not None:
                try:
                    decoded = b64decode(sr.text).decode()[:100]
                    _log(f'  saml-request (décodé) : {decoded}…')
                except Exception:
                    _log(f'  saml-request : (présent, {len(sr.text or "")} cars base64)')
            if msg:
                _log(f'  msg={msg}')

            if status == 'Success' and sam in ('REDIRECT', 'POST'):
                _log(f'  ✔ Endpoint {iface} fonctionnel (SAML {sam})')
            else:
                _log(f'  ⚠ Endpoint {iface} : status={status}')

        except Exception as e:
            err = str(e)
            if len(err) > 150:
                err = err[:150] + '…'
            _log(f'  ✘ Erreur : {err}')

    _log('\n=== Fin du diagnostic ===')


def _do_prelogin_request(server, clientos, path, verify, allow_insecure):
    """Envoie un POST prelogin sur le chemin donné et retourne la Response."""
    endpoint = f'https://{server}/{path}'
    s = _make_session(verify=verify, allow_insecure=allow_insecure)
    return s.post(endpoint, verify=verify,
                  data={'tmp': 'tmp', 'kerberos-support': 'yes',
                        'ipv6-support': 'yes', 'clientVer': '4100',
                        'clientos': clientos},
                  timeout=15)


def do_prelogin(server, clientos='Windows', interface='portal',
                verify=True, allow_insecure=False):
    """Effectue le prelogin et retourne les infos SAML complètes.

    Retourne un dict :
      - 'status'             : 'Success' | 'Error'
      - 'saml_method'        : 'REDIRECT' | 'POST'
      - 'saml_request'       : URL ou HTML (décodé depuis base64)
      - 'is_cloud'           : True si saml-default-browser=yes
      - 'region'             : ex. 'DE'
      - 'actual_interface'   : 'portal' ou 'gateway' (endpoint réellement utilisé)
    """
    if2prelogin = {'portal': 'global-protect/prelogin.esp',
                   'gateway': 'ssl-vpn/prelogin.esp'}
    primary_path = if2prelogin.get(interface, if2prelogin['portal'])
    r = _do_prelogin_request(server, clientos, primary_path, verify, allow_insecure)
    actual_interface = interface

    _need_portal_fallback = False
    if r.status_code == 404 and interface == 'gateway':
        _need_portal_fallback = True
    elif interface == 'gateway' and r.status_code < 400:
        try:
            _xml = ET.fromstring(r.content)
            _st = _xml.find('status')
            if _st is None or _st.text != 'Success':
                _need_portal_fallback = True
        except ET.ParseError:
            _need_portal_fallback = True

    if _need_portal_fallback:
        fallback_path = if2prelogin['portal']
        r = _do_prelogin_request(server, clientos, fallback_path, verify,
                                 allow_insecure)
        actual_interface = 'portal'

    endpoint = f'https://{server}/{if2prelogin.get(actual_interface, primary_path)}'

    if r.status_code == 404:
        raise RuntimeError(
            f'Endpoint {interface} introuvable (HTTP 404) : {endpoint}\n'
            f'  Ce serveur ne supporte peut-être pas le mode « {interface} ».')
    if r.status_code >= 400:
        raise RuntimeError(
            f'Erreur HTTP {r.status_code} sur {endpoint}')

    try:
        xml_root = ET.fromstring(r.content)
    except ET.ParseError as e:
        raise RuntimeError(
            f'Réponse non-XML du serveur ({endpoint}) : {e}\n'
            f'  Début de la réponse : {r.text[:200]}') from e

    status_el = xml_root.find('status')
    if status_el is None or status_el.text != 'Success':
        msg_el = xml_root.find('msg')
        raise RuntimeError(msg_el.text if msg_el is not None else 'prelogin failed')

    sam_el = xml_root.find('saml-auth-method')
    sr_el  = xml_root.find('saml-request')
    sdb_el = xml_root.find('saml-default-browser')
    reg_el = xml_root.find('region')

    if sam_el is None or sr_el is None:
        raise RuntimeError(
            f'Réponse prelogin ({interface}) sans tags SAML.\n'
            f'  → Essayez un autre mode de connexion ou un autre clientos.\n'
            f'  → Endpoint : {endpoint}')

    decoded = b64decode(sr_el.text).decode()
    return {
        'status':       'Success',
        'saml_method':  sam_el.text,
        'saml_request': decoded,
        'is_cloud':     (sdb_el is not None and
                         (sdb_el.text or '').lower() == 'yes'),
        'region':       reg_el.text if reg_el is not None else None,
        'actual_interface': actual_interface,
    }


# ─────────────────────────────────────────────
#  Auth via navigateur externe (Prisma Access)
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
#  WebView SAML intégrée (remplace gp-saml-gui)
# ─────────────────────────────────────────────

_SAML_COOKIE_FIELDS = ('prelogin-cookie', 'portal-userauthcookie')


_webkit_ctx_initialized = False


def _init_webkit_context():
    """Configure le contexte WebKit2 par défaut (une seule fois par processus).

    Enregistre le schema globalprotectcallback:// pour que le WebView
    l'intercepte au lieu de le deleguer au systeme.
    """
    global _webkit_ctx_initialized
    if _webkit_ctx_initialized:
        return
    _webkit_ctx_initialized = True

    cookie_file = CONFIG_DIR / 'cookies.txt'
    try:
        cookie_file.unlink(missing_ok=True)
    except Exception:
        pass

    ctx = WebKit2.WebContext.get_default()
    cm = ctx.get_cookie_manager()
    cm.set_accept_policy(WebKit2.CookieAcceptPolicy.ALWAYS)

    try:
        sec_mgr = ctx.get_security_manager()
        sec_mgr.register_uri_scheme_as_local('globalprotectcallback')
    except Exception:
        pass


class SAMLWebViewDialog(Gtk.Dialog):
    """Fenêtre WebKit2 intégrée pour l'authentification SAML.

    Intercepte les headers HTTP et le body HTML pour capturer les cookies
    SAML (prelogin-cookie / portal-userauthcookie / saml-username).
    Spoofe navigator.platform pour passer le Conditional Access Microsoft.
    """

    def __init__(self, saml_url, saml_html=None, clientos='Windows',
                 user_agent=None, verify_ssl=True, allow_insecure=False,
                 parent=None, log_fn=None):
        super().__init__(
            title='SAML Login',
            transient_for=parent,
            modal=True,
            destroy_with_parent=True,
        )
        self.set_default_size(520, 640)
        self._log = log_fn or (lambda msg: None)
        self.saml_result = {}
        self.success = False
        self.cancelled = False
        self._loop = None
        self._destroyed = False
        self._finish_scheduled = False
        self._wview_handlers = []
        self._self_handlers = []

        if not HAS_WEBKIT2:
            raise RuntimeError('WebKit2 (gir1.2-webkit2-4.1 ou 4.0) non disponible')

        _init_webkit_context()

        ctx = WebKit2.WebContext.get_default()
        if not verify_ssl or allow_insecure:
            ctx.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)

        self.wview = WebKit2.WebView()
        settings = self.wview.get_settings()
        webview_ua = WEBVIEW_UA.get(clientos, WEBVIEW_UA.get('Linux', ''))
        if webview_ua:
            settings.set_user_agent(webview_ua)
        settings.set_enable_javascript(True)
        self.wview.set_settings(settings)

        # Spoofing navigator.platform + navigator.userAgentData
        # En mode Linux natif, pas de spoofing (le CA autorise Linux)
        if clientos != 'Linux':
            _platform_map = {
                'Windows': 'Win32', 'Mac': 'MacIntel',
            }
            _nav_platform = _platform_map.get(clientos, 'Win32')
            _spoof_js = (
                "Object.defineProperty(navigator,'platform',"
                "{get:function(){return '%s';}});"
                "Object.defineProperty(navigator,'userAgentData',"
                "{get:function(){return undefined;}});"
            ) % _nav_platform
            ucm = self.wview.get_user_content_manager()
            ucm.add_script(WebKit2.UserScript(
                _spoof_js,
                WebKit2.UserContentInjectedFrames.ALL_FRAMES,
                WebKit2.UserScriptInjectionTime.START,
                None, None,
            ))

        # Intercepter globalprotectcallback:// au niveau JS
        ucm = self.wview.get_user_content_manager()
        ucm.add_script(WebKit2.UserScript(
            "(function(){"
            "var orig=window.open;window.open=function(u){"
            "if(u&&u.indexOf('globalprotectcallback://')===0){"
            "window.location=u;return null;}"
            "return orig.apply(this,arguments);};"
            "})();",
            WebKit2.UserContentInjectedFrames.ALL_FRAMES,
            WebKit2.UserScriptInjectionTime.START,
            None, None,
        ))

        # Signaux — on retient les handler_ids pour pouvoir les déconnecter
        # dans _finish_idle (thread principal), sinon les méthodes liées
        # (self._on_*) créent un cycle dlg → wview → handler → dlg que Python
        # ne collecte qu'à un GC ultérieur, potentiellement depuis le thread
        # d'authentification. PyGObject appellerait alors g_object_unref sur
        # le WebView depuis un thread non-main → SIGABRT
        # « g_object_unref: assertion 'G_IS_OBJECT (object)' failed ».
        self._wview_handlers = [
            self.wview.connect('load-changed', self._on_load_changed),
            self.wview.connect('decide-policy', self._on_decide_policy),
            self.wview.connect('create', self._on_create_new_window),
            self.wview.connect('web-process-terminated',
                               self._on_web_process_terminated),
        ]
        self._self_handlers = [
            self.connect('delete-event', self._on_close),
        ]

        # Layout
        scrolled = Gtk.ScrolledWindow()
        scrolled.add(self.wview)
        box = self.get_content_area()
        box.pack_start(scrolled, True, True, 0)
        self.show_all()

        # Charger la page
        if saml_html:
            self.wview.load_html(saml_html, saml_url or '')
        else:
            self.wview.load_uri(saml_url)

    def _on_web_process_terminated(self, webview, reason):
        reason_str = {0: 'CRASHED', 1: 'EXCEEDED_MEMORY_LIMIT'}.get(
            int(reason), str(reason))
        self._log(f'  [WebView] ✘ Processus web terminé ({reason_str})')
        # Ne pas détruire pendant que le crash est en cours de signalement :
        # différer à la prochaine itération de la boucle pour éviter un SIGABRT.
        if not self.success:
            self.cancelled = True
        self._schedule_finish()

    def _on_close(self, *_args):
        if not self.success:
            self.cancelled = True
        self._schedule_finish()
        return True

    def _schedule_finish(self):
        """Programme la destruction de la fenêtre + sortie de la MainLoop.

        Centralisé pour éviter les double-destroy et les crashes WebKit quand
        on appelle destroy() depuis un handler de signal (decide-policy,
        web-process-terminated, load-changed…).
        """
        if self._finish_scheduled:
            return
        self._finish_scheduled = True
        GLib.idle_add(self._finish_idle)

    def _finish_idle(self):
        if not self._destroyed:
            self._destroyed = True
            self._release_webkit_refs()
            try:
                self.destroy()
            except Exception:
                pass
        if self._loop is not None and self._loop.is_running():
            self._loop.quit()
        return False

    def _release_webkit_refs(self):
        """Libère les références WebKit/GTK depuis le thread principal.

        WebKit2Gtk n'est pas thread-safe : tout g_object_unref doit se faire
        sur le thread GTK principal. Or les signaux (self.wview.connect(...,
        self._on_*)) créent des cycles de références que le GC Python peut
        casser depuis n'importe quel thread (y compris le _auth_thread qui
        détient le GIL à ce moment-là). Lorsque cela arrive, PyGObject appelle
        g_object_unref sur le WebView depuis un thread secondaire, ce qui
        peut corrompre la mémoire WebKit et déclencher un SIGABRT au prochain
        unref (« g_object_unref: assertion 'G_IS_OBJECT (object)' failed »).

        On casse donc explicitement les cycles ici (thread principal) pour
        que le refcount tombe à zéro sur le bon thread.
        """
        wview = getattr(self, 'wview', None)
        if wview is not None:
            for hid in getattr(self, '_wview_handlers', ()):
                try:
                    wview.disconnect(hid)
                except Exception:
                    pass
            self._wview_handlers = []
            try:
                wview.stop_loading()
            except Exception:
                pass
            try:
                wview.load_uri('about:blank')
            except Exception:
                pass
            self.wview = None
        for hid in getattr(self, '_self_handlers', ()):
            try:
                self.disconnect(hid)
            except Exception:
                pass
        self._self_handlers = []

    def _on_decide_policy(self, webview, decision, decision_type):
        """Intercepte les navigations vers globalprotectcallback://."""
        if decision_type != WebKit2.PolicyDecisionType.NAVIGATION_ACTION:
            return False
        nav = decision.get_navigation_action()
        req = nav.get_request()
        uri = req.get_uri() if req else ''
        if uri.startswith('globalprotectcallback://'):
            decision.ignore()
            self._log(f'  [WebView] Callback intercepté : {uri[:80]}…')
            self._parse_callback_uri(uri)
            return True
        return False

    def _on_create_new_window(self, webview, nav_action):
        """Intercepte TOUTES les tentatives d'ouverture de nouvelle fenetre."""
        req = nav_action.get_request()
        uri = req.get_uri() if req else ''
        if uri.startswith('globalprotectcallback://'):
            self._log(f'  [WebView] Callback (new-window) : {uri[:80]}…')
            self._parse_callback_uri(uri)
            return self.wview
        if uri:
            self._log(f'  [WebView] Redirect (new-window) : {uri[:80]}…')
            self.wview.load_uri(uri)
        return self.wview

    def _parse_callback_uri(self, uri):
        """Extrait les cookies SAML d'une URI globalprotectcallback://."""
        try:
            parsed = urlparse(uri)
            fragment = parsed.fragment or ''
            raw = parsed.path
            if parsed.query:
                raw += '?' + parsed.query
            if fragment:
                raw += '#' + fragment

            params = parse_qs(parsed.query) if parsed.query else {}

            found = {}
            for k in ('prelogin-cookie', 'portal-userauthcookie',
                      'saml-username', 'user'):
                vals = params.get(k)
                if vals:
                    found[k] = vals[0]

            if not found:
                data = unquote(raw.lstrip('/'))
                try:
                    padded = data + '=' * (-len(data) % 4)
                    decoded = b64decode(padded).decode('utf-8', errors='replace')
                    for line in decoded.splitlines():
                        if '=' in line:
                            k, _, v = line.partition('=')
                            k = k.strip().lower()
                            if k in ('prelogin-cookie', 'portal-userauthcookie',
                                     'saml-username', 'user'):
                                found[k] = v.strip()
                except Exception:
                    pairs = data.split('&')
                    for pair in pairs:
                        if '=' in pair:
                            k, _, v = pair.partition('=')
                            k = unquote(k).strip().lower()
                            v = unquote(v).strip()
                            if k in ('prelogin-cookie', 'portal-userauthcookie',
                                     'saml-username', 'user'):
                                found[k] = v

            if 'user' in found and 'saml-username' not in found:
                found['saml-username'] = found.pop('user')

            if found:
                self._log(f'  [WebView] Callback SAML : {list(found.keys())}')
                self.saml_result.update(found)
                self._check_done()
            else:
                self._log('  [WebView] ⚠ Callback reçu mais aucun cookie trouvé.')
        except Exception as e:
            self._log(f'  [WebView] Erreur parsing callback : {e}')

    def _on_load_changed(self, webview, event):
        if event != WebKit2.LoadEvent.FINISHED:
            return

        mr = webview.get_main_resource()
        uri = mr.get_uri()
        rs = mr.get_response()
        h = rs.get_http_headers() if rs else None

        # Titre de fenêtre avec indicateur de sécurité
        urip = urlparse(uri)
        lock = '\U0001F512' if urip.scheme == 'https' else '\U0001F534'
        self.set_title(f'SAML Login ({lock} {urip.netloc})')

        if not rs or not h:
            return

        # Extraire les headers SAML
        headers = {}
        h.foreach(lambda k, v: headers.__setitem__(k.lower(), v))
        saml_headers = {
            k: v for k, v in headers.items()
            if k.startswith('saml-') or k in _SAML_COOKIE_FIELDS
        }
        if saml_headers:
            self._log(f'  [WebView] Headers SAML détectés : {list(saml_headers.keys())}')
            self.saml_result.update(saml_headers)
            self.saml_result['server'] = urip.netloc
            if self._check_done():
                return

        # Fallback : chercher dans le body HTML (commentaires XML)
        ct = h.get_content_type() if h else None
        mr.get_data(None, self._on_body_received, ct)

    def _on_body_received(self, resource, result, ct):
        try:
            data = resource.get_data_finish(result)
        except Exception:
            return
        charset = ct.params.get('charset') if ct and ct.params else None
        try:
            content = data.decode(charset or 'utf-8', errors='replace')
        except Exception:
            return

        # Parser les commentaires HTML pour les tags SAML
        from html.parser import HTMLParser

        class _CommentParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.comments = []
            def handle_comment(self, data):
                self.comments.append(data.strip())

        parser = _CommentParser()
        try:
            parser.feed(content)
        except Exception:
            return

        found = {}
        for comment in parser.comments:
            try:
                root = ET.fromstring(f'<r>{comment}</r>')
                for el in root:
                    if el.tag.startswith('saml-') or el.tag in _SAML_COOKIE_FIELDS:
                        found[el.tag] = el.text
            except ET.ParseError:
                pass

        if found:
            self._log(f'  [WebView] Tags SAML dans body : {list(found.keys())}')
            self.saml_result.update(found)
            if 'server' not in self.saml_result:
                self.saml_result['server'] = urlparse(resource.get_uri()).netloc
            if not self._check_done():
                GLib.timeout_add(1000, self._check_done)

    def _check_done(self):
        d = self.saml_result
        if ('saml-username' in d and
                ('prelogin-cookie' in d or 'portal-userauthcookie' in d)):
            if not self.success:
                self.success = True
                self._log('  [WebView] ✔ Cookies SAML capturés.')
            # destroy() différé via _schedule_finish : appeler destroy()
            # synchroniquement depuis un handler WebKit (decide-policy,
            # load-changed, navigate-action…) fait crasher le processus web
            # (SIGABRT sur Ubuntu 24.04+/25.10 Wayland).
            self._schedule_finish()
            return True
        return False

    def _on_timeout(self):
        if not self.success and not self.cancelled:
            self._log(f'  [WebView] ✘ Timeout auth')
            self.cancelled = True
            self._schedule_finish()
        return False

    def run_auth(self, timeout=300):
        """Bloque jusqu'à succès, annulation, crash ou timeout. Retourne le résultat.

        Utilise un GLib.MainLoop imbriqué (méthode standard GTK) plutôt qu'une
        boucle manuelle avec Gtk.main_iteration_do() + sleep, qui provoquait des
        freezes et des crashes WebKit sur les systèmes récents.

        Le timeout par défaut (300 s) est volontairement généreux pour couvrir
        les flux MFA Microsoft avec approbation push / TOTP qui peuvent durer
        plusieurs minutes.
        """
        self.show()
        self._loop = GLib.MainLoop()
        timeout_id = GLib.timeout_add_seconds(timeout, self._on_timeout)
        try:
            self._loop.run()
        finally:
            try:
                GLib.source_remove(timeout_id)
            except Exception:
                pass
            self._loop = None
            if not self._destroyed:
                self._destroyed = True
                self._release_webkit_refs()
                try:
                    self.destroy()
                except Exception:
                    pass
        return self.saml_result if self.success else None


def _run_saml_webview_dialog(saml_url, saml_html, clientos, user_agent,
                             verify, allow_insecure, parent_window, log_fn):
    """Ouvre le dialog WebView SAML et retourne le résultat brut.

    DOIT être appelé sur le thread GTK principal.
    Retourne le dict brut du dialog ou None si annulé.
    """
    _log = log_fn or (lambda msg: None)
    dlg = SAMLWebViewDialog(
        saml_url=saml_url,
        saml_html=saml_html,
        clientos=clientos,
        user_agent=user_agent,
        verify_ssl=verify,
        allow_insecure=allow_insecure,
        parent=parent_window,
        log_fn=_log,
    )
    return dlg.run_auth()


def _parse_saml_result(raw_result, clientos, server):
    """Transforme le résultat brut du dialog WebView en dict normalisé."""
    if raw_result is None:
        return None

    cookie_field = 'prelogin-cookie'
    cookie_value = raw_result.get('prelogin-cookie')
    if not cookie_value:
        cookie_field = 'portal-userauthcookie'
        cookie_value = raw_result.get('portal-userauthcookie')

    os_map = {'Windows': 'win', 'Mac': 'mac-intel', 'Linux': 'linux-64'}
    return {
        'USER': raw_result.get('saml-username', ''),
        'COOKIE': cookie_value,
        'cookie_field': cookie_field,
        'OS': os_map.get(clientos, 'mac-intel'),
        'server': raw_result.get('server', server),
    }


def webview_saml_auth(server, clientos='Windows', interface='portal',
                      user_agent=None, verify=True, allow_insecure=False,
                      parent_window=None, log_fn=None):
    """Authentification SAML via WebView intégrée (convenance, tout-en-un).

    Attention : cette fonction fait du réseau puis de l'UI.
    Ne PAS l'appeler depuis le thread GTK (sinon freeze).
    Retourne un dict {'USER': ..., 'COOKIE': ..., ...} ou None.
    """
    _log = log_fn or (lambda msg: None)

    _log(f'  [WebView] Prelogin ({interface})…')
    info = do_prelogin(server, clientos=clientos, interface=interface,
                       verify=verify, allow_insecure=allow_insecure)

    actual = info.get('actual_interface', interface)
    if actual != interface:
        _log(f'  [WebView] ⚠ Endpoint {interface} (ssl-vpn/) indisponible, '
             f'fallback sur endpoint {actual} (global-protect/).')

    saml_url = saml_html = None
    if info['saml_method'] == 'REDIRECT':
        saml_url = info['saml_request']
    elif info['saml_method'] == 'POST':
        saml_html = info['saml_request']
    else:
        raise RuntimeError(f"Méthode SAML inconnue : {info['saml_method']}")

    _log(f'  [WebView] Ouverture SAML ({info["saml_method"]})…')
    raw = _run_saml_webview_dialog(
        saml_url, saml_html, clientos, user_agent,
        verify, allow_insecure, parent_window, _log)
    return _parse_saml_result(raw, clientos, server)


_CALLBACK_FILE_PREFIX = '/tmp/gpc-callback-'


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler qui capture le globalprotectcallback:// redirigé."""

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == '/callback':
            data = params.get('data', [''])[0]
            if data and not self.server.callback_data:
                self.server.callback_data = data
            self._send_success_page()
            return

        if parsed.path in ('/', '/status'):
            if self.server.callback_data:
                self._send_success_page()
            else:
                self._send_paste_page()
            return

        if parsed.path == '/paste':
            self._send_paste_page()
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        params = parse_qs(body)
        url_val = params.get('url', [''])[0].strip()
        if url_val:
            cb = url_val
            for pfx in ('globalprotectcallback://', 'globalprotectcallback:'):
                if cb.startswith(pfx):
                    cb = cb[len(pfx):]
                    break
            if cb and not self.server.callback_data:
                self.server.callback_data = cb
        self._send_success_page()

    def _send_success_page(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(
            '<html><body style="font-family:sans-serif;text-align:center;padding:40px">'
            '<h2>GP Connect</h2>'
            '<p style="color:green;font-size:1.3em">&#10004; Cookie capturé.</p>'
            '<p>Vous pouvez fermer cet onglet et revenir à GP Connect.</p>'
            '<script>window.close()</script>'
            '</body></html>'.encode())

    def _send_paste_page(self):
        port = self.server.server_address[1]
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write((
            '<html><head><style>'
            'body{font-family:sans-serif;max-width:650px;margin:40px auto;line-height:1.6}'
            'code{background:#f0f0f0;padding:2px 6px;border-radius:3px}'
            '.step{margin:12px 0;padding:10px 14px;background:#f8f8f8;border-left:3px solid #4a9}'
            'textarea{width:100%;font-size:0.85em;font-family:monospace}'
            'button{padding:10px 28px;font-size:1em;background:#4a9;color:#fff;'
            'border:none;border-radius:4px;cursor:pointer}'
            '</style></head><body>'
            '<h2>GP Connect &mdash; Collage manuel du callback</h2>'
            '<p>L\'authentification SAML est terminée mais le callback automatique '
            'n\'a pas fonctionné. Suivez ces étapes&nbsp;:</p>'
            '<div class="step"><b>Étape 1.</b> Dans Chrome, après l\'authentification, '
            'une boîte de dialogue apparaît en haut : '
            '<em>«&nbsp;Ouvrir&nbsp;GP&nbsp;Connect&nbsp;Callback&nbsp;?&nbsp;»</em>. '
            '<b>Cliquez sur «&nbsp;Ouvrir&nbsp;».</b></div>'
            '<div class="step"><b>Étape 2.</b> Si la boîte n\'apparaît pas ou si vous '
            'l\'avez fermée, regardez la barre d\'adresse de Chrome. '
            'Elle devrait contenir une URL commençant par '
            '<code>globalprotectcallback://PAS…</code><br>'
            'Copiez <b>l\'intégralité</b> de cette URL et collez-la ci-dessous.</div>'
            f'<form method="POST" action="http://127.0.0.1:{port}/manual">'
            '<textarea name="url" rows="5" '
            'placeholder="globalprotectcallback://PAS…"></textarea><br><br>'
            '<button type="submit">Valider</button></form>'
            '<div class="step"><b>Important&nbsp;:</b> L\'URL doit commencer par '
            '<code>globalprotectcallback://PAS</code> ou <code>globalprotectcallback://CAS</code>. '
            'Une URL commençant par <code>https://</code> ne fonctionnera pas.</div>'
            '</body></html>').encode())

    def log_message(self, fmt, *args):
        pass


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _parse_callback_data(raw_data):
    """Parse le payload globalprotectcallback:// et retourne un dict auth."""
    data = unquote(raw_data)

    # Supprimer le préfixe protocol si encore présent
    for pfx in ('globalprotectcallback://', 'globalprotectcallback:'):
        if data.startswith(pfx):
            data = data[len(pfx):]

    for prefix in ('PAS', 'CAS'):
        if data.startswith(prefix):
            b64part = data[len(prefix):]
            padded = b64part + '=' * (-len(b64part) % 4)
            try:
                decoded = b64decode(padded).decode('utf-8', errors='replace')
                result = _parse_callback_keyval(decoded)
                if result:
                    return result
            except Exception:
                pass

    if '=' in data and not data.startswith('http'):
        return _parse_callback_keyval(data)

    return {}


def _parse_callback_keyval(text):
    """Extrait les paires clé=valeur depuis un texte de callback."""
    result = {}

    if '&' in text and '=' in text:
        for pair in text.split('&'):
            if '=' in pair:
                k, _, v = pair.partition('=')
                result[unquote(k.strip())] = unquote(v.strip())

    if not result:
        try:
            root = ET.fromstring(f'<root>{text}</root>')
            for child in root:
                if child.text:
                    result[child.tag] = child.text
        except ET.ParseError:
            pass

    if not result:
        for line in text.splitlines():
            if ':' in line:
                k, _, v = line.partition(':')
                k = k.strip().lower()
                if k in ('prelogin-cookie', 'portal-userauthcookie',
                          'saml-username', 'username', 'user'):
                    result[k] = v.strip()

    return result


def _register_callback_handler(port, callback_file):
    """Enregistre le handler globalprotectcallback:// de manière robuste.

    Le handler utilise un script Python (pas bash) pour éviter les problèmes
    de shell escaping. Il écrit le callback brut dans un fichier ET envoie
    une requête HTTP au serveur local.
    """
    tmpdir = tempfile.mkdtemp(prefix='gpc-callback-')

    script_path = os.path.join(tmpdir, 'gpc-callback-handler.py')
    with open(script_path, 'w') as f:
        f.write(f'''#!/usr/bin/env python3
import sys, os
if len(sys.argv) < 2:
    sys.exit(0)
url = sys.argv[1]
prefix = 'globalprotectcallback://'
data = url[len(prefix):] if url.startswith(prefix) else url
# Écrire dans le fichier callback (méthode principale, zéro dépendance réseau)
try:
    with open({callback_file!r}, 'w') as f:
        f.write(data)
except Exception:
    pass
# Aussi notifier le serveur HTTP (méthode secondaire)
try:
    from urllib.request import urlopen
    from urllib.parse import quote
    urlopen('http://127.0.0.1:{port}/callback?data=' + quote(data, safe=''), timeout=3)
except Exception:
    pass
''')
    os.chmod(script_path, stat.S_IRWXU)

    # 1. Installer le .desktop dans ~/.local/share/applications/
    local_apps = Path.home() / '.local' / 'share' / 'applications'
    local_apps.mkdir(parents=True, exist_ok=True)
    installed = local_apps / 'gpc-callback.desktop'
    with open(str(installed), 'w') as f:
        f.write(f'''[Desktop Entry]
Type=Application
Name=GP Connect Callback
Exec={script_path} %u
MimeType=x-scheme-handler/globalprotectcallback;
NoDisplay=true
Terminal=false
''')

    # 2. Mettre à jour la base desktop
    subprocess.run(
        ['update-desktop-database', str(local_apps)],
        capture_output=True, timeout=5)

    # 3. xdg-mime (NOM du fichier, pas chemin)
    subprocess.run(
        ['xdg-mime', 'default', 'gpc-callback.desktop',
         'x-scheme-handler/globalprotectcallback'],
        capture_output=True, timeout=5)

    # 4. xdg-settings pour Chrome/Chromium
    subprocess.run(
        ['xdg-settings', 'set', 'default-url-scheme-handler',
         'globalprotectcallback', 'gpc-callback.desktop'],
        capture_output=True, timeout=5)

    # 5. Écriture directe dans mimeapps.list
    for mimeapps_path in (Path.home() / '.config' / 'mimeapps.list',
                          local_apps / 'mimeapps.list'):
        try:
            cfg = configparser.ConfigParser()
            cfg.optionxform = str
            if mimeapps_path.exists():
                cfg.read(str(mimeapps_path))
            if 'Default Applications' not in cfg:
                cfg['Default Applications'] = {}
            cfg['Default Applications']['x-scheme-handler/globalprotectcallback'] = \
                'gpc-callback.desktop'
            with open(str(mimeapps_path), 'w') as f:
                cfg.write(f, space_around_delimiters=False)
        except Exception:
            pass

    return tmpdir, str(installed)


def _cleanup_callback_handler(tmpdir, installed_desktop='', callback_file=''):
    """Supprime les fichiers temporaires du handler de callback."""
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass
    if callback_file:
        try:
            os.unlink(callback_file)
        except Exception:
            pass
    if installed_desktop:
        try:
            os.unlink(installed_desktop)
        except Exception:
            pass
    for mimeapps_path in (Path.home() / '.config' / 'mimeapps.list',
                          Path.home() / '.local' / 'share' / 'applications' / 'mimeapps.list'):
        if mimeapps_path.exists():
            try:
                cfg = configparser.ConfigParser()
                cfg.optionxform = str
                cfg.read(str(mimeapps_path))
                if cfg.has_option('Default Applications',
                                  'x-scheme-handler/globalprotectcallback'):
                    cfg.remove_option('Default Applications',
                                      'x-scheme-handler/globalprotectcallback')
                    with open(str(mimeapps_path), 'w') as f:
                        cfg.write(f, space_around_delimiters=False)
            except Exception:
                pass


def external_browser_auth(server, clientos='Windows', interface='portal',
                          verify=True, allow_insecure=False, timeout=180,
                          log_fn=None):
    """Authentification SAML via le navigateur système.

    Retourne un dict {'USER': ..., 'COOKIE': ..., 'cookie_field': ...}
    ou lève une exception.
    """
    _log = log_fn or (lambda msg: None)

    # 1. Prelogin
    _log('  [ExtAuth] Prelogin…')
    info = do_prelogin(server, clientos=clientos, interface=interface,
                       verify=verify, allow_insecure=allow_insecure)
    if info['saml_method'] == 'REDIRECT':
        saml_url = info['saml_request']
    elif info['saml_method'] == 'POST':
        _log('  [ExtAuth] Méthode POST — extraction URL…')
        import re
        m = re.search(r'action=["\']([^"\']+)', info['saml_request'])
        if m:
            saml_url = m.group(1).replace('&amp;', '&')
        else:
            raise RuntimeError('Impossible d\'extraire l\'URL SAML du formulaire POST')
    else:
        raise RuntimeError(
            f"Méthode SAML '{info['saml_method']}' non supportée")

    # 2. Serveur HTTP local
    port = _find_free_port()
    httpd = HTTPServer(('127.0.0.1', port), _CallbackHandler)
    httpd.callback_data = None
    httpd.timeout = 1
    _log(f'  [ExtAuth] Serveur callback sur 127.0.0.1:{port}')

    # Fichier callback (mécanisme principal, plus fiable que HTTP+curl)
    callback_file = f'{_CALLBACK_FILE_PREFIX}{port}.dat'
    try:
        os.unlink(callback_file)
    except FileNotFoundError:
        pass

    # 3. Handler de protocole
    tmpdir, installed_desktop = _register_callback_handler(port, callback_file)
    _log('  [ExtAuth] Handler globalprotectcallback:// enregistré')

    try:
        # 4. Ouvrir le navigateur
        _log('  [ExtAuth] Ouverture du navigateur…')
        subprocess.Popen(['xdg-open', saml_url],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _log('  ✋ Complétez l\'authentification dans votre navigateur…')
        _log('  ℹ️  Après connexion, Chrome demandera « Ouvrir GP Connect Callback ? »')
        _log('  ℹ️  → Cliquez sur « Ouvrir » pour transmettre le cookie.')
        _log(f'  ℹ️  Si ça ne fonctionne pas : http://127.0.0.1:{port}/paste')

        # 5. Attendre le callback (poll fichier + HTTP)
        elapsed = 0
        while elapsed < timeout:
            # Vérifier le fichier callback (prioritaire)
            try:
                if os.path.exists(callback_file):
                    with open(callback_file, 'r') as f:
                        file_data = f.read().strip()
                    if file_data:
                        _log(f'  [ExtAuth] Callback reçu via fichier ({len(file_data)} octets)')
                        httpd.callback_data = file_data
                        break
            except Exception:
                pass

            # Vérifier le HTTP (secondaire, aussi pour le paste manuel)
            httpd.handle_request()
            if httpd.callback_data is not None:
                _log(f'  [ExtAuth] Callback reçu via HTTP ({len(httpd.callback_data)} octets)')
                break
            elapsed += 1

        if httpd.callback_data is None:
            raise TimeoutError(
                f'Pas de callback reçu après {timeout}s.\n'
                f'  → Ouvrez http://127.0.0.1:{port}/paste pour coller l\'URL manuellement.')

        raw = httpd.callback_data

        # Vérifier que ce n'est pas juste une URL https (ACS redirect, pas le token)
        clean = raw.strip()
        for pfx in ('globalprotectcallback://', 'globalprotectcallback:'):
            if clean.startswith(pfx):
                clean = clean[len(pfx):]
        if clean.startswith('https://') or clean.startswith('http://'):
            raise RuntimeError(
                f'Le callback contient une URL au lieu du token SAML :\n'
                f'  {clean[:120]}\n'
                f'  Cela signifie que le navigateur a redirigé vers la page ACS\n'
                f'  au lieu d\'envoyer le token PAS/CAS.\n'
                f'  → Essayez de coller l\'URL commençant par\n'
                f'    globalprotectcallback://PAS… dans la page de collage.')

        auth = _parse_callback_data(raw)

        cookie_value = (auth.get('prelogin-cookie')
                        or auth.get('portal-userauthcookie')
                        or auth.get('cookie'))
        username = (auth.get('saml-username')
                    or auth.get('username')
                    or auth.get('user', ''))

        if not cookie_value:
            _log(f'  [ExtAuth] Données brutes ({len(raw)} octets) : {raw[:200]}')
            raise RuntimeError(
                f'Callback reçu mais pas de cookie.\n'
                f'  Données ({len(raw)} octets) : {raw[:200]}')

        cookie_field = 'prelogin-cookie'
        if 'portal-userauthcookie' in auth:
            cookie_field = 'portal-userauthcookie'

        return {
            'USER': username,
            'COOKIE': cookie_value,
            'cookie_field': cookie_field,
        }
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass
        _cleanup_callback_handler(tmpdir, installed_desktop, callback_file)


def get_portal_config(server, cookie_field, cookie_value, username,
                      clientos='Mac', verify=True, allow_insecure=False,
                      log_fn=None):
    """Interroge getconfig.esp → gateways, cookie, IHD et config HIP.

    Le prelogin-cookie est à usage unique : ce seul appel le consomme.
    Le portail retourne en échange un portal-userauthcookie réutilisable
    pour l'authentification sur les gateways.

    Retour :
      gateways          — liste de dicts {'hostname','description',…}
      portal_cookie     — (field, value) ou None
      ihd               — {'ip': ..., 'host': ...}
      hip_interval      — intervalle HIP en secondes (défaut 3600)
      collect_hip       — 'yes'|'no' (si 'no', openconnect ignore le HIP)
      expected_vendors  — vendors/produits attendus par la passerelle
    """
    _log = log_fn or (lambda m: None)
    s = _make_session(verify=verify, allow_insecure=allow_insecure)
    r = s.post(
        f'https://{server}/global-protect/getconfig.esp',
        verify=verify,
        data={
            'user':         username,
            cookie_field:   cookie_value,
            'clientos':     clientos,
            'clientVer':    '4100',
            'computer':     'Linux-GP-Connect',
            'ipv6-support': 'yes',
        },
        timeout=15,
    )
    # Détecter un refus explicite : HTTP 512 (cookie invalidé côté serveur)
    # ou body vide. Dans les deux cas, l'appelant doit refaire un SAML et
    # ne PAS continuer avec ce cookie (sinon openconnect rejoue le même
    # cookie → re-512 → boucle fgets/getpass cassée sur Ubuntu).
    if r.status_code == 512:
        raise RuntimeError(
            f'getconfig.esp HTTP 512 — cookie {cookie_field} refusé '
            f'par le portail (session expirée/révoquée)')
    if not r.content or not r.content.strip():
        raise RuntimeError(
            f'getconfig.esp a retourné un body vide (HTTP {r.status_code})')
    xml_root = ET.fromstring(r.content)

    # Nouveau cookie émis par le portail pour les connexions gateway
    portal_auth_cookie = None
    for tag in ('portal-userauthcookie', 'prelogin-cookie', 'portal-prelogon-cookie'):
        el = xml_root.find(f'.//{tag}')
        if el is not None and el.text:
            portal_auth_cookie = (tag, el.text)
            break

    # Liste des gateways (externes et internes distingués)
    gateways = []
    for entry in xml_root.findall('.//external/list/entry'):
        hostname = entry.get('name', '')
        if not hostname:
            continue
        desc_el  = entry.find('description')
        desc     = (desc_el.text or hostname) if desc_el is not None else hostname
        prio_el  = entry.find('.//priority')
        priority = int(prio_el.text) if prio_el is not None and prio_el.text else 999
        gateways.append({'hostname': hostname, 'description': desc,
                         'priority': priority, 'type': 'external'})
    for entry in xml_root.findall('.//internal/list/entry'):
        hostname = entry.get('name', '')
        if not hostname:
            continue
        desc_el  = entry.find('description')
        desc     = (desc_el.text or hostname) if desc_el is not None else hostname
        prio_el  = entry.find('.//priority')
        priority = int(prio_el.text) if prio_el is not None and prio_el.text else 999
        gateways.append({'hostname': hostname, 'description': desc,
                         'priority': priority, 'type': 'internal'})
    gateways.sort(key=lambda x: x['priority'])

    # Internal Host Detection (IHD) — permet de détecter si on est sur le LAN
    ihd = {}
    ihd_el = xml_root.find('.//internal-host-detection')
    if ihd_el is not None:
        ip_el   = ihd_el.find('ip-address')
        host_el = ihd_el.find('host')
        if ip_el is not None and ip_el.text:
            ihd['ip'] = ip_el.text.strip()
        if host_el is not None and host_el.text:
            ihd['host'] = host_el.text.strip()

    # HIP collection interval (secondes)
    hip_interval = 3600
    hip_el = xml_root.find('.//hip-collection/hip-report-interval')
    if hip_el is not None and hip_el.text:
        try:
            hip_interval = int(hip_el.text) * 60
        except ValueError:
            pass

    # ── Diagnostic HIP : la passerelle réclame-t-elle un rapport HIP ? ──
    # PAN-OS retourne dans getconfig.esp un bloc <hip-collection> qui dit :
    #   <collect-hip-data>yes|no</collect-hip-data>      (souvent absent → yes)
    #   <hip-report-interval>60</hip-report-interval>    (en minutes)
    # Sur Prisma Access cloud, c'est typiquement "yes" et l'intervalle 60min.
    # Si "no", openconnect IGNORE le csd-wrapper → aucun HIP n'est jamais
    # envoyé, ce qui peut expliquer un user "no HIP profile".
    collect_hip = 'yes'   # défaut PAN-OS si absent
    collect_el = xml_root.find('.//hip-collection/collect-hip-data')
    if collect_el is not None and collect_el.text:
        collect_hip = collect_el.text.strip().lower()
    # Vendors / produits que la passerelle attend (si exposés dans la config) :
    expected_vendors = []
    for vp in xml_root.findall('.//hip-collection/vendor-product'):
        v_el = vp.find('vendor')
        p_el = vp.find('product')
        if v_el is not None and v_el.text:
            entry = {'vendor': v_el.text.strip(),
                     'product': p_el.text.strip() if (p_el is not None
                                                      and p_el.text) else ''}
            expected_vendors.append(entry)

    _log(f'  [Portal] HIP collect-hip-data    : {collect_hip}')
    _log(f'  [Portal] HIP report interval     : {hip_interval}s')
    if collect_hip == 'no':
        _log('  [Portal] ⚠ La passerelle ne réclame PAS de rapport HIP — '
             'openconnect ignorera le csd-wrapper.')
    if expected_vendors:
        _log(f'  [Portal] HIP vendors/produits attendus '
             f'({len(expected_vendors)}) :')
        for v in expected_vendors:
            _log(f'  [Portal]   • {v["vendor"]} / {v["product"] or "(any)"}')
    else:
        _log('  [Portal] HIP vendors/produits attendus : (non spécifiés '
             'dans getconfig — matching basé sur HIP Objects côté firewall)')

    return gateways, portal_auth_cookie, ihd, hip_interval, collect_hip, expected_vendors


# ─────────────────────────────────────────────
#  Détection réseau interne (auto-switch)
# ─────────────────────────────────────────────

_RFC1918 = (
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16'),
)


def _is_rfc1918(ip_str):
    """Vérifie si une IP est strictement RFC 1918 (réseaux d'entreprise)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RFC1918)
    except ValueError:
        return False


def _looks_like_hostname(name):
    """True si la chaîne ressemble à un hostname DNS (et non à un libellé)."""
    return bool(name) and ' ' not in name and '.' in name


def _is_legacy_hip_template(xml):
    """True si le template HIP utilise l'ancien format ProductInfo/PascalCase.

    Ce format n'est pas matché par les HIP Objects PAN-OS modernes
    (catégories minuscules + <name>/<vendor>/<product-version>).
    """
    if not xml:
        return True
    if '<ProductInfo' in xml or '<Prod ' in xml:
        return True
    if 'name="AntiVirus"' in xml or 'name="Firewall"' in xml:
        return True
    if 'name="host-info"' not in xml and 'name="antivirus"' not in xml:
        return True
    return False


def _resolve_gateway_hostname(preferred, server, gateways=None):
    """Retourne le hostname DNS de la passerelle à sonder.

    Utilise le gateway préféré s'il est un hostname, sinon cherche dans la
    liste getconfig par description, sinon retombe sur le serveur portail.
    """
    if preferred:
        if _looks_like_hostname(preferred):
            return preferred
        if gateways:
            for gw in gateways:
                if preferred in (gw.get('hostname'), gw.get('description')):
                    return gw['hostname']
    return server or None


def _primary_uplink_iface():
    """Interface uplink (route vers Internet), hors tunnels VPN."""
    try:
        out = subprocess.run(
            ['ip', 'route', 'get', '1.1.1.1'],
            check=False, capture_output=True, text=True, timeout=2).stdout
        parts = out.split()
        if 'dev' in parts:
            idx = parts.index('dev')
            if idx + 1 < len(parts):
                iface = parts[idx + 1]
                if not iface.startswith(('tun', 'gpd', 'ppp', 'wg')):
                    return iface
    except Exception:
        pass
    return ''


def _iface_dns_servers(iface):
    """Serveurs DNS IPv4 configurés sur une interface (resolvectl)."""
    if not iface:
        return []
    tool, path = _detect_dns_tool()
    if not path or tool not in ('resolvectl', 'systemd-resolve'):
        return []
    try:
        out = subprocess.run(
            [path, 'status', iface],
            capture_output=True, text=True, timeout=3).stdout
        import re as _re
        servers = []
        for m in _re.finditer(r'DNS Servers?:\s*(.+)', out):
            for tok in m.group(1).split():
                # IPv4 uniquement
                if tok.count('.') == 3 and tok not in servers:
                    servers.append(tok)
        return servers
    except Exception:
        return []


def _dns_query_a(hostname, nameserver, timeout=2.0):
    """Résout les A records via un serveur DNS précis (bypass stub/VPN).

    Utilise dig/host si dispo, sinon requête DNS UDP minimale.
    """
    if not hostname or not nameserver:
        return []
    # 1) dig
    dig = shutil.which('dig')
    if dig:
        try:
            out = subprocess.run(
                [dig, f'@{nameserver}', hostname, 'A',
                 '+short', '+time=2', '+tries=1', '+nosearch'],
                capture_output=True, text=True, timeout=timeout + 1)
            ips = []
            for line in (out.stdout or '').splitlines():
                line = line.strip()
                if line.count('.') == 3 and not line.endswith('.'):
                    try:
                        ipaddress.ip_address(line)
                        ips.append(line)
                    except ValueError:
                        pass
            if ips:
                return ips
        except Exception:
            pass
    # 2) host
    host_bin = shutil.which('host')
    if host_bin:
        try:
            out = subprocess.run(
                [host_bin, '-t', 'A', '-W', str(int(timeout)),
                 hostname, nameserver],
                capture_output=True, text=True, timeout=timeout + 1)
            import re as _re
            ips = _re.findall(
                r'has address\s+(\d+\.\d+\.\d+\.\d+)', out.stdout or '')
            if ips:
                return ips
        except Exception:
            pass
    # 3) Requête DNS UDP minimale (A)
    try:
        import struct, random
        txid = random.randint(0, 65535)
        # Header + QNAME + QTYPE A + QCLASS IN
        labels = hostname.strip('.').encode('idna').split(b'.')
        qname = b''.join(bytes([len(l)]) + l for l in labels) + b'\x00'
        packet = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
        packet += qname + struct.pack('!HH', 1, 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (nameserver, 53))
            data, _ = sock.recvfrom(512)
        finally:
            sock.close()
        if len(data) < 12 or struct.unpack('!H', data[:2])[0] != txid:
            return []
        ancount = struct.unpack('!H', data[6:8])[0]
        # Skip question
        pos = 12
        while pos < len(data) and data[pos] != 0:
            pos += 1 + data[pos]
        pos += 5  # zero + type + class
        ips = []
        for _ in range(ancount):
            if pos >= len(data):
                break
            # Name (possibly pointer)
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while pos < len(data) and data[pos] != 0:
                    pos += 1 + data[pos]
                pos += 1
            if pos + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack('!HHIH', data[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4 and pos + 4 <= len(data):
                ips.append(socket.inet_ntoa(data[pos:pos + 4]))
            pos += rdlen
        return ips
    except Exception:
        return []


def _resolve_portal_via_uplink(hostname, log_fn=None):
    """Résout le portail via le DNS de l'uplink (jamais via tun/VPN).

    Indispensable : si un tunnel est encore monté (DNS Domain ~. sur tun0),
    le résolveur système renvoie l'IP privée interne → faux positif LAN.
    """
    _log = log_fn or (lambda m: None)
    uplink = _primary_uplink_iface()
    servers = _iface_dns_servers(uplink) if uplink else []
    # Fallback : DNS des ifaces non-tunnel via status global
    if not servers:
        tool, path = _detect_dns_tool()
        if path and tool in ('resolvectl', 'systemd-resolve'):
            try:
                out = subprocess.run(
                    [path, 'status'],
                    capture_output=True, text=True, timeout=5).stdout
                import re as _re
                for m in _re.finditer(
                        r'Link \d+ \((?!lo|tun|gpd|ppp|wg|docker|br-|virbr)'
                        r'([^)]+)\)(.*?)(?=Link \d+|\Z)', out, _re.S):
                    block = m.group(2)
                    dm = _re.search(r'DNS Servers?:\s*(.+)', block)
                    if not dm:
                        continue
                    for tok in dm.group(1).split():
                        if tok.count('.') == 3 and tok not in servers:
                            servers.append(tok)
            except Exception:
                pass

    if not servers:
        _log('  [Auto/DNS] Aucun DNS uplink trouvé — fallback résolveur système')
        return None

    _log(f'  [Auto/DNS] Résolution via uplink'
         f'{f" ({uplink})" if uplink else ""} '
         f'DNS={", ".join(servers[:3])}')
    for ns in servers[:4]:
        ips = _dns_query_a(hostname, ns, timeout=2.0)
        if ips:
            return ips
        _log(f'  [Auto/DNS] @{ns} : pas de réponse A pour {hostname}')
    return []


def _detect_lan_by_dns(hostname, log_fn=None):
    """Détecte le réseau via la résolution DNS du portail VPN.

    Critère : résolution via le DNS de l'**uplink** (Wi-Fi/Ethernet),
    jamais via le DNS du tunnel VPN (qui renverrait toujours l'IP privée
    interne une fois le tunnel monté).

      - True  : IP privée RFC 1918 → sur le LAN (sans tunnel)
      - False : IP publique → hors LAN (tunnel requis)
      - None  : résolution impossible → traité comme hors LAN
    """
    _log = log_fn or (lambda m: None)
    if not hostname:
        return None

    ips = _resolve_portal_via_uplink(hostname, log_fn=_log)
    if ips is None:
        # Pas de DNS uplink : dernier recours = getaddrinfo, mais on
        # refuse de conclure "LAN" si un tunnel DNS est actif.
        tun_dns_active = False
        try:
            tool, path = _detect_dns_tool()
            if path and tool in ('resolvectl', 'systemd-resolve'):
                out = subprocess.run(
                    [path, 'status'],
                    capture_output=True, text=True, timeout=3).stdout
                import re as _re
                for m in _re.finditer(
                        r'Link \d+ \((tun\d+|gpd\d+)\)(.*?)(?=Link \d+|\Z)',
                        out, _re.S):
                    block = m.group(2)
                    if 'DNS Domain: ~.' in block or 'Default Route: yes' in block:
                        tun_dns_active = True
                        break
        except Exception:
            pass
        if tun_dns_active:
            _log('  [Auto/DNS] Tunnel DNS actif (tun/~.) sans DNS uplink '
                 'fiable → hors LAN (tunnel requis)')
            return False
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET,
                                       socket.SOCK_STREAM)
            ips = sorted({info[4][0] for info in infos})
            _log(f'  [Auto/DNS] Fallback système → {", ".join(ips)}')
        except socket.gaierror:
            _log(f'  [Auto/DNS] {hostname} : résolution DNS échouée')
            return None

    if not ips:
        _log(f'  [Auto/DNS] {hostname} : aucune adresse IPv4 via uplink')
        return None

    private = [ip for ip in ips if _is_rfc1918(ip)]
    if private:
        shown = ', '.join(private)
        _log(
            f'  [Auto/DNS] {hostname} → {shown} '
            f'(IP privée uplink → réseau interne, sans tunnel)')
        return True
    shown = ', '.join(ips)
    _log(
        f'  [Auto/DNS] {hostname} → {shown} '
        f'(IP publique uplink → hors LAN, tunnel requis)')
    return False


def _has_rfc1918_interface():
    """Retourne True si une interface locale a une IP RFC 1918.

    Indicateur faible : on est probablement sur un réseau d'entreprise
    ou domestique, mais pas forcément sur le LAN du portail. À combiner
    avec une sonde réseau pour conclure.
    """
    try:
        out = subprocess.run(
            ['ip', '-4', '-o', 'addr', 'show', 'scope', 'global'],
            capture_output=True, text=True, timeout=2)
        for line in (out.stdout or '').splitlines():
            # Ignorer tunnels / docker / bridges
            if any(x in line for x in (' tun', ' gpd', ' docker', ' br-',
                                       ' virbr', ' veth')):
                continue
            for tok in line.split():
                if '/' in tok and tok.count('.') == 3:
                    ip = tok.split('/', 1)[0]
                    if _is_rfc1918(ip):
                        return True
    except Exception:
        pass
    return False


def _probe_ihd(ihd, timeout=2.0, log_fn=None):
    """Sonde l'Internal Host Detection (IHD) fourni par le portail.

    PAN-OS publie via getconfig.esp une IP et un hostname interne que le
    client doit pouvoir joindre uniquement depuis le LAN. C'est le signal
    LE PLUS FIABLE pour détecter qu'on est sur le réseau interne, car il
    ne dépend pas du DNS public du portail.

    Retourne True si la sonde IHD réussit, False sinon (ou si l'IHD est
    absent / mal formé).
    """
    _log = log_fn or (lambda m: None)
    if not ihd or not isinstance(ihd, dict):
        return False
    ip   = ihd.get('ip')
    host = ihd.get('host')
    if not ip and not host:
        return False

    # 1. Vérifier la résolution DNS du host IHD si fourni : si le
    #    résolveur retourne l'IP IHD attendue, on est presque sûrement
    #    sur le LAN (le DNS interne répond).
    if host:
        try:
            resolved = socket.gethostbyname(host)
            if ip and resolved == ip:
                _log(f'  [Auto/IHD] {host} → {resolved} (correspond à l\'IHD) '
                     f'→ LAN détecté')
                return True
            if _is_rfc1918(resolved):
                _log(f'  [Auto/IHD] {host} → {resolved} (RFC 1918) '
                     f'→ LAN détecté')
                return True
            _log(f'  [Auto/IHD] {host} → {resolved} (résolu mais hors RFC 1918)')
        except socket.gaierror:
            _log(f'  [Auto/IHD] {host} non résolu (DNS interne absent)')

    # 2. Tenter un TCP connect direct sur l'IP IHD (port 443 puis 80).
    if ip:
        for port in (443, 80):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                rc = sock.connect_ex((ip, port))
            except OSError:
                rc = -1
            finally:
                sock.close()
            if rc == 0:
                _log(f'  [Auto/IHD] {ip}:{port} joignable → LAN détecté')
                return True
        _log(f'  [Auto/IHD] {ip} injoignable (TCP 443/80) → hors LAN')

    return False


def _is_on_internal_network(server, ihd=None, gateway_host=None,
                            timeout=2.0, log_fn=None):
    """Détecte si le poste est sur le réseau interne via DNS du portail.

    Critère unique et fiable — résolution DNS du hostname du portail VPN
    (ex. vpn.company.com) :
      - IP privée RFC 1918 → sur le LAN → mode sans tunnel
      - IP publique / échec DNS → hors LAN → tunnel requis

    gateway_host / ihd / timeout sont ignorés (compatibilité d'appel) :
    seul le portail compte pour la détection.
    """
    _log = log_fn or (lambda m: None)
    del ihd, gateway_host, timeout  # conservés pour compatibilité d'appel

    host = server
    result = _detect_lan_by_dns(host, log_fn=_log)
    if result is not None:
        return result

    _log(f'  [Auto] Portail {host} non résolu → hors LAN (tunnel requis)')
    return False


def _auto_detect_mode(server, ihd=None, gateway_host=None, server_modes=None,
                      server_deployment=None, verify=True,
                      allow_insecure=False, clientos='Linux',
                      timeout=4.0, log_fn=None):
    """Détecte automatiquement le mode de connexion adapté.

    Retourne l'un de :
      - 'internal' : sur le LAN, login + HIP sans tunnel
      - 'portal'   : hors LAN, déploiement cloud (Prisma Access)
      - 'gateway'  : hors LAN, déploiement on-prem (passerelle directe)

    Stratégie :
      1. Résolution DNS du portail VPN :
         - IP privée RFC 1918 → 'internal' (sans tunnel)
         - sinon              → hors LAN (tunnel requis)
      2. Hors LAN : mode mémorisé portal/gateway uniquement
         (jamais 'internal' — celui-ci est décidé uniquement par le DNS)
      3. Sinon sonde prelogin (info) puis défaut 'portal'
    """
    _log = log_fn or (lambda m: None)
    del gateway_host  # détection LAN = DNS portail uniquement

    # 1) Détection LAN via résolution DNS du portail VPN
    if _is_on_internal_network(server, timeout=timeout, log_fn=_log):
        _log('  [Auto] LAN détecté (DNS portail privé) → mode interne '
             '(sans tunnel)')
        return 'internal'

    # 2) Hors LAN : modes mémorisés portal/gateway seulement.
    #    Un ancien 'internal' mémorisé (connexion LAN précédente) ne doit
    #    JAMAIS forcer le no-tunnel quand le DNS du portail est public.
    memorized = (server_modes or {}).get(server)
    if memorized == 'internal':
        _log(f'  [Auto] Mode internal mémorisé pour {server} ignoré '
             f'(hors LAN — DNS portail non privé)')
    elif memorized in ('portal', 'gateway'):
        _log(f'  [Auto] Mode efficace mémorisé pour {server} → {memorized}')
        return memorized

    # 3) Pas de mémoire utile : sonde prelogin pour info, mais on reste prudent.
    info = probe_prelogin(server, verify=verify,
                          allow_insecure=allow_insecure, clientos=clientos)
    if info.get('status') == 'Success':
        is_cloud = bool(info.get('is_cloud'))
        region = info.get('region')
        if is_cloud:
            _log(f'  [Auto] Prelogin → Prisma Access (cloud{f", region={region}" if region else ""})')
        else:
            _log('  [Auto] Prelogin → déploiement on-prem détecté '
                 '(mode portail par sécurité, sera basculé en passerelle '
                 'directe automatiquement après détection)')
    else:
        _log('  [Auto] Prelogin indisponible')

    # 4) Décision finale : défaut 'portal' tant qu'aucun mode hors-LAN n'a
    #    été validé. Le mode 'gateway' sera mémorisé après la 1re connexion
    #    réussie quand pertinent (cf. `_remember_mode_for_server`).
    _log('  [Auto] Mode portail par défaut (sécurité — sera ajusté '
         'automatiquement après la 1re connexion réussie)')
    return 'portal'


# ─────────────────────────────────────────────
#  Mode Passerelle Interne (no-tunnel)
# ─────────────────────────────────────────────

def _get_local_ip(target_host):
    """Retourne l'IP locale utilisée pour joindre target_host (sans connexion)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((target_host, 443))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '0.0.0.0'


def gateway_login(server, cookie_field, cookie_value, username,
                  clientos='Linux', user_agent='PAN GlobalProtect',
                  internal=False, verify=True, allow_insecure=False,
                  log_fn=None):
    """Authentification au gateway (mode tunnel ou no-tunnel).

    Envoie POST /ssl-vpn/prelogin.esp + POST /ssl-vpn/login.esp avec
    `internal=yes` ou `internal=no` selon le paramètre `internal`.

    Le cookie d'entrée peut être un prelogin-cookie (one-shot frais SAML)
    ou un portal-userauthcookie (réutilisable). En sortie, on récupère
    un `authcookie` propre au gateway, qu'openconnect peut consommer
    directement via `--usergroup=gateway:authcookie` sans repasser par
    getconfig/prelogin → contourne les portails Prisma Access qui
    refusent les cookies portail sur leur propre getconfig.

    Retourne un dict avec authcookie, portal, user, domain,
    connection-type, ou lève RuntimeError en cas d'échec.
    """
    _log = log_fn or (lambda m: None)
    os_type = CLIENTOS_OS_MAP.get(clientos, 'mac-intel')
    hostname = socket.gethostname()
    client_ip = _get_local_ip(server)
    s = _make_session(verify=verify, allow_insecure=allow_insecure)
    s.headers['User-Agent'] = user_agent

    # --- Prelogin au gateway ---
    _log(f'  [Internal] Prelogin → {server} (ssl-vpn/prelogin.esp)')
    pre_r = s.post(
        f'https://{server}/ssl-vpn/prelogin.esp',
        verify=verify,
        data={
            'tmp': 'tmp', 'clientVer': '4100',
            'clientos': clientos,
        },
        timeout=15,
    )
    if pre_r.status_code >= 400:
        raise RuntimeError(f'Prelogin gateway HTTP {pre_r.status_code}')

    # --- Login au gateway ---
    _internal_flag = 'yes' if internal else 'no'
    _log(f'  [GW-Login] Login → {server} (ssl-vpn/login.esp, '
         f'internal={_internal_flag})')
    login_data = {
        'prot':        'https:',
        'server':      server,
        'jnlpReady':   'jnlpReady',
        'ok':          'Login',
        'direct':      'yes',
        'clientVer':   '4100',
        'internal':    _internal_flag,
        'clientos':    clientos,
        'os-version':  os_type,
        'computer':    hostname,
        'user':        username,
        'passwd':      '',
        cookie_field:  cookie_value,
        'portal-userauthcookie':         'empty',
        'portal-prelogonuserauthcookie': 'empty',
        'ipv6-support': 'yes',
        'client-ip':   client_ip,
    }
    # En mode tunnel, on n'écrase pas portal-userauthcookie si c'est
    # lui-même le cookie qu'on présente.
    if cookie_field == 'portal-userauthcookie':
        login_data['portal-userauthcookie'] = cookie_value
    login_r = s.post(
        f'https://{server}/ssl-vpn/login.esp',
        verify=verify,
        data=login_data,
        timeout=15,
    )
    if login_r.status_code >= 400:
        raise RuntimeError(f'Login gateway HTTP {login_r.status_code}')

    # --- Parser la réponse XML ---
    try:
        xml_root = ET.fromstring(login_r.content)
    except ET.ParseError as e:
        raise RuntimeError(f'Réponse login non-XML : {e}')

    result = {}

    # Format 1: tags nommes (<authcookie>, <portal>, <user>, etc.)
    for el in xml_root.iter():
        tag = el.tag.lower()
        if tag == 'authcookie' and el.text:
            result['authcookie'] = el.text.strip()
        elif tag == 'portal' and el.text:
            result['portal'] = el.text.strip()
        elif tag == 'user' and el.text:
            result['user'] = el.text.strip()
        elif tag == 'domain' and el.text:
            result['domain'] = el.text.strip()
        elif tag == 'connection-type' and el.text:
            result['connection-type'] = el.text.strip()
        elif tag == 'authentication-source' and el.text:
            result['authentication-source'] = el.text.strip()

    # Format 2: JNLP <argument> positionnels — aligné sur openconnect
    # auth-globalprotect.c (gp_login_args[]).
    if not result.get('authcookie'):
        args = [el.text or '' for el in xml_root.findall('.//argument')]

        def _jnlp_val(idx):
            if idx >= len(args):
                return None
            v = (args[idx] or '').strip()
            if not v or v in ('(null)', '-1'):
                return None
            return unquote(v)

        ac = _jnlp_val(1)
        if ac and len(ac) == 32:
            result['authcookie'] = ac
        if _jnlp_val(3):
            result['portal'] = _jnlp_val(3)
        if _jnlp_val(4):
            result['user'] = _jnlp_val(4)
        if _jnlp_val(5):
            result['authentication-source'] = _jnlp_val(5)
        if _jnlp_val(7):
            result['domain'] = _jnlp_val(7)
        conn = _jnlp_val(11)
        if not conn:
            for v in args:
                vv = (v or '').strip()
                if vv in ('notunnel', 'tunnel'):
                    conn = vv
                    break
        if conn:
            result['connection-type'] = conn
        if _jnlp_val(14):
            result['preferred-ip'] = _jnlp_val(14)
        if ac:
            _log(f'  [Internal] Réponse JNLP parsée (authcookie={ac[:8]}…)')

    conn_type = result.get('connection-type', '')
    _log(f'  [Internal] connection-type={conn_type}')

    if not result.get('authcookie'):
        raise RuntimeError(
            f'Login gateway : authcookie manquant (réponse : {login_r.text[:200]})')

    result['server'] = server
    result['client-ip'] = client_ip
    result['hostname'] = hostname
    result['session'] = s
    return result


def gateway_login_notunnel(server, cookie_field, cookie_value, username,
                           clientos='Mac', user_agent='PAN GlobalProtect',
                           verify=True, allow_insecure=False, log_fn=None):
    """Compat : wrapper historique vers gateway_login(internal=True)."""
    return gateway_login(server, cookie_field, cookie_value, username,
                         clientos=clientos, user_agent=user_agent,
                         internal=True, verify=verify,
                         allow_insecure=allow_insecure, log_fn=log_fn)


def _parse_gp_cookie_str(cookie_str):
    """Décode authcookie=…&portal=… en champs POST plats."""
    fields = {}
    if not cookie_str:
        return fields
    for part in cookie_str.split('&'):
        if '=' in part:
            k, _, v = part.partition('=')
            fields[unquote(k)] = unquote(v)
    return fields


def _build_gp_ssl_vpn_form(cookie_str=None, *, authcookie='', portal='',
                           user='', domain='', computer='',
                           client_ip=None, md5=None, report=None,
                           server=None):
    """Corps POST ssl-vpn/* aligné sur openconnect (champs plats).

    PAN-OS attend authcookie, portal, user, domain et computer comme
    clés de formulaire distinctes — pas un unique champ « cookie ».
    """
    data = {'client-role': 'global-protect-full'}
    if cookie_str:
        data.update(_parse_gp_cookie_str(cookie_str))
    if authcookie:
        data['authcookie'] = authcookie
    if portal:
        data['portal'] = portal
    elif server and not data.get('portal'):
        data['portal'] = server
    if user:
        data['user'] = user
    if domain or 'domain' not in data:
        data['domain'] = domain or data.get('domain', '')
    if computer:
        data['computer'] = computer
    if client_ip:
        data['client-ip'] = client_ip
    if md5:
        data['md5'] = md5
    if report is not None:
        data['report'] = report
    return data


def gateway_hip_check(session, server, authcookie, portal_name,
                      username, domain, hostname, client_ip, md5_token,
                      verify=True, log_fn=None):
    """POST /ssl-vpn/hipreportcheck.esp — vérifie si un HIP report est nécessaire.

    Retourne True si hip-report-needed=yes, False sinon.
    """
    _log = log_fn or (lambda m: None)
    if not portal_name:
        portal_name = server
    r = session.post(
        f'https://{server}/ssl-vpn/hipreportcheck.esp',
        verify=verify,
        data=_build_gp_ssl_vpn_form(
            authcookie=authcookie, portal=portal_name, user=username,
            domain=domain, computer=hostname, client_ip=client_ip,
            md5=md5_token, server=server),
        timeout=15,
    )
    if r.status_code >= 400:
        _log(f'  [HIP] hipreportcheck HTTP {r.status_code}')
        if r.text:
            for ln in r.text.splitlines()[:8]:
                _log(f'  [HIP]   ← {ln}')
        return True  # soumettre quand même en cas de doute
    try:
        xml = ET.fromstring(r.content)
        needed_el = xml.find('.//hip-report-needed')
        if needed_el is not None and needed_el.text:
            needed = needed_el.text.strip().lower()
            _log(f'  [HIP] hip-report-needed = {needed}')
            return needed == 'yes'
        _log('  [HIP] hip-report-needed absent — soumission par précaution')
    except ET.ParseError:
        if r.text:
            _log(f'  [HIP] hipreportcheck réponse non-XML : {r.text[:200]}')
    if r.text and 'status="error"' in r.text.lower():
        _log('  [HIP] ⚠ hipreportcheck : erreur PAN-OS (cookie invalide ?)')
        for ln in r.text.splitlines()[:12]:
            _log(f'  [HIP]   ← {ln}')
    return True


def gateway_hip_submit(session, server, authcookie, portal_name,
                       username, domain, hostname, client_ip, report_xml,
                       verify=True, log_fn=None):
    """POST /ssl-vpn/hipreport.esp — soumet le rapport HIP complet."""
    _log = log_fn or (lambda m: None)
    if not portal_name:
        portal_name = server
    r = session.post(
        f'https://{server}/ssl-vpn/hipreport.esp',
        verify=verify,
        data=_build_gp_ssl_vpn_form(
            authcookie=authcookie, portal=portal_name, user=username,
            domain=domain, computer=hostname, client_ip=client_ip,
            report=report_xml, server=server),
        timeout=15,
    )
    body_err = r.text and 'status="error"' in r.text.lower()
    ok = r.status_code < 400 and not body_err
    if ok:
        _log(f'  [HIP] ✔ hipreport.esp HTTP {r.status_code} '
              f'({len(report_xml)} octets XML)')
    elif body_err:
        _log(f'  [HIP] ✘ hipreport.esp : PAN-OS status=error (HTTP {r.status_code})')
    else:
        _log(f'  [HIP] ✘ hipreport.esp HTTP {r.status_code}')
    if r.text:
        for ln in r.text.splitlines()[:10]:
            _log(f'  [HIP]   ← {ln}')
        if body_err:
            _log('  [HIP] ⚠ PAN-OS a renvoyé une erreur HIP explicite')
    return ok


def gateway_logout(session, server, authcookie, portal_name,
                   username, domain, hostname,
                   verify=True, log_fn=None):
    """POST /ssl-vpn/logout.esp — supprime le user-ID du firewall."""
    _log = log_fn or (lambda m: None)
    if not portal_name:
        portal_name = server
    try:
        session.post(
            f'https://{server}/ssl-vpn/logout.esp',
            verify=verify,
            data=_build_gp_ssl_vpn_form(
                authcookie=authcookie, portal=portal_name, user=username,
                domain=domain, computer=hostname, server=server),
            timeout=10,
        )
        _log('  [Internal] Logout envoyé au gateway.')
    except Exception as e:
        _log(f'  [Internal] Erreur logout : {e}')


def compute_hip_md5(hostname, cookie_str):
    """Calcule le MD5 token à l'identique d'openconnect (gpst.c, build_csd_token).

    Référence : openconnect/gpst.c lignes 835-861 (v9.12) :
        filter_opts(buf, vpninfo->cookie,
                    "authcookie,preferred-ip,preferred-ipv6", 0);
        openconnect_md5(md5, buf->data, buf->pos);

    Algorithme :
      1. Prendre la chaîne cookie complète (k=v séparés par &)
      2. Retirer les couples dont la clé ∈ {authcookie, preferred-ip,
         preferred-ipv6}  — comparaison sur la CLÉ entière, pas un préfixe
      3. Réassembler la chaîne (sans préfixe `computer=...&`)
      4. MD5 hex lowercase

    Le paramètre `hostname` est conservé pour compatibilité d'API mais n'est
    pas utilisé : openconnect n'ajoute PAS de prefix au cookie.
    """
    import hashlib
    _drop = {'authcookie', 'preferred-ip', 'preferred-ipv6'}
    kept = []
    for part in cookie_str.split('&'):
        key = part.split('=', 1)[0]
        if key not in _drop:
            kept.append(part)
    data = '&'.join(kept)
    return hashlib.md5(data.encode()).hexdigest()


# ─────────────────────────────────────────────
#  Dialogue Paramètres
# ─────────────────────────────────────────────

class SettingsDialog(Gtk.Dialog):
    def __init__(self, parent, config):
        super().__init__(
            title="Paramètres",
            parent=parent,
            flags=Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT,
        )
        self.parent_window = parent
        self.config = config
        self.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_SAVE,   Gtk.ResponseType.OK,
        )
        self.set_default_size(560, 620)
        self._build()

    def _build(self):
        outer = self.get_content_area()

        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer.pack_start(sw, True, True, 0)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(14)
        box.set_margin_end(14)
        sw.add(box)

        def section(title):
            lbl = Gtk.Label(xalign=0)
            lbl.set_markup(f'<small><b>{title}</b></small>')
            lbl.set_margin_top(6)
            box.pack_start(lbl, False, False, 0)

        def make_grid():
            g = Gtk.Grid()
            g.set_column_spacing(8)
            g.set_row_spacing(4)
            g.set_margin_start(8)
            return g

        # ── Connexion ──────────────────────────
        section('Connexion')
        grid = make_grid()

        grid.attach(Gtk.Label(label='Serveur VPN :', xalign=1), 0, 0, 1, 1)
        self.server_entry = Gtk.Entry()
        self.server_entry.set_text(self.config.get('server'))
        self.server_entry.set_placeholder_text('vpn.monentreprise.com')
        self.server_entry.set_hexpand(True)
        grid.attach(self.server_entry, 1, 0, 2, 1)

        grid.attach(Gtk.Label(label='Client OS :', xalign=1), 0, 1, 1, 1)
        self.os_combo = Gtk.ComboBoxText()
        for name in ['Windows', 'Mac', 'Linux']:
            self.os_combo.append_text(name)
        cur = self.config.get('clientos', 'Linux')
        self.os_combo.set_active(
            ['Windows', 'Mac', 'Linux'].index(cur)
            if cur in ['Windows', 'Mac', 'Linux'] else 2)
        grid.attach(self.os_combo, 1, 1, 1, 1)

        self._os_warn_label = Gtk.Label(xalign=0)
        self._os_warn_label.set_margin_start(12)
        grid.attach(self._os_warn_label, 0, 2, 2, 1)

        def _on_os_changed_warn(*_args):
            os_name = self.os_combo.get_active_text() or ''
            if os_name == 'Linux':
                self._os_warn_label.set_markup(
                    '<small><span foreground="#e55">⚠ Linux est bloqué par '
                    'le Conditional Access Microsoft Entra ID\n'
                    'sur la plupart des portails cloud (Prisma Access).\n'
                    'Préférez Windows ou Mac. '
                    'L\'auto-détection corrigera au lancement.</span></small>')
            else:
                self._os_warn_label.set_text('')
        self.os_combo.connect('changed', _on_os_changed_warn)
        _on_os_changed_warn()

        box.pack_start(grid, False, False, 0)

        # ── User-Agent ────────────────────────
        section('User-Agent (Conditional Access)')
        ua_grid = make_grid()

        ua_grid.attach(Gtk.Label(label='Présets :', xalign=1), 0, 0, 1, 1)
        self.ua_combo = Gtk.ComboBoxText()
        self.ua_combo.set_hexpand(True)
        ua_grid.attach(self.ua_combo, 1, 0, 2, 1)

        ua_grid.attach(Gtk.Label(label='User-Agent :', xalign=1), 0, 1, 1, 1)
        self.ua_entry = Gtk.Entry()
        self.ua_entry.set_text(self.config.get('user_agent'))
        self.ua_entry.set_hexpand(True)
        ua_grid.attach(self.ua_entry, 1, 1, 2, 1)

        ua_hint = Gtk.Label(xalign=0)
        ua_hint.set_markup(
            '<small><span foreground="#888">Sélectionnez un préset ou '
            'saisissez un User-Agent personnalisé ci-dessus.</span></small>')
        ua_hint.set_margin_start(12)
        ua_grid.attach(ua_hint, 0, 2, 3, 1)

        # Remplir le ComboBox UA selon l'OS sélectionné
        def _populate_ua_combo(*_args):
            self.ua_combo.remove_all()
            os_name = self.os_combo.get_active_text() or 'Linux'
            presets = UA_PRESETS_BY_OS.get(os_name, {})
            current_ua = self.ua_entry.get_text().strip()
            active_idx = 0
            for i, (label, ua) in enumerate(presets.items()):
                self.ua_combo.append_text(label)
                if ua == current_ua:
                    active_idx = i
            if presets:
                self.ua_combo.set_active(active_idx)

        def _on_ua_combo_changed(*_args):
            os_name = self.os_combo.get_active_text() or 'Linux'
            presets = UA_PRESETS_BY_OS.get(os_name, {})
            idx = self.ua_combo.get_active()
            if idx >= 0:
                ua_values = list(presets.values())
                if idx < len(ua_values):
                    self.ua_entry.set_text(ua_values[idx])

        self.ua_combo.connect('changed', _on_ua_combo_changed)
        self.os_combo.connect('changed', _populate_ua_combo)
        _populate_ua_combo()

        box.pack_start(ua_grid, False, False, 0)

        # ── Gateway ───────────────────────────
        section('Gateway préféré')
        gw_grid = make_grid()

        gw_grid.attach(Gtk.Label(label='Nom ou hostname :', xalign=1), 0, 0, 1, 1)
        self.gw_entry = Gtk.Entry()
        self.gw_entry.set_text(self.config.get('preferred_gateway'))
        self.gw_entry.set_placeholder_text('Laisser vide pour demander à chaque connexion')
        self.gw_entry.set_hexpand(True)
        gw_grid.attach(self.gw_entry, 1, 0, 2, 1)
        box.pack_start(gw_grid, False, False, 0)

        # ── HIP (Host Information Profile) ────
        section('HIP — Rapport de conformité du poste')

        hip_info = Gtk.Label(xalign=0)
        hip_info.set_markup(
            '<small><span foreground="#666">Le rapport HIP informe le gateway Palo Alto '
            'sur l\'état de sécurité du poste\n'
            '(pare-feu, antivirus, chiffrement disque…). '
            'Requis pour un accès VPN complet.</span></small>')
        hip_info.set_margin_start(12)
        hip_info.set_line_wrap(True)
        box.pack_start(hip_info, False, False, 0)

        hip_grid = make_grid()

        # Activer HIP
        self.hip_check = Gtk.CheckButton(
            label='Envoyer automatiquement le rapport HIP après connexion')
        self.hip_check.set_active(self.config.get('hip_enabled', True))
        hip_grid.attach(self.hip_check, 0, 0, 4, 1)

        # Mode : intégré / personnalisé / fake
        hip_grid.attach(Gtk.Label(label='Mode HIP :', xalign=1), 0, 1, 1, 1)
        self.hip_builtin_radio = Gtk.RadioButton.new_with_label(
            None, 'Script intégré')
        hip_grid.attach(self.hip_builtin_radio, 1, 1, 1, 1)
        self.hip_custom_radio = Gtk.RadioButton.new_with_label_from_widget(
            self.hip_builtin_radio, 'Script personnalisé')
        hip_grid.attach(self.hip_custom_radio, 2, 1, 1, 1)
        self.hip_fake_radio = Gtk.RadioButton.new_with_label_from_widget(
            self.hip_builtin_radio, 'Valeurs simulées (fake)')
        self.hip_fake_radio.set_tooltip_text(
            'Envoie un rapport HIP avec des valeurs définies manuellement,\n'
            'sans détecter la configuration réelle du poste.')
        hip_grid.attach(self.hip_fake_radio, 3, 1, 1, 1)

        hip_mode = self.config.get('hip_mode', 'builtin')
        if hip_mode == 'custom':
            self.hip_custom_radio.set_active(True)
        elif hip_mode == 'fake':
            self.hip_fake_radio.set_active(True)

        # Chemin script personnalisé
        hip_grid.attach(Gtk.Label(label='Chemin :', xalign=1), 0, 2, 1, 1)
        self.hip_script_entry = Gtk.Entry()
        self.hip_script_entry.set_text(self.config.get('hip_script', ''))
        self.hip_script_entry.set_placeholder_text('/chemin/vers/hipreport.py')
        self.hip_script_entry.set_hexpand(True)
        hip_grid.attach(self.hip_script_entry, 1, 2, 2, 1)

        hip_browse_btn = Gtk.Button(label='Parcourir…')
        hip_browse_btn.connect('clicked', self._on_hip_browse)
        hip_grid.attach(hip_browse_btn, 3, 2, 1, 1)

        # Afficher le chemin intégré en info
        builtin_lbl = Gtk.Label(xalign=0)
        builtin_lbl.set_markup(
            f'<small><span foreground="#888">Script intégré : '
            f'{HIP_SCRIPT_BUILTIN}</span></small>')
        hip_grid.attach(builtin_lbl, 1, 3, 3, 1)

        box.pack_start(hip_grid, False, False, 0)

        # ── Boutons template HIP (toujours visibles) ──
        hip_tpl_box = Gtk.Box(spacing=8)
        hip_tpl_box.set_margin_start(12)
        hip_tpl_box.set_margin_top(4)

        open_tpl_btn = Gtk.Button()
        open_tpl_inner = Gtk.Box(spacing=6)
        open_tpl_inner.pack_start(
            Gtk.Image.new_from_icon_name('document-open-symbolic',
                                         Gtk.IconSize.BUTTON),
            False, False, 0)
        open_tpl_inner.pack_start(
            Gtk.Label(label='Ouvrir le template HIP…'), False, False, 0)
        open_tpl_btn.add(open_tpl_inner)
        open_tpl_btn.set_tooltip_text(
            f'Ouvre {CONFIG_DIR}/hip_template.xml dans l\'éditeur système')
        open_tpl_btn.connect('clicked', self._on_open_fake_hip_file)
        hip_tpl_box.pack_start(open_tpl_btn, False, False, 0)

        regen_tpl_btn = Gtk.Button()
        regen_tpl_inner = Gtk.Box(spacing=6)
        regen_tpl_inner.pack_start(
            Gtk.Image.new_from_icon_name('view-refresh-symbolic',
                                         Gtk.IconSize.BUTTON),
            False, False, 0)
        regen_tpl_inner.pack_start(
            Gtk.Label(label='Regénérer le template par défaut'),
            False, False, 0)
        regen_tpl_btn.add(regen_tpl_inner)
        regen_tpl_btn.set_tooltip_text(
            'Recrée le template avec les valeurs par défaut '
            '(Trend Micro, LUKS, Intune)')
        regen_tpl_btn.connect('clicked', self._on_regen_default_hip_template)
        hip_tpl_box.pack_start(regen_tpl_btn, False, False, 0)

        # Bouton "Regenerer comme un client Windows" : permet de spoofer un
        # poste Windows quand les HIP Objects du tenant Prisma ne ciblent
        # que Windows/Mac et qu'aucun n'est defini pour Linux. Souvent la
        # cause de "no HIP profile assigned" en cloud.
        win_tpl_btn = Gtk.Button()
        win_tpl_inner = Gtk.Box(spacing=6)
        win_tpl_inner.pack_start(
            Gtk.Image.new_from_icon_name('computer-symbolic',
                                         Gtk.IconSize.BUTTON),
            False, False, 0)
        win_tpl_inner.pack_start(
            Gtk.Label(label='Mimic Windows'), False, False, 0)
        win_tpl_btn.add(win_tpl_inner)
        win_tpl_btn.set_tooltip_text(
            "Génère un template HIP qui imite un client Windows 10 :\n"
            "OS=Microsoft Windows / Defender / BitLocker / Windows Firewall.\n"
            "Utile quand le tenant Prisma n'a pas de HIP Object pour Linux.")
        win_tpl_btn.connect('clicked', self._on_regen_windows_hip_template)
        hip_tpl_box.pack_start(win_tpl_btn, False, False, 0)

        box.pack_start(hip_tpl_box, False, False, 0)

        hip_tpl_path_lbl = Gtk.Label(xalign=0)
        hip_tpl_path_lbl.set_markup(
            f'<small><span foreground="#888">📄 Template : '
            f'{CONFIG_DIR}/hip_template.xml</span></small>')
        hip_tpl_path_lbl.set_margin_start(12)
        box.pack_start(hip_tpl_path_lbl, False, False, 2)

        # ── Panneau fake HIP ──────────────────
        self.fake_frame = Gtk.Frame()
        self.fake_frame.set_margin_start(12)
        self.fake_frame.set_margin_top(4)
        fake_lbl = Gtk.Label()
        fake_lbl.set_markup('<b> Valeurs simulées du rapport HIP </b>')
        self.fake_frame.set_label_widget(fake_lbl)
        self.fake_frame.set_no_show_all(True)

        fake_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        fake_box.set_margin_top(8)
        fake_box.set_margin_bottom(8)
        fake_box.set_margin_start(10)
        fake_box.set_margin_end(10)

        fg = Gtk.Grid()
        fg.set_column_spacing(10)
        fg.set_row_spacing(6)

        # Nom d'hôte simulé
        fg.attach(Gtk.Label(label='Nom d\'hôte :', xalign=1), 0, 0, 1, 1)
        self.fake_hostname_entry = Gtk.Entry()
        self.fake_hostname_entry.set_text(self.config.get('hip_fake_hostname', ''))
        self.fake_hostname_entry.set_placeholder_text('Laisser vide = nom réel')
        self.fake_hostname_entry.set_hexpand(True)
        fg.attach(self.fake_hostname_entry, 1, 0, 3, 1)

        # Pare-feu
        self.fake_fw_check = Gtk.CheckButton(label='Pare-feu actif')
        self.fake_fw_check.set_active(self.config.get('hip_fake_firewall', False))
        fg.attach(self.fake_fw_check, 0, 1, 2, 1)
        fg.attach(Gtk.Label(label='Nom :', xalign=1), 2, 1, 1, 1)
        self.fake_fw_name_entry = Gtk.Entry()
        self.fake_fw_name_entry.set_text(self.config.get('hip_fake_firewall_name', 'UFW'))
        self.fake_fw_name_entry.set_hexpand(True)
        fg.attach(self.fake_fw_name_entry, 3, 1, 1, 1)

        # Antivirus (Anti-Malware) — vendor + product matchent le HIP Object
        self.fake_av_check = Gtk.CheckButton(label='Antivirus actif')
        self.fake_av_check.set_active(self.config.get('hip_fake_antivirus', True))
        fg.attach(self.fake_av_check, 0, 2, 1, 1)
        self.fake_av_rt_check = Gtk.CheckButton(label='Real-time protection')
        self.fake_av_rt_check.set_active(
            self.config.get('hip_fake_antivirus_real_time', True))
        fg.attach(self.fake_av_rt_check, 1, 2, 4, 1)

        # Ligne 3 : Vendor
        fg.attach(Gtk.Label(label='AV Vendor :', xalign=1), 0, 3, 1, 1)
        self.fake_av_vendor_entry = Gtk.Entry()
        self.fake_av_vendor_entry.set_text(
            self.config.get('hip_fake_antivirus_vendor', 'Trend Micro, Inc.'))
        self.fake_av_vendor_entry.set_placeholder_text('ex : Trend Micro, Inc.')
        self.fake_av_vendor_entry.set_hexpand(True)
        fg.attach(self.fake_av_vendor_entry, 1, 3, 4, 1)

        # Ligne 4 : Product + version
        fg.attach(Gtk.Label(label='AV Produit :', xalign=1), 0, 4, 1, 1)
        self.fake_av_name_entry = Gtk.Entry()
        self.fake_av_name_entry.set_text(self.config.get(
            'hip_fake_antivirus_name', 'Trend Micro Deep Security Agent'))
        self.fake_av_name_entry.set_placeholder_text(
            'ex : Trend Micro Deep Security Agent')
        self.fake_av_name_entry.set_hexpand(True)
        fg.attach(self.fake_av_name_entry, 1, 4, 3, 1)
        fg.attach(Gtk.Label(label='Ver. :', xalign=1), 4, 4, 1, 1)
        # NB: la grille a 5 colonnes ; "Ver." est attaché en col 4 et l'Entry
        # est placée sur la ligne suivante pour ne pas casser la mise en page.
        self.fake_av_ver_entry = Gtk.Entry()
        self.fake_av_ver_entry.set_text(
            self.config.get('hip_fake_antivirus_version', '20.0.0.0000'))
        self.fake_av_ver_entry.set_width_chars(12)
        fg.attach(self.fake_av_ver_entry, 5, 4, 1, 1)

        # Chiffrement disque
        self.fake_enc_check = Gtk.CheckButton(label='Chiffrement disque (LUKS)')
        self.fake_enc_check.set_active(self.config.get('hip_fake_encryption', True))
        fg.attach(self.fake_enc_check, 0, 5, 6, 1)

        # MDM (Intune)
        self.fake_mdm_check = Gtk.CheckButton(label='MDM déployé')
        self.fake_mdm_check.set_active(self.config.get('hip_fake_mdm', True))
        fg.attach(self.fake_mdm_check, 0, 6, 2, 1)
        fg.attach(Gtk.Label(label='Produit :', xalign=1), 2, 6, 1, 1)
        self.fake_mdm_name_entry = Gtk.Entry()
        self.fake_mdm_name_entry.set_text(
            self.config.get('hip_fake_mdm_name', 'Microsoft Intune'))
        self.fake_mdm_name_entry.set_hexpand(True)
        fg.attach(self.fake_mdm_name_entry, 3, 6, 3, 1)

        # Sauvegarde
        self.fake_bk_check = Gtk.CheckButton(label='Sauvegarde activée')
        self.fake_bk_check.set_active(self.config.get('hip_fake_backup', False))
        fg.attach(self.fake_bk_check, 0, 7, 2, 1)
        fg.attach(Gtk.Label(label='Outil :', xalign=1), 2, 7, 1, 1)
        self.fake_bk_name_entry = Gtk.Entry()
        self.fake_bk_name_entry.set_text(
            self.config.get('hip_fake_backup_name', 'timeshift'))
        self.fake_bk_name_entry.set_hexpand(True)
        fg.attach(self.fake_bk_name_entry, 3, 7, 3, 1)

        def _update_fake_sens(*_):
            av_on = self.fake_av_check.get_active()
            self.fake_av_vendor_entry.set_sensitive(av_on)
            self.fake_av_name_entry.set_sensitive(av_on)
            self.fake_av_ver_entry.set_sensitive(av_on)
            self.fake_av_rt_check.set_sensitive(av_on)
            fw_on = self.fake_fw_check.get_active()
            self.fake_fw_name_entry.set_sensitive(fw_on)
            mdm_on = self.fake_mdm_check.get_active()
            self.fake_mdm_name_entry.set_sensitive(mdm_on)
            bk_on = self.fake_bk_check.get_active()
            self.fake_bk_name_entry.set_sensitive(bk_on)

        self.fake_av_check.connect('toggled', _update_fake_sens)
        self.fake_fw_check.connect('toggled', _update_fake_sens)
        self.fake_mdm_check.connect('toggled', _update_fake_sens)
        self.fake_bk_check.connect('toggled', _update_fake_sens)
        _update_fake_sens()

        fake_box.pack_start(fg, False, False, 0)

        # Bouton pour générer et éditer le XML
        edit_btn = Gtk.Button()
        edit_btn_inner = Gtk.Box(spacing=6)
        edit_btn_inner.pack_start(
            Gtk.Image.new_from_icon_name('text-editor-symbolic', Gtk.IconSize.BUTTON),
            False, False, 0)
        edit_btn_inner.pack_start(
            Gtk.Label(label='Générer et modifier le rapport XML…'),
            False, False, 0)
        edit_btn.add(edit_btn_inner)
        edit_btn.set_margin_top(6)
        edit_btn.connect('clicked', self._on_edit_fake_hip)
        fake_box.pack_start(edit_btn, False, False, 0)

        open_btn = Gtk.Button(label='Ouvrir le fichier template…')
        open_btn.connect('clicked', self._on_open_fake_hip_file)
        fake_box.pack_start(open_btn, False, False, 0)

        saved_lbl = Gtk.Label(xalign=0)
        saved_lbl.set_markup(
            f'<small><span foreground="#888">Template sauvegardé : '
            f'{CONFIG_DIR}/hip_template.xml</span></small>')
        fake_box.pack_start(saved_lbl, False, False, 0)

        self.fake_frame.add(fake_box)
        box.pack_start(self.fake_frame, False, False, 0)

        # Lier sensibilité des widgets HIP
        def _update_hip_sens(*_):
            enabled = self.hip_check.get_active()
            custom  = self.hip_custom_radio.get_active()
            fake    = self.hip_fake_radio.get_active()
            self.hip_builtin_radio.set_sensitive(enabled)
            self.hip_custom_radio.set_sensitive(enabled)
            self.hip_fake_radio.set_sensitive(enabled)
            self.hip_script_entry.set_sensitive(enabled and custom)
            hip_browse_btn.set_sensitive(enabled and custom)
            if enabled and fake:
                self.fake_frame.show_all()   # show_all() pour révéler les enfants
            else:
                self.fake_frame.hide()

        self.hip_check.connect('toggled', _update_hip_sens)
        self.hip_builtin_radio.connect('toggled', _update_hip_sens)
        self.hip_custom_radio.connect('toggled', _update_hip_sens)
        self.hip_fake_radio.connect('toggled', _update_hip_sens)
        _update_hip_sens()

        # ── Avancé ────────────────────────────
        section('Avancé')
        adv_grid = make_grid()

        self.verify_check = Gtk.CheckButton(label='Vérifier le certificat SSL du serveur')
        self.verify_check.set_active(self.config.get('verify_ssl', True))
        adv_grid.attach(self.verify_check, 0, 0, 2, 1)

        self.insecure_crypto_check = Gtk.CheckButton(
            label='Autoriser la renegociation TLS legacy (--allow-insecure-crypto)')
        self.insecure_crypto_check.set_active(
            self.config.get('allow_insecure_crypto', False))
        insecure_info = Gtk.Label(xalign=0)
        insecure_info.set_markup(
            '<small><span foreground="#888">Nécessaire si le serveur retourne '
            '"unsafe legacy renegotiation disabled"</span></small>')
        insecure_info.set_margin_start(24)
        adv_grid.attach(self.insecure_crypto_check, 0, 1, 2, 1)
        adv_grid.attach(insecure_info, 0, 2, 2, 1)

        # ── Mode de connexion ──────────────────────────────
        adv_grid.attach(Gtk.Separator(), 0, 3, 2, 1)
        adv_grid.attach(Gtk.Label(label='Mode connexion :', xalign=1), 0, 4, 1, 1)

        conn_mode_box = Gtk.Box(spacing=6)
        self.conn_auto_radio = Gtk.RadioButton.new_with_label(
            None, 'Auto (interne/externe)')
        self.conn_auto_radio.set_tooltip_text(
            'Détecte automatiquement le mode adapté :\n'
            '• Sur le LAN (DNS du portail → IP privée) → interne (sans tunnel)\n'
            '• Hors LAN (DNS du portail → IP publique) → tunnel\n'
            '  (cloud Prisma Access → portail, on-prem → passerelle directe)')
        self.conn_portal_radio = Gtk.RadioButton.new_with_label_from_widget(
            self.conn_auto_radio, 'Portail interactif')
        self.conn_portal_radio.set_tooltip_text(
            'Connexion via le portail (recommandé pour les serveurs cloud).\n'
            'openconnect appelle getconfig.esp en interne et affiche\n'
            'la liste des gateways disponibles.')
        self.conn_gateway_radio = Gtk.RadioButton.new_with_label_from_widget(
            self.conn_auto_radio, 'Passerelle directe (on-prem)')
        self.conn_gateway_radio.set_tooltip_text(
            'Envoie le cookie SAML directement au gateway sans passer\n'
            'par getconfig.esp. Recommandé quand le portail et le gateway\n'
            'sont sur le même hôte (ex. vpn.company.com).')
        self.conn_internal_radio = Gtk.RadioButton.new_with_label_from_widget(
            self.conn_auto_radio, 'Passerelle interne (sans tunnel)')
        self.conn_internal_radio.set_tooltip_text(
            'Authentification + rapports HIP périodiques sans monter\n'
            'de tunnel VPN. Le firewall connaît votre identité et\n'
            'l\'état de sécurité du poste (user-ID + HIP).\n'
            'Utile quand vous êtes déjà sur le réseau interne.')
        conn_mode_box.pack_start(self.conn_auto_radio,     False, False, 0)
        conn_mode_box.pack_start(self.conn_portal_radio,   False, False, 0)
        conn_mode_box.pack_start(self.conn_gateway_radio,  False, False, 0)
        conn_mode_box.pack_start(self.conn_internal_radio, False, False, 0)
        adv_grid.attach(conn_mode_box, 1, 4, 1, 1)

        conn_mode_info = Gtk.Label(xalign=0)
        conn_mode_info.set_markup(
            '<small><span foreground="#888">'
            'Auto → DNS du portail : IP privée = LAN (sans tunnel),\n'
            'IP publique = tunnel (portail ou passerelle selon le déploiement)\n'
            'Cloud gateways (Prisma) → Portail interactif\n'
            'On-prem / même hôte → Passerelle directe\n'
            'Déjà sur le LAN → Passerelle interne (sans tunnel)'
            '</span></small>')
        conn_mode_info.set_margin_start(24)
        adv_grid.attach(conn_mode_info, 0, 5, 2, 1)

        self.force_dns_check = Gtk.CheckButton(
            label='Forcer tout le DNS via le tunnel VPN')
        self.force_dns_check.set_active(self.config.get('force_vpn_dns', True))
        adv_grid.attach(self.force_dns_check, 0, 6, 2, 1)
        force_dns_info = Gtk.Label(xalign=0)
        force_dns_info.set_markup(
            '<small><span foreground="#888">'
            'Applique resolvectl domain &lt;tun&gt; ~. après connexion.\n'
            'Utile si des domaines ne se résolvent pas hors split-DNS.'
            '</span></small>')
        force_dns_info.set_margin_start(24)
        adv_grid.attach(force_dns_info, 0, 7, 2, 1)

        adv_grid.attach(
            Gtk.Label(label='DNS VPN (fallback) :', xalign=1), 0, 8, 1, 1)
        self.vpn_dns_entry = Gtk.Entry()
        self.vpn_dns_entry.set_text(
            self.config.get('vpn_dns_servers', ''))
        self.vpn_dns_entry.set_placeholder_text(
            '10.0.0.1, 10.0.0.2')
        self.vpn_dns_entry.set_tooltip_text(
            'Serveurs DNS du VPN (séparés par des virgules).\n'
            'Utilisé si vpnc-script ne configure pas les DNS.\n'
            'Se remplit automatiquement après une connexion réussie\n'
            'depuis le réseau interne.')
        adv_grid.attach(self.vpn_dns_entry, 1, 8, 1, 1)

        adv_grid.attach(
            Gtk.Label(label='Domaines VPN :', xalign=1), 0, 9, 1, 1)
        self.vpn_suffix_entry = Gtk.Entry()
        self.vpn_suffix_entry.set_text(
            self.config.get('vpn_dns_suffixes', ''))
        self.vpn_suffix_entry.set_placeholder_text(
            'corp.local, internal.lan')
        self.vpn_suffix_entry.set_tooltip_text(
            'Suffixes DNS du VPN (séparés par des virgules).')
        adv_grid.attach(self.vpn_suffix_entry, 1, 9, 1, 1)

        self.minimize_tray_check = Gtk.CheckButton(
            label='Fermer la fenêtre => réduire dans la zone de notification')
        self.minimize_tray_check.set_active(
            self.config.get('minimize_to_tray', True))
        adv_grid.attach(self.minimize_tray_check, 0, 8, 2, 1)

        adv_grid.attach(Gtk.Separator(), 0, 9, 2, 1)
        sudo_box = Gtk.Box(spacing=6)
        sudo_btn = Gtk.Button(label='Config. sudo')
        sudo_btn.set_tooltip_text(
            'Configurer openconnect/resolvectl sans mot de passe sudo')
        sudo_btn.connect('clicked', self._on_setup_sudo_clicked)
        sudo_box.pack_start(sudo_btn, False, False, 0)
        sudo_rm_btn = Gtk.Button(label='Supprimer config sudo')
        sudo_rm_btn.set_tooltip_text(
            'Supprime la règle sudoers créée par GP Connect')
        sudo_rm_btn.connect('clicked', self._on_remove_sudo_clicked)
        sudo_box.pack_start(sudo_rm_btn, False, False, 0)
        sudo_help = Gtk.Label(xalign=0)
        sudo_help.set_markup(
            '<small><span foreground="#888">'
            'À faire une seule fois pour éviter les prompts et appliquer le DNS.'
            '</span></small>')
        sudo_box.pack_start(sudo_help, False, False, 0)
        adv_grid.attach(sudo_box, 0, 10, 2, 1)

        _cm = self.config.get('connection_mode', 'auto')
        if _cm == 'auto':
            self.conn_auto_radio.set_active(True)
        elif _cm == 'gateway':
            self.conn_gateway_radio.set_active(True)
        elif _cm == 'internal':
            self.conn_internal_radio.set_active(True)
        else:
            self.conn_portal_radio.set_active(True)

        box.pack_start(adv_grid, False, False, 0)

        outer.show_all()

    def _generate_fake_hip_xml(self, client_ip='0.0.0.0', md5='<md5-placeholder>',
                               username='', ipv6=''):
        """Génère le XML HIP à partir des valeurs simulées configurées dans le dialogue."""
        import socket as _socket, uuid as _uuid
        from datetime import datetime as _dt

        hostname  = self.fake_hostname_entry.get_text().strip() or _socket.gethostname()
        has_fw    = self.fake_fw_check.get_active()
        fw_name   = self.fake_fw_name_entry.get_text().strip() or 'UFW'
        has_av    = self.fake_av_check.get_active()
        av_vendor = (self.fake_av_vendor_entry.get_text().strip()
                     or 'Trend Micro, Inc.')
        av_name   = (self.fake_av_name_entry.get_text().strip()
                     or 'Trend Micro Deep Security Agent')
        av_ver    = self.fake_av_ver_entry.get_text().strip() or '20.0.0.0000'
        av_rt     = self.fake_av_rt_check.get_active()
        has_enc   = self.fake_enc_check.get_active()
        has_mdm   = self.fake_mdm_check.get_active()
        mdm_name  = self.fake_mdm_name_entry.get_text().strip() or 'Microsoft Intune'
        has_bk    = self.fake_bk_check.get_active()
        bk_name   = self.fake_bk_name_entry.get_text().strip() or 'timeshift'
        now       = _dt.now().strftime('%m/%d/%Y %H:%M:%S')
        # host-id = UUID DMI/SMBIOS — colonne HOST ID dans la console Palo Alto
        host_id   = _get_dmi_machine_uuid()
        if not username:
            username = self.config.get('last_username', 'user@example.com')

        # OS pour matcher "Host Info → OS Contains Linux"
        os_label  = 'Linux'
        try:
            with open('/etc/os-release') as _f:
                _osr = {ln.split('=', 1)[0]: ln.split('=', 1)[1].strip().strip('"')
                        for ln in _f if '=' in ln}
            os_label = f"Linux {_osr.get('NAME', 'Linux')} {_osr.get('VERSION_ID', '')}".strip()
        except Exception:
            pass

        def _e(s):
            return (str(s).replace('&', '&amp;').replace('<', '&lt;')
                    .replace('>', '&gt;').replace('"', '&quot;'))

        rt_str = 'yes' if av_rt else 'no'
        defver = _dt.now().strftime('%Y%m%d')
        am = (f'''      <list>
        <entry>
          <vendor>{_e(av_vendor)}</vendor>
          <name>{_e(av_name)}</name>
          <product-version>{_e(av_ver)}</product-version>
          <real-time-protection>{rt_str}</real-time-protection>
          <definition-version>{defver}</definition-version>
          <last-scan-time>{now}</last-scan-time>
        </entry>
      </list>''' if has_av else '      <list/>')

        fw = (f'''      <list>
        <entry>
          <name>{_e(fw_name)}</name>
          <status>yes</status>
        </entry>
      </list>''' if has_fw else '''      <list>
        <entry>
          <name>iptables</name>
          <status>no</status>
        </entry>
      </list>''')

        enc = ('''      <list>
        <entry>
          <name>LUKS</name>
          <status>yes</status>
        </entry>
      </list>''' if has_enc else '      <list/>')

        bk = (f'''      <list>
        <entry>
          <name>{_e(bk_name)}</name>
          <status>yes</status>
        </entry>
      </list>''' if has_bk else '      <list/>')

        mdm = (f'''      <list>
        <entry>
          <name>{_e(mdm_name)}</name>
          <status>yes</status>
        </entry>
      </list>''' if has_mdm else '      <list/>')

        # Format aligné sur la doc Palo Alto :
        #   • <hip-report> sans attribut name
        #   • Syntaxe simplifiée : <name>, <vendor>, <product-version>,
        #     <real-time-protection>, <definition-version>, <last-scan-time>
        #   • Catégories en minuscules
        #   • antivirus + anti-malware émis tous deux (compat PAN-OS)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<hip-report>
  <md5-sum>{_e(md5)}</md5-sum>
  <user-name>{_e(username)}</user-name>
  <domain></domain>
  <host-name>{_e(hostname)}</host-name>
  <host-id>{_e(host_id)}</host-id>
  <ip-address>{_e(client_ip)}</ip-address>
  <ipv6-address>{_e(ipv6)}</ipv6-address>
  <generate-time>{now}</generate-time>
  <hip-report-version>4</hip-report-version>
  <categories>
    <entry name="host-info">
      <client-version>6.0.0-1</client-version>
      <os>{_e(os_label)}</os>
      <os-vendor>Linux</os-vendor>
      <domain></domain>
      <host-name>{_e(hostname)}</host-name>
      <host-id>{_e(host_id)}</host-id>
      <network-interface>
        <entry name="eth0">
          <description>eth0</description>
          <mac-address>00:00:00:00:00:00</mac-address>
          <ip-address><entry name="{_e(client_ip)}"/></ip-address>
        </entry>
      </network-interface>
    </entry>
    <entry name="antivirus">
{am}
    </entry>
    <entry name="anti-malware">
{am}
    </entry>
    <entry name="disk-backup">
{bk}
    </entry>
    <entry name="disk-encryption">
{enc}
    </entry>
    <entry name="firewall">
{fw}
    </entry>
    <entry name="patch-management">
      <list/>
    </entry>
    <entry name="data-loss-prevention">
      <list/>
    </entry>
    <entry name="mobile-device-management">
{mdm}
    </entry>
  </categories>
</hip-report>"""

    def _on_edit_fake_hip(self, _btn):
        """Ouvre l'éditeur XML pour le rapport HIP fake."""
        xml = self._generate_fake_hip_xml()
        dlg = HipXmlEditorDialog(self, xml)
        if dlg.run() == Gtk.ResponseType.OK:
            edited = dlg.get_xml()
            try:
                CONFIG_DIR.mkdir(parents=True, exist_ok=True)
                with open(CONFIG_DIR / 'hip_template.xml', 'w') as f:
                    f.write(edited)
                info_dlg = Gtk.MessageDialog(
                    parent=self, flags=Gtk.DialogFlags.MODAL,
                    type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK,
                    message_format='Template HIP sauvegardé ✔')
                info_dlg.format_secondary_text(
                    str(CONFIG_DIR / 'hip_template.xml'))
                info_dlg.run()
                info_dlg.destroy()
            except Exception as e:
                err_dlg = Gtk.MessageDialog(
                    parent=self, flags=Gtk.DialogFlags.MODAL,
                    type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.OK,
                    message_format=f'Erreur sauvegarde : {e}')
                err_dlg.run()
                err_dlg.destroy()
        dlg.destroy()

    def _on_hip_browse(self, _btn):
        dlg = Gtk.FileChooserDialog(
            title='Choisir le script HIP',
            parent=self,
            action=Gtk.FileChooserAction.OPEN,
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_OPEN,   Gtk.ResponseType.OK,
        )
        flt = Gtk.FileFilter()
        flt.set_name('Scripts Python (*.py)')
        flt.add_pattern('*.py')
        dlg.add_filter(flt)
        if dlg.run() == Gtk.ResponseType.OK:
            self.hip_script_entry.set_text(dlg.get_filename())
        dlg.destroy()

    def _on_setup_sudo_clicked(self, _btn):
        parent = self.parent_window
        if parent and hasattr(parent, '_on_setup_sudo'):
            parent._on_setup_sudo(None)

    def _on_open_fake_hip_file(self, _btn):
        path = CONFIG_DIR / 'hip_template.xml'
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                with open(path, 'w') as f:
                    f.write(self._generate_fake_hip_xml())
            subprocess.Popen(['xdg-open', str(path)])
        except Exception as e:
            err_dlg = Gtk.MessageDialog(
                parent=self, flags=Gtk.DialogFlags.MODAL,
                type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.OK,
                message_format=f'Impossible d\'ouvrir le template : {e}')
            err_dlg.run()
            err_dlg.destroy()

    def _on_regen_default_hip_template(self, _btn):
        """Regénère le template HIP avec les valeurs par défaut."""
        path = CONFIG_DIR / 'hip_template.xml'
        try:
            xml = self._generate_fake_hip_xml()
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                f.write(xml)
            dlg = Gtk.MessageDialog(
                parent=self, flags=Gtk.DialogFlags.MODAL,
                type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK,
                message_format='Template HIP regénéré ✔')
            dlg.format_secondary_text(
                f'Valeurs par défaut appliquées :\n'
                f'• Antivirus : Trend Micro (actif)\n'
                f'• Chiffrement : LUKS partition complète\n'
                f'• MDM : Microsoft Intune (déployé)\n\n'
                f'Fichier : {path}')
            dlg.run()
            dlg.destroy()
        except Exception as e:
            err_dlg = Gtk.MessageDialog(
                parent=self, flags=Gtk.DialogFlags.MODAL,
                type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.OK,
                message_format=f'Erreur : {e}')
            err_dlg.run()
            err_dlg.destroy()

    def _on_regen_windows_hip_template(self, _btn):
        """Regénère le template HIP en imitant un client Windows 10.

        Utile quand les HIP Objects du tenant Prisma Access ne ciblent que
        des postes Windows/Mac (cas fréquent en cloud) et qu'aucun n'est
        défini pour Linux. C'est la solution la plus rapide pour valider
        l'hypothèse "no HIP profile = pas de HIP Object Linux".
        """
        path = CONFIG_DIR / 'hip_template.xml'
        try:
            xml = self._generate_windows_hip_xml()
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                f.write(xml)
            dlg = Gtk.MessageDialog(
                parent=self, flags=Gtk.DialogFlags.MODAL,
                type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK,
                message_format='Template HIP « Windows » regénéré ✔')
            dlg.format_secondary_text(
                'Valeurs simulées :\n'
                '• OS              : Microsoft Windows 10 Pro , 64-bit\n'
                '• OS Vendor       : Microsoft\n'
                '• Client version  : 6.2.4-26\n'
                '• Antivirus       : Microsoft / Windows Defender\n'
                '• Firewall        : Microsoft / Windows Firewall\n'
                '• Disk encryption : Microsoft / Windows BitLocker\n'
                '• MDM             : Microsoft Intune\n\n'
                f'Fichier : {path}\n\n'
                '⚠ Le hostname et host-id restent ceux de votre poste Linux.\n'
                '   Si la console PA filtre par OS uniquement, vous serez\n'
                '   matché comme un poste Windows.')
            dlg.run()
            dlg.destroy()
        except Exception as e:
            err_dlg = Gtk.MessageDialog(
                parent=self, flags=Gtk.DialogFlags.MODAL,
                type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.OK,
                message_format=f'Erreur : {e}')
            err_dlg.run()
            err_dlg.destroy()

    def _generate_windows_hip_xml(self, client_ip='0.0.0.0',
                                  md5='<md5-placeholder>',
                                  username='', ipv6=''):
        """Génère un XML HIP qui imite un client GlobalProtect Windows 10.

        Format aligné sur ce qu'envoie réellement le client GP Windows :
          - <os>Microsoft Windows 10 Pro , 64-bit</os>
          - <os-vendor>Microsoft</os-vendor>
          - <client-version>6.2.4-26</client-version>
          - Antivirus = Microsoft / Windows Defender
          - Firewall  = Microsoft / Windows Firewall
          - Disk encryption = Microsoft / Windows BitLocker
        """
        import socket as _socket
        from datetime import datetime as _dt

        hostname  = self.fake_hostname_entry.get_text().strip() or _socket.gethostname()
        now       = _dt.now().strftime('%m/%d/%Y %H:%M:%S')
        defver    = _dt.now().strftime('%Y%m%d')
        host_id   = _get_dmi_machine_uuid()
        if not username:
            username = self.config.get('last_username', 'user@example.com')

        def _e(s):
            return (str(s).replace('&', '&amp;').replace('<', '&lt;')
                    .replace('>', '&gt;').replace('"', '&quot;'))

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<hip-report>
  <md5-sum>{_e(md5)}</md5-sum>
  <user-name>{_e(username)}</user-name>
  <domain></domain>
  <host-name>{_e(hostname)}</host-name>
  <host-id>{_e(host_id)}</host-id>
  <ip-address>{_e(client_ip)}</ip-address>
  <ipv6-address>{_e(ipv6)}</ipv6-address>
  <generate-time>{now}</generate-time>
  <hip-report-version>4</hip-report-version>
  <categories>
    <entry name="host-info">
      <client-version>6.2.4-26</client-version>
      <os>Microsoft Windows 10 Pro , 64-bit</os>
      <os-vendor>Microsoft</os-vendor>
      <domain></domain>
      <host-name>{_e(hostname)}</host-name>
      <host-id>{_e(host_id)}</host-id>
      <network-interface>
        <entry name="Ethernet">
          <description>Ethernet</description>
          <mac-address>00-00-00-00-00-00</mac-address>
          <ip-address><entry name="{_e(client_ip)}"/></ip-address>
        </entry>
      </network-interface>
    </entry>
    <entry name="antivirus">
      <list>
        <entry>
          <vendor>Microsoft Corp.</vendor>
          <name>Windows Defender</name>
          <product-version>4.18.{defver[:4]}.0</product-version>
          <real-time-protection>yes</real-time-protection>
          <definition-version>{defver}</definition-version>
          <last-scan-time>{now}</last-scan-time>
        </entry>
      </list>
    </entry>
    <entry name="anti-malware">
      <list>
        <entry>
          <vendor>Microsoft Corp.</vendor>
          <name>Windows Defender</name>
          <product-version>4.18.{defver[:4]}.0</product-version>
          <real-time-protection>yes</real-time-protection>
          <definition-version>{defver}</definition-version>
          <last-scan-time>{now}</last-scan-time>
        </entry>
      </list>
    </entry>
    <entry name="disk-backup">
      <list/>
    </entry>
    <entry name="disk-encryption">
      <list>
        <entry>
          <name>Windows BitLocker</name>
          <vendor>Microsoft Corp.</vendor>
          <product-version>10.0</product-version>
          <status>yes</status>
        </entry>
      </list>
    </entry>
    <entry name="firewall">
      <list>
        <entry>
          <name>Windows Firewall</name>
          <vendor>Microsoft Corp.</vendor>
          <product-version>10.0</product-version>
          <status>yes</status>
        </entry>
      </list>
    </entry>
    <entry name="patch-management">
      <list>
        <entry>
          <vendor>Microsoft Corp.</vendor>
          <name>Windows Update Agent</name>
          <product-version>10.0</product-version>
          <enabled>yes</enabled>
        </entry>
      </list>
      <missing-patches>
        <severity>0</severity>
        <patches>
          <entry/>
        </patches>
      </missing-patches>
    </entry>
    <entry name="data-loss-prevention">
      <list/>
    </entry>
    <entry name="mobile-device-management">
      <list/>
    </entry>
  </categories>
</hip-report>"""

    def _on_remove_sudo_clicked(self, _btn):
        parent = self.parent_window
        if parent and hasattr(parent, '_on_remove_sudo'):
            parent._on_remove_sudo(None)

    def apply(self):
        self.config.set('server',            self.server_entry.get_text().strip())
        self.config.set('clientos',          self.os_combo.get_active_text())
        self.config.set('user_agent',        self.ua_entry.get_text().strip())
        self.config.set('preferred_gateway', self.gw_entry.get_text().strip())
        self.config.set('verify_ssl',             self.verify_check.get_active())
        self.config.set('allow_insecure_crypto',  self.insecure_crypto_check.get_active())
        if self.conn_auto_radio.get_active():
            _conn_mode = 'auto'
        elif self.conn_internal_radio.get_active():
            _conn_mode = 'internal'
        elif self.conn_gateway_radio.get_active():
            _conn_mode = 'gateway'
        else:
            _conn_mode = 'portal'
        self.config.set('connection_mode', _conn_mode)
        self.config.set('force_vpn_dns',          self.force_dns_check.get_active())
        self.config.set('vpn_dns_servers',        self.vpn_dns_entry.get_text().strip())
        self.config.set('vpn_dns_suffixes',       self.vpn_suffix_entry.get_text().strip())
        self.config.set('minimize_to_tray',       self.minimize_tray_check.get_active())
        self.config.set('hip_enabled',            self.hip_check.get_active())
        if self.hip_fake_radio.get_active():
            hip_mode = 'fake'
        elif self.hip_custom_radio.get_active():
            hip_mode = 'custom'
        else:
            hip_mode = 'builtin'
        self.config.set('hip_mode',   hip_mode)
        self.config.set('hip_script', self.hip_script_entry.get_text().strip())
        # Valeurs fake HIP
        self.config.set('hip_fake_hostname',
                        self.fake_hostname_entry.get_text().strip())
        self.config.set('hip_fake_firewall',
                        self.fake_fw_check.get_active())
        self.config.set('hip_fake_firewall_name',
                        self.fake_fw_name_entry.get_text().strip())
        self.config.set('hip_fake_antivirus',
                        self.fake_av_check.get_active())
        self.config.set('hip_fake_antivirus_vendor',
                        self.fake_av_vendor_entry.get_text().strip())
        self.config.set('hip_fake_antivirus_name',
                        self.fake_av_name_entry.get_text().strip())
        self.config.set('hip_fake_antivirus_version',
                        self.fake_av_ver_entry.get_text().strip())
        self.config.set('hip_fake_antivirus_real_time',
                        self.fake_av_rt_check.get_active())
        self.config.set('hip_fake_encryption',
                        self.fake_enc_check.get_active())
        self.config.set('hip_fake_mdm',
                        self.fake_mdm_check.get_active())
        self.config.set('hip_fake_mdm_name',
                        self.fake_mdm_name_entry.get_text().strip())
        self.config.set('hip_fake_backup',
                        self.fake_bk_check.get_active())
        self.config.set('hip_fake_backup_name',
                        self.fake_bk_name_entry.get_text().strip())


# ─────────────────────────────────────────────
#  Dialogue éditeur XML HIP (mode fake)
# ─────────────────────────────────────────────

class HipXmlEditorDialog(Gtk.Dialog):
    """Éditeur plein texte du rapport XML HIP.

    Les champs dynamiques (<ip-address>, <md5-sum>, <generate-time>,
    <user-name>) seront mis à jour automatiquement à chaque connexion.
    """

    def __init__(self, parent, xml_content):
        super().__init__(
            title='Rapport HIP — Éditeur XML',
            parent=parent,
            flags=Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT,
        )
        self.add_buttons(
            Gtk.STOCK_CANCEL,  Gtk.ResponseType.CANCEL,
            'Sauvegarder',     Gtk.ResponseType.OK,
        )
        self.set_default_size(700, 560)
        self._build(xml_content)

    def _build(self, xml_content):
        area = self.get_content_area()
        area.set_spacing(6)
        area.set_margin_top(12)
        area.set_margin_bottom(8)
        area.set_margin_start(12)
        area.set_margin_end(12)

        info = Gtk.Label(xalign=0)
        info.set_markup(
            '<small><span foreground="#555">'
            '⚠ Les champs <b>&lt;ip-address&gt;</b>, <b>&lt;md5-sum&gt;</b>, '
            '<b>&lt;generate-time&gt;</b> et <b>&lt;user-name&gt;</b>\n'
            'seront mis à jour automatiquement à chaque connexion VPN.'
            '</span></small>')
        info.set_line_wrap(True)
        area.pack_start(info, False, False, 0)

        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_vexpand(True)

        self.tv = Gtk.TextView()
        self.tv.set_monospace(True)
        self.tv.set_wrap_mode(Gtk.WrapMode.NONE)
        self.tv.get_buffer().set_text(xml_content)

        # Coloration légère du fond
        self.tv.override_background_color(
            Gtk.StateFlags.NORMAL,
            Gdk.RGBA(0.98, 0.98, 0.98, 1))

        sw.add(self.tv)
        area.pack_start(sw, True, True, 0)
        area.show_all()

    def get_xml(self):
        buf = self.tv.get_buffer()
        return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)


# ─────────────────────────────────────────────
#  Dialogue sélection Gateway
# ─────────────────────────────────────────────

class GatewayDialog(Gtk.Dialog):
    def __init__(self, parent, gateways, preferred=None):
        super().__init__(
            title='Choisir un serveur VPN',
            parent=parent,
            flags=Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT,
        )
        self.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            'Connexion',      Gtk.ResponseType.OK,
        )
        self.set_default_size(460, 320)
        self._build(gateways, preferred)

    def _build(self, gateways, preferred):
        box = self.get_content_area()
        box.set_spacing(8)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(16)
        box.set_margin_end(16)

        label = Gtk.Label(label='Sélectionnez le serveur de connexion :', xalign=0)
        box.pack_start(label, False, False, 0)

        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        sw.set_min_content_height(220)

        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.listbox.connect('row-activated', lambda lb, row: self.response(Gtk.ResponseType.OK))

        preferred_row = None
        for gw in gateways:
            row = Gtk.ListBoxRow()
            row.gw = gw

            hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            hbox.set_margin_top(10)
            hbox.set_margin_bottom(10)
            hbox.set_margin_start(12)
            hbox.set_margin_end(12)

            icon = Gtk.Image.new_from_icon_name('network-server-symbolic', Gtk.IconSize.BUTTON)
            hbox.pack_start(icon, False, False, 0)

            vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            name_lbl = Gtk.Label(label=gw['description'], xalign=0)
            name_lbl.get_style_context().add_class('title')
            host_lbl = Gtk.Label(label=gw['hostname'], xalign=0)
            host_lbl.get_style_context().add_class('dim-label')
            host_lbl.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
            vbox.pack_start(name_lbl, False, False, 0)
            vbox.pack_start(host_lbl, False, False, 0)
            hbox.pack_start(vbox, True, True, 0)

            row.add(hbox)
            self.listbox.add(row)

            if preferred and preferred in (gw['hostname'], gw['description']):
                preferred_row = row

        # Sélection par défaut
        default = preferred_row or self.listbox.get_row_at_index(0)
        if default:
            self.listbox.select_row(default)

        sw.add(self.listbox)
        box.pack_start(sw, True, True, 0)
        box.show_all()

    def get_selected_gateway(self):
        row = self.listbox.get_selected_row()
        return row.gw if row else None


# ─────────────────────────────────────────────
#  Fenêtre principale
# ─────────────────────────────────────────────

STATES = {
    'disconnected': {
        'icon': 'network-vpn-symbolic',
        'title': 'Déconnecté',
        'subtitle': '',
        'btn': 'Se connecter',
        'btn_class': 'btn-connect',
        'spinner': False,
    },
    'authenticating': {
        'icon': 'network-vpn-acquiring-symbolic',
        'title': 'Authentification SSO…',
        'subtitle': 'Fenêtre de connexion en cours',
        'btn': 'Annuler',
        'btn_class': 'btn-cancel',
        'spinner': True,
    },
    'fetching': {
        'icon': 'network-vpn-acquiring-symbolic',
        'title': 'Récupération des serveurs…',
        'subtitle': '',
        'btn': 'Annuler',
        'btn_class': 'btn-cancel',
        'spinner': True,
    },
    'connecting': {
        'icon': 'network-vpn-acquiring-symbolic',
        'title': 'Connexion en cours…',
        'subtitle': '',
        'btn': 'Annuler',
        'btn_class': 'btn-cancel',
        'spinner': True,
    },
    'connected': {
        'icon': 'network-vpn-symbolic',
        'title': 'Connecté',
        'subtitle': '',
        'btn': 'Déconnecter',
        'btn_class': 'btn-disconnect',
        'spinner': False,
    },
    'error': {
        'icon': 'network-error-symbolic',
        'title': 'Erreur',
        'subtitle': '',
        'btn': 'Réessayer',
        'btn_class': 'btn-connect',
        'spinner': False,
    },
}


def _fmt_bytes(n, suffix='/s'):
    """Formate un nombre d'octets en unité lisible (K, M, G)."""
    for unit in ('', 'K', 'M', 'G'):
        if abs(n) < 1024:
            if unit == '':
                return f'{int(n)} B{suffix}'
            return f'{n:.1f} {unit}{suffix}'
        n /= 1024
    return f'{n:.1f} T{suffix}'


class _BandwidthMonitor:
    """Lit les compteurs kernel, mesure la latence et le jitter.

    La mesure de latence (TCP connect vers la gateway, jusqu'à 2 s de timeout)
    est exécutée dans un thread dédié pour ne pas bloquer le thread GTK.
    poll() ne fait que des lectures sysfs quasi-instantanées (µs).
    """

    HIST_SIZE = 300

    def __init__(self, iface, gateway_ip=''):
        self.iface = iface
        self.gateway_ip = gateway_ip
        self._base = f'/sys/class/net/{iface}/statistics'
        self._prev_rx = self._read('rx_bytes')
        self._prev_tx = self._read('tx_bytes')
        self._prev_t = _time_mod.monotonic()
        self._rx_rate = 0.0
        self._tx_rate = 0.0
        self._total_rx = 0
        self._total_tx = 0
        self._latency = 0.0
        self._jitter = 0.0
        self._packet_loss = 0.0
        self._prev_latency = 0.0
        self._ping_count = 0
        self._ping_fail = 0
        self._history = collections.deque(maxlen=self.HIST_SIZE)
        # Thread de mesure latence en arrière-plan
        self._stop_evt = threading.Event()
        self._lat_lock = threading.Lock()
        if self.gateway_ip:
            self._lat_thread = threading.Thread(
                target=self._latency_loop, daemon=True)
            self._lat_thread.start()
        else:
            self._lat_thread = None

    def stop(self):
        """Arrête proprement le thread de latence (à appeler en déconnexion)."""
        self._stop_evt.set()

    def _read(self, name):
        try:
            with open(f'{self._base}/{name}') as f:
                return int(f.read().strip())
        except Exception:
            return 0

    def _latency_loop(self):
        """Boucle background : mesure latence toutes les ~2 s."""
        while not self._stop_evt.wait(2.0):
            if not self.gateway_ip:
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                start = _time_mod.monotonic()
                rc = sock.connect_ex((self.gateway_ip, 443))
                elapsed = (_time_mod.monotonic() - start) * 1000
                try:
                    sock.close()
                except Exception:
                    pass
                with self._lat_lock:
                    if rc == 0:
                        self._jitter = abs(elapsed - self._prev_latency)
                        self._prev_latency = self._latency
                        self._latency = elapsed
                    else:
                        self._ping_fail += 1
                    self._ping_count += 1
                    if self._ping_count > 0:
                        self._packet_loss = (
                            self._ping_fail / self._ping_count) * 100
            except Exception:
                with self._lat_lock:
                    self._ping_fail += 1
                    self._ping_count += 1
                    if self._ping_count > 0:
                        self._packet_loss = (
                            self._ping_fail / self._ping_count) * 100

    def poll(self):
        """Lit les compteurs, calcule le debit et stocke dans l'historique.

        Opération rapide (~µs) : pas d'IO réseau, uniquement lecture sysfs.
        Safe à appeler depuis le thread GTK principal.
        """
        now = _time_mod.monotonic()
        dt = now - self._prev_t
        if dt <= 0:
            return
        rx = self._read('rx_bytes')
        tx = self._read('tx_bytes')
        d_rx = max(0, rx - self._prev_rx)
        d_tx = max(0, tx - self._prev_tx)
        self._rx_rate = d_rx / dt
        self._tx_rate = d_tx / dt
        self._total_rx += d_rx
        self._total_tx += d_tx
        self._prev_rx = rx
        self._prev_tx = tx
        self._prev_t = now
        with self._lat_lock:
            latency = self._latency
        self._history.append((self._rx_rate, self._tx_rate, latency))

    def get_rate(self):
        return self._rx_rate, self._tx_rate

    def get_latency(self):
        with self._lat_lock:
            return self._latency, self._jitter, self._packet_loss

    def get_history(self):
        return list(self._history)

    def get_total(self):
        return self._total_rx, self._total_tx


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title='GP Connect')
        self.config              = Config()
        self.state               = 'disconnected'
        self.openconnect_proc    = None
        self._cancel_requested   = False
        self._hip_wrapper_tmp    = None
        self._last_auth_info     = {}
        self._reusable_portal_cookie = None  # (field, value) portal-userauthcookie
        self._tunnel_up_handled  = False
        self._reconnect_count    = 0
        self._existing_vpn_pid   = None   # PID openconnect externe (avant démarrage app)
        self._vpn_monitor_source = None   # source GLib.timeout pour surveillance
        self._dns_route_snapshot = {}     # ex: {'wlp0s20f3': True, 'tun0': True}
        self._dns_forced_iface   = ''     # interface VPN sur laquelle DNS a été forcé
        self._dns_auth_warned    = False  # évite les logs/boîtes en boucle
        self._startup_sudo_checked = False
        self._forced_conn_mode   = None   # forçage ponctuel du mode ('auto'/'portal'/'gateway'/'internal')
        self._forced_clientos    = None   # forçage ponctuel du clientos (ex. Mac sur 512)
        self._mode_retry_attempted = False
        self._os_retry_attempted = False    # True après un retry auto de clientos
        self._os_retry_list      = []       # clientos restants à essayer
        self._os_512_retry_attempted = False
        self._internal_session = None
        self._hip_stop_event   = None
        self._bw_monitor       = None
        self._bw_timer_source  = None
        self._conn_timer_source = None
        self._conn_scan_inflight = False
        self._vpn_iface        = ''
        self._vpn_client_ip    = ''
        self._vpn_dns_servers  = []
        self._quitting = False
        self.tray_icon = None
        self.tray_menu = None
        self.app_indicator = None
        self._tray_backend = 'none'

        self.set_default_size(420, 380)
        self.set_resizable(False)
        self.connect('delete-event', self._on_window_delete)
        self._build_ui()
        self._build_tray_icon()
        self._ensure_fake_hip_template_exists()
        self._apply_state('disconnected')
        GLib.timeout_add(600, self._detect_existing_vpn)
        GLib.timeout_add(1100, self._check_sudo_setup_on_startup)
        GLib.timeout_add(2000, self._auto_reconnect_on_startup)

    # ── Interface ──────────────────────────────────────────────────────────

    def _build_ui(self):
        css_prov = Gtk.CssProvider()
        css_prov.load_from_data(b"""
/* -- Base (OPEX Hunter palette) -- */
window, .main-panel { background: #0d1117; color: #c9d1d9; }
headerbar {
    background: #161b22; color: #c9d1d9;
    border-bottom: 1px solid #21262d;
}
headerbar .title { color: #e6edf3; font-weight: 600; }
headerbar .subtitle { color: #8b949e; font-size: 10px; }
headerbar button {
    color: #8b949e; border: 1px solid #30363d;
    border-radius: 6px; background: #21262d;
}
headerbar button:hover { color: #e6edf3; background: #30363d; }

/* -- Status -- */
.status-title { color: #e6edf3; font-size: 18px; font-weight: 700; }
.status-sub { color: #8b949e; font-size: 11px; }
.version-lbl { color: #484f58; font-size: 9px; font-family: monospace; }
.server-lbl { color: #58a6ff; font-size: 10px; font-family: monospace; }

/* -- Buttons (gradient + shadow) -- */
.btn-connect {
    background-image: linear-gradient(135deg, #6366f1, #a855f7, #ec4899);
    color: #ffffff; border: none;
    border-radius: 6px; font-weight: 600; font-size: 12px;
    padding: 10px 28px; min-height: 38px;
    box-shadow: 0 2px 8px rgba(99,102,241,0.3);
}
.btn-connect:hover {
    background-image: linear-gradient(135deg, #818cf8, #c084fc, #f472b6);
    box-shadow: 0 4px 14px rgba(99,102,241,0.4);
}
.btn-disconnect {
    background-image: linear-gradient(135deg, #ec4899, #a855f7, #6366f1);
    color: #ffffff; border: none;
    border-radius: 6px; font-weight: 600; font-size: 12px;
    padding: 10px 28px; min-height: 38px;
    box-shadow: 0 2px 8px rgba(236,72,153,0.3);
}
.btn-disconnect:hover {
    background-image: linear-gradient(135deg, #f472b6, #c084fc, #818cf8);
    box-shadow: 0 4px 14px rgba(236,72,153,0.4);
}
.btn-secondary {
    background: #161b22; color: #a78bfa;
    border: 1px solid #6366f1;
    border-radius: 6px; font-size: 11px;
    padding: 10px 18px; min-height: 38px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.3);
}
.btn-secondary:hover {
    background: rgba(99,102,241,0.1); color: #c4b5fd;
    box-shadow: 0 2px 8px rgba(99,102,241,0.2);
}
.btn-cancel {
    background-image: linear-gradient(135deg, #ec4899, #f43f5e);
    color: #ffffff; border: none;
    border-radius: 6px; font-weight: 600; font-size: 12px;
    padding: 10px 28px; min-height: 38px;
    box-shadow: 0 2px 8px rgba(236,72,153,0.3);
}
.btn-cancel:hover {
    background-image: linear-gradient(135deg, #f472b6, #fb7185);
    box-shadow: 0 4px 14px rgba(236,72,153,0.4);
}

/* -- Card panels -- */
.card-panel {
    background: #161b22;
    border: none;
    border-radius: 4px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.4), inset 0 2px 0 #8b5cf6;
}
.card-header {
    color: #a78bfa; font-size: 8px;
    font-family: monospace; letter-spacing: 2px;
    font-weight: 600;
}

/* -- System info card -- */
.sysinfo-box {
    background: #161b22;
    border: none;
    border-radius: 4px;
    padding: 10px 14px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.4), inset 0 2px 0 #8b5cf6;
}
.sysinfo-box label { font-size: 8px; font-family: monospace; color: #8b949e; }
.sysinfo-title {
    color: #a78bfa; font-size: 7px;
    font-family: monospace; letter-spacing: 2px;
    font-weight: 600;
}
.sysinfo-val { color: #c9d1d9; font-size: 8px; font-family: monospace; }

/* -- Log -- */
.log-view {
    background: transparent; color: #8b949e;
    font-size: 9px; font-family: monospace;
}

/* -- Right monitor panel -- */
.monitor-panel {
    background: #010409;
    border-left: 1px solid #21262d;
}
.monitor-panel label {
    color: #8b949e; font-size: 8px; font-family: monospace;
}
.mon-header {
    color: #a78bfa; font-size: 7px;
    font-family: monospace; letter-spacing: 2px;
    font-weight: 600;
}
.mon-stat-rx {
    color: #58a6ff; font-size: 11px;
    font-weight: bold; font-family: monospace;
}
.mon-stat-tx {
    color: #f0883e; font-size: 11px;
    font-weight: bold; font-family: monospace;
}
.mon-stat-dim { color: #484f58; font-size: 8px; font-family: monospace; }
.mon-conn-view {
    background: #0d1117; color: #c9d1d9;
    font-size: 8px; font-family: monospace;
    border: 1px solid #21262d; border-radius: 4px;
}
.mon-conn-view header button {
    font-size: 7px; font-family: monospace;
    color: #484f58; min-height: 18px;
    background: transparent; border: none;
}
""")
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), css_prov,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        # ── Header bar ─────────────────────────
        hb = Gtk.HeaderBar()
        hb.set_show_close_button(True)
        hb.props.title = 'GP Connect'
        hb.props.subtitle = 'GlobalProtect VPN'

        settings_btn = Gtk.Button()
        settings_btn.set_tooltip_text('Paramètres')
        settings_btn.add(Gtk.Image.new_from_icon_name(
            'preferences-system-symbolic', Gtk.IconSize.BUTTON))
        settings_btn.connect('clicked', self._on_settings)
        hb.pack_end(settings_btn)

        self._monitor_toggle = Gtk.ToggleButton()
        self._monitor_toggle.set_tooltip_text('Panneau monitoring')
        self._monitor_toggle.add(Gtk.Image.new_from_icon_name(
            'utilities-system-monitor-symbolic', Gtk.IconSize.BUTTON))
        self._monitor_toggle.connect('toggled', self._on_monitor_toggled)
        self._monitor_toggle.set_no_show_all(True)
        hb.pack_end(self._monitor_toggle)

        self.set_titlebar(hb)

        # ── Paned layout ──────────────────────
        self._paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.add(self._paned)

        # ── Left panel (main UI) ──────────────
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        root.get_style_context().add_class('main-panel')
        root.set_size_request(420, -1)

        # ── System info bar ───────────────────
        self._sysinfo_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=1)
        self._sysinfo_box.get_style_context().add_class('sysinfo-box')
        self._sysinfo_box.set_margin_start(12)
        self._sysinfo_box.set_margin_end(12)
        self._sysinfo_box.set_margin_top(8)

        si_title = Gtk.Label(label='SYSTEM INFO', xalign=0)
        si_title.get_style_context().add_class('sysinfo-title')
        self._sysinfo_box.pack_start(si_title, False, False, 0)

        self._sysinfo_label = Gtk.Label(xalign=0)
        self._sysinfo_label.get_style_context().add_class('sysinfo-val')
        self._sysinfo_label.set_line_wrap(True)
        self._sysinfo_label.set_selectable(True)
        self._sysinfo_box.pack_start(self._sysinfo_label, False, False, 0)
        root.pack_start(self._sysinfo_box, False, False, 0)
        GLib.idle_add(self._refresh_sysinfo)

        # ── Status area ──────────────────────
        status_area = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        status_area.set_valign(Gtk.Align.CENTER)
        status_area.set_vexpand(True)
        status_area.set_margin_top(12)
        status_area.set_margin_bottom(6)
        status_area.set_margin_start(30)
        status_area.set_margin_end(30)

        self.status_icon = Gtk.Image.new_from_icon_name(
            APP_ID, Gtk.IconSize.DIALOG)
        self.status_icon.set_pixel_size(52)
        status_area.pack_start(self.status_icon, False, False, 0)

        self.title_lbl = Gtk.Label()
        self.title_lbl.get_style_context().add_class('status-title')
        self.title_lbl.set_text('Disconnected')
        status_area.pack_start(self.title_lbl, False, False, 0)

        self.subtitle_lbl = Gtk.Label()
        self.subtitle_lbl.get_style_context().add_class('status-sub')
        self.subtitle_lbl.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        status_area.pack_start(self.subtitle_lbl, False, False, 0)

        self.version_lbl = Gtk.Label()
        self.version_lbl.get_style_context().add_class('version-lbl')
        self.version_lbl.set_text(f'v{APP_VERSION}')
        status_area.pack_start(self.version_lbl, False, False, 0)

        root.pack_start(status_area, True, True, 0)

        self.spinner = Gtk.Spinner()
        self.spinner.set_no_show_all(True)
        self.spinner.set_margin_bottom(4)
        root.pack_start(self.spinner, False, False, 0)

        self.server_lbl = Gtk.Label()
        self.server_lbl.get_style_context().add_class('server-lbl')
        self.server_lbl.set_margin_bottom(8)
        root.pack_start(self.server_lbl, False, False, 0)
        self._refresh_server_label()

        # ── Buttons ──────────────────────────
        btn_box = Gtk.Box(spacing=10)
        btn_box.set_halign(Gtk.Align.CENTER)
        btn_box.set_margin_bottom(12)

        self.action_btn = Gtk.Button(label='Se connecter')
        self.action_btn.get_style_context().add_class('btn-connect')
        self.action_btn.set_size_request(160, -1)
        self.action_btn.connect('clicked', self._on_action)
        btn_box.pack_start(self.action_btn, False, False, 0)

        self.diag_btn = Gtk.Button(label='Diagnostiquer')
        self.diag_btn.get_style_context().add_class('btn-secondary')
        self.diag_btn.set_tooltip_text(
            'Teste DNS, TLS et prelogin pour vérifier la configuration.')
        self.diag_btn.connect('clicked', self._on_diagnose)
        btn_box.pack_start(self.diag_btn, False, False, 0)

        self.diag_hip_btn = Gtk.Button(label='Diag HIP')
        self.diag_hip_btn.get_style_context().add_class('btn-secondary')
        self.diag_hip_btn.set_tooltip_text(
            'Affiche le rapport HIP qui sera envoyé, le dernier rapport '
            'capturé, et interroge la passerelle (hipreportcheck.esp).')
        self.diag_hip_btn.connect('clicked', self._on_diagnose_hip)
        btn_box.pack_start(self.diag_hip_btn, False, False, 0)

        root.pack_start(btn_box, False, False, 0)

        # ── Log panel ────────────────────────
        log_outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        log_outer.get_style_context().add_class('card-panel')
        log_outer.set_margin_start(12)
        log_outer.set_margin_end(12)
        log_outer.set_margin_bottom(8)

        log_hdr = Gtk.Label(label='CONNECTION LOG', xalign=0)
        log_hdr.get_style_context().add_class('card-header')
        log_hdr.set_margin_start(12)
        log_hdr.set_margin_top(8)
        log_hdr.set_margin_bottom(4)
        log_outer.pack_start(log_hdr, False, False, 0)

        log_sw = Gtk.ScrolledWindow()
        log_sw.set_min_content_height(130)
        log_sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.log_view = Gtk.TextView()
        self.log_view.set_editable(False)
        self.log_view.set_cursor_visible(False)
        self.log_view.set_monospace(True)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.log_view.get_style_context().add_class('log-view')
        self.log_buf = self.log_view.get_buffer()
        log_sw.add(self.log_view)
        log_outer.pack_start(log_sw, True, True, 0)

        root.pack_start(log_outer, False, False, 0)

        self._paned.pack1(root, resize=False, shrink=False)

        # ── Right panel (network monitor) ─────
        self._mon_panel = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._mon_panel.get_style_context().add_class('monitor-panel')
        self._mon_panel.set_size_request(340, -1)

        mp = self._mon_panel  # shorthand

        hdr = Gtk.Label(label='NETWORK MONITOR', xalign=0)
        hdr.get_style_context().add_class('mon-header')
        hdr.set_margin_start(10)
        hdr.set_margin_top(10)
        hdr.set_margin_bottom(4)
        mp.pack_start(hdr, False, False, 0)

        # Live stats row
        stats_box = Gtk.Box(spacing=0)
        stats_box.set_margin_start(10)
        stats_box.set_margin_end(10)
        stats_box.set_margin_bottom(2)

        self._rx_stat = Gtk.Label(xalign=0)
        self._rx_stat.get_style_context().add_class('mon-stat-rx')
        self._rx_stat.set_markup('\u2193 0 B/s')
        stats_box.pack_start(self._rx_stat, True, True, 0)

        self._tx_stat = Gtk.Label(xalign=0)
        self._tx_stat.get_style_context().add_class('mon-stat-tx')
        self._tx_stat.set_markup('\u2191 0 B/s')
        stats_box.pack_start(self._tx_stat, True, True, 0)
        mp.pack_start(stats_box, False, False, 0)

        self._bw_total_label = Gtk.Label(xalign=0)
        self._bw_total_label.get_style_context().add_class('mon-stat-dim')
        self._bw_total_label.set_markup('total  \u2193 0 B  \u2191 0 B')
        self._bw_total_label.set_margin_start(10)
        self._bw_total_label.set_margin_bottom(6)
        mp.pack_start(self._bw_total_label, False, False, 0)

        # Graph
        self._bw_draw_area = Gtk.DrawingArea()
        self._bw_draw_area.set_size_request(-1, 180)
        self._bw_draw_area.connect('draw', self._on_bw_draw)
        mp.pack_start(self._bw_draw_area, False, False, 0)

        # Separator
        sep = Gtk.Separator()
        sep.set_margin_top(6)
        sep.set_margin_bottom(4)
        mp.pack_start(sep, False, False, 0)

        # Connections header
        conn_hdr = Gtk.Label(label='ACTIVE CONNECTIONS (VPN)', xalign=0)
        conn_hdr.get_style_context().add_class('mon-header')
        conn_hdr.set_margin_start(10)
        conn_hdr.set_margin_bottom(4)
        mp.pack_start(conn_hdr, False, False, 0)

        # Connections table: addr, port, process, rx, tx, color
        self._conn_store = Gtk.ListStore(str, str, str, str, str, str)
        conn_tv = Gtk.TreeView(model=self._conn_store)
        conn_tv.get_style_context().add_class('mon-conn-view')
        conn_tv.set_headers_visible(True)
        conn_tv.set_enable_search(False)
        conn_tv.set_grid_lines(Gtk.TreeViewGridLines.HORIZONTAL)

        for i, (title, expand) in enumerate([
                ('Adresse', True), ('Port', False), ('Proc', False),
                ('Recv', False), ('Send', False)]):
            cr_text = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, cr_text, text=i, foreground=5)
            col.set_expand(expand)
            col.set_resizable(True)
            conn_tv.append_column(col)

        conn_sw = Gtk.ScrolledWindow()
        conn_sw.set_policy(
            Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        conn_sw.set_vexpand(True)
        conn_sw.add(conn_tv)
        mp.pack_start(conn_sw, True, True, 0)

        # Connection count footer
        self._conn_count_lbl = Gtk.Label(xalign=0)
        self._conn_count_lbl.get_style_context().add_class('mon-stat-dim')
        self._conn_count_lbl.set_margin_start(10)
        self._conn_count_lbl.set_margin_top(2)
        self._conn_count_lbl.set_margin_bottom(6)
        mp.pack_start(self._conn_count_lbl, False, False, 0)

        self._paned.pack2(self._mon_panel, resize=True, shrink=False)
        self._mon_panel.set_no_show_all(True)

        # Dummy ref for backward compat
        self.monitor_box = self._mon_panel
        self._bw_rate_label = self._rx_stat

    def clear_logs(self):
        """Réinitialise le journal affiché."""
        if self.log_buf is not None:
            self.log_buf.set_text('')

    def _ensure_fake_hip_template_exists(self):
        """Crée ou régénère le template HIP fake s'il est absent/obsolète."""
        try:
            path = CONFIG_DIR / 'hip_template.xml'
            need_regen = True
            if path.exists():
                try:
                    xml = path.read_text(encoding='utf-8', errors='ignore')
                    need_regen = _is_legacy_hip_template(xml)
                    if need_regen:
                        self._log(
                            '  [HIP] Template obsolète (format ProductInfo/'
                            'PascalCase) → régénération au format PAN-OS')
                except Exception:
                    need_regen = True
            if not need_regen:
                return
            xml = self._generate_fake_hip_xml_from_config()
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                f.write(xml)
        except Exception:
            pass

    def _ensure_hip_template_current(self):
        """Garantit un template HIP au bon format avant connexion."""
        self._ensure_fake_hip_template_exists()
        # Activer le pare-feu fake si encore à False (souvent requis HIP)
        if not self.config.get('hip_fake_firewall', True):
            self.config.set('hip_fake_firewall', True)

    def _build_tray_icon(self):
        """Crée l'icône de zone de notification (AppIndicator puis fallback)."""
        self.tray_menu = Gtk.Menu()
        show_item = Gtk.MenuItem(label='Afficher / Masquer')
        show_item.connect('activate', self._on_tray_toggle_window)
        self.tray_menu.append(show_item)
        forget_item = Gtk.MenuItem(label='Oublier la session')
        forget_item.connect('activate', lambda _: self._disconnect_and_forget())
        self.tray_menu.append(forget_item)
        quit_item = Gtk.MenuItem(label='Quitter')
        quit_item.connect('activate', self._on_tray_quit)
        self.tray_menu.append(quit_item)
        self.tray_menu.show_all()

        # 1) AppIndicator (GNOME moderne, recommandé)
        if HAS_APPINDICATOR and AppIndicator3 is not None:
            try:
                self.app_indicator = AppIndicator3.Indicator.new(
                    APP_ID,
                    'network-vpn-symbolic',
                    AppIndicator3.IndicatorCategory.APPLICATION_STATUS,
                )
                self.app_indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
                self.app_indicator.set_menu(self.tray_menu)
                self._tray_backend = 'appindicator'
                return
            except Exception:
                self.app_indicator = None

        # 2) Fallback legacy StatusIcon
        try:
            self.tray_icon = Gtk.StatusIcon.new_from_icon_name('network-vpn-symbolic')
            self.tray_icon.set_tooltip_text('GP Connect')
            self.tray_icon.set_title('GP Connect')
            self.tray_icon.set_visible(True)
            self.tray_icon.connect('activate', self._on_tray_activate)
            self.tray_icon.connect('popup-menu', self._on_tray_popup_menu)
            self._tray_backend = 'statusicon'
        except Exception:
            self.tray_icon = None
            self._tray_backend = 'none'

    def _on_tray_activate(self, _icon):
        self._toggle_window_visibility()

    def _on_tray_popup_menu(self, _icon, button, activate_time):
        if self.tray_menu:
            self.tray_menu.popup(None, None, None, None, button, activate_time)

    def _on_tray_toggle_window(self, _item):
        self._toggle_window_visibility()

    def _on_tray_quit(self, _item):
        self._quitting = True
        self._bw_stop()
        app = self.get_application()
        if app:
            app.quit()

    def _toggle_window_visibility(self):
        if self.is_visible():
            self.hide()
        else:
            self.show_all()
            self.present()

    def _on_window_delete(self, *_args):
        # Si activé, fermer la fenêtre => minimiser en zone de notification.
        if not self._quitting and self.config.get('minimize_to_tray', True):
            if self._tray_backend in ('appindicator', 'statusicon'):
                self.hide()
            else:
                # Fallback si pas de tray supportée : minimiser au dock.
                self.iconify()
            return True
        return False

    def _refresh_server_label(self):
        srv = self.config.get('server')
        if srv:
            self.server_lbl.set_text(srv)
        else:
            self.server_lbl.set_markup(
                '<span foreground="red">⚠ Aucun serveur configuré</span>')

    @staticmethod
    def _discover_dhcp_dns():
        """Découvre les DNS distribués par le DHCP (multiples sources)."""
        dns_servers = []
        dns_domains = []

        # 1) resolvectl/systemd-resolve status (plus fiable)
        tool, path = _detect_dns_tool()
        if path and tool in ('resolvectl', 'systemd-resolve'):
            try:
                out = subprocess.run(
                    [path, 'status'],
                    capture_output=True, text=True, timeout=5).stdout
                import re as _re
                for m in _re.finditer(
                        r'Link \d+ \((?!lo|tun|gpd|docker|br-|virbr)([^)]+)\)'
                        r'(.*?)(?=Link \d+|\Z)', out, _re.S):
                    iface_name = m.group(1)
                    block = m.group(2)
                    dm = _re.search(r'DNS Servers?:\s*(.+)', block)
                    if dm:
                        for s in dm.group(1).split():
                            s = s.strip()
                            if s and s not in dns_servers:
                                dns_servers.append(s)
                    dd = _re.search(r'DNS Domain:\s*(.+)', block)
                    if dd:
                        for d in dd.group(1).split():
                            d = d.strip()
                            if d and d not in dns_domains:
                                dns_domains.append(d)
            except Exception:
                pass

        # 2) NetworkManager nmcli (fallback)
        if not dns_servers and shutil.which('nmcli'):
            try:
                out = subprocess.run(
                    ['nmcli', '-t', '-f', 'IP4.DNS,IP4.DOMAIN',
                     'device', 'show'],
                    capture_output=True, text=True, timeout=5).stdout
                for line in out.splitlines():
                    if line.startswith('IP4.DNS'):
                        val = line.split(':', 1)[1].strip()
                        if val and val not in dns_servers:
                            dns_servers.append(val)
                    elif line.startswith('IP4.DOMAIN'):
                        val = line.split(':', 1)[1].strip()
                        if val and val not in dns_domains:
                            dns_domains.append(val)
            except Exception:
                pass

        # 3) Fichiers lease DHCP
        if not dns_servers:
            import glob as _glob
            for pattern in ('/var/lib/dhcp/dhclient*.leases',
                            '/var/lib/NetworkManager/dhclient*.lease*',
                            '/var/lib/NetworkManager/internal-*.lease'):
                for fpath in _glob.glob(pattern):
                    try:
                        with open(fpath) as f:
                            for line in f:
                                if 'domain-name-servers' in line:
                                    parts = line.split('domain-name-servers')[1]
                                    parts = parts.strip().rstrip(';').strip()
                                    for s in parts.replace(',', ' ').split():
                                        s = s.strip()
                                        if s and s not in dns_servers:
                                            dns_servers.append(s)
                    except Exception:
                        pass

        return dns_servers, dns_domains

    def _refresh_sysinfo(self):
        """Collecte et affiche les informations systeme."""
        lines = []
        try:
            with open('/etc/os-release') as f:
                for l in f:
                    if l.startswith('PRETTY_NAME='):
                        lines.append(l.split('=', 1)[1].strip().strip('"'))
                        break
        except Exception:
            lines.append('Linux')

        try:
            with open('/proc/cpuinfo') as f:
                for l in f:
                    if l.startswith('model name'):
                        cpu = l.split(':', 1)[1].strip()
                        lines.append(f'CPU: {cpu}')
                        break
        except Exception:
            pass

        try:
            with open('/proc/meminfo') as f:
                for l in f:
                    if l.startswith('MemTotal:'):
                        kb = int(l.split()[1])
                        lines.append(f'RAM: {kb // 1048576 + 1} GB')
                        break
        except Exception:
            pass

        tool, _ = _detect_dns_tool()
        lines.append(f'DNS mgr: {tool or "unknown"}')

        dhcp_dns, dhcp_domains = self._discover_dhcp_dns()
        if dhcp_dns:
            lines.append(f'DHCP DNS: {", ".join(dhcp_dns[:4])}')
        if dhcp_domains:
            lines.append(f'Domains: {", ".join(dhcp_domains[:4])}')

        try:
            out = subprocess.run(
                ['hostname', '-I'], capture_output=True, text=True, timeout=3).stdout
            ips = [ip.strip() for ip in out.split() if ip.strip() and ':' not in ip]
            if ips:
                lines.append(f'IPs: {", ".join(ips[:4])}')
        except Exception:
            pass

        try:
            iface = self._primary_uplink_iface()
            if iface:
                lines.append(f'Iface: {iface}')
        except Exception:
            pass

        try:
            import platform
            lines.append(f'Kernel: {platform.release()}')
        except Exception:
            pass

        self._sysinfo_label.set_text('\n'.join(lines))
        return False

    def _apply_state(self, state, subtitle=None, error_msg=None):
        self.state = state
        cfg = STATES.get(state, STATES['disconnected'])

        self.status_icon.set_from_icon_name(cfg['icon'], Gtk.IconSize.DIALOG)
        title = error_msg if state == 'error' else cfg['title']
        self.title_lbl.set_text(title)

        sub = subtitle if subtitle is not None else cfg['subtitle']
        self.subtitle_lbl.set_text(sub or '')

        self.action_btn.set_label(cfg['btn'])
        ctx = self.action_btn.get_style_context()
        for cls in ('btn-connect', 'btn-disconnect', 'btn-cancel'):
            ctx.remove_class(cls)
        ctx.add_class(cfg['btn_class'])

        if cfg['spinner']:
            self.spinner.show()
            self.spinner.start()
        else:
            self.spinner.stop()
            self.spinner.hide()

        if state == 'connected':
            iface = self._oc_iface() or self._primary_uplink_iface()
            if iface:
                self._bw_start(iface)
            self._monitor_toggle.show()
            self._monitor_toggle.set_active(True)
        else:
            if self._bw_monitor:
                self._bw_stop()
            self._monitor_toggle.set_active(False)
            self._monitor_toggle.hide()
            self._hide_monitor_panel()
            if hasattr(self, '_conn_store'):
                self._conn_store.clear()

        self._update_tray_icon()

    def _update_tray_icon(self):
        if self._tray_backend == 'none':
            return
        icon = 'network-vpn-symbolic'
        if self.state == 'connected':
            icon = 'network-transmit-receive-symbolic'
        elif self.state == 'error':
            icon = 'dialog-error-symbolic'
        elif self.state in ('authenticating', 'fetching', 'connecting'):
            icon = 'network-idle-symbolic'
        try:
            srv = self.config.get('server', '')
            tip = f'GP Connect - {self.state}{" - " + srv if srv else ""}'
            if self._tray_backend == 'appindicator' and self.app_indicator is not None:
                self.app_indicator.set_icon_full(icon, tip)
                bw_label = ''
                if self.state == 'connected' and self._bw_monitor:
                    rx, tx = self._bw_monitor.get_rate()
                    bw_label = f'\u2191{_fmt_bytes(tx)}  \u2193{_fmt_bytes(rx)}'
                self.app_indicator.set_label(bw_label, '')
            elif self.tray_icon is not None:
                self.tray_icon.set_from_icon_name(icon)
                self.tray_icon.set_tooltip_text(tip)
        except Exception:
            pass

    # ── Bandwidth monitoring ───────────────────────────────────────────────

    def _bw_start(self, iface):
        """Demarre le monitoring de bande passante sur l'interface VPN."""
        self._bw_stop()
        if not iface:
            return
        self._vpn_iface = iface
        gw_ip = ''
        try:
            server = self.config.get('server', '')
            if server:
                gw_ip = socket.gethostbyname(server)
        except Exception:
            pass
        self._bw_monitor = _BandwidthMonitor(iface, gateway_ip=gw_ip)
        self._bw_timer_source = GLib.timeout_add(1000, self._bw_tick)
        self._conn_timer_source = GLib.timeout_add(5000, self._connections_tick)

    def _bw_stop(self):
        """Arrete le monitoring de bande passante."""
        if self._bw_timer_source:
            GLib.source_remove(self._bw_timer_source)
            self._bw_timer_source = None
        if self._conn_timer_source:
            GLib.source_remove(self._conn_timer_source)
            self._conn_timer_source = None
        if self._bw_monitor is not None:
            try:
                self._bw_monitor.stop()
            except Exception:
                pass
        self._bw_monitor = None
        self._vpn_iface = ''
        if self._tray_backend == 'appindicator' and self.app_indicator:
            try:
                self.app_indicator.set_label('', '')
            except Exception:
                pass

    def _bw_tick(self):
        """Callback 1s : poll compteurs, update tray + graphique + latence."""
        if self.state != 'connected' or not self._bw_monitor:
            return False
        self._bw_monitor.poll()
        self._update_tray_icon()
        if hasattr(self, '_bw_draw_area') and self._mon_panel.get_visible():
            self._bw_draw_area.queue_draw()
            rx, tx = self._bw_monitor.get_rate()
            total_rx, total_tx = self._bw_monitor.get_total()
            latency, jitter, loss = self._bw_monitor.get_latency()
            self._rx_stat.set_markup(f'\u2193 {_fmt_bytes(rx)}')
            self._tx_stat.set_markup(f'\u2191 {_fmt_bytes(tx)}')
            lat_color = '#4ade80' if latency < 50 else (
                '#facc15' if latency < 150 else '#f87171')
            self._bw_total_label.set_markup(
                f'total  \u2193 {_fmt_bytes(total_rx, "")}  '
                f'\u2191 {_fmt_bytes(total_tx, "")}   '
                f'<span foreground="{lat_color}">'
                f'{latency:.0f}ms</span>  '
                f'jitter {jitter:.0f}ms  '
                f'loss {loss:.0f}%')
        return True

    _CONN_STATE_COLORS = {
        'ESTAB': '#818cf8',
        'TIME-WAIT': '#484f58',
        'CLOSE-WAIT': '#f472b6',
        'SYN-SENT': '#c084fc',
        'SYN-RECV': '#c084fc',
        'FIN-WAIT': '#64748b',
        'LAST-ACK': '#64748b',
        'CLOSING': '#f472b6',
    }

    def _connections_tick(self):
        """Callback 5 s (thread GTK) : déclenche un scan `ss` en arrière-plan."""
        if self.state != 'connected':
            return False
        if not hasattr(self, '_conn_store'):
            return True
        if getattr(self, '_conn_scan_inflight', False):
            # Un scan précédent est encore en cours — on attend.
            return True
        self._conn_scan_inflight = True
        vpn_ip = getattr(self, '_vpn_client_ip', '')
        threading.Thread(
            target=self._connections_scan_worker,
            args=(vpn_ip,),
            daemon=True).start()
        return True

    def _connections_scan_worker(self, vpn_ip):
        """Lance `ss -tnpiH` en thread et pousse le résultat au thread GTK."""
        try:
            out = subprocess.run(
                ['ss', '-tnpiH'],
                capture_output=True, text=True, timeout=5).stdout
            rows = self._parse_ss_output(out, vpn_ip)
        except Exception:
            rows = []
        finally:
            # Important : libérer le verrou même en cas d'erreur.
            self._conn_scan_inflight = False
        GLib.idle_add(self._connections_apply, rows)

    def _parse_ss_output(self, out, vpn_ip):
        rows = []
        lines = out.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            parts = line.split()
            if len(parts) < 5 or parts[0] in ('State', 'Recv-Q'):
                i += 1
                continue
            state = parts[0]
            recv_q = parts[1]
            send_q = parts[2]
            local = parts[3]
            remote = parts[4]

            rx_bytes = int(recv_q) if recv_q.isdigit() else 0
            tx_bytes = int(send_q) if send_q.isdigit() else 0
            proc = ''
            for p in parts[5:]:
                if 'users:' in p:
                    proc = p.split('"')[1] if '"' in p else p
                    break
            while i + 1 < len(lines) and lines[i + 1].startswith('\t'):
                i += 1
                info_line = lines[i].strip()
                for token in info_line.split():
                    if token.startswith('bytes_received:'):
                        try:
                            rx_bytes = int(token.split(':')[1])
                        except ValueError:
                            pass
                    elif token.startswith('bytes_sent:'):
                        try:
                            tx_bytes = int(token.split(':')[1])
                        except ValueError:
                            pass

            if vpn_ip and not local.startswith(vpn_ip + ':'):
                i += 1
                continue

            r_addr, _, r_port = remote.rpartition(':')
            color = '#4ade80'
            for prefix, c in self._CONN_STATE_COLORS.items():
                if state.startswith(prefix):
                    color = c
                    break
            rows.append((
                r_addr.strip('[]'), r_port, proc or '-',
                _fmt_bytes(rx_bytes, ''), _fmt_bytes(tx_bytes, ''),
                color))
            i += 1
        return rows

    def _connections_apply(self, rows):
        """Applique le résultat du scan au ListStore (thread GTK)."""
        if not hasattr(self, '_conn_store'):
            return False
        seen = set()
        unique = []
        for r in rows:
            key = (r[0], r[1])
            if key not in seen:
                seen.add(key)
                unique.append(r)
        unique.sort(key=lambda x: x[1])
        self._conn_store.clear()
        for addr, port, proc, rx, tx, color in unique[:80]:
            self._conn_store.append([addr, port, proc, rx, tx, color])
        if hasattr(self, '_conn_count_lbl'):
            self._conn_count_lbl.set_markup(
                f'{len(unique)} connexion{"s" if len(unique) != 1 else ""}')
        return False

    def _on_monitor_toggled(self, btn):
        """Toggle le panneau monitoring."""
        if btn.get_active():
            self._show_monitor_panel()
        else:
            self._hide_monitor_panel()

    def _show_monitor_panel(self):
        self._mon_panel.set_no_show_all(False)
        self._mon_panel.show_all()
        self.resize(800, 480)
        self._paned.set_position(420)

    def _hide_monitor_panel(self):
        self._mon_panel.set_no_show_all(True)
        self._mon_panel.hide()
        self.resize(420, 380)

    def _on_bw_draw(self, widget, cr):
        """Dessine le graphique avec fond sombre integre et style technique."""
        alloc = widget.get_allocation()
        w, h = alloc.width, alloc.height

        # Fond sombre avec coins arrondis
        radius = 6
        cr.new_sub_path()
        cr.arc(w - radius, radius, radius, -1.5708, 0)
        cr.arc(w - radius, h - radius, radius, 0, 1.5708)
        cr.arc(radius, h - radius, radius, 1.5708, 3.1416)
        cr.arc(radius, radius, radius, 3.1416, 4.7124)
        cr.close_path()
        cr.set_source_rgba(0.051, 0.067, 0.090, 0.95)
        cr.fill_preserve()
        cr.set_source_rgba(1, 1, 1, 0.04)
        cr.set_line_width(0.5)
        cr.stroke()

        if not self._bw_monitor:
            return
        history = self._bw_monitor.get_history()

        pad_l, pad_r, pad_t, pad_b = 42, 8, 14, 22
        gw = w - pad_l - pad_r
        gh = h - pad_t - pad_b
        if gw < 10 or gh < 10:
            return

        if len(history) < 2:
            cr.select_font_face('monospace',
                                0, 0)  # NORMAL, NORMAL
            cr.set_font_size(9)
            cr.set_source_rgba(1, 1, 1, 0.2)
            cr.move_to(w / 2 - 30, h / 2)
            cr.show_text('waiting...')
            return

        # Bandwidth: indices 0=rx, 1=tx; Latency: index 2
        all_bw = [max(p[0], p[1]) for p in history]
        y_max = max(max(all_bw) * 1.15, 1024)
        all_lat = [p[2] if len(p) > 2 else 0 for p in history]
        lat_max = max(max(all_lat) * 1.3, 10)

        cr.select_font_face('monospace', 0, 0)

        # Grille horizontale (bande passante)
        cr.set_line_width(0.4)
        for i in range(1, 5):
            y = pad_t + gh - (gh * i / 5)
            cr.set_source_rgba(1, 1, 1, 0.04)
            cr.move_to(pad_l, y)
            cr.line_to(pad_l + gw, y)
            cr.stroke()
            cr.set_source_rgba(1, 1, 1, 0.18)
            cr.set_font_size(7)
            cr.move_to(2, y + 3)
            cr.show_text(_fmt_bytes(y_max * i / 5))

        # Axe X temporel
        n = len(history)
        total_sec = n
        x_step = gw / max(n - 1, 1)
        cr.set_source_rgba(1, 1, 1, 0.15)
        cr.set_font_size(7)
        for sec_ago in range(0, total_sec + 1, 60):
            if sec_ago > total_sec:
                break
            idx = n - 1 - sec_ago
            if idx < 0:
                break
            x = pad_l + idx * x_step
            m = sec_ago // 60
            label = f'{m}m' if m > 0 else '0'
            cr.move_to(x - 4, pad_t + gh + 14)
            cr.show_text(label)

        def draw_curve(data_idx, r, g, b, fill_a, max_val=None):
            ymax = max_val or y_max
            cr.set_source_rgba(r, g, b, 0.85)
            cr.set_line_width(1.2)
            for i, point in enumerate(history):
                val = point[data_idx] if data_idx < len(point) else 0
                x = pad_l + i * x_step
                y = pad_t + gh - (min(val, ymax) / ymax * gh)
                if i == 0:
                    cr.move_to(x, y)
                else:
                    cr.line_to(x, y)
            cr.stroke_preserve()
            last_x = pad_l + (n - 1) * x_step
            cr.line_to(last_x, pad_t + gh)
            cr.line_to(pad_l, pad_t + gh)
            cr.close_path()
            cr.set_source_rgba(r, g, b, fill_a)
            cr.fill()

        # RX = indigo #6366f1 (gradient start)
        draw_curve(0, 0.388, 0.400, 0.945, 0.15)
        # TX = rose #ec4899 (gradient end)
        draw_curve(1, 0.925, 0.282, 0.600, 0.10)
        # Latency = violet #a855f7 (gradient middle)
        draw_curve(2, 0.659, 0.333, 0.969, 0.06, max_val=lat_max)

        # Axe Y latence (cote droit)
        cr.set_source_rgba(0.659, 0.333, 0.969, 0.4)
        cr.set_font_size(6)
        for i in range(1, 4):
            val = lat_max * i / 4
            y = pad_t + gh - (gh * i / 4)
            cr.move_to(pad_l + gw - 28, y + 3)
            cr.show_text(f'{val:.0f}ms')

        # Legende
        cr.set_font_size(7)
        lx = pad_l + 2
        ly = pad_t + 4
        labels = [
            (0.388, 0.400, 0.945, 'RX'),
            (0.925, 0.282, 0.600, 'TX'),
            (0.659, 0.333, 0.969, 'Latency'),
        ]
        for i, (r, g, b, txt) in enumerate(labels):
            ox = lx + i * 52
            cr.set_source_rgba(r, g, b, 0.95)
            cr.rectangle(ox, ly, 6, 6)
            cr.fill()
            cr.set_source_rgba(0.788, 0.835, 0.882, 0.6)
            cr.move_to(ox + 9, ly + 6)
            cr.show_text(txt)

    def _set_state(self, state, subtitle=None, error_msg=None):
        GLib.idle_add(self._apply_state, state, subtitle, error_msg)

    def _log(self, msg):
        # Mirror sur stderr pour permettre `gp-connect 2>&1 | tee /tmp/gp.log`
        # (debugging HIP, openconnect, SAML…). Le panneau UI reste la source
        # primaire visible par l'utilisateur final.
        try:
            sys.stderr.write(f'{msg}\n')
            sys.stderr.flush()
        except Exception:
            pass
        GLib.idle_add(self._log_append, msg)

    def _log_append(self, msg):
        it = self.log_buf.get_end_iter()
        self.log_buf.insert(it, msg + '\n')
        adj = self.log_view.get_parent().get_vadjustment()
        adj.set_value(adj.get_upper())
        return False

    # ── Actions ────────────────────────────────────────────────────────────

    def _on_settings(self, _btn):
        config_snapshot = json.dumps(self.config.data, sort_keys=True)
        dlg = SettingsDialog(self, self.config)
        if dlg.run() == Gtk.ResponseType.OK:
            dlg.apply()
            self._refresh_server_label()
            if json.dumps(self.config.data, sort_keys=True) != config_snapshot:
                self._cached_is_internal = None
                self._cached_conn_mode = None
                self._prompt_apply_settings_restart()
        dlg.destroy()

    def _prompt_apply_settings_restart(self):
        """Propose de redémarrer la connexion pour appliquer les paramètres."""
        if self.state not in ('connected', 'connecting', 'authenticating', 'fetching'):
            return

        dlg = Gtk.MessageDialog(
            parent=self, flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.NONE,
            message_format='Paramètres enregistrés',
        )
        dlg.format_secondary_text(
            'Les modifications ont été sauvegardées.\n\n'
            'Souhaitez-vous redémarrer la connexion VPN maintenant pour '
            'les appliquer ?\n\n'
            'Si vous choisissez « Plus tard », les modifications seront '
            'prises en compte lors du prochain redémarrage de la connexion.')
        dlg.add_button('Plus tard', Gtk.ResponseType.CANCEL)
        dlg.add_button('Redémarrer maintenant', Gtk.ResponseType.OK)
        dlg.set_default_response(Gtk.ResponseType.OK)
        response = dlg.run()
        dlg.destroy()

        if response == Gtk.ResponseType.OK:
            self._log(
                'Redémarrage de la connexion pour appliquer les '
                'nouveaux paramètres…')
            self._cancel(kill_tunnel=True, logout_internal=False)
            GLib.timeout_add(500, self._start_connect)

    def _on_diagnose(self, _btn):
        server = self.config.get('server')
        if not server:
            self._show_msg('Veuillez configurer le serveur VPN dans les paramètres.',
                           Gtk.MessageType.WARNING)
            self._on_settings(None)
            return
        self.log_buf.set_text('')
        self.diag_btn.set_sensitive(False)

        def _run():
            diagnose_connection(
                server,
                clientos=self.config.get('clientos', 'Linux'),
                verify=self.config.get('verify_ssl', True),
                allow_insecure=self.config.get('allow_insecure_crypto', False),
                log_fn=self._log,
            )
            GLib.idle_add(self.diag_btn.set_sensitive, True)

        threading.Thread(target=_run, daemon=True).start()

    def _on_diagnose_hip(self, _btn):
        """Diagnostic dédié HIP : génère le XML, le dump et interroge la passerelle."""
        server = self.config.get('server')
        if not server:
            self._show_msg('Veuillez configurer le serveur VPN dans les paramètres.',
                           Gtk.MessageType.WARNING)
            self._on_settings(None)
            return
        self.log_buf.set_text('')
        self.diag_hip_btn.set_sensitive(False)

        def _run():
            try:
                self._log('═════════════════════════════════════════════════')
                self._log('  Diagnostic HIP — vérification end-to-end')
                self._log('═════════════════════════════════════════════════')

                # 1) Afficher la config HIP en cours
                mode = self.config.get('hip_mode', 'builtin')
                enabled = self.config.get('hip_enabled', True)
                self._log(f'[HIP] Mode               : {mode}')
                self._log(f'[HIP] Activé             : {enabled}')
                self._log(f'[HIP] Script intégré     : {HIP_SCRIPT_BUILTIN}')
                self._log(f'[HIP] Script existe      : {os.path.isfile(HIP_SCRIPT_BUILTIN)}')

                # 2) Générer le XML qui sera envoyé (depuis la config courante)
                self._log('')
                self._log('[HIP] === XML qui sera envoyé à la passerelle ===')
                try:
                    xml = self._generate_hip_xml_for_submit(
                        client_ip='0.0.0.0',
                        md5='<sera-calculé-au-runtime>',
                        username=self.config.get('last_username', ''),
                    )
                    for ln in xml.splitlines():
                        self._log(f'  {ln}')
                    self._log('[HIP] === Fin du XML ===')
                except Exception as e:
                    self._log(f'[HIP] ⚠ Erreur génération XML : {e}')
                    xml = ''

                # 2b) Récap "machine-friendly" : extrait des champs clés.
                #     À comparer trait pour trait avec ce que voit l'admin PA
                #     dans `debug user-id dump hip-report` côté firewall.
                #     Tout désaccord = HIP Object qui ne match pas → no profile.
                if xml:
                    self._log('')
                    self._log('[HIP] === Résumé des champs envoyés ===')
                    self._log('[HIP]   (compare ces valeurs avec PAN-OS : '
                              '`debug user-id dump hip-report computer X ip Y user Z`)')
                    fields = self._extract_hip_summary(xml)
                    keylen = max((len(k) for k in fields), default=10)
                    for k, v in fields.items():
                        self._log(f'[HIP]   {k.ljust(keylen)} = {v}')
                    self._log('[HIP] === Fin du résumé ===')

                # 3) Dump précédent (capturé pendant la dernière connexion)
                self._log('')
                dump_path = getattr(self, '_hip_dump_path',
                                    '/tmp/gp-connect-last-hip-report.xml')
                if os.path.isfile(dump_path):
                    try:
                        size = os.path.getsize(dump_path)
                        mtime = _time_mod.strftime(
                            '%Y-%m-%d %H:%M:%S',
                            _time_mod.localtime(os.path.getmtime(dump_path)))
                        self._log(
                            f'[HIP] Dernier dump réel : {dump_path} '
                            f'({size} octets, {mtime})')
                    except Exception:
                        pass
                else:
                    self._log(f'[HIP] Aucun dump capturé pour le moment '
                              f'({dump_path} absent)')

                # 4) Host-ID DMI (ce qui devrait apparaître côté PA)
                hostid = _get_dmi_machine_uuid()
                self._log('')
                self._log(f'[HIP] Host-ID DMI         : {hostid}')
                self._log(f'[HIP] Hostname            : {socket.gethostname()}')

                # 4b) MD5 calculé selon l'algo openconnect (build_csd_token)
                #     Référence : openconnect/gpst.c lignes 835-861.
                #     Algo : md5(filter_opts(cookie, "authcookie,preferred-ip,
                #                                     preferred-ipv6", 0))
                hostname = socket.gethostname()
                fake_cookie = (
                    f'authcookie=PLACEHOLDER'
                    f'&portal={quote(self.config.get("server", ""))}'
                    f'&user={quote(self.config.get("last_username", "user"))}'
                    f'&domain='
                    f'&computer={quote(hostname)}')
                fake_md5 = compute_hip_md5(hostname, fake_cookie)
                self._log(
                    f'[HIP] MD5 simulé          : {fake_md5}')
                self._log(
                    '[HIP]   (algorithme : md5(filter_opts(cookie, '
                    '"authcookie,preferred-ip,preferred-ipv6")) — '
                    'identique à openconnect 9.x)')

                # 5) Requête prelogin pour vérifier que la passerelle répond
                self._log('')
                self._log(f'[HIP] Test connectivité passerelle ({server})…')
                verify = self.config.get('verify_ssl', True)
                allow_insec = self.config.get('allow_insecure_crypto', False)
                try:
                    s = _make_session(verify=verify, allow_insecure=allow_insec)
                    s.headers['User-Agent'] = self.config.get(
                        'user_agent', 'PAN GlobalProtect')
                    r = s.post(f'https://{server}/ssl-vpn/prelogin.esp',
                               verify=verify, timeout=10,
                               data={'clientos': 'Linux'})
                    self._log(f'[HIP]   ssl-vpn/prelogin.esp → HTTP {r.status_code} '
                              f'({len(r.content)} octets)')
                    if r.status_code != 200:
                        self._log(f'[HIP] ⚠ Passerelle KO — {r.text[:200]}')
                except Exception as e:
                    self._log(f'[HIP] ⚠ Erreur réseau : {e}')

                # 6) Si une session "internal" est active, on peut faire
                #    une vraie requête hipreportcheck.esp avec authcookie
                sess_info = getattr(self, '_internal_session', None)
                if sess_info:
                    self._log('')
                    self._log('[HIP] Session interne active — test hipreportcheck.esp réel…')
                    try:
                        cookie_str = (
                            f"authcookie={sess_info['authcookie']}"
                            f"&portal={quote(sess_info['portal'])}"
                            f"&user={quote(sess_info['user'])}"
                            f"&domain={quote(sess_info['domain'])}"
                            f"&computer={quote(sess_info['hostname'])}")
                        md5_token = compute_hip_md5(sess_info['hostname'], cookie_str)
                        r = sess_info['session'].post(
                            f"https://{sess_info['server']}/ssl-vpn/hipreportcheck.esp",
                            verify=sess_info['verify'], timeout=15,
                            data=_build_gp_ssl_vpn_form(
                                cookie_str=cookie_str,
                                client_ip=sess_info.get('client_ip', '0.0.0.0'),
                                md5=md5_token,
                                server=sess_info['server']))
                        self._log(f'[HIP]   HTTP {r.status_code} '
                                  f'({len(r.content)} octets)')
                        self._log('[HIP]   === Réponse du firewall ===')
                        for ln in r.text.splitlines():
                            self._log(f'    {ln}')
                        self._log('[HIP]   === Fin de la réponse ===')
                    except Exception as e:
                        self._log(f'[HIP] ⚠ Échec test : {e}')
                else:
                    # 6 bis) Mode tunnel : pas de session 'internal' mais un
                    #        tunnel actif. Le contexte (authcookie + gateway)
                    #        a été sauvegardé par hipreport.py via le csd-wrapper
                    #        dans /tmp/.gp-current-authcookie. On l'utilise
                    #        pour POSTer hipreportcheck.esp + hipreport.esp
                    #        directement et capturer la réponse complète de PAN-OS.
                    self._diag_hip_via_saved_context()

                self._log('')
                self._log('═════════════════════════════════════════════════')
                self._log('  Diagnostic HIP terminé')
                self._log('═════════════════════════════════════════════════')
            finally:
                GLib.idle_add(self.diag_hip_btn.set_sensitive, True)

        threading.Thread(target=_run, daemon=True).start()

    def _extract_hip_summary(self, xml):
        """Extrait les champs clés du XML HIP pour résumé/comparaison.

        Retourne un OrderedDict dont les clés correspondent aux champs que
        PAN-OS utilise pour matcher les HIP Objects :
          - host-info : os, os-vendor, host-name, host-id, client-version
          - antivirus / anti-malware : vendor, name, product-version,
            real-time-protection, definition-version, last-scan-time
          - firewall : name, status
          - disk-encryption : name, status
          - mobile-device-management : name, status

        Toute différence entre ces valeurs et celles configurées dans les
        HIP Objects côté firewall = pas de match = pas de HIP profile.
        """
        from collections import OrderedDict
        out = OrderedDict()
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as e:
            out['ERROR'] = f'XML invalide : {e}'
            return out

        def _find(path, default=''):
            el = root.find(path)
            return (el.text or '').strip() if (el is not None
                                                and el.text is not None) else default

        out['md5-sum']        = _find('md5-sum')
        out['user-name']      = _find('user-name')
        out['host-name']      = _find('host-name')
        out['host-id']        = _find('host-id')
        out['ip-address']     = _find('ip-address')
        out['hip-report-version'] = _find('hip-report-version')

        # ⚠ "host-info" est un attribut name="host-info", pas un tag.
        hi_path = './/categories/entry[@name="host-info"]'
        out['os']             = _find(f'{hi_path}/os')
        out['os-vendor']      = _find(f'{hi_path}/os-vendor')
        out['client-version'] = _find(f'{hi_path}/client-version')

        # Anti-Malware (1ère entrée) — format moderne OU ProductInfo legacy
        am = root.find('.//categories/entry[@name="anti-malware"]/list/entry')
        if am is None:
            am = root.find('.//categories/entry[@name="antivirus"]/list/entry')
        if am is None:
            am = root.find('.//categories/entry[@name="AntiVirus"]/list/entry')
        if am is not None:
            prod = am.find('.//Prod')
            out['av.vendor'] = (am.findtext('vendor') or '').strip()
            out['av.name'] = (
                (am.findtext('name') or '').strip()
                or (prod.get('name') if prod is not None else '')
                or '')
            out['av.version'] = (
                (am.findtext('product-version') or '').strip()
                or (prod.get('version') if prod is not None else '')
                or '')
            out['av.real-time'] = (
                (am.findtext('real-time-protection') or '').strip()
                or (am.findtext('.//real-time-protection') or '').strip())
            out['av.defver'] = (
                (am.findtext('definition-version') or '').strip()
                or (prod.get('defver') if prod is not None else '')
                or '')
            out['av.last-scan'] = (
                (am.findtext('last-scan-time') or '').strip()
                or (am.findtext('.//last-full-scan-time') or '').strip())
            out['av.installed'] = 'yes'
        else:
            out['av.installed'] = 'no'

        fw = root.find('.//categories/entry[@name="firewall"]/list/entry')
        if fw is None:
            fw = root.find('.//categories/entry[@name="Firewall"]/list/entry')
        if fw is not None:
            prod = fw.find('.//Prod')
            out['fw.name'] = (
                (fw.findtext('name') or '').strip()
                or (prod.get('name') if prod is not None else '')
                or '')
            out['fw.status'] = (
                (fw.findtext('status') or '').strip()
                or (fw.findtext('is-enabled') or '').strip())
            out['fw.vendor'] = (fw.findtext('vendor') or '').strip()
            out['fw.installed'] = 'yes'
        else:
            out['fw.installed'] = 'no'

        enc = root.find(
            './/categories/entry[@name="disk-encryption"]/list/entry')
        if enc is None:
            enc = root.find(
                './/categories/entry[@name="Disk-Encryption"]/list/entry')
        if enc is not None:
            prod = enc.find('.//Prod')
            out['enc.name'] = (
                (enc.findtext('name') or '').strip()
                or (prod.get('name') if prod is not None else '')
                or '')
            out['enc.status'] = (enc.findtext('status') or '').strip() or 'yes'
            out['enc.installed'] = 'yes'
        else:
            out['enc.installed'] = 'no'

        mdm = root.find(
            './/categories/entry[@name="mobile-device-management"]/list/entry')
        if mdm is None:
            mdm = root.find(
                './/categories/entry[@name="Mobile-Device-Management"]'
                '/list/entry')
        if mdm is not None:
            prod = mdm.find('.//Prod')
            out['mdm.name'] = (
                (mdm.findtext('name') or '').strip()
                or (prod.get('name') if prod is not None else '')
                or '')
            out['mdm.status'] = (
                (mdm.findtext('status') or '').strip()
                or (mdm.findtext('is-enabled') or '').strip())
            out['mdm.installed'] = 'yes'
        else:
            out['mdm.installed'] = 'no'

        # Compter les interfaces (host-info ou racine legacy)
        ifaces = root.findall(
            './/categories/entry[@name="host-info"]/network-interface/entry')
        if not ifaces:
            ifaces = root.findall('.//network-interface/entry')
        out['network-interfaces'] = str(len(ifaces))

        return out

    def _run_hip_script_capture(self, script, client_ip, md5, username,
                                computer, cookie_str):
        """Exécute hipreport.py (ou script custom) et retourne le XML stdout."""
        python3 = shutil.which('python3') or 'python3'
        gateway = (self.config.get('current_gateway')
                   or self.config.get('server', ''))
        hostname = computer or socket.gethostname()
        if not cookie_str:
            cookie_str = (
                f'authcookie=PLACEHOLDER'
                f'&portal={quote(self.config.get("server", ""))}'
                f'&user={quote(username or self.config.get("last_username", ""))}'
                f'&domain='
                f'&computer={quote(hostname)}')
        env = os.environ.copy()
        hip_mode = self.config.get('hip_mode', 'builtin')
        if hip_mode == 'fake':
            template_path = str(CONFIG_DIR / 'hip_template.xml')
            env['GP_HIP_MODE'] = 'fake'
            if os.path.isfile(template_path):
                env['GP_HIP_TEMPLATE'] = template_path
        try:
            proc = subprocess.run(
                [python3, script,
                 '--cookie', cookie_str,
                 '--client-ip', client_ip or '0.0.0.0',
                 '--md5', md5 or '',
                 '--computer', hostname,
                 '--gateway', gateway],
                capture_output=True, text=True, timeout=45, env=env)
        except Exception as e:
            self._log(f'  [HIP] ⚠ Exécution script échouée : {e}')
            return ''
        if proc.stderr:
            for ln in proc.stderr.splitlines():
                if ln.strip():
                    self._log(f'  [HIP/script] {ln}')
        if proc.returncode != 0:
            self._log(
                f'  [HIP] ⚠ Script HIP exit={proc.returncode}')
            return proc.stdout.strip()
        xml = proc.stdout.strip()
        if not xml or '<hip-report' not in xml:
            self._log('  [HIP] ⚠ Script HIP : XML vide ou invalide')
            return ''
        return xml

    def _generate_hip_xml_for_submit(self, client_ip='0.0.0.0', md5='',
                                     username='', cookie_str='',
                                     computer=''):
        """Génère le XML HIP selon hip_mode (builtin/custom/fake)."""
        if not self.config.get('hip_enabled', True):
            return ''
        hip_mode = self.config.get('hip_mode', 'builtin')
        if hip_mode == 'fake':
            template_path = str(CONFIG_DIR / 'hip_template.xml')
            if os.path.isfile(template_path):
                try:
                    import re as _re
                    with open(template_path) as f:
                        report_xml = f.read()
                    from datetime import datetime as _dt
                    now = _dt.now().strftime('%m/%d/%Y %H:%M:%S')

                    def _upd(tag, val, xml):
                        return _re.sub(
                            rf'<{tag}>[^<]*</{tag}>',
                            f'<{tag}>{val}</{tag}>',
                            xml, count=1)
                    if client_ip:
                        report_xml = _upd('ip-address', client_ip, report_xml)
                    if md5:
                        report_xml = _upd('md5-sum', md5, report_xml)
                    if username:
                        report_xml = _upd('user-name', username, report_xml)
                    report_xml = _upd('generate-time', now, report_xml)
                    return report_xml
                except Exception as e:
                    self._log(f'  [HIP] ⚠ Template fake : {e}')
            return self._generate_fake_hip_xml_from_config(
                client_ip=client_ip, md5=md5 or '<md5-placeholder>',
                username=username)
        if hip_mode == 'custom':
            script = self.config.get('hip_script', '').strip()
            if script and os.path.isfile(script):
                return self._run_hip_script_capture(
                    script, client_ip, md5, username, computer, cookie_str)
            self._log('  [HIP] ⚠ Script personnalisé introuvable')
            return ''
        if HIP_SCRIPT_BUILTIN and os.path.isfile(HIP_SCRIPT_BUILTIN):
            return self._run_hip_script_capture(
                HIP_SCRIPT_BUILTIN, client_ip, md5, username, computer,
                cookie_str)
        self._log(f'  [HIP] ⚠ Script intégré introuvable : {HIP_SCRIPT_BUILTIN}')
        return ''

    def _report_hip_delivery_status(self, target_host, hip_state):
        """Bilan détaillé de l'envoi HIP une fois le tunnel établi."""
        enabled = self.config.get('hip_enabled', True)
        portal_info = getattr(self, '_portal_hip_info', {}) or {}
        collect_hip = portal_info.get('collect_hip', 'yes')
        hip_mode = self.config.get('hip_mode', 'builtin')

        self._log('  [HIP] ═══ Bilan envoi HIP ═══')
        self._log(f'  [HIP] Activé (paramètres)       : '
                  f'{"oui" if enabled else "non"}')
        self._log(f'  [HIP] Mode configuré            : {hip_mode}')
        self._log(f'  [HIP] Passerelle                : {target_host}')
        self._log(f'  [HIP] collect-hip-data (portail): {collect_hip}')

        if not enabled:
            self._log('  [HIP] ➜ HIP désactivé — aucun envoi.')
            self._log('  [HIP] ═══ Fin bilan HIP ═══')
            return

        if collect_hip == 'no':
            self._log('  [HIP] ⚠ Le portail indique collect-hip-data=no : '
                      'openconnect n\'appellera PAS le script HIP.')
            self._log('  [HIP] ➜ Aucun rapport ne sera expédié tant que '
                      'cette option reste « no » côté PAN-OS.')

        wrapper_ok = hip_state.get('wrapper_configured', False)
        self._log(f'  [HIP] csd-wrapper configuré     : '
                  f'{"oui" if wrapper_ok else "non"}')
        if not wrapper_ok:
            script = (self.config.get('hip_script', '').strip()
                      if hip_mode == 'custom' else HIP_SCRIPT_BUILTIN)
            self._log(f'  [HIP] Script attendu          : {script}')
            if script and not os.path.isfile(script):
                self._log('  [HIP] ⚠ Script introuvable — HIP non expédié.')

        vendors = portal_info.get('expected_vendors') or []
        if vendors:
            self._log(f'  [HIP] Produits attendus ({len(vendors)}) :')
            for v in vendors:
                self._log(f'  [HIP]   • {v.get("vendor", "?")} / '
                          f'{v.get("product") or "(any)"}')

        check_count = hip_state.get('check_count', 0)
        script_ok   = hip_state.get('script_ok', False)
        hip_failed  = hip_state.get('failed', False)
        dump_path   = hip_state.get('dump_path', '')

        self._log(f'  [HIP] Appels hipreportcheck     : {check_count}')
        self._log(f'  [HIP] Script exécuté (openconnect): '
                  f'{"oui" if script_ok else "non"}')
        if hip_failed:
            self._log('  [HIP] ✘ La passerelle a signalé un échec HIP')
        elif script_ok and check_count > 0:
            self._log('  [HIP] ✔ Rapport généré et cycle HIP openconnect OK')
        elif script_ok and check_count == 0:
            self._log('  [HIP] ⚠ Script exécuté mais aucun hipreportcheck '
                      'détecté — le portail n\'a peut-être pas demandé le HIP')
        elif wrapper_ok and not script_ok:
            self._log('  [HIP] ⚠ csd-wrapper actif mais script non exécuté '
                      'ou en échec — rapport probablement non expédié')

        if dump_path and os.path.isfile(dump_path):
            try:
                size = os.path.getsize(dump_path)
                self._log(f'  [HIP] Dernier XML capturé       : {dump_path} '
                          f'({size} octets)')
                with open(dump_path) as f:
                    xml = f.read()
                if xml.strip():
                    summary = self._extract_hip_summary(xml)
                    for k, v in summary.items():
                        self._log(f'  [HIP]   {k} = {v}')
            except Exception as e:
                self._log(f'  [HIP] ⚠ Lecture dump : {e}')
        else:
            self._log('  [HIP] Aucun dump XML capturé pour cette connexion')

        self._log('  [HIP] ═══ Fin bilan HIP ═══')

    def _verify_hip_after_connect(self, target_host):
        """Vérifie côté passerelle si le HIP a bien été reçu (post-connexion)."""
        if not self.config.get('hip_enabled', True):
            return
        ctx_path = getattr(self, '_hip_ctx_path',
                           '/tmp/.gp-current-authcookie')

        def _run():
            import time as _t
            _t.sleep(2)
            if self.state != 'connected':
                return
            if not os.path.isfile(ctx_path):
                self._log('  [HIP] Vérif. post-connexion : pas de contexte '
                          f'({ctx_path}) — le csd-wrapper n\'a peut-être '
                          'pas été invoqué.')
                return
            try:
                with open(ctx_path) as f:
                    ctx = json.load(f)
            except Exception as e:
                self._log(f'  [HIP] Vérif. post-connexion : lecture ctx : {e}')
                return

            server = target_host or self.config.get('server', '')
            # ctx.gateway peut être vide ou un libellé portail (Office-Gateway-N)
            # — ne l'utiliser que s'il ressemble à un hostname DNS.
            gw_ctx = ctx.get('gateway') or ''
            if _looks_like_hostname(gw_ctx):
                server = gw_ctx
            cookie_str = ctx.get('cookie', '')
            client_ip  = ctx.get('client_ip', '0.0.0.0')
            computer   = ctx.get('computer', socket.gethostname())
            md5_token  = ctx.get('md5', '')
            if not server or not cookie_str:
                self._log('  [HIP] Vérif. post-connexion : contexte incomplet')
                return

            verify = self.config.get('verify_ssl', True)
            allow_insec = self.config.get('allow_insecure_crypto', False)
            try:
                sess = _make_session(verify=verify, allow_insecure=allow_insec)
                sess.headers['User-Agent'] = self.config.get(
                    'user_agent', 'PAN GlobalProtect')
                self._log(
                    f'  [HIP] Vérif. post-connexion → '
                    f'https://{server}/ssl-vpn/hipreportcheck.esp…')
                r = sess.post(
                    f'https://{server}/ssl-vpn/hipreportcheck.esp',
                    verify=verify, timeout=15,
                    data=_build_gp_ssl_vpn_form(
                        cookie_str=cookie_str, client_ip=client_ip,
                        md5=md5_token, server=server))
                self._log(f'  [HIP] Réponse hipreportcheck : HTTP {r.status_code}')
                needed = None
                err_msg = None
                for ln in r.text.splitlines():
                    self._log(f'  [HIP]   ← {ln}')
                    low = ln.lower()
                    if 'hip-report-needed' in low:
                        import re as _re
                        m = _re.search(
                            r'<hip-report-needed[^>]*>\s*([^<]+)\s*</', ln)
                        if m:
                            needed = m.group(1).strip().lower()
                    if '<error>' in low:
                        import re as _re
                        m = _re.search(r'<error>([^<]+)</error>', ln, _re.I)
                        if m:
                            err_msg = m.group(1).strip()
                if err_msg:
                    self._log(
                        f'  [HIP] ⚠ hipreportcheck erreur : {err_msg}')
                elif needed == 'no':
                    self._log('  [HIP] ✔ Passerelle : rapport HIP à jour '
                              '(hip-report-needed=no)')
                elif needed == 'yes':
                    self._log('  [HIP] ⚠ Passerelle : rapport HIP MANQUANT '
                              '(hip-report-needed=yes) — soumission directe…')
                    xml = self._generate_hip_xml_for_submit(
                        client_ip=client_ip, md5=md5_token,
                        username=ctx.get('user', ''), cookie_str=cookie_str,
                        computer=computer)
                    if xml:
                        from urllib.parse import unquote_plus
                        cf = {}
                        for part in cookie_str.split('&'):
                            if '=' in part:
                                k, _, v = part.partition('=')
                                cf[unquote_plus(k)] = unquote_plus(v)
                        ok = gateway_hip_submit(
                            sess, server,
                            cf.get('authcookie', ''),
                            cf.get('portal', ''),
                            cf.get('user', ''),
                            cf.get('domain', ''),
                            computer, client_ip, xml,
                            verify=verify, log_fn=self._log)
                        if ok:
                            self._log('  [HIP] ✔ Rapport HIP soumis en secours '
                                      'à la passerelle')
                        else:
                            self._log('  [HIP] ✘ Échec soumission HIP de secours')
                else:
                    self._log('  [HIP] ℹ Réponse hipreportcheck ambiguë — '
                              'voir lignes ci-dessus')
            except Exception as e:
                self._log(f'  [HIP] Vérif. post-connexion échouée : {e}')

        threading.Thread(target=_run, daemon=True).start()

    def _diag_hip_via_saved_context(self):
        """Re-soumet hipreportcheck.esp + hipreport.esp via la session tunnel
        active, en utilisant le contexte sauvegardé par hipreport.py.

        Utile en mode portail interactif Prisma : le tunnel openconnect tourne,
        on n'a pas de session 'internal', mais le csd-wrapper a déposé
        l'authcookie + portal + user + computer + client-ip + gateway dans
        /tmp/.gp-current-authcookie au dernier appel HIP.

        Permet d'éditer ~/.config/gp-connect/hip_template.xml, cliquer
        Diag HIP, et voir immédiatement la réponse PAN-OS — sans devoir
        recycler le tunnel.
        """
        ctx_path = getattr(self, '_hip_ctx_path',
                           '/tmp/.gp-current-authcookie')
        if not os.path.isfile(ctx_path):
            self._log('')
            self._log('[HIP] (Pas de contexte sauvegardé — connectez-vous '
                      'au moins une fois pour interroger '
                      'hipreport.esp réellement)')
            self._log(f'[HIP]   Fichier attendu : {ctx_path}')
            return

        try:
            with open(ctx_path) as f:
                ctx = json.load(f)
        except Exception as e:
            self._log(f'[HIP] ⚠ Impossible de lire {ctx_path} : {e}')
            return

        # Le serveur cible est le gateway (pas le portail) — c'est lui
        # qui parse le HIP report et assigne le HIP profile.
        server = (ctx.get('gateway') or self.config.get('current_gateway')
                  or self.config.get('server', ''))
        cookie_str = ctx.get('cookie', '')
        client_ip  = ctx.get('client_ip', '0.0.0.0')
        computer   = ctx.get('computer', socket.gethostname())
        user       = ctx.get('user', '')
        md5_token  = ctx.get('md5', '')
        saved_at   = ctx.get('saved_at', '?')

        if not server or not cookie_str:
            self._log('')
            self._log('[HIP] ⚠ Contexte sauvegardé incomplet '
                      '(gateway/cookie manquant) — abandon.')
            return

        verify     = self.config.get('verify_ssl', True)
        allow_insec = self.config.get('allow_insecure_crypto', False)

        self._log('')
        self._log('[HIP] Tunnel actif — re-soumission via contexte sauvegardé')
        self._log(f'[HIP]   Contexte    : {ctx_path} (sauvegardé {saved_at})')
        self._log(f'[HIP]   Gateway     : {server}')
        self._log(f'[HIP]   User        : {user}')
        self._log(f'[HIP]   Computer    : {computer}')
        self._log(f'[HIP]   Client IP   : {client_ip}')
        self._log(f'[HIP]   MD5 token   : {md5_token}')

        try:
            sess = _make_session(verify=verify, allow_insecure=allow_insec)
            sess.headers['User-Agent'] = self.config.get(
                'user_agent', 'PAN GlobalProtect')

            # 1) hipreportcheck.esp — nécessite la passerelle d'envoyer
            #    hip-report-needed=yes/no.
            self._log('')
            self._log('[HIP] ── POST hipreportcheck.esp ──')
            r = sess.post(
                f'https://{server}/ssl-vpn/hipreportcheck.esp',
                verify=verify, timeout=15,
                data=_build_gp_ssl_vpn_form(
                    cookie_str=cookie_str, client_ip=client_ip,
                    md5=md5_token, server=server))
            self._log(f'[HIP]   HTTP {r.status_code} ({len(r.content)} octets)')
            for ln in r.text.splitlines():
                self._log(f'[HIP]   ← {ln}')

            # 2) hipreport.esp — POST du XML courant. PAN-OS écrase
            #    l'ancien rapport ; pas d'effet de bord.
            try:
                xml = self._generate_hip_xml_for_submit(
                    client_ip=client_ip, md5=md5_token, username=user,
                    cookie_str=cookie_str, computer=computer)
            except Exception as e:
                self._log(f'[HIP] ⚠ Impossible de regénérer le XML : {e}')
                return

            self._log('')
            self._log(f'[HIP] ── POST hipreport.esp ({len(xml)} octets de XML) ──')
            r = sess.post(
                f'https://{server}/ssl-vpn/hipreport.esp',
                verify=verify, timeout=20,
                data=_build_gp_ssl_vpn_form(
                    cookie_str=cookie_str, client_ip=client_ip,
                    report=xml, server=server))
            self._log(f'[HIP]   HTTP {r.status_code} ({len(r.content)} octets)')
            for ln in r.text.splitlines():
                self._log(f'[HIP]   ← {ln}')

            # Détection rapide d'erreur explicite côté PA
            body_low = r.text.lower()
            if 'status="error"' in body_low or '<msg>' in body_low:
                self._log('[HIP] ⚠ PAN-OS a renvoyé une erreur — voir le body.')
            elif 'status="success"' in body_low:
                self._log('[HIP] ✔ PAN-OS a accepté le rapport.')
                self._log('[HIP]   → Si "no HIP profile" reste affiché côté '
                          'console, c\'est un problème de matching')
                self._log('[HIP]     HIP Object (vendor/product/OS), pas de '
                          'soumission. Voir section 2 du plan.')
        except Exception as e:
            self._log(f'[HIP] ⚠ Échec POST direct : {e}')

    def _on_action(self, _btn):
        if self.state in ('disconnected', 'error'):
            if not self.config.get('server'):
                self._show_msg('Veuillez configurer le serveur VPN dans les paramètres.',
                               Gtk.MessageType.WARNING)
                self._on_settings(None)
                return
            self._start_connect()
        elif self.state == 'connected':
            self._disconnect()
        else:
            self._cancel()

    def _cancel(self, kill_tunnel=False, logout_internal=False):
        """Annule / déconnecte la session courante.

        Paramètres :
          kill_tunnel      — True si l'utilisateur veut couper le tunnel
                             VPN (clic « Déconnecter »). False si on
                             interrompt juste une tentative de connexion.
          logout_internal  — True pour envoyer le logout au gateway interne
                             (invalide l'authcookie côté serveur). Réservé
                             à l'action « Oublier la session ». Par défaut
                             on coupe juste le HIP keepalive pour préserver
                             le token réutilisable.
        """
        self._cancel_requested = True
        if self._vpn_monitor_source:
            GLib.source_remove(self._vpn_monitor_source)
            self._vpn_monitor_source = None
        self._existing_vpn_pid = None
        if self._internal_session:
            if logout_internal:
                # Logout explicite : invalide l'authcookie côté firewall.
                threading.Thread(target=self._internal_disconnect,
                                 daemon=True).start()
            else:
                # Arrêter la boucle HIP sans faire logout — le token
                # authcookie reste valide pour une reprise rapide.
                stop_ev = getattr(self, '_hip_stop_event', None)
                if stop_ev:
                    stop_ev.set()
                self._internal_session = None
        if kill_tunnel:
            self._restore_dns_routes()
            if self.openconnect_proc and self.openconnect_proc.poll() is None:
                try:
                    self.openconnect_proc.terminate()
                except Exception:
                    pass
            threading.Thread(target=self._kill_all_openconnect, daemon=True).start()
        else:
            if self.openconnect_proc and self.openconnect_proc.poll() is None:
                try:
                    self.openconnect_proc.terminate()
                except Exception:
                    pass
        self._set_state('disconnected')

    @staticmethod
    def _kill_all_openconnect():
        """Tue tous les processus openconnect (SIGTERM puis SIGKILL si nécessaire)."""
        import time as _time
        # 1. SIGTERM — demande d'arrêt propre
        subprocess.run(['sudo', '-n', 'pkill', '-SIGTERM', '-x', 'openconnect'],
                       capture_output=True)
        _time.sleep(1.5)
        # 2. Vérifier s'il en reste
        remaining = subprocess.run(
            ['pgrep', '-x', 'openconnect'],
            capture_output=True, text=True)
        if remaining.returncode == 0:
            # 3. SIGKILL — forcer la terminaison
            subprocess.run(['sudo', '-n', 'pkill', '-SIGKILL', '-x', 'openconnect'],
                           capture_output=True)

    def _disconnect(self):
        """Déconnexion manuelle : coupe le tunnel mais PRÉSERVE la session.

        Le token de session sauvegardé (prelogin-cookie / portal-userauth-
        cookie / authcookie interne) reste sur disque et reste valide côté
        serveur, ce qui permet à la prochaine connexion de reprendre sans
        repasser par SAML tant que le token n'a pas expiré.
        """
        self._log('Déconnexion du tunnel VPN (session conservée)…')
        self._cancel(kill_tunnel=True, logout_internal=False)

    def _disconnect_and_forget(self):
        """Déconnexion + suppression du token du serveur courant.

        Force un logout côté gateway (mode interne) ET supprime le fichier
        de session local : la prochaine connexion repassera obligatoirement
        par SAML.
        """
        server = self.config.get('server', '')
        self._log('Déconnexion + suppression des tokens de session…')
        # Par sécurité, on efface uniquement le token du serveur courant —
        # les autres serveurs VPN éventuellement utilisés restent intacts.
        _clear_session_token(server or None, log_fn=self._log)
        self._reconnect_count = 99
        self._cancel(kill_tunnel=True, logout_internal=True)

    def _auto_reconnect_on_startup(self):
        """Auto-reconnexion au démarrage avec token sauvegardé."""
        if self.state != 'disconnected':
            return False
        server = self.config.get('server', '')
        if not server:
            return False
        self._set_state('authenticating')
        self._reconnect_count = 0
        if self._try_reuse_session():
            return False
        self._log('  [Session] Reconnexion — auth SAML via WebView…')
        self._start_connect()
        return False

    def _resume_internal_session(self, server, session, clientos, user_agent,
                                  verify):
        """Reprend une session interne avec l'authcookie sauvegardé."""
        self._set_state('connecting', subtitle=f'Reprise {server}…')
        authcookie = session['cookie_value']
        user = session.get('username', '')
        portal = session.get('portal', '')
        domain = session.get('domain', '')
        hostname = session.get('hostname', socket.gethostname())
        client_ip = session.get('client_ip', '0.0.0.0')
        hip_interval = 3600

        self._vpn_client_ip = client_ip
        self._internal_session = {
            'session': _make_session(
                verify=verify,
                allow_insecure=self.config.get('allow_insecure_crypto', False)),
            'server': server,
            'authcookie': authcookie,
            'portal': portal,
            'user': user,
            'domain': domain,
            'hostname': hostname,
            'client_ip': client_ip,
            'verify': verify,
            'hip_interval': hip_interval,
        }

        self._log(
            f'  [Internal] Reprise session : {user} @ {server}')
        self._set_state('connected',
                        subtitle=f'Interne {server} (sans tunnel)')

        self._hip_stop_event = threading.Event()
        threading.Thread(
            target=self._hip_keepalive_loop, daemon=True).start()

    # ── Détection VPN existant ─────────────────────────────────────────────

    def _detect_existing_vpn(self):
        """Appelé une fois au démarrage : détecte un openconnect déjà actif.

        Utilise l'état sauvegardé pour une reprise robuste après mise à jour.
        """
        try:
            res = subprocess.run(
                ['pgrep', '-x', 'openconnect'],
                capture_output=True, text=True)
            if res.returncode == 0:
                pids = [p for p in res.stdout.strip().split('\n') if p]
                if pids:
                    pid = int(pids[0])
                    saved = _load_vpn_state()
                    if saved:
                        server = saved.get('server', '')
                        iface = saved.get('iface', '') or self._oc_iface()
                        self._vpn_client_ip = saved.get('client_ip', '')
                    else:
                        server = self._oc_server_from_pid(pid)
                        iface = self._oc_iface()
                    GLib.idle_add(self._on_vpn_detected, pid, server, iface)
                    return False
        except Exception:
            pass
        _clear_vpn_state()
        return False

    @staticmethod
    def _oc_server_from_pid(pid):
        """Lit /proc/PID/cmdline et extrait l'hôte cible."""
        try:
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                parts = f.read().split(b'\x00')
            parts = [p.decode(errors='replace') for p in parts if p]
            # Chercher dernier argument non-option qui ressemble à un hostname
            for p in reversed(parts):
                if p and not p.startswith('-') and '.' in p and '=' not in p:
                    return p
        except Exception:
            pass
        return ''

    @staticmethod
    def _oc_iface():
        """Retourne la première interface tunnel (gpd* ou tun*) trouvée."""
        try:
            for name in sorted(os.listdir('/sys/class/net/')):
                if name.startswith(('gpd', 'tun')):
                    return name
        except Exception:
            pass
        return ''

    @staticmethod
    def _iface_by_ip(ip_addr):
        """Retourne l'interface qui porte l'IP donnée, sinon ''. """
        if not ip_addr:
            return ''
        try:
            out = subprocess.run(
                ['ip', '-o', 'addr', 'show'],
                capture_output=True, text=True, check=False).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    iface = parts[1]
                    cidr = parts[3]
                    ip = cidr.split('/')[0]
                    if ip == ip_addr:
                        return iface
        except Exception:
            pass
        return ''

    @staticmethod
    def _parse_default_routes():
        """Retourne {iface: bool} depuis resolvectl/systemd-resolve status."""
        routes = {}
        tool, path = _detect_dns_tool()
        if not path or tool not in ('resolvectl', 'systemd-resolve'):
            return routes
        try:
            out = subprocess.run(
                [path, 'status'],
                check=False, capture_output=True, text=True).stdout
            import re as _re
            blocks = _re.split(r'(?m)^Link \d+ \([^)]+\)\n', out)
            heads = _re.findall(r'(?m)^Link \d+ \(([^)]+)\)\n', out)
            for iface, block in zip(heads, blocks[1:]):
                m = _re.search(r'(?m)^\s*Default Route:\s*(yes|no)\s*$', block)
                if m:
                    routes[iface] = (m.group(1) == 'yes')
        except Exception:
            pass
        return routes

    @staticmethod
    def _run_resolvectl(args, check=False):
        """Exécute l'outil DNS en mode non-interactif (sudo -n).

        Essaie resolvectl d'abord, puis systemd-resolve en fallback
        (Ubuntu 22.04 et antérieurs).
        """
        tool, path = _detect_dns_tool()
        if not path or tool not in ('resolvectl', 'systemd-resolve'):
            if check:
                raise FileNotFoundError('Aucun outil DNS (resolvectl/systemd-resolve) trouvé')
            return subprocess.CompletedProcess([], 1, '', 'no dns tool')
        r2 = subprocess.run(
            ['sudo', '-n', path, *args],
            check=False, capture_output=True, text=True)
        if r2.returncode != 0 and tool == 'resolvectl':
            alt = shutil.which('systemd-resolve')
            if alt:
                r2 = subprocess.run(
                    ['sudo', '-n', alt, *args],
                    check=False, capture_output=True, text=True)
        if check and r2.returncode != 0:
            raise subprocess.CalledProcessError(
                r2.returncode, r2.args, output=r2.stdout, stderr=r2.stderr)
        return r2

    @staticmethod
    def _primary_uplink_iface():
        """Retourne l'interface uplink primaire (route vers Internet)."""
        return _primary_uplink_iface()

    def _ensure_uplink_dns_route(self):
        """Assure qu'au moins une interface LAN a default-route DNS=yes."""
        routes = self._parse_default_routes()
        if any(routes.values()):
            return True
        uplink = self._primary_uplink_iface()
        if not uplink:
            self._log('  [DNS] ⚠ Impossible de détecter l’interface uplink.')
            return False
        if not can_sudo_resolvectl():
            if not self._dns_auth_warned:
                self._log(
                    '  [DNS] ⚠ Permission DNS manquante (sudo -n resolvectl). '
                    'Cliquez sur "Config. sudo" une fois pour autoriser resolvectl.')
                self._dns_auth_warned = True
            return False
        try:
            self._run_resolvectl(['default-route', uplink, 'yes'], check=True)
            self._log(f'  [DNS] ✔ Rétablissement DNS LAN : {uplink} -> default-route yes')
            return True
        except Exception as e:
            self._log(
                f'  [DNS] ✘ Rétablissement DNS LAN échoué ({e}). '
                f'Exécutez: resolvectl default-route {uplink} yes')
            return False

    def _apply_default_routes_for_vpn(self, iface):
        """Force default-route DNS vers iface, et no sur les autres liens utiles."""
        if not can_sudo_resolvectl():
            raise PermissionError('sudo -n resolvectl non autorisé')
        tool, path = _detect_dns_tool()
        if not path:
            raise FileNotFoundError('Aucun outil DNS trouvé')
        out = subprocess.run(
            [path, 'status'],
            check=False, capture_output=True, text=True).stdout
        import re as _re
        links = _re.findall(r'^Link \d+ \(([^)]+)\)', out, _re.M)
        for link in links:
            if link.startswith(('lo', 'docker', 'br-', 'virbr')):
                continue
            val = 'yes' if link == iface else 'no'
            self._run_resolvectl(['default-route', link, val], check=False)

    def _restore_dns_routes(self):
        """Restaure les routes DNS modifiées par _force_dns_over_vpn()."""
        snap = self._dns_route_snapshot or {}
        if not snap:
            # Même sans snapshot (crash/restart), garantir un DNS LAN utilisable.
            self._ensure_uplink_dns_route()
            return
        try:
            for iface, was_yes in snap.items():
                if iface.startswith(('lo', 'docker', 'br-', 'virbr')):
                    continue
                self._run_resolvectl(
                    ['default-route', iface, 'yes' if was_yes else 'no'],
                    check=False)
            if self._dns_forced_iface:
                # Supprimer l'éventuel "~." explicitement posé sur l'iface VPN
                self._run_resolvectl(
                    ['domain', self._dns_forced_iface, ''],
                    check=False)
            self._log('  [DNS] ↩ Routes DNS restaurées (déconnexion).')
        except Exception:
            pass
        finally:
            self._dns_route_snapshot = {}
            self._dns_forced_iface = ''
            # Sécurité : si tout est en "no", remettre l'uplink en "yes".
            self._ensure_uplink_dns_route()

    def _get_iface_dns_servers(self, iface):
        """Lit les serveurs DNS configurés sur une interface via resolvectl."""
        tool, path = _detect_dns_tool()
        if not path or tool not in ('resolvectl', 'systemd-resolve'):
            return []
        try:
            out = subprocess.run(
                [path, 'status', iface],
                capture_output=True, text=True, timeout=5).stdout
            import re as _re
            m = _re.search(r'DNS Servers?:\s*(.+)', out)
            if m:
                return [s.strip() for s in m.group(1).split() if s.strip()]
        except Exception:
            pass
        return []

    def _get_lan_dns_servers(self):
        """Récupère les serveurs DNS des interfaces LAN (avant tunnel)."""
        tool, path = _detect_dns_tool()
        if not path or tool not in ('resolvectl', 'systemd-resolve'):
            return []
        try:
            out = subprocess.run(
                [path, 'status'],
                capture_output=True, text=True, timeout=5).stdout
            import re as _re
            servers = []
            for m in _re.finditer(
                    r'Link \d+ \((?!tun|gpd|lo|docker|br-|virbr)([^)]+)\)'
                    r'.*?DNS Servers?:\s*(.+?)$',
                    out, _re.M | _re.S):
                for s in m.group(2).split():
                    s = s.strip()
                    if s and s not in servers:
                        servers.append(s)
            return servers
        except Exception:
            return []

    def _force_dns_over_vpn(self, client_ip=''):
        """Force le DNS via le tunnel VPN.

        Compatible Ubuntu 22.04-25.10 : vérifie que vpnc-script a bien
        configuré les DNS, corrige si nécessaire (bug vpnc-scripts 24.04+).
        """
        iface = ''
        for _ in range(12):
            iface = self._iface_by_ip(client_ip) or self._oc_iface()
            if iface:
                break
            _time_mod.sleep(0.5)

        if not iface:
            self._log(
                '  [DNS] ⚠ Interface tunnel introuvable (tun*/gpd*) '
                'même après retry.')
            return

        tool, _ = _detect_dns_tool()
        self._log(f'  [DNS] Gestionnaire détecté : {tool or "aucun"}')

        if not self._dns_route_snapshot:
            self._dns_route_snapshot = self._parse_default_routes()
        self._dns_forced_iface = iface

        if tool not in ('resolvectl', 'systemd-resolve'):
            if shutil.which('nmcli'):
                try:
                    subprocess.run(
                        ['nmcli', 'device', 'modify', iface,
                         'ipv4.dns-priority', '-10'],
                        check=True, capture_output=True, timeout=5)
                    self._log(f'  [DNS] ✔ DNS forcé via nmcli ({iface})')
                    return
                except Exception as e:
                    self._log(f'  [DNS] ⚠ nmcli échoué: {e}')
            self._log(
                f'  [DNS] ✘ Aucun outil DNS compatible.\n'
                f'  → sudo resolvectl domain {iface} ~.')
            return

        # Étape 1 : vérifier si vpnc-script a configuré les DNS
        _time_mod.sleep(1)
        dns_on_tun = self._get_iface_dns_servers(iface)
        server = self.config.get('server', '')

        if dns_on_tun:
            self._log(
                f'  [DNS] Serveurs sur {iface} : {", ".join(dns_on_tun)}')
            # Mémoriser pour les prochaines connexions (auto-learning)
            if server:
                learned = self.config.get('learned_vpn_dns', {})
                learned[server] = ' '.join(dns_on_tun)
                self.config.set('learned_vpn_dns', learned)
                self._log(f'  [DNS] Serveurs mémorisés pour {server}')
        else:
            self._log(
                f'  [DNS] ⚠ Aucun serveur DNS sur {iface} '
                f'(bug vpnc-script Ubuntu 24.04+)')

            # Sources de DNS par priorité :
            # 1) Config manuelle (vpn_dns_servers)
            # 2) DNS mémorisés d'une précédente connexion réussie
            # 3) DNS parsés depuis stdout openconnect
            fix_dns = []
            fix_source = ''

            manual = self.config.get('vpn_dns_servers', '')
            if manual:
                fix_dns = [s.strip() for s in manual.replace(',', ' ').split()
                           if s.strip()]
                fix_source = 'configuration manuelle'

            if not fix_dns and server:
                learned = self.config.get('learned_vpn_dns', {})
                learned_str = learned.get(server, '')
                if learned_str:
                    fix_dns = learned_str.split()
                    fix_source = 'mémorisés (connexion précédente)'

            if not fix_dns:
                fix_dns = getattr(self, '_vpn_dns_servers', [])
                if fix_dns:
                    fix_source = 'openconnect stdout'

            if fix_dns:
                self._log(
                    f'  [DNS] Serveurs ({fix_source}) : {", ".join(fix_dns)}')
                try:
                    self._run_resolvectl(
                        ['dns', iface] + fix_dns, check=True)
                    self._log(
                        f'  [DNS] ✔ DNS configurés sur {iface}')
                    if server:
                        learned = self.config.get('learned_vpn_dns', {})
                        learned[server] = ' '.join(fix_dns)
                        self.config.set('learned_vpn_dns', learned)
                except Exception as e:
                    self._log(f'  [DNS] ⚠ Échec: {e}')
            else:
                self._log(
                    '  [DNS] ✘ Aucun serveur DNS disponible.\n'
                    '  → Ouvrez Paramètres et renseignez les DNS VPN\n'
                    '  → Ou connectez-vous depuis le réseau interne '
                    '(les DNS seront mémorisés automatiquement).')

        # Domaines VPN
        suffixes = self.config.get('vpn_dns_suffixes', '')
        if suffixes:
            suffix_list = [s.strip() for s in suffixes.replace(',', ' ').split()
                           if s.strip()]
            if suffix_list:
                try:
                    self._run_resolvectl(
                        ['domain', iface] + suffix_list + ['~.'],
                        check=False)
                except Exception:
                    pass

        # Étape 2 : forcer domaine ~. et default-route
        try:
            self._run_resolvectl(['domain', iface, '~.'], check=True)
            self._apply_default_routes_for_vpn(iface)
            self._log(f'  [DNS] ✔ DNS forcé via tunnel ({iface}, domaine ~.)')
        except subprocess.CalledProcessError as e:
            err = (e.stderr or e.stdout or '').strip()
            self._log(f'  [DNS] ⚠ resolvectl domain échoué: {err or e}')
            try:
                self._apply_default_routes_for_vpn(iface)
                self._log(
                    f'  [DNS] ✔ Fallback default-route DNS -> {iface}')
            except Exception as e2:
                self._log(f'  [DNS] ⚠ Fallback default-route échoué: {e2}')

        # Étape 4 : vérification finale + test de résolution réel
        final_dns = self._get_iface_dns_servers(iface)
        if final_dns:
            self._log(
                f'  [DNS] ✔ Vérification OK : {iface} → '
                f'{", ".join(final_dns)}')
        else:
            self._log(
                f'  [DNS] ✘ {iface} n\'a toujours pas de serveurs DNS.')

        # Test de résolution réel
        server = self.config.get('server', '')
        test_hosts = [server, 'google.com'] if server else ['google.com']
        for host in test_hosts:
            try:
                result = subprocess.run(
                    ['resolvectl', 'query', host],
                    capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    first_line = result.stdout.strip().split('\n')[0]
                    self._log(f'  [DNS] ✔ Test {host} → {first_line}')
                else:
                    err = result.stderr.strip().split('\n')[0] if result.stderr else '?'
                    self._log(f'  [DNS] ✘ Test {host} ÉCHOUÉ : {err}')
            except Exception as e:
                self._log(f'  [DNS] ✘ Test {host} erreur : {e}')

        # Dump complet pour diagnostic
        try:
            status = subprocess.run(
                ['resolvectl', 'status', iface],
                capture_output=True, text=True, timeout=5).stdout
            for ln in status.strip().split('\n'):
                self._log(f'  [DNS]   {ln.strip()}')
        except Exception:
            pass


    def _on_vpn_detected(self, pid, server, iface):
        """Met à jour l'UI quand un VPN existant est détecté au démarrage."""
        self._existing_vpn_pid = pid
        self.log_buf.set_text('')
        self._log('=== VPN déjà connecté — reprise ===')
        self._log(f'Processus openconnect détecté  (PID {pid})')
        if server:
            self._log(f'Serveur  : {server}')
        if iface:
            self._log(f'Tunnel   : {iface}')
        self._set_state('connected', subtitle=server or iface or f'PID {pid}')
        # Surveiller que le processus reste actif
        self._vpn_monitor_source = GLib.timeout_add(
            4000, self._poll_vpn_alive)
        return False

    def _poll_vpn_alive(self):
        """Vérifie périodiquement si le processus openconnect tourne encore."""
        if self.state != 'connected':
            self._vpn_monitor_source = None
            return False
        # Si le VPN est géré par notre proc interne, le loop stdout suffit
        if self.openconnect_proc is not None:
            self._vpn_monitor_source = None
            return False
        pid = self._existing_vpn_pid
        if pid:
            try:
                os.kill(pid, 0)  # signal 0 = test d'existence
                return True      # toujours actif
            except (ProcessLookupError, PermissionError):
                pass
        # Processus disparu
        self._existing_vpn_pid   = None
        self._vpn_monitor_source = None
        self._log('VPN déconnecté (processus terminé).')
        self._set_state('disconnected')
        return False

    def _generate_fake_hip_xml_from_config(self, client_ip='0.0.0.0',
                                           md5='<md5-placeholder>',
                                           username='', ipv6=''):
        """Génère le XML HIP depuis self.config (utilisé hors dialogue)."""
        import socket as _socket, uuid as _uuid
        from datetime import datetime as _dt

        cfg       = self.config
        hostname  = cfg.get('hip_fake_hostname', '') or _socket.gethostname()
        has_fw    = cfg.get('hip_fake_firewall', False)
        fw_name   = cfg.get('hip_fake_firewall_name', 'UFW')
        has_av    = cfg.get('hip_fake_antivirus', True)
        av_vendor = cfg.get('hip_fake_antivirus_vendor', 'Trend Micro, Inc.')
        av_name   = cfg.get('hip_fake_antivirus_name',
                            'Trend Micro Deep Security Agent')
        av_ver    = cfg.get('hip_fake_antivirus_version', '20.0.0.0000')
        av_rt     = cfg.get('hip_fake_antivirus_real_time', True)
        has_enc   = cfg.get('hip_fake_encryption', True)
        has_mdm   = cfg.get('hip_fake_mdm', True)
        mdm_name  = cfg.get('hip_fake_mdm_name', 'Microsoft Intune')
        has_bk    = cfg.get('hip_fake_backup', False)
        bk_name   = cfg.get('hip_fake_backup_name', 'timeshift')
        now       = _dt.now().strftime('%m/%d/%Y %H:%M:%S')
        # host-id = UUID DMI/SMBIOS — colonne HOST ID dans la console Palo Alto
        host_id   = _get_dmi_machine_uuid()
        if not username:
            username = cfg.get('last_username', 'user@example.com')

        # OS pour matcher "Host Info → OS Contains Linux"
        os_label  = 'Linux'
        try:
            with open('/etc/os-release') as _f:
                _osr = {ln.split('=', 1)[0]: ln.split('=', 1)[1].strip().strip('"')
                        for ln in _f if '=' in ln}
            os_label = f"Linux {_osr.get('NAME', 'Linux')} {_osr.get('VERSION_ID', '')}".strip()
        except Exception:
            pass

        def _e(s):
            return (str(s).replace('&', '&amp;').replace('<', '&lt;')
                    .replace('>', '&gt;').replace('"', '&quot;'))

        rt_str = 'yes' if av_rt else 'no'
        defver = _dt.now().strftime('%Y%m%d')
        am = (f'''      <list>
        <entry>
          <vendor>{_e(av_vendor)}</vendor>
          <name>{_e(av_name)}</name>
          <product-version>{_e(av_ver)}</product-version>
          <real-time-protection>{rt_str}</real-time-protection>
          <definition-version>{defver}</definition-version>
          <last-scan-time>{now}</last-scan-time>
        </entry>
      </list>''' if has_av else '      <list/>')

        fw = (f'''      <list>
        <entry>
          <name>{_e(fw_name)}</name>
          <status>yes</status>
        </entry>
      </list>''' if has_fw else '''      <list>
        <entry>
          <name>iptables</name>
          <status>no</status>
        </entry>
      </list>''')

        enc = ('''      <list>
        <entry>
          <name>LUKS</name>
          <status>yes</status>
        </entry>
      </list>''' if has_enc else '      <list/>')

        bk = (f'''      <list>
        <entry>
          <name>{_e(bk_name)}</name>
          <status>yes</status>
        </entry>
      </list>''' if has_bk else '      <list/>')

        mdm = (f'''      <list>
        <entry>
          <name>{_e(mdm_name)}</name>
          <status>yes</status>
        </entry>
      </list>''' if has_mdm else '      <list/>')

        # Format aligné sur la doc Palo Alto fournie (syntaxe simplifiée)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<hip-report>
  <md5-sum>{_e(md5)}</md5-sum>
  <user-name>{_e(username)}</user-name>
  <domain></domain>
  <host-name>{_e(hostname)}</host-name>
  <host-id>{_e(host_id)}</host-id>
  <ip-address>{_e(client_ip)}</ip-address>
  <ipv6-address>{_e(ipv6)}</ipv6-address>
  <generate-time>{now}</generate-time>
  <hip-report-version>4</hip-report-version>
  <categories>
    <entry name="host-info">
      <client-version>6.0.0-1</client-version>
      <os>{_e(os_label)}</os>
      <os-vendor>Linux</os-vendor>
      <domain></domain>
      <host-name>{_e(hostname)}</host-name>
      <host-id>{_e(host_id)}</host-id>
      <network-interface>
        <entry name="eth0">
          <description>eth0</description>
          <mac-address>00:00:00:00:00:00</mac-address>
          <ip-address><entry name="{_e(client_ip)}"/></ip-address>
        </entry>
      </network-interface>
    </entry>
    <entry name="antivirus">
{am}
    </entry>
    <entry name="anti-malware">
{am}
    </entry>
    <entry name="disk-backup">
{bk}
    </entry>
    <entry name="disk-encryption">
{enc}
    </entry>
    <entry name="firewall">
{fw}
    </entry>
    <entry name="patch-management">
      <list/>
    </entry>
    <entry name="data-loss-prevention">
      <list/>
    </entry>
    <entry name="mobile-device-management">
{mdm}
    </entry>
  </categories>
</hip-report>"""

    # ── Flux de connexion ──────────────────────────────────────────────────

    def _start_connect(self):
        self._cancel_requested   = False
        self._existing_vpn_pid   = None
        self._mode_retry_attempted = False
        self._forced_conn_mode = None
        self._forced_clientos  = None
        self._os_retry_list      = []
        self._os_retry_attempted = False
        self._os_512_retry_attempted = False
        self._oc_512_terminated = False
        self._internal_session = None
        self._hip_stop_event   = None
        self._cached_is_internal = None
        self._cached_conn_mode = None
        self._reusable_portal_cookie = None
        self._tunnel_up_handled = False
        self.config.reload()
        if self._vpn_monitor_source:
            GLib.source_remove(self._vpn_monitor_source)
            self._vpn_monitor_source = None
        self.log_buf.set_text('')
        self._set_state('authenticating')
        self._log('=== Démarrage connexion GP Connect ===')
        # Tenter la réutilisation d'un token sauvegardé
        if self._try_reuse_session():
            return
        threading.Thread(target=self._auth_thread, daemon=True).start()

    def _try_reuse_session(self):
        """Tente de réutiliser un token de session sauvegardé.

        Politique :
          1. Recherche dans le keyring GNOME (libsecret), puis dans le
             cache fichier local.
          2. Si l'access token est encore frais, on l'utilise directement.
          3. Si l'access est consommé/expiré mais que le refresh token
             (portal-userauthcookie / authcookie) est encore valide, il
             est promu en access automatiquement par `_load_session_token`.
          4. Si tout est expiré → retour False (déclenche un SAML).

        Retourne True si la session a été reprise (skip SAML), False sinon.
        """
        server = self.config.get('server', '')
        if not server:
            return False
        self._log('  [Session] Recherche dans le keyring GNOME et cache local…')
        session = _load_session_token(server, log_fn=self._log)
        if not session:
            self._log('  [Session] Aucun token réutilisable → '
                      'authentification SAML requise')
            return False

        cookie_field = session.get('cookie_field', '')
        cookie_value = session.get('cookie_value', '')
        conn_mode = session.get('conn_mode', '')
        used_refresh = (
            session.get('refresh_field') == cookie_field
            and session.get('refresh_value') == cookie_value
            and session.get('access_ts') == session.get('refresh_ts'))

        if used_refresh:
            self._log(f'  [Session] ✓ Refresh token utilisé pour renouveler '
                      f'l\'accès ({cookie_field})')

        if cookie_field == 'authcookie' and cookie_value and conn_mode == 'internal':
            # Une session interne n'est valable QUE sur le LAN. Re-vérifier
            # via DNS du portail : hors site, basculer sur le token portail
            # réutilisable s'il existe (évite un nouveau SAML).
            global_mode = self.config.get('connection_mode', 'auto')
            on_lan = True
            if global_mode == 'auto':
                on_lan = _is_on_internal_network(server, log_fn=self._log)
            elif global_mode != 'internal':
                on_lan = False

            if not on_lan:
                # Préférer le refresh portal-userauthcookie pour éviter SSO
                rf = session.get('refresh_field')
                rv = session.get('refresh_value')
                if rf == 'portal-userauthcookie' and rv:
                    self._log(
                        '  [Session] Authcookie interne ignoré (hors LAN) — '
                        'réutilisation du portal-userauthcookie')
                    cookie_field = rf
                    cookie_value = rv
                    conn_mode = 'portal'
                    # Mettre à jour la session persistée (mode tunnel)
                    _save_session_token(server, {
                        'cookie_field': cookie_field,
                        'cookie_value': cookie_value,
                        'username': session.get('username', ''),
                        'os_type': session.get('os_type', 'linux-64'),
                        'clientos': session.get('clientos', 'Linux'),
                        'user_agent': session.get(
                            'user_agent', 'PAN GlobalProtect'),
                        'conn_mode': 'portal',
                    }, log_fn=self._log)
                    # tombe dans la branche portal-userauthcookie ci-dessous
                else:
                    self._log(
                        '  [Session] Authcookie interne ignoré — hors LAN '
                        '(pas de portal-userauthcookie) → SSO requis')
                    _clear_session_token(server, log_fn=self._log)
                    modes = self.config.get('server_modes', {}) or {}
                    if modes.get(server) == 'internal':
                        modes.pop(server, None)
                        self.config.set('server_modes', modes)
                    return False
            else:
                self._log('  [Session] Authcookie interne → reprise directe '
                          '(sans tunnel, HIP keepalive immédiat)')
                clientos = session.get('clientos', 'Linux')
                user_agent = session.get('user_agent', 'PAN GlobalProtect')
                verify = self.config.get('verify_ssl', True)
                self._reconnect_count = 0
                threading.Thread(
                    target=self._resume_internal_session,
                    args=(server, session, clientos, user_agent, verify),
                    daemon=True).start()
                return True

        if cookie_field == 'portal-userauthcookie' and cookie_value:
            self._log(f'  [Session] Token réutilisable ({cookie_field}) '
                      f'→ getconfig pour récupérer la liste des gateways')
            username = session.get('username', '')
            os_type = session.get('os_type', 'linux-64')
            clientos = session.get('clientos', 'Linux')
            user_agent = session.get('user_agent', 'PAN GlobalProtect')
            verify = self.config.get('verify_ssl', True)
            self._reconnect_count = 0
            threading.Thread(
                target=lambda: self._fetch_and_connect(
                    server, cookie_field, cookie_value,
                    username, os_type, clientos, user_agent, verify),
                daemon=True).start()
            return True

        # Un prelogin-cookie est strictement one-shot et n'a aucune valeur
        # une fois sorti de la session courante : on ne tente JAMAIS de le
        # rejouer au démarrage (getconfig refuserait avec HTTP 512).
        if cookie_field in _ONESHOT_FIELDS:
            self._log('  [Session] Cookie one-shot orphelin → purge + SAML')
            _clear_session_token(server, log_fn=self._log)
            return False

        self._log('  [Session] Token non exploitable → authentification SAML')
        return False

    def _auth_thread(self):
        """Lance l'authentification SAML et récupère le cookie.

        Utilise la WebView intégrée avec spoofing de plateforme.
        Fallback sur gpclient (globalprotect-openconnect) si la WebView
        est bloquée par Conditional Access.
        """
        self._ensure_uplink_dns_route()

        server     = self.config.get('server')
        clientos   = self.config.get('clientos', 'Linux')
        user_agent = self.config.get('user_agent')
        verify     = self.config.get('verify_ssl', True)

        allow_insecure = self.config.get('allow_insecure_crypto', False)
        global_mode    = self.config.get('connection_mode', 'auto')

        forced_mode = self._forced_conn_mode
        if forced_mode in ('portal', 'gateway', 'internal', 'auto'):
            conn_mode = forced_mode
            self._log(f'ℹ️  Mode connexion forcé pour cette tentative : {forced_mode}')
            self._forced_conn_mode = None
            # Propager le mode forcé au cache pour que _fetch_and_connect
            # ne retombe pas sur l'ancien mode cached d'une tentative
            # précédente (cas typique : retry portail après échec gateway).
            self._cached_conn_mode = conn_mode if conn_mode != 'auto' else None
            self._cached_is_internal = (conn_mode == 'internal')
        elif global_mode == 'auto':
            ihd = (self.config.get('server_ihd', {}) or {}).get(server)
            server_modes = self.config.get('server_modes', {}) or {}
            server_deployment = self.config.get('server_deployment', {}) or {}
            gateway_host = _resolve_gateway_hostname(
                self.config.get('preferred_gateway', ''), server)
            conn_mode = _auto_detect_mode(
                server,
                ihd=ihd,
                gateway_host=gateway_host,
                server_modes=server_modes,
                server_deployment=server_deployment,
                verify=verify,
                allow_insecure=allow_insecure,
                clientos=clientos,
                log_fn=self._log,
            )
            # Purge un éventuel 'internal' stale (ancien bug : forçait le
            # no-tunnel hors LAN). Le mode internal n'est plus mémorisé.
            if (conn_mode != 'internal'
                    and server_modes.get(server) == 'internal'):
                server_modes.pop(server, None)
                self.config.set('server_modes', server_modes)
            self._cached_is_internal = (conn_mode == 'internal')
            self._cached_conn_mode = conn_mode
            self._log(f'  [Auto] Mode résolu : {conn_mode}')
        else:
            conn_mode = global_mode
            self._cached_conn_mode = conn_mode
            self._cached_is_internal = (conn_mode == 'internal')
            self._log(
                f'  Mode manuel : {conn_mode} '
                f'(sans détection automatique)')
        forced_os = self._forced_clientos
        if forced_os:
            clientos = forced_os
            presets = UA_PRESETS_BY_OS.get(clientos, {})
            user_agent = next(iter(presets.values()), 'PAN GlobalProtect')
            self._log(f'ℹ️  clientos forcé pour cette tentative : {clientos}')
            self._forced_clientos = None

        # ── Détection cloud (info seulement, pas d'override) ────────────
        _is_cloud = False
        if conn_mode == 'portal':
            portal_info = probe_prelogin(
                server, verify=verify, allow_insecure=allow_insecure,
                clientos=clientos)
            _is_cloud = portal_info.get('is_cloud', False)
            # Mémoriser le type de déploiement pour l'auto-détection future
            if portal_info.get('status') == 'Success':
                _dep = self.config.get('server_deployment', {}) or {}
                _new = 'cloud' if _is_cloud else 'onprem'
                if _dep.get(server) != _new:
                    _dep[server] = _new
                    self.config.set('server_deployment', _dep)
                    self._log(
                        f'  [Auto] Déploiement mémorisé pour {server} : {_new}')
            if _is_cloud:
                self._log(
                    f'  [Cloud] Portail Prisma Access détecté '
                    f'(region={portal_info.get("region", "?")})')
        self._log(f'  clientos={clientos}  user_agent={user_agent}')

        self._log(f'Auth SSO → {server}')

        # ── WebView intégrée (méthode principale) ─────────────────────
        if _ensure_webkit2():
            self._log('  Authentification via WebView intégrée…')
            try:
                interface = 'gateway' if conn_mode in ('gateway', 'internal') else 'portal'

                # ── Étape 1 : prelogin (réseau) — thread background ──────
                self._log(f'  [WebView] Prelogin ({interface})…')
                info = do_prelogin(server, clientos=clientos,
                                   interface=interface, verify=verify,
                                   allow_insecure=allow_insecure)
                actual = info.get('actual_interface', interface)
                if actual != interface:
                    self._log(
                        f'  [WebView] ⚠ Endpoint {interface} (ssl-vpn/) '
                        f'indisponible, fallback → {actual} (global-protect/).')

                saml_url = saml_html = None
                if info['saml_method'] == 'REDIRECT':
                    saml_url = info['saml_request']
                elif info['saml_method'] == 'POST':
                    saml_html = info['saml_request']
                else:
                    raise RuntimeError(
                        f"Méthode SAML inconnue : {info['saml_method']}")

                if self._cancel_requested:
                    return

                # ── Étape 2 : dialog WebView (UI) — thread GTK ──────────
                self._log(
                    f'  [WebView] Ouverture SAML ({info["saml_method"]})…')
                dlg_result = [None]
                dlg_done = threading.Event()

                def _run_webview_dialog():
                    try:
                        dlg_result[0] = _run_saml_webview_dialog(
                            saml_url, saml_html, clientos, user_agent,
                            verify, allow_insecure, self, self._log)
                    except Exception as e:
                        self._log(f'  [WebView] Erreur dialog : {e}')
                    finally:
                        dlg_done.set()

                GLib.idle_add(_run_webview_dialog)
                dlg_done.wait(timeout=300)

                if self._cancel_requested:
                    return

                result = _parse_saml_result(dlg_result[0], clientos, server)
                if result and result.get('COOKIE'):
                    username     = result.get('USER', '')
                    cookie_value = result['COOKIE']
                    cookie_field = result.get('cookie_field', 'prelogin-cookie')
                    os_type      = result.get('OS', CLIENTOS_OS_MAP.get(clientos, 'mac-intel'))
                    vpn_server   = result.get('server', server)

                    self._log(f'Authentifié : {username}')
                    self._log(f'Cookie ({cookie_field}) obtenu.')
                    if username:
                        self.config.set('last_username', username)

                    _save_session_token(vpn_server, {
                        'cookie_field': cookie_field,
                        'cookie_value': cookie_value,
                        'username': username,
                        'os_type': os_type,
                        'clientos': clientos,
                        'user_agent': user_agent,
                        'conn_mode': conn_mode,
                    }, log_fn=self._log)

                    self._fetch_and_connect(
                        vpn_server, cookie_field, cookie_value,
                        username, os_type, clientos, user_agent, verify)
                    return

                if dlg_result[0] is None:
                    self._log('Fenêtre SAML fermée par l\'utilisateur.')
                    self._set_state('disconnected')
                    return

                self._log('  [WebView] Cookie non obtenu.')
                if _is_cloud:
                    self._log('  [Cloud] Fallback → gpclient…')
                    self._try_gpclient_fallback(server, verify)
                    return
                self._set_state('error',
                                error_msg='Cookie d\'authentification absent')
                return

            except Exception as e:
                self._log(f'  [WebView] Erreur : {e}')
                err_str = str(e)
                if conn_mode in ('gateway', 'internal'):
                    self._retry_with_portal_mode(
                        f'prelogin gateway échoué ({err_str[:120]})')
                    return
                if _is_cloud:
                    self._log('  [Cloud] Fallback → gpclient…')
                    self._try_gpclient_fallback(server, verify)
                    return
                # WebView crash/timeout → fallback navigateur externe
                self._log('  [WebView] Fallback → authentification navigateur externe…')
                try:
                    result = external_browser_auth(
                        server, clientos=clientos, interface='portal',
                        verify=verify, allow_insecure=allow_insecure,
                        log_fn=self._log)
                    if result and result.get('COOKIE'):
                        username     = result.get('USER', '')
                        cookie_value = result['COOKIE']
                        cookie_field = result.get('cookie_field', 'prelogin-cookie')
                        os_type      = result.get('OS', CLIENTOS_OS_MAP.get(clientos, 'mac-intel'))
                        vpn_server   = result.get('server', server)
                        self._log(f'Authentifié (navigateur) : {username}')
                        if username:
                            self.config.set('last_username', username)
                        _save_session_token(vpn_server, {
                            'cookie_field': cookie_field,
                            'cookie_value': cookie_value,
                            'username': username,
                            'os_type': os_type,
                            'clientos': clientos,
                            'user_agent': user_agent,
                            'conn_mode': conn_mode,
                        }, log_fn=self._log)
                        self._fetch_and_connect(
                            vpn_server, cookie_field, cookie_value,
                            username, os_type, clientos, user_agent, verify)
                        return
                except Exception as e2:
                    self._log(f'  [ExtAuth] Échec navigateur externe : {e2}')
                self._set_state('error', error_msg=str(e)[:60])
                return

        # ── Fallback : gp-saml-gui externe (si WebKit2 absent) ────────
        if not _ensure_webkit2():
            self._log('  ⚠️ WebKit2 non disponible, tentative gp-saml-gui…')
            gp_saml_gui = resolve_gp_saml_gui()
            if not gp_saml_gui:
                self._log('✘ gp-saml-gui introuvable.')
                if _is_cloud:
                    self._try_gpclient_fallback(server, verify)
                else:
                    self._set_state('error', error_msg='WebKit2 et gp-saml-gui absents')
                return
            self._auth_via_gp_saml_gui(
                gp_saml_gui, server, clientos, user_agent,
                conn_mode, verify, allow_insecure, _is_cloud)
            return

        # Catch-all : aucune méthode d'auth n'a abouti
        self._set_state('error', error_msg='Échec authentification')

    def _auth_via_gp_saml_gui(self, gp_saml_gui, server, clientos,
                               user_agent, conn_mode, verify,
                               allow_insecure, _is_cloud):
        """Authentification via le processus externe gp-saml-gui (legacy)."""
        cmd = [gp_saml_gui,
               '--clientos', clientos,
               '--user-agent', user_agent,
               '-q']
        if conn_mode in ('gateway', 'internal'):
            cmd.append('-g')
        if not verify:
            cmd.append('--no-verify')
        if allow_insecure:
            cmd.append('--allow-insecure-crypto')
        cmd.append(server)

        try:
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=300)
        except subprocess.TimeoutExpired:
            self._log('Timeout — authentification annulée.')
            self._set_state('disconnected')
            return
        except Exception as e:
            self._log(f'Erreur lancement : {e}')
            self._set_state('error', error_msg='Impossible de lancer l\'auth')
            return

        if self._cancel_requested:
            return

        if proc.returncode != 0:
            stderr_out = proc.stderr.strip()
            self._log(f'Échec auth (code {proc.returncode})\n{stderr_out}')
            if _is_cloud and ('AADSTS' in stderr_out or 'unknown' in stderr_out.lower()):
                self._log('  [Cloud] WebView bloqué par Conditional Access.')
                self._try_gpclient_fallback(server, verify)
                return
            self._set_state('error', error_msg='Échec de l\'authentification')
            return

        auth = {}
        for line in proc.stdout.strip().splitlines():
            if '=' in line:
                k, _, v = line.partition('=')
                auth[k.strip()] = v.strip().strip("'\"")

        if not auth.get('COOKIE'):
            self._log(f'Cookie non obtenu.\nSortie : {proc.stdout}')
            self._set_state('error', error_msg='Cookie d\'authentification absent')
            return

        username     = auth.get('USER', '')
        cookie_value = auth['COOKIE']
        os_type      = auth.get('OS', 'mac-intel')

        if os_type == 'linux-64':
            self._log('ℹ️  Client OS = Linux (linux-64).')

        parsed      = urlparse(auth.get('HOST', f'https://{server}/portal:prelogin-cookie'))
        vpn_server  = parsed.netloc or server
        path_info   = parsed.path.lstrip('/')
        cookie_field = path_info.split(':', 1)[1] if ':' in path_info else 'prelogin-cookie'

        self._log(f'Authentifié : {username}')
        self._log(f'Cookie ({cookie_field}) obtenu.')

        if username:
            self.config.set('last_username', username)

        _save_session_token(vpn_server, {
            'cookie_field': cookie_field,
            'cookie_value': cookie_value,
            'username': username,
            'os_type': os_type,
            'clientos': clientos,
            'user_agent': user_agent,
        }, log_fn=self._log)

        self._fetch_and_connect(vpn_server, cookie_field, cookie_value,
                                username, os_type, clientos, user_agent, verify)

    def _try_gpclient_fallback(self, server, verify):
        """Tentative 3 : utiliser gpclient (globalprotect-openconnect) comme fallback."""
        gpclient = shutil.which('gpclient')
        if not gpclient:
            self._log('  [Fallback] gpclient (globalprotect-openconnect) non installé.')
            self._log('  Pour l\'installer :')
            self._log('    sudo add-apt-repository ppa:yuezk/globalprotect-openconnect')
            self._log('    sudo apt install globalprotect-openconnect')
            self._set_state('error',
                            error_msg='Auth impossible — installez globalprotect-openconnect')
            return

        self._log(f'  [Fallback] Lancement gpclient connect --default-browser {server}…')
        try:
            proc = subprocess.run(
                [gpclient, 'connect', '--default-browser', server],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            self._log('  [Fallback] gpclient timeout.')
            self._set_state('disconnected')
            return
        except Exception as e:
            self._log(f'  [Fallback] Erreur gpclient : {e}')
            self._set_state('error', error_msg='Erreur gpclient')
            return

        if proc.returncode != 0:
            self._log(f'  [Fallback] gpclient échoué (code {proc.returncode})')
            self._log(f'  {proc.stderr.strip()}')
            self._set_state('error', error_msg='gpclient : échec connexion')
            return

        self._log('  [Fallback] gpclient connecté avec succès.')
        self._log('  ℹ️  La connexion VPN est gérée par gpclient.')
        self._log('  Pour se déconnecter : gpclient disconnect')
        self._set_state('connected')
        self._start_vpn_monitor_external('gpclient')

    def _start_vpn_monitor_external(self, tool_name):
        """Surveille un VPN géré par un outil externe (gpclient, etc.)."""
        def _check():
            if self.state != 'connected':
                self._vpn_monitor_source = None
                return False
            try:
                result = subprocess.run(
                    ['pgrep', '-f', tool_name],
                    capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return True
            except Exception:
                pass
            self._log(f'VPN déconnecté ({tool_name} terminé).')
            self._set_state('disconnected')
            self._vpn_monitor_source = None
            return False

        self._vpn_monitor_source = GLib.timeout_add(5000, _check)

    def _fetch_and_connect(self, server, cookie_field, cookie_value,
                           username, os_type, clientos, user_agent, verify):
        """Route la connexion selon le type de cookie obtenu après l'authentification.

        • prelogin-cookie  (SAML one-shot) → openconnect portail interactif
          On NE DOIT PAS appeler getconfig.esp nous-mêmes : cela consommerait
          le token AVANT qu'openconnect puisse l'utiliser, causant une erreur 512.

        • portal-userauthcookie / GP_SESSION_CK (session token) → appel getconfig
          puis connexion directe au gateway cloud.
        """
        preferred       = self.config.get('preferred_gateway', '')
        allow_insecure  = self.config.get('allow_insecure_crypto', False)
        global_mode     = self.config.get('connection_mode', 'auto')
        forced = getattr(self, '_forced_conn_mode', None)
        if forced in ('portal', 'gateway', 'internal'):
            conn_mode = forced
            self._cached_conn_mode = conn_mode
            self._cached_is_internal = (conn_mode == 'internal')
            self._log(f'  [Auto] Mode forcé (post-auth) : {conn_mode}')
        elif global_mode == 'auto':
            cached_mode = getattr(self, '_cached_conn_mode', None)
            if cached_mode in ('internal', 'portal', 'gateway'):
                conn_mode = cached_mode
            else:
                ihd = (self.config.get('server_ihd', {}) or {}).get(server)
                server_modes = self.config.get('server_modes', {}) or {}
                server_deployment = self.config.get('server_deployment', {}) or {}
                gateway_host = _resolve_gateway_hostname(preferred, server)
                conn_mode = _auto_detect_mode(
                    server,
                    ihd=ihd,
                    gateway_host=gateway_host,
                    server_modes=server_modes,
                    server_deployment=server_deployment,
                    verify=self.config.get('verify_ssl', True),
                    allow_insecure=allow_insecure,
                    clientos=self.config.get('clientos', 'Linux'),
                    log_fn=self._log,
                )
                self._cached_conn_mode = conn_mode
                self._cached_is_internal = (conn_mode == 'internal')
            self._log(f'  [Auto] Mode résolu (post-auth) : {conn_mode}')
        else:
            conn_mode = global_mode
            self._cached_conn_mode = conn_mode
            self._cached_is_internal = (conn_mode == 'internal')
            self._log(
                f'  Mode manuel (post-auth) : {conn_mode} '
                f'(sans détection automatique)')

        # ── Cas 0 : mode passerelle interne (sans tunnel) ─────────────────────
        if conn_mode == 'internal':
            self._log(
                'Token SAML — mode passerelle interne (sans tunnel)\n'
                f'  Login direct → {server} (user-ID + HIP)')
            # Avant le login interne : récupérer un portal-userauthcookie
            # réutilisable via getconfig (pour les prochaines connexions
            # hors LAN sans nouveau SSO). Le prelogin-cookie one-shot est
            # consommé ici ; on continue avec le cookie portail.
            login_field, login_value = cookie_field, cookie_value
            if cookie_field in _ONESHOT_FIELDS:
                try:
                    (_gws, portal_auth, _ihd, _hip_iv,
                     _collect_hip, _hip_vendors) = get_portal_config(
                        server, cookie_field, cookie_value, username,
                        clientos, verify,
                        allow_insecure=allow_insecure, log_fn=self._log)
                    self._portal_hip_info = {
                        'collect_hip': _collect_hip,
                        'expected_vendors': _hip_vendors,
                        'interval': _hip_iv,
                    }
                    if portal_auth and portal_auth[0] in _REFRESH_FIELDS:
                        login_field, login_value = portal_auth
                        self._reusable_portal_cookie = portal_auth
                        self._log(
                            f'  [Internal] Token réutilisable obtenu : '
                            f'{login_field}')
                        _save_session_token(server, {
                            'cookie_field': login_field,
                            'cookie_value': login_value,
                            'username': username,
                            'os_type': os_type,
                            'clientos': clientos,
                            'user_agent': user_agent,
                            'conn_mode': 'portal',
                        }, log_fn=self._log)
                    if _ihd:
                        ihd_map = self.config.get('server_ihd', {}) or {}
                        if ihd_map.get(server) != _ihd:
                            ihd_map[server] = _ihd
                            self.config.set('server_ihd', ihd_map)
                except Exception as e:
                    self._log(
                        f'  [Internal] getconfig (harvest token) : {e} '
                        f'— login interne avec {cookie_field}')
            threading.Thread(
                target=self._internal_connect,
                args=(server, login_field, login_value,
                      username, clientos, user_agent, verify),
                daemon=True,
            ).start()
            return False

        # ── Cas 1a : prelogin-cookie + mode passerelle directe ────────────────
        #   Envoie le prelogin-cookie SAML frais au gateway on-prem sans
        #   passer par getconfig.esp (qui consommerait le token).
        if cookie_field == 'prelogin-cookie' and conn_mode == 'gateway':
            self._log(
                'Token SAML — mode passerelle directe\n'
                f'  Connexion directe → gateway {server} '
                f'(usergroup=gateway:prelogin-cookie)')
            self._set_state('connecting', subtitle=server)
            threading.Thread(
                target=self._do_connect,
                args=(server, preferred or server, cookie_field, cookie_value,
                      username, os_type, user_agent, False),  # gateway direct
                daemon=True,
            ).start()
            return False

        # ── Cas 1b/2 : prelogin-cookie en portail OU portal-userauthcookie ───
        # On appelle nous-mêmes getconfig.esp pour :
        #   1) obtenir la liste des gateways,
        #   2) récupérer un portal-userauthcookie RÉUTILISABLE que l'on
        #      sauvegarde pour éviter un SAML à chaque reconnexion,
        #   3) utiliser ce cookie long-terme avec openconnect
        #      (--usergroup=gateway:portal-userauthcookie) plutôt que le
        #      prelogin-cookie one-shot qui provoque HTTP 512 au niveau
        #      gateway quand openconnect essaie de le rejouer.
        self._set_state('fetching', subtitle='Récupération des serveurs disponibles…')
        self._log('Récupération de la config portail (getconfig.esp)…')

        try:
            (gateways, portal_auth, _ihd, _hip_interval,
             _collect_hip, _hip_vendors) = get_portal_config(
                server, cookie_field, cookie_value, username, clientos, verify,
                allow_insecure=allow_insecure, log_fn=self._log)
            self._portal_hip_info = {
                'collect_hip': _collect_hip,
                'expected_vendors': _hip_vendors,
                'interval': _hip_interval,
            }
            self._log(f'{len(gateways)} serveur(s) disponible(s).')
            # Mémoriser l'IHD pour l'auto-détection future (sonde LAN fiable)
            if _ihd:
                ihd_map = self.config.get('server_ihd', {}) or {}
                if ihd_map.get(server) != _ihd:
                    ihd_map[server] = _ihd
                    self.config.set('server_ihd', ihd_map)
                    self._log(
                        f'  [Auto] IHD mémorisée pour {server} : '
                        f'{_ihd.get("host") or "?"} ({_ihd.get("ip") or "?"})')
            # Mémoriser le type de déploiement (cloud vs on-prem) : si la
            # liste des gateways comporte plus d'une passerelle externe,
            # c'est typiquement un déploiement cloud (Prisma Access).
            try:
                _ext = [g for g in gateways if g.get('type') == 'external']
                deployment = 'cloud' if len(_ext) > 1 else 'onprem'
                _dep = self.config.get('server_deployment', {}) or {}
                if _dep.get(server) != deployment:
                    _dep[server] = deployment
                    self.config.set('server_deployment', _dep)
                    self._log(
                        f'  [Auto] Déploiement mémorisé pour {server} : '
                        f'{deployment}')
            except Exception:
                pass
            if portal_auth:
                gw_cookie_field, gw_cookie_value = portal_auth
                self._log(f'Token gateway obtenu : {gw_cookie_field}')
                # Mémoriser le portal-userauthcookie comme token RÉUTILISABLE
                # (refresh) — indépendant du prelogin-cookie one-shot passé
                # ensuite à openconnect. Permet de skip SSO au prochain
                # démarrage, en interne comme en externe.
                if gw_cookie_field in _REFRESH_FIELDS and gw_cookie_value:
                    self._reusable_portal_cookie = (
                        gw_cookie_field, gw_cookie_value)
                    _save_session_token(server, {
                        'cookie_field': gw_cookie_field,
                        'cookie_value': gw_cookie_value,
                        'username': username,
                        'os_type': os_type,
                        'clientos': clientos,
                        'user_agent': user_agent,
                        # Mode neutre : la détection DNS décide à chaque fois
                        'conn_mode': 'portal',
                    }, log_fn=self._log)
            else:
                gw_cookie_field, gw_cookie_value = cookie_field, cookie_value
                self._log('Aucun portal-userauthcookie — fallback stdin gateway.')
        except Exception as e:
            self._log(f'Erreur getconfig : {e}')
            err_str = str(e)
            # Si on réutilisait un cookie (one-shot consommé ou refresh
            # révoqué) et que le portail le refuse (HTTP 512), il faut
            # purger et relancer un SAML frais : le renvoyer à openconnect
            # ne ferait que reproduire le 512 et finir en stdin loop.
            is_rejected = (
                '512' in err_str
                or 'refusé' in err_str.lower()
                or 'expirée' in err_str.lower()
                or 'révoquée' in err_str.lower())
            if (is_rejected
                    and cookie_field in (*_ONESHOT_FIELDS, *_REFRESH_FIELDS)
                    and not self._mode_retry_attempted):
                self._log(
                    f'  [Session] Cookie {cookie_field} rejeté par getconfig '
                    f'— purge et nouvelle authentification SAML.')
                _clear_session_token(server, log_fn=self._log)
                self._retry_with_portal_mode('token rejeté par le portail')
                return False
            gateways, gw_cookie_field, gw_cookie_value = [], cookie_field, cookie_value

        if not gateways:
            self._log('Aucun gateway trouvé — connexion directe au portail.')
            GLib.idle_add(self._do_connect, server, '', gw_cookie_field,
                          gw_cookie_value, username, os_type, user_agent, True)
            return False

        # Lister les gateways dispos pour aider au diagnostic
        _external = [g for g in gateways if g.get('type') == 'external']
        _internal = [g for g in gateways if g.get('type') == 'internal']
        if _external:
            self._log(f'  Gateways externes ({len(_external)}) :')
            for g in _external:
                self._log(f'    • {g["description"]} ({g["hostname"]}, '
                          f'priority={g["priority"]})')
        if _internal:
            self._log(f'  Gateways internes ({len(_internal)}) :')
            for g in _internal:
                self._log(f'    • {g["description"]} ({g["hostname"]}, '
                          f'priority={g["priority"]})')

        # Routage critique côté openconnect :
        #   • portal-userauthcookie est un cookie CÔTÉ PORTAIL (cf. PAN-OS :
        #     il sert à appeler /global-protect/getconfig.esp pour
        #     enumérer les gateways et obtenir un authcookie gateway). Le
        #     passer à --usergroup=gateway:... fait taper /ssl-vpn/login.esp
        #     avec un cookie de mauvais type → HTTP 512.
        #     ⇒ on force le mode portail (openconnect appellera getconfig
        #     lui-même avec ce cookie et choisira un gateway via stdin).
        #   • prelogin-cookie peut aller en direct au gateway sur la
        #     plupart des déploiements on-prem (mode efficace mémorisé en
        #     `server_modes`), mais sur cloud Prisma Access il faut passer
        #     par le portail aussi.
        use_portal_stdin_default = (gw_cookie_field == 'portal-userauthcookie')

        # Filtrage des gateways internes : uniquement en mode Auto.
        # Critère = résolution DNS du portail (pas du gateway préféré) :
        # IP privée → LAN, sinon → extérieur (tunnel).
        # En mode manuel (portal/gateway/internal), le choix utilisateur
        # est respecté sans détection DNS.
        if global_mode == 'auto':
            dns_internal = _detect_lan_by_dns(server, log_fn=self._log)
            if dns_internal is not None:
                cached_internal = dns_internal
                self._cached_is_internal = dns_internal
            else:
                # Échec DNS → hors LAN (tunnel requis), cohérent avec
                # `_is_on_internal_network`.
                cached_internal = False
                self._cached_is_internal = False
            is_external = not cached_internal
            if is_external and _external:
                candidate_pool = _external
                if _internal:
                    self._log(
                        '  [Auto] Réseau externe détecté (DNS portail) → '
                        'gateways internes filtrés '
                        '(joignables uniquement depuis le LAN).')
            else:
                candidate_pool = gateways
        else:
            cached_internal = (conn_mode == 'internal')
            self._cached_is_internal = cached_internal
            candidate_pool = gateways
            is_external = not cached_internal
            self._log(
                f'  Mode manuel ({conn_mode}) — tous les gateways '
                f'disponibles ({len(candidate_pool)}), sans filtrage DNS.')

        is_cloud_dep = ((self.config.get('server_deployment', {}) or {})
                        .get(server) == 'cloud')

        def _connect_via_gw(gw):
            """Lance la connexion openconnect pour un gateway donné.

            Stratégie selon le déploiement :
              • Cloud Prisma Access : les gateways ont leur PROPRE pool
                SAML, distinct du portail. Les cookies portail ne sont
                pas valides côté /ssl-vpn/login.esp du gateway. On refait
                donc SAML directement sur le hostname du gateway. La
                session IdP étant active dans le WebView, le 2e SAML
                est silencieux (pas de prompt utilisateur). On passe
                ensuite le prelogin-cookie gateway-side à openconnect.
              • On-prem : on peut soit échanger portal-userauthcookie
                contre un authcookie via /ssl-vpn/login.esp sur le
                gateway, soit retomber sur le routage classique.
            """
            gw_hostname = gw['hostname']
            gw_desc     = gw['description']

            if is_cloud_dep:
                self._log(
                    f'  [Cloud] SAML gateway → {gw_hostname}\n'
                    f'  [Cloud] (session IdP active, le 2e SAML devrait '
                    f'être silencieux)')
                self._set_state('authenticating',
                                subtitle=f'SAML gateway {gw_hostname}…')

                # Le WebView WebKit2 + GtkDialog DOIVENT s'exécuter sur le
                # main thread GTK. Depuis ce worker thread on dispatch via
                # GLib.idle_add et on attend la complétion via Event.
                _saml_result   = [None]
                _saml_error    = [None]
                _saml_done_evt = threading.Event()

                def _run_gw_saml_on_main():
                    try:
                        _saml_result[0] = webview_saml_auth(
                            gw_hostname, clientos=clientos,
                            interface='gateway', user_agent=user_agent,
                            verify=verify, allow_insecure=allow_insecure,
                            parent_window=self, log_fn=self._log)
                    except Exception as exc:
                        _saml_error[0] = exc
                    finally:
                        _saml_done_evt.set()
                    return False

                GLib.idle_add(_run_gw_saml_on_main)
                # Timeout généreux (5 min). Si l'utilisateur ne valide pas,
                # on libère le thread proprement.
                if not _saml_done_evt.wait(timeout=300):
                    self._log('  [Cloud] ⚠ Timeout SAML gateway (5 min).')

                try:
                    if _saml_error[0]:
                        raise _saml_error[0]
                    gw_saml = _saml_result[0]
                    if not gw_saml:
                        raise RuntimeError('SAML gateway annulé ou sans cookie')
                    gw_cookie = (gw_saml.get('prelogin-cookie')
                                 or gw_saml.get('COOKIE'))
                    if not gw_cookie:
                        raise RuntimeError(
                            f'Cookie gateway introuvable dans la réponse SAML : '
                            f'{list(gw_saml.keys())}')
                    self._log(
                        f'  [Cloud] ✔ prelogin-cookie gateway obtenu '
                        f'({gw_cookie[:8]}…)')
                    threading.Thread(
                        target=self._do_connect,
                        args=(gw_hostname, gw_desc, 'prelogin-cookie',
                              gw_cookie, username, os_type, user_agent,
                              False),  # gateway direct
                        daemon=True,
                    ).start()
                    return
                except Exception as e:
                    self._log(
                        f'  [Cloud] ⚠ SAML gateway échoué : {e}\n'
                        f'  [Cloud] Fallback : openconnect portail-stdin '
                        f'sur le portail (peut échouer en 512).')
                    threading.Thread(
                        target=self._do_connect,
                        args=(server, gw_desc, 'prelogin-cookie',
                              cookie_value, username, os_type, user_agent,
                              True),
                        daemon=True,
                    ).start()
                    return

            # ── On-prem : tentative d'échange portal-userauthcookie → authcookie
            if gw_cookie_field == 'portal-userauthcookie':
                self._log(
                    f'  [GW-Login] Échange portal-userauthcookie → '
                    f'authcookie gateway sur {gw_hostname}…')
                try:
                    login_res = gateway_login(
                        gw_hostname, gw_cookie_field, gw_cookie_value,
                        username, clientos=clientos, user_agent=user_agent,
                        internal=False, verify=verify,
                        allow_insecure=allow_insecure, log_fn=self._log)
                    authcookie = login_res.get('authcookie')
                    if not authcookie:
                        raise RuntimeError('authcookie manquant')
                    self._log(
                        f'  [GW-Login] ✔ authcookie obtenu ({authcookie[:8]}…)')
                    threading.Thread(
                        target=self._do_connect,
                        args=(gw_hostname, gw_desc, 'authcookie', authcookie,
                              username, os_type, user_agent, False),
                        daemon=True,
                    ).start()
                    return
                except Exception as e:
                    self._log(
                        f'  [GW-Login] ⚠ Échange portal→gateway échoué : {e}\n'
                        f'  [GW-Login] Fallback : passage du portal-userauthcookie '
                        f'à openconnect en mode portail-stdin.')
                    threading.Thread(
                        target=self._do_connect,
                        args=(server, gw_desc, gw_cookie_field, gw_cookie_value,
                              username, os_type, user_agent, True),
                        daemon=True,
                    ).start()
                    return

            same_host  = (gw_hostname == server)
            target     = server if same_host else gw_hostname
            use_portal = use_portal_stdin_default and same_host
            threading.Thread(
                target=self._do_connect,
                args=(target, gw_desc, gw_cookie_field, gw_cookie_value,
                      username, os_type, user_agent, use_portal),
                daemon=True,
            ).start()

        # Gateway préféré trouvé dans la liste → connexion directe (mais
        # seulement s'il est dans le pool de candidats valide).
        if preferred:
            for gw in candidate_pool:
                if preferred in (gw['hostname'], gw['description']):
                    self._log(f'Gateway préféré sélectionné : {gw["description"]}')
                    _connect_via_gw(gw)
                    return False
            # Préférence pointe vers un gateway non joignable depuis ici.
            if is_external and _external and any(
                    preferred in (g['hostname'], g['description'])
                    for g in _internal):
                self._log(
                    f'  ℹ️  Gateway préféré « {preferred} » est interne '
                    f'— ignoré sur réseau externe.')
            else:
                self._log(
                    f'⚠ Gateway préféré « {preferred} » absent de la liste '
                    f'— sélection manuelle.')

        # Un seul candidat → auto-sélection sans dialogue
        if len(candidate_pool) == 1:
            gw = candidate_pool[0]
            self._log(f'Gateway unique → sélection auto : {gw["description"]}')
            _connect_via_gw(gw)
            return False

        # Dialogue de sélection (thread GTK) — sur le pool filtré
        GLib.idle_add(self._show_gateway_dialog, candidate_pool, gw_cookie_field,
                      gw_cookie_value, username, os_type, user_agent, preferred, server)
        return False

    def _show_gateway_dialog(self, gateways, cookie_field, cookie_value,
                             username, os_type, user_agent, preferred, portal_server):
        """Affiche le dialogue de sélection de gateway (thread GTK principal)."""
        self._apply_state('fetching')
        dlg = GatewayDialog(self, gateways, preferred)
        response = dlg.run()
        gw = dlg.get_selected_gateway()
        dlg.destroy()

        if response == Gtk.ResponseType.OK and gw:
            self.config.set('preferred_gateway', gw['description'])
            clientos    = self.config.get('clientos', 'Linux')
            verify      = self.config.get('verify_ssl', True)
            allow_insecure = self.config.get('allow_insecure_crypto', False)
            # Cohérent avec _fetch_and_connect : portal-userauthcookie →
            # pré-login gateway pour obtenir un authcookie réel.
            if cookie_field == 'portal-userauthcookie':
                gw_hostname = gw['hostname']
                gw_desc     = gw['description']

                def _do_gw_login_and_connect():
                    self._log(
                        f'  [GW-Login] Échange portal-userauthcookie → '
                        f'authcookie sur {gw_hostname}…')
                    try:
                        login_res = gateway_login(
                            gw_hostname, cookie_field, cookie_value,
                            username, clientos=clientos, user_agent=user_agent,
                            internal=False, verify=verify,
                            allow_insecure=allow_insecure, log_fn=self._log)
                        authcookie = login_res.get('authcookie')
                        if not authcookie:
                            raise RuntimeError('authcookie manquant')
                        self._log(
                            f'  [GW-Login] ✔ authcookie obtenu '
                            f'({authcookie[:8]}…)')
                        self._do_connect(
                            gw_hostname, gw_desc, 'authcookie', authcookie,
                            username, os_type, user_agent, False)
                    except Exception as e:
                        self._log(
                            f'  [GW-Login] ⚠ Échange échoué : {e} — '
                            f'fallback portail-stdin.')
                        self._do_connect(
                            portal_server, gw_desc, cookie_field, cookie_value,
                            username, os_type, user_agent, True)

                threading.Thread(target=_do_gw_login_and_connect,
                                 daemon=True).start()
                return False

            same_host = (gw['hostname'] == portal_server)
            target    = portal_server if same_host else gw['hostname']
            use_portal = same_host  # on-prem same-host : portail-stdin
            threading.Thread(
                target=self._do_connect,
                args=(target, gw['description'], cookie_field,
                      cookie_value, username, os_type, user_agent, use_portal),
                daemon=True,
            ).start()
        else:
            self._apply_state('disconnected')
        return False

    # ── Mode Passerelle Interne (no-tunnel) ────────────────────────────────

    def _internal_connect(self, server, cookie_field, cookie_value,
                          username, clientos, user_agent, verify,
                          hip_interval=3600):
        """Connexion interne sans tunnel : login + boucle HIP périodique."""
        allow_insecure = self.config.get('allow_insecure_crypto', False)
        self._log(f'  [Internal] Connexion au gateway interne {server}…')
        self._set_state('connecting', subtitle=f'Interne {server}')

        login_result = None
        last_error = None
        # Ordre de tentative : clientos choisi, puis Mac en fallback si 512
        os_attempts = [clientos]
        if clientos != 'Mac':
            os_attempts.append('Mac')

        for attempt_os in os_attempts:
            attempt_ua = user_agent
            if attempt_os != clientos:
                presets = UA_PRESETS_BY_OS.get(attempt_os, {})
                attempt_ua = next(iter(presets.values()), 'PAN GlobalProtect')
                self._log(
                    f'  [Internal] ↻ Retry avec clientos={attempt_os}…')
            try:
                login_result = gateway_login_notunnel(
                    server, cookie_field, cookie_value, username,
                    clientos=attempt_os, user_agent=attempt_ua,
                    verify=verify, allow_insecure=allow_insecure,
                    log_fn=self._log)
                break
            except RuntimeError as e:
                last_error = e
                if '512' in str(e) and attempt_os != os_attempts[-1]:
                    self._log(
                        f'  [Internal] HTTP 512 avec clientos={attempt_os}')
                    continue
                break
            except Exception as e:
                last_error = e
                break

        if login_result is None:
            self._log(f'  [Internal] Échec login gateway : {last_error}')
            self._set_state('error', error_msg='Échec login interne')
            return

        conn_type = login_result.get('connection-type', '')
        if conn_type != 'notunnel':
            self._log(
                f'  [Internal] ⚠ connection-type inattendu : {conn_type!r} '
                f'(attendu: notunnel)')

        authcookie  = login_result['authcookie']
        portal_name = login_result.get('portal', '') or server
        user        = login_result.get('user', username)
        domain      = login_result.get('domain', '')
        hostname    = login_result.get('hostname', socket.gethostname())
        client_ip   = login_result.get('client-ip', '0.0.0.0')
        self._vpn_client_ip = client_ip
        session     = login_result.get('session')

        self._internal_session = {
            'session':     session,
            'server':      server,
            'authcookie':  authcookie,
            'portal':      portal_name,
            'user':        user,
            'domain':      domain,
            'hostname':    hostname,
            'client_ip':   client_ip,
            'verify':      verify,
            'hip_interval': hip_interval,
        }

        self._log(
            f'  [Internal] Authentifié : {user} (IP={client_ip})\n'
            f'  [Internal] Pas de tunnel VPN — mode user-ID + HIP')
        self._set_state('connected',
                        subtitle=f'Interne {server} (sans tunnel)')
        # Le mode internal n'est pas mémorisé : il est redécidé à chaque
        # connexion via la résolution DNS du portail (IP privée = LAN).

        _save_session_token(server, {
            'cookie_field': 'authcookie',
            'cookie_value': authcookie,
            'username': user,
            'conn_mode': 'internal',
            'portal': portal_name,
            'domain': domain,
            'hostname': hostname,
            'client_ip': client_ip,
            'clientos': clientos,
            'user_agent': user_agent,
            # Conserver le portal-userauthcookie comme refresh pour pouvoir
            # basculer hors LAN sans nouveau SSO.
            **({
                'refresh_field': self._reusable_portal_cookie[0],
                'refresh_value': self._reusable_portal_cookie[1],
            } if getattr(self, '_reusable_portal_cookie', None) else {}),
        }, log_fn=self._log)

        self._hip_stop_event = threading.Event()
        if self.config.get('hip_enabled', True):
            self._log('  [HIP] Envoi HIP activé — boucle keepalive démarrée')
        else:
            self._log('  [HIP] Envoi HIP désactivé dans les paramètres')
        threading.Thread(
            target=self._hip_keepalive_loop, daemon=True).start()

    def _hip_keepalive_loop(self):
        """Boucle périodique : check HIP + soumission au gateway interne."""
        if not self.config.get('hip_enabled', True):
            self._log('  [HIP] Désactivé dans les paramètres — pas d\'envoi')
            return
        sess_info = getattr(self, '_internal_session', None)
        if not sess_info:
            return
        stop_ev   = self._hip_stop_event
        session   = sess_info['session']
        server    = sess_info['server']
        authcookie = sess_info['authcookie']
        portal    = sess_info['portal']
        user      = sess_info['user']
        domain    = sess_info['domain']
        hostname  = sess_info['hostname']
        client_ip = sess_info['client_ip']
        verify    = sess_info['verify']
        interval  = sess_info.get('hip_interval', 3600)

        cookie_str = (f'authcookie={authcookie}&portal={quote(portal)}'
                      f'&user={quote(user)}&domain={quote(domain)}'
                      f'&computer={quote(hostname)}')
        md5_token = compute_hip_md5(hostname, cookie_str)

        self._log(f'  [HIP] Boucle keepalive démarrée (intervalle={interval}s)')

        first_run = True
        while not stop_ev.is_set():
            if not first_run:
                if stop_ev.wait(timeout=interval):
                    break
            first_run = False

            if self._cancel_requested or stop_ev.is_set():
                break

            try:
                self._log('  [HIP] Vérification HIP (hipreportcheck)…')
                needed = gateway_hip_check(
                    session, server, authcookie, portal,
                    user, domain, hostname, client_ip, md5_token,
                    verify=verify, log_fn=self._log)

                if needed:
                    self._log('  [HIP] Rapport requis — génération…')
                    hip_xml = self._generate_hip_xml_for_submit(
                        client_ip=client_ip, md5=md5_token,
                        username=user, cookie_str=cookie_str,
                        computer=hostname)
                    if hip_xml:
                        ok = gateway_hip_submit(
                            session, server, authcookie, portal,
                            user, domain, hostname, client_ip, hip_xml,
                            verify=verify, log_fn=self._log)
                        if ok:
                            self._log('  [HIP] ✔ Rapport expédié au gateway '
                                      'interne')
                        else:
                            self._log('  [HIP] ✘ Échec envoi au gateway '
                                      'interne')
                    else:
                        self._log('  [HIP] ✘ XML vide — rapport non expédié')
                else:
                    self._log('  [HIP] Rapport à jour (hip-report-needed=no)')
            except Exception as e:
                self._log(f'  [HIP] Erreur keepalive : {e}')

        self._log('  [HIP] Boucle keepalive arrêtée.')

    def _internal_disconnect(self):
        """Déconnexion du mode interne : arrêt boucle HIP + logout gateway."""
        stop_ev = getattr(self, '_hip_stop_event', None)
        if stop_ev:
            stop_ev.set()

        sess_info = getattr(self, '_internal_session', None)
        if sess_info:
            gateway_logout(
                sess_info['session'], sess_info['server'],
                sess_info['authcookie'], sess_info['portal'],
                sess_info['user'], sess_info['domain'],
                sess_info['hostname'],
                verify=sess_info['verify'], log_fn=self._log)
            self._internal_session = None

    # ── Retries ─────────────────────────────────────────────────────────────

    def _retry_with_portal_mode(self, reason=''):
        """Fallback auto : relance une auth SSO en mode portail interactif."""
        if self._cancel_requested or self._mode_retry_attempted:
            return
        self._mode_retry_attempted = True
        self._forced_conn_mode = 'portal'
        server = self.config.get('server')
        if reason:
            self._log(f'⚠ Échec mode passerelle directe ({reason}).')
        self._log(
            '↻ Fallback automatique : nouvelle authentification en mode '
            '"portail interactif".')
        self._set_state('authenticating', subtitle=f'Fallback portail {server}…')
        threading.Thread(target=self._auth_thread, daemon=True).start()

    def _retry_with_gateway_direct(self, reason=''):
        """Fallback auto : relance en mode passerelle directe (on-prem 512)."""
        if self._cancel_requested or self._mode_retry_attempted:
            return
        self._mode_retry_attempted = True
        self._forced_conn_mode = 'gateway'
        server = self.config.get('server')
        if reason:
            self._log(f'⚠ Échec mode portail interactif ({reason}).')
        self._log(
            '↻ Fallback automatique : nouvelle authentification en mode '
            '"passerelle directe" (on-prem).')
        self._set_state('authenticating', subtitle=f'Retry gateway {server}…')
        threading.Thread(target=self._auth_thread, daemon=True).start()

    def _retry_with_mac_for_gateway(self, server):
        """Retry gateway : le gateway a rejeté Linux (HTTP 512), ré-auth avec Mac."""
        if self._cancel_requested or self._os_512_retry_attempted:
            return
        self._os_512_retry_attempted = True
        self._forced_conn_mode = 'gateway'
        self._forced_clientos  = 'Mac'
        self._log(
            '⚠ Le gateway a rejeté clientos=Linux (HTTP 512).\n'
            '↻ Retry automatique avec clientos=Mac…')
        self._set_state('authenticating',
                        subtitle=f'Retry Mac — {server}…')
        threading.Thread(target=self._auth_thread, daemon=True).start()

    def _retry_with_different_os(self, reason=''):
        """Relance l'auth avec le prochain clientos de la liste de priorité."""
        if self._cancel_requested or not self._os_retry_list:
            return False
        next_os = self._os_retry_list.pop(0)
        self._os_retry_attempted = True
        server = self.config.get('server')
        if reason:
            self._log(f'⚠ Échec avec le type de device actuel ({reason}).')
        self._log(
            f'↻ Retry automatique avec clientos={next_os} '
            f'(reste à essayer : {self._os_retry_list or "aucun"})')
        self._set_state('authenticating',
                        subtitle=f'Retry {next_os} — {server}…')
        threading.Thread(target=self._auth_thread, daemon=True).start()
        return True

    def _remember_os_for_server(self, clientos):
        """Mémorise le clientos efficace pour le serveur courant."""
        if clientos not in CLIENTOS_OS_MAP:
            return
        server = self.config.get('server')
        if not server:
            return
        server_os = self.config.get('server_os', {})
        if server_os.get(server) != clientos:
            server_os[server] = clientos
            self.config.set('server_os', server_os)
            self._log(f'ℹ️  OS mémorisé pour {server} : {clientos}')

    def _remember_mode_for_server(self, mode):
        """Mémorise le mode efficace hors-LAN pour le serveur courant.

        'internal' n'est pas mémorisé : il est décidé à chaque connexion
        uniquement via la résolution DNS du portail (IP privée = LAN).
        """
        if mode not in ('portal', 'gateway'):
            return
        server = self.config.get('server')
        if not server:
            return
        modes = self.config.get('server_modes', {})
        if modes.get(server) != mode:
            modes[server] = mode
            self.config.set('server_modes', modes)
            self._log(f'ℹ️  Mode mémorisé pour {server} : {mode}')

    def _do_connect(self, target_host, gateway_desc, cookie_field, cookie_value,
                    username, os_type, user_agent, use_portal_stdin=False):
        """Lance openconnect vers le gateway (avec portal-userauthcookie).

        use_portal_stdin=True : fallback — connexion via portail + sélection stdin.
        use_portal_stdin=False : connexion directe au gateway (cas nominal).
        """
        # Vérifier sudo avant de continuer
        if not can_sudo_openconnect():
            self._log('⚠ openconnect ne peut pas s\'exécuter sans mot de passe sudo.')
            self._log('  → Ouvrez ⚙ Paramètres, cliquez sur "Config. sudo" et relancez.')
            self._set_state('error', error_msg='Autorisation sudo manquante')
            GLib.idle_add(self._prompt_sudo_setup)
            return

        # Réinit du flag 512-terminated : chaque appel à _do_connect est une
        # nouvelle tentative openconnect, potentiellement après un
        # _retry_with_portal_mode / _retry_with_gateway_direct qui ne repasse
        # pas par _start_connect.
        self._oc_512_terminated = False

        if use_portal_stdin:
            usergroup = f'portal:{cookie_field}'
            self._set_state('connecting', subtitle=gateway_desc or target_host)
            self._log(
                f'Connexion → portail {target_host} '
                f'(sélection gateway via stdout)')
        else:
            usergroup = f'gateway:{cookie_field}'
            self._set_state('connecting', subtitle=gateway_desc)
            self._log(f'Connexion → gateway {gateway_desc} ({target_host})')

        allow_insecure = self.config.get('allow_insecure_crypto', False)

        self._last_auth_info = {
            'server': target_host,
            'cookie_field': cookie_field,
            'cookie_value': cookie_value,
            'username': username,
            'os_type': os_type,
            'clientos': self.config.get('clientos', 'Linux'),
            'user_agent': user_agent,
            'verify': self.config.get('verify_ssl', False),
            'allow_insecure': allow_insecure,
            'conn_mode': 'portal' if use_portal_stdin else 'gateway',
        }
        # Si on a un portal-userauthcookie réutilisable (harvest getconfig),
        # c'est LUI qu'on persiste — pas le prelogin one-shot.
        reusable = getattr(self, '_reusable_portal_cookie', None)
        if reusable and reusable[0] in _REFRESH_FIELDS and reusable[1]:
            self._last_auth_info['cookie_field'] = reusable[0]
            self._last_auth_info['cookie_value'] = reusable[1]
            self._last_auth_info['refresh_field'] = reusable[0]
            self._last_auth_info['refresh_value'] = reusable[1]
            self._last_auth_info['conn_mode'] = 'portal'
        elif cookie_field in _REFRESH_FIELDS:
            self._last_auth_info['refresh_field'] = cookie_field
            self._last_auth_info['refresh_value'] = cookie_value

        self._tunnel_up_handled = False

        cmd = [
            'sudo', '-n', 'openconnect',
            '--protocol=gp',
            f'--os={os_type}',
            f'--user={username}',
            f'--usergroup={usergroup}',
            f'--useragent={user_agent}',
            '--passwd-on-stdin',
        ]
        if allow_insecure:
            cmd.append('--allow-insecure-crypto')

        # Sauvegarder le gateway courant pour le script HIP
        self.config.set('current_gateway', target_host)

        # ── HIP report wrapper ──────────────────
        hip_enabled = self.config.get('hip_enabled', True)
        if hip_enabled:
            hip_mode   = self.config.get('hip_mode', 'builtin')
            python3    = shutil.which('python3') or 'python3'

            if hip_mode == 'fake':
                hip_script    = HIP_SCRIPT_BUILTIN
                template_path = str(CONFIG_DIR / 'hip_template.xml')
                # Toujours s'assurer que le template est au format PAN-OS
                self._ensure_hip_template_current()
                if not os.path.isfile(template_path):
                    self._log('HIP fake : génération du template initial…')
                    try:
                        xml = self._generate_fake_hip_xml_from_config()
                        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
                        with open(template_path, 'w') as f:
                            f.write(xml)
                    except Exception as e:
                        self._log(f'⚠ HIP fake : erreur génération template : {e}')
                        template_path = ''
                else:
                    self._log(f'HIP fake activé → template : {template_path}')
            elif hip_mode == 'custom':
                hip_script    = self.config.get('hip_script', '').strip()
                template_path = ''
            else:
                hip_script    = HIP_SCRIPT_BUILTIN
                template_path = ''

            if hip_script and os.path.isfile(hip_script):
                import tempfile, stat as _stat
                # Chemin du context file : permet au "Diag HIP" de
                # re-soumettre le rapport pendant que le tunnel tourne.
                hip_ctx_path = '/tmp/.gp-current-authcookie'
                self._hip_ctx_path = hip_ctx_path
                # POST de verification optionnel : si actif, hipreport.py
                # fait un POST direct au gateway en plus de openconnect,
                # pour capturer le body de la reponse PAN-OS.
                # POST de vérification systématique : capture la réponse
                # PAN-OS dans les logs (hipreport.esp) pour confirmer l'envoi.
                hip_verify = '1'

                env_parts = [f'GP_HIP_CONTEXT_FILE="{hip_ctx_path}"',
                             f'GP_HIP_VERIFY_POST={hip_verify}',
                             f'GP_HIP_GATEWAY="{target_host}"']
                if template_path:
                    env_parts.insert(0, f'GP_HIP_TEMPLATE="{template_path}"')
                    env_parts.insert(0, 'GP_HIP_MODE=fake')
                else:
                    self._log(f'HIP activé → {hip_script}')
                env_lines = (
                    '\n'.join(env_parts) + '\n'
                    + 'export ' + ' '.join(p.split('=', 1)[0]
                                           for p in env_parts) + '\n')

                # Wrapper avec capture du XML pour debug.
                # Le rapport est :
                #   • envoyé à openconnect via stdout (comportement nominal)
                #   • copié dans /tmp/gp-connect-last-hip-report.xml
                #   • résumé sur stderr (visible dans tee /tmp/gp.log)
                hip_dump = '/tmp/gp-connect-last-hip-report.xml'
                self._hip_dump_path = hip_dump
                wrapper_content = (
                    '#!/bin/bash\n'
                    f'{env_lines}'
                    f'HIP_DUMP="{hip_dump}"\n'
                    'echo "[HIP-WRAPPER] $(date +%H:%M:%S) Exécution hipreport.py (args=$#)" >&2\n'
                    'echo "[HIP-WRAPPER] Args : $@" >&2\n'
                    f'XML="$({python3} "{hip_script}" "$@" 2>&1 1>/tmp/.gp-hip.stdout)"\n'
                    'EXIT=$?\n'
                    'cp /tmp/.gp-hip.stdout "$HIP_DUMP" 2>/dev/null || true\n'
                    'chmod 644 "$HIP_DUMP" 2>/dev/null || true\n'
                    'SIZE=$(wc -c < "$HIP_DUMP" 2>/dev/null || echo 0)\n'
                    'echo "[HIP-WRAPPER] Rapport généré → $HIP_DUMP (taille=${SIZE} octets, exit=${EXIT})" >&2\n'
                    'echo "[HIP-WRAPPER] === stderr de hipreport.py ===" >&2\n'
                    'echo "$XML" >&2\n'
                    'echo "[HIP-WRAPPER] === fin stderr ===" >&2\n'
                    'cat /tmp/.gp-hip.stdout\n'   # → stdout du wrapper → openconnect
                    'rm -f /tmp/.gp-hip.stdout\n'
                    'exit $EXIT\n')
                tf = tempfile.NamedTemporaryFile(
                    'w', prefix='gp_hip_', suffix='.sh', delete=False)
                tf.write(wrapper_content)
                tf.close()
                os.chmod(tf.name, _stat.S_IRWXU | _stat.S_IRGRP | _stat.S_IXGRP)
                self._hip_wrapper_tmp = tf.name
                cmd += [f'--csd-wrapper={tf.name}']
            else:
                self._log('⚠ HIP activé mais script introuvable — désactivé.')
        else:
            self._log('  [HIP] Désactivé dans les paramètres — pas de csd-wrapper')

        cmd.append(target_host)
        self._log('$ ' + ' '.join(cmd))

        try:
            self.openconnect_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            if not use_portal_stdin:
                # ── Cas nominal : cookie gateway direct ──────────────────────
                self.openconnect_proc.stdin.write(cookie_value + '\n')
                self.openconnect_proc.stdin.flush()
                self.openconnect_proc.stdin.close()
            else:
                # ── Mode portail interactif ──────────────────────────────────
                # Envoyer le cookie IMMÉDIATEMENT pour éviter le blocage :
                # openconnect appelle fgets(stdin) avant de produire du stdout,
                # ce qui deadlockerait si stdin est vide.
                self._log(f'  stdin[1] : {cookie_field}')
                self.openconnect_proc.stdin.write(cookie_value + '\n')
                self.openconnect_proc.stdin.flush()
                # stdin reste OUVERT pour la sélection du gateway plus tard

            # ── État pour le mode portail interactif ─────────────────────────
            import re as _re
            _gateway_list       = []      # gateways parsés depuis le stdout
            _in_gw_list         = False   # on est dans le bloc liste de gateways
            _gateway_selected   = False   # sélection de gateway effectuée

            # ── Suivi HIP ────────────────────────────────────────────────────
            _hip_check_count = 0
            _hip_script_ok   = False
            _hip_failed      = False
            _hip_wrapper_ok  = hip_enabled and bool(
                getattr(self, '_hip_wrapper_tmp', None))
            # Capture des N lignes apres un POST hipreport*.esp (utile en -vv,
            # ou pour attraper les "Got HTTP response" / "Got XX bytes" qu'oc
            # log meme sans verbose). Permet de surfacer la reponse PAN-OS.
            _hip_response_capture = 0      # nb de lignes a republier
            _hip_response_kind    = ''     # 'check' | 'submit'
            _dns_forced      = False
            _configured_ip   = ''
            _auth_error_hint = ''
            self._vpn_dns_servers = []

            for line in self.openconnect_proc.stdout:
                line = line.rstrip()
                self._log(line)

                if line.startswith('Got DNS server '):
                    dns_srv = line.split('Got DNS server ', 1)[1].strip()
                    if dns_srv and dns_srv not in self._vpn_dns_servers:
                        self._vpn_dns_servers.append(dns_srv)

                # Heuristiques d'échec auth / mode (utile pour fallback auto)
                lower = line.lower()
                if ('unexpected 512 result from server' in lower
                        or 'authentication failed' in lower
                        or 'failed to complete authentication' in lower
                        or 'got http response: http/1.1 512' in lower):
                    _auth_error_hint = 'HTTP 512 / auth'
                    # HTTP 512 = le gateway refuse le cookie fourni. Pas de
                    # sens d'attendre qu'openconnect reprompt « Enter login
                    # credentials » : notre stdin est déjà fermé (ou bientôt),
                    # ce qui déclencherait au mieux un ValueError « I/O
                    # operation on closed file. » au pire 2-3 s de bruit
                    # (`fgets (stdin): ioctl() inapproprié`) avant d'exiter.
                    # On termine tout de suite pour laisser le fallback
                    # prendre le relais plus proprement.
                    if ('unexpected 512 result from server' in lower
                            and not getattr(self, '_oc_512_terminated', False)):
                        self._oc_512_terminated = True
                        if not use_portal_stdin:
                            # Gateway direct avec prelogin-cookie brut :
                            # clairement un échec on-prem. Si le mode
                            # « passerelle directe » est mémorisé pour ce
                            # serveur, on l'oublie.
                            if cookie_field == 'prelogin-cookie':
                                _modes = self.config.get('server_modes', {})
                                if _modes.get(target_host) == 'gateway':
                                    _modes.pop(target_host, None)
                                    self.config.set('server_modes', _modes)
                                    self._log(
                                        f'  ℹ️  Mode « passerelle directe » '
                                        f'désmémorisé pour {target_host}.')
                                self._log(
                                    '  [Auto] HTTP 512 en mode passerelle '
                                    'directe — arrêt pour fallback portail.')
                            else:
                                # Gateway direct avec portal-userauthcookie :
                                # la passerelle choisie refuse ce cookie
                                # (probablement mauvais gateway — external vs
                                # internal). Le cookie peut rester valide,
                                # on ne le purge PAS : le retry ou une autre
                                # passerelle peut encore marcher.
                                self._log(
                                    '  [Auto] HTTP 512 — cette passerelle '
                                    'refuse le cookie (clientos / HIP / '
                                    'gateway non approprié).')
                        else:
                            self._log(
                                '  [Auto] HTTP 512 en mode portail (gateway '
                                'rejette le cookie) — arrêt immédiat.')
                        # Fermer stdin AVANT terminate() : openconnect a
                        # typiquement un second prompt getpass() en file
                        # d'attente qui, sur pipe non-TTY, échoue avec
                        # « fgets (stdin): ioctl() inapproprié ». Fermer stdin
                        # force un EOF immédiat → fgets retourne NULL →
                        # openconnect sort proprement.
                        try:
                            if (self.openconnect_proc.stdin is not None
                                    and not self.openconnect_proc.stdin.closed):
                                self.openconnect_proc.stdin.close()
                        except Exception:
                            pass
                        try:
                            self.openconnect_proc.terminate()
                        except Exception:
                            pass
                elif ('got http response: http/1.1 404' in lower
                      or 'unexpected 404 result' in lower):
                    _auth_error_hint = 'HTTP 404 / endpoint introuvable'
                elif ('fgets (stdin)' in lower and 'inapproprié' in lower):
                    _auth_error_hint = 'stdin credential loop'
                elif ('unknown device' in lower
                      or 'device type' in lower
                      or 'unsupported device' in lower
                      or 'portal config error' in lower
                      or 'failed to get portal config' in lower):
                    _auth_error_hint = 'unknown device type'

                # ── Mode portail interactif : collecter gateways + sélectionner ─
                if use_portal_stdin:
                    # 1. Collecter la liste des gateways
                    if _re.search(r'\d+\s+gateway server', line, _re.I):
                        _in_gw_list = True

                    elif _in_gw_list:
                        m = _re.match(r'\s{2,}(.+?)\s+\(([^)]+)\)\s*$', line)
                        if m:
                            _gateway_list.append({
                                'description': m.group(1).strip(),
                                'hostname':    m.group(2).strip(),
                            })
                        elif line.strip() and not line.startswith(' '):
                            _in_gw_list = False

                    # 3. Auto-détection on-prem : si le seul gateway == portail
                    #    → mémoriser pour les prochaines connexions
                    if (_gateway_list and not _gateway_selected
                            and _re.search(
                                r'Please select GlobalProtect gateway', line)):
                        _all_same = all(
                            gw['hostname'] == target_host
                            for gw in _gateway_list)
                        if _all_same and len(_gateway_list) == 1:
                            _modes = self.config.get('server_modes', {})
                            if _modes.get(target_host) != 'gateway':
                                _modes[target_host] = 'gateway'
                                self.config.set('server_modes', _modes)
                                self._log(
                                    f'  ℹ️  On-prem détecté pour {target_host}.\n'
                                    f'     Mode "passerelle directe" mémorisé '
                                    f'→ sera utilisé à la prochaine connexion.')

                    # 3. Sélectionner le gateway quand openconnect demande
                    if ('Please select GlobalProtect gateway' in line
                            and not _gateway_selected):
                        _in_gw_list = False
                        if _gateway_list:
                            self._log(
                                f'  Gateways disponibles ({len(_gateway_list)}) :')
                            for _gw in _gateway_list:
                                self._log(
                                    f'    • {_gw["description"]}'
                                    f' ({_gw["hostname"]})')

                        # Chercher la gateway préférée
                        _pref = gateway_desc or self.config.get(
                            'preferred_gateway', '')
                        _selected = None
                        for _gw in _gateway_list:
                            if _pref in (_gw['hostname'], _gw['description']):
                                _selected = _gw['description']
                                break

                        if _selected is None and _gateway_list:
                            if len(_gateway_list) == 1:
                                _selected = _gateway_list[0]['description']
                            else:
                                # Montrer le dialogue de sélection
                                _evt = threading.Event()
                                _choice = [_gateway_list[0]['description']]
                                def _show_dlg(_list=_gateway_list, _c=_choice,
                                              _e=_evt):
                                    _dlg = GatewayDialog(self, _list, _pref)
                                    if (_dlg.run() == Gtk.ResponseType.OK
                                            and _dlg.get_selected_gateway()):
                                        _c[0] = _dlg.get_selected_gateway()[
                                            'description']
                                    _dlg.destroy()
                                    _e.set()
                                    return False
                                GLib.idle_add(_show_dlg)
                                _evt.wait(timeout=60)
                                _selected = _choice[0]

                        if _selected:
                            self._log(f'  → stdin gateway : {_selected}')
                            self.openconnect_proc.stdin.write(_selected + '\n')
                            self.openconnect_proc.stdin.flush()
                            # NE PAS fermer stdin : le gateway peut demander
                            # des credentials supplémentaires
                            _gateway_selected = True

                    # 4. Fallback : prompt GATEWAY: [opt1|opt2]:
                    elif ('GATEWAY:' in line and '[' in line
                          and not _gateway_selected):
                        m = _re.search(r'GATEWAY:\s*\[([^\]]+)\]', line)
                        if m:
                            _opts = [o.strip() for o in m.group(1).split('|')]
                            _pref = gateway_desc or self.config.get(
                                'preferred_gateway', '')
                            _sel = _opts[0]
                            for _o in _opts:
                                if _pref and _pref in _o:
                                    _sel = _o
                                    break
                            self._log(f'  → stdin gateway (fallback) : {_sel}')
                            self.openconnect_proc.stdin.write(_sel + '\n')
                            self.openconnect_proc.stdin.flush()
                            _gateway_selected = True

                    # 5. Credentials gateway (après sélection) :
                    #    openconnect redemande un cookie pour le gateway on-prem.
                    #    On renvoie le prelogin-cookie SAML original — le gateway
                    #    partageant le portail l'accepte souvent.
                    elif (_gateway_selected
                          and 'Enter login credentials' in line):
                        stdin_fh = self.openconnect_proc.stdin
                        # Garder-fou : si on a déjà envoyé+fermé stdin lors d'un
                        # « Enter login credentials » précédent (typiquement
                        # après un HTTP 512 où le gateway reprompt), ne pas
                        # rejouer — sinon write() lève ValueError et fait
                        # remonter « I/O operation on closed file. » jusqu'à
                        # l'UI.
                        if stdin_fh is None or stdin_fh.closed:
                            self._log(
                                '  ⚠ Nouveau prompt credentials mais stdin '
                                'déjà fermé — on laisse openconnect sortir.')
                        else:
                            self._log(
                                f'  → stdin gateway credentials : {cookie_field}')
                            try:
                                stdin_fh.write(cookie_value + '\n')
                                stdin_fh.flush()
                                stdin_fh.close()
                            except (BrokenPipeError, OSError, ValueError):
                                pass   # stdin déjà fermé par openconnect

                # ── Détection de l'état du rapport HIP ──────────────────
                if line.startswith('[HIP-WRAPPER] Args :'):
                    # Extraire le --md5 passé par openconnect au wrapper
                    # (= la valeur que <md5-sum> du XML doit reproduire)
                    import re as _re
                    m = _re.search(r'--md5\s+(\S+)', line)
                    if m:
                        self._log(
                            f'  [HIP] MD5 fourni par openconnect (csd_token) : '
                            f'{m.group(1)}')
                    m = _re.search(r'--client-ip\s+(\S+)', line)
                    if m:
                        self._log(f'  [HIP] IP client transmise : {m.group(1)}')

                if line.startswith('[HIP-WRAPPER] Rapport généré'):
                    # Le wrapper vient d'écrire le XML — l'afficher en entier
                    # dans les logs pour permettre la vérification côté admin.
                    dump = getattr(self, '_hip_dump_path',
                                   '/tmp/gp-connect-last-hip-report.xml')
                    try:
                        with open(dump) as _fh:
                            _xml = _fh.read()
                        self._log(f'  [HIP] === Contenu du rapport ({dump}) ===')
                        for _ln in _xml.splitlines():
                            self._log(f'    {_ln}')
                        self._log('  [HIP] === Fin du rapport ===')
                    except Exception as e:
                        self._log(f'  [HIP] ⚠ Impossible de lire {dump} : {e}')

                # ── Capture des lignes qui suivent un POST hipreport*.esp ──
                # Bloc independant (pas un elif) pour ne pas court-circuiter
                # les detections "HIP script completed successfully" / fail
                # ci-dessous qui maintiennent _hip_script_ok / _hip_failed.
                if (_hip_response_capture > 0
                        and 'hipreportcheck.esp' not in line
                        and 'hipreport.esp' not in line.lower()):
                    _stripped = line.strip()
                    if _stripped:
                        self._log(
                            f'  [HIP-RESP/{_hip_response_kind}] {_stripped}')
                        _low = _stripped.lower()
                        if 'hip-report-needed' in _low:
                            import re as _re
                            m = _re.search(
                                r'<hip-report-needed[^>]*>\s*([^<]+)\s*</',
                                _stripped)
                            if m:
                                self._log(
                                    f'  [HIP] ➜ hip-report-needed = '
                                    f'{m.group(1).strip()}')
                        if 'status="error"' in _low or '<msg>' in _low:
                            self._log(
                                '  [HIP] ⚠ PAN-OS a renvoyé une erreur '
                                'explicite — voir la ligne ci-dessus.')
                    _hip_response_capture -= 1

                if 'hipreportcheck.esp' in line:
                    _hip_check_count += 1
                    if _hip_check_count == 1:
                        self._log(
                            '  [HIP] 🔍 Passerelle : vérification du profil HIP…')
                    elif _hip_check_count >= 2 and _hip_script_ok and not _hip_failed:
                        self._log(
                            '  [HIP] ✔ Rapport HIP accepté par la passerelle !')
                    # Armer le capteur de reponse : les ~6 lignes suivantes
                    # contiennent typiquement "Got HTTP response", headers,
                    # body parse. En -vv on aura aussi le XML brut.
                    _hip_response_capture = 6
                    _hip_response_kind    = 'check'

                elif 'hipreport.esp' in line.lower():
                    # Ligne openconnect du type :
                    #   "POST https://server/ssl-vpn/hipreport.esp"
                    self._log('  [HIP] 📤 Soumission du rapport à la passerelle…')
                    _hip_response_capture = 8
                    _hip_response_kind    = 'submit'

                elif ('HIP script' in line and
                      'completed successfully' in line):
                    _hip_script_ok = True
                    # Extraire la taille du rapport depuis "(report is NNN bytes)"
                    import re as _re
                    m = _re.search(r'report is (\d+) bytes', line)
                    if m:
                        size = int(m.group(1))
                        if size == 0:
                            self._log('  [HIP] ⚠ Rapport généré mais vide (0 octets) '
                                      '— le VPN peut être restreint.')
                        else:
                            self._log(
                                f'  [HIP] ✔ Rapport soumis à openconnect '
                                f'({size} octets).')
                    else:
                        self._log('  [HIP] ✔ Script HIP exécuté avec succès.')

                elif ('HIP script' in line and
                      'returned non-zero status' in line):
                    self._log('  [HIP] ✘ Script HIP a retourné une erreur '
                              '— connexion peut être limitée.')

                elif 'HIP report submission failed' in line:
                    _hip_failed = True
                    self._log('  [HIP] ✘ La passerelle a refusé le rapport HIP '
                              '— vérifiez le contenu XML.')

                elif ('WARNING' in line and
                      'submit HIP report' in line):
                    # "Server asked us to submit HIP report with md5sum ..."
                    import re as _re
                    m = _re.search(r'md5sum\s+(\S+)', line)
                    md5_expected = m.group(1) if m else '?'
                    self._log(
                        f'  [HIP] 📋 Profil MD5 attendu : {md5_expected}')

                elif line.startswith('Configured as '):
                    try:
                        _configured_ip = line.split('Configured as ', 1)[1] \
                                             .split(',', 1)[0].strip()
                        self._vpn_client_ip = _configured_ip
                    except Exception:
                        _configured_ip = ''

                # ── Tunnel connecté (une seule fois) ─────────────────────
                if (not getattr(self, '_tunnel_up_handled', False)
                        and any(kw in line for kw in
                       ('Tunnel is up', 'ESP tunnel connected', 'DTLS connected',
                        'Connected as', 'assigned address', 'Configured as',
                        'SSL connected and ESP unsuccessful'))):
                    self._tunnel_up_handled = True
                    self._set_state('connected', subtitle=gateway_desc or target_host)
                    # Persister le token RÉUTILISABLE (portal-userauthcookie)
                    # rattaché au portail config, pas au FQDN gateway cloud.
                    if getattr(self, '_last_auth_info', None):
                        portal_server = (
                            self.config.get('server') or target_host)
                        _save_session_token(
                            portal_server, dict(self._last_auth_info),
                            log_fn=self._log)
                        self._reconnect_count = 0
                    oc_pid = (self.openconnect_proc.pid
                              if self.openconnect_proc else None)
                    _save_vpn_state(
                        target_host,
                        iface=self._oc_iface(),
                        client_ip=_configured_ip,
                        pid=oc_pid)
                    # Mémoriser le mode et l'OS qui fonctionnent
                    if use_portal_stdin:
                        self._remember_mode_for_server('portal')
                    else:
                        self._remember_mode_for_server('gateway')
                    effective_os = OS_TO_CLIENTOS.get(os_type, '')
                    if effective_os:
                        self._remember_os_for_server(effective_os)
                    self._os_retry_list = []
                    if self.config.get('force_vpn_dns', True) and not _dns_forced:
                        # Lancer en arrière-plan pour ne pas bloquer la lecture stdout.
                        threading.Thread(
                            target=self._force_dns_over_vpn,
                            args=(_configured_ip,),
                            daemon=True).start()
                        _dns_forced = True
                    self._report_hip_delivery_status(
                        target_host, {
                            'wrapper_configured': _hip_wrapper_ok,
                            'check_count': _hip_check_count,
                            'script_ok': _hip_script_ok,
                            'failed': _hip_failed,
                            'dump_path': getattr(
                                self, '_hip_dump_path',
                                '/tmp/gp-connect-last-hip-report.xml'),
                        })
                    self._verify_hip_after_connect(target_host)

            self.openconnect_proc.wait()

            if not self._cancel_requested:
                if self.state == 'connected':
                    self._log('Connexion VPN terminée.')
                    self._restore_dns_routes()
                    reconnect_count = getattr(self, '_reconnect_count', 0)
                    if reconnect_count < 3:
                        self._reconnect_count = reconnect_count + 1
                        self._log(
                            f'  [Reconnect] Tentative '
                            f'{self._reconnect_count}/3 dans 5s…')
                        self._set_state('connecting',
                                        subtitle=f'Reconnexion…')
                        _time_mod.sleep(5)
                        if not self._cancel_requested:
                            GLib.idle_add(self._start_connect)
                        return
                    self._set_state('disconnected')
                else:
                    # Retry auto avec un clientos différent si device type inconnu
                    if (_auth_error_hint == 'unknown device type'
                            and self._os_retry_list):
                        if self._retry_with_different_os(_auth_error_hint):
                            return

                    # Portal interactif + HTTP 512 = on-prem (portail == gateway).
                    # Le prelogin-cookie a été consommé par getconfig → relancer
                    # en mode passerelle directe où le cookie va au gateway sans
                    # passer par getconfig.
                    if (use_portal_stdin
                            and 'HTTP 512' in (_auth_error_hint or '')
                            and not self._mode_retry_attempted):
                        self._log(
                            '⚠ HTTP 512 en mode portail interactif '
                            '(prelogin-cookie consommé par getconfig).')
                        self._remember_mode_for_server('gateway')
                        self._retry_with_gateway_direct(
                            _auth_error_hint or 'HTTP 512 portal→gateway')
                        return

                    # Si échec en mode passerelle directe, bascule auto vers portail.
                    if (not use_portal_stdin and not self._mode_retry_attempted):
                        self._retry_with_portal_mode(_auth_error_hint or 'échec de connexion')
                        return

                    # Plus aucun fallback possible — message contextuel.
                    if 'HTTP 512' in (_auth_error_hint or ''):
                        self._log(
                            '✘ Le serveur a refusé le cookie d\'authentification '
                            'en mode portail ET en mode passerelle directe.\n'
                            '  Causes possibles :\n'
                            '    - clientos non autorisé (essayez Mac/Windows dans ⚙)\n'
                            '    - HIP refusé (vérifiez profil HIP dans ⚙)\n'
                            '    - session SAML expirée (relancez la connexion)')
                        self._set_state('error',
                                        error_msg='Cookie rejeté par le gateway')
                    else:
                        self._set_state('error', error_msg='Connexion interrompue')

        except Exception as e:
            self._log(f'Erreur openconnect : {e}')
            self._set_state('error', error_msg=str(e)[:60])
        finally:
            if self._hip_wrapper_tmp:
                try:
                    os.unlink(self._hip_wrapper_tmp)
                except Exception:
                    pass
                self._hip_wrapper_tmp = None

    # ── Utilitaires ────────────────────────────────────────────────────────

    def _on_copy_logs(self, _btn):
        """Copie le contenu du journal dans le presse-papier."""
        text = self.log_buf.get_text(
            self.log_buf.get_start_iter(),
            self.log_buf.get_end_iter(),
            False,
        )
        clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        clipboard.set_text(text, -1)
        self._show_msg('Logs copiés dans le presse-papier ✔', Gtk.MessageType.INFO)

    def _on_setup_sudo(self, _btn):
        """Configure sudoers pour openconnect + resolvectl (via pkexec)."""
        oc_ok = can_sudo_openconnect()
        rc_ok = can_sudo_resolvectl()
        if oc_ok and rc_ok:
            self._show_msg(
                'Permissions sudo déjà configurées ✔\n'
                '  - openconnect : OK\n'
                '  - resolvectl : OK',
                Gtk.MessageType.INFO)
            return

        missing = []
        if not oc_ok:
            missing.append('openconnect')
        if not rc_ok:
            missing.append('resolvectl')

        dlg = Gtk.MessageDialog(
            parent=self, flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text='Autorisation sudo requise',
        )
        dlg.format_secondary_text(
            'GP Connect doit exécuter certaines commandes en sudo non-interactif.\n\n'
            f'Commandes manquantes actuellement : {", ".join(missing)}\n\n'
            'Cliquez sur "Oui" pour ouvrir le dialogue d\'authentification GNOME '
            f'et créer la règle sudoers :\n{SUDOERS_FILE}')
        response = dlg.run()
        dlg.destroy()

        if response != Gtk.ResponseType.YES:
            return

        self._log('Configuration sudoers via pkexec…')
        threading.Thread(target=self._run_sudo_setup, daemon=True).start()

    def _run_sudo_setup(self):
        ok = setup_sudoers_rule()
        if ok:
            self._dns_auth_warned = False
            self._log(
                '✔ Règle sudoers créée — openconnect/resolvectl sans mot de passe.')
            GLib.idle_add(self._show_msg,
                          'Configuration réussie !\n'
                          'openconnect et resolvectl peuvent maintenant s\'exécuter '
                          'sans mot de passe sudo.',
                          Gtk.MessageType.INFO)
        else:
            self._log('✘ Échec de la configuration sudoers.')
            GLib.idle_add(self._show_msg,
                          'Échec de la configuration.\n'
                          'Vous pouvez également l\'ajouter manuellement :\n\n'
                          f'sudo visudo -f {SUDOERS_FILE}',
                          Gtk.MessageType.ERROR)

    def _on_remove_sudo(self, _btn):
        """Supprime la règle sudoers GP Connect (retour état Ubuntu par défaut)."""
        dlg = Gtk.MessageDialog(
            parent=self, flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text='Supprimer la configuration sudo ?',
        )
        dlg.format_secondary_text(
            'Cette action supprime la règle :\n'
            f'{SUDOERS_FILE}\n\n'
            'Conséquence : GP Connect redemandera une configuration sudo '
            'avant de pouvoir se connecter.')
        response = dlg.run()
        dlg.destroy()

        if response != Gtk.ResponseType.YES:
            return

        self._log('Suppression de la règle sudoers via pkexec…')
        threading.Thread(target=self._run_sudo_remove, daemon=True).start()

    def _run_sudo_remove(self):
        ok = remove_sudoers_rule()
        if ok:
            self._dns_auth_warned = False
            self._startup_sudo_checked = False
            self._log('✔ Règle sudoers supprimée (retour configuration Ubuntu).')
            GLib.idle_add(
                self._show_msg,
                'Configuration sudo supprimée.\n'
                'Ubuntu est revenu à son comportement par défaut.',
                Gtk.MessageType.INFO)
        else:
            self._log('✘ Échec de suppression de la règle sudoers.')
            GLib.idle_add(
                self._show_msg,
                'Impossible de supprimer la configuration sudo.\n'
                f'Vous pouvez le faire manuellement : sudo rm -f {SUDOERS_FILE}',
                Gtk.MessageType.ERROR)

    def _ensure_sudo_openconnect(self):
        """Vérifie sudo avant connexion, propose la config si nécessaire. Retourne True si OK."""
        if can_sudo_openconnect():
            return True

        # Proposer la configuration graphique
        GLib.idle_add(self._prompt_sudo_setup)
        return False

    def _check_sudo_setup_on_startup(self):
        """Au lancement, propose la config sudo si incomplète."""
        if self._startup_sudo_checked:
            return False
        self._startup_sudo_checked = True

        if can_sudo_all_required():
            return False
        # Ne pas interrompre une session déjà connectée détectée au démarrage.
        if self.state == 'connected':
            return False
        GLib.idle_add(self._prompt_sudo_setup, True)
        return False

    def _prompt_sudo_setup(self, startup=False):
        dlg = Gtk.MessageDialog(
            parent=self, flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE,
            text='Configuration sudo requise',
        )
        dlg.format_secondary_text(
            'GP Connect a besoin des permissions sudo non-interactives pour:\n'
            ' - openconnect\n'
            ' - resolvectl\n\n'
            'Cliquez sur "Configurer" pour appliquer la règle automatiquement '
            '(une seule fois nécessaire).')
        dlg.add_button('Annuler',    Gtk.ResponseType.CANCEL)
        dlg.add_button('Configurer', Gtk.ResponseType.OK)
        dlg.set_default_response(Gtk.ResponseType.OK)
        response = dlg.run()
        dlg.destroy()

        if response == Gtk.ResponseType.OK:
            self._on_setup_sudo(None)
        elif not startup:
            self._set_state('disconnected')
        return False

    def _show_msg(self, message, msg_type=Gtk.MessageType.INFO):
        dlg = Gtk.MessageDialog(
            parent=self, flags=Gtk.DialogFlags.MODAL,
            type=msg_type, buttons=Gtk.ButtonsType.OK,
            message_format=message,
        )
        dlg.run()
        dlg.destroy()


# ─────────────────────────────────────────────
#  Application GNOME
# ─────────────────────────────────────────────

class GPConnectApp(Gtk.Application):
    def __init__(self):
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )

    def do_activate(self):
        wins = self.get_windows()
        if wins:
            if hasattr(wins[0], 'clear_logs'):
                wins[0].clear_logs()
            wins[0].present()
            return
        win = MainWindow(self)
        win.clear_logs()
        win.show_all()
        win.present()


def main():
    app = GPConnectApp()
    app.run(None)


if __name__ == '__main__':
    main()
