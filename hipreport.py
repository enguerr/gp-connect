#!/usr/bin/env python3
"""
GP Connect - Script de rapport HIP (Host Information Profile)
Pour GlobalProtect / Palo Alto

Appelé automatiquement par openconnect via --csd-wrapper :
    hipreport.py --cookie COOKIE --client-ip IP --md5 MD5
                 --computer HOSTNAME --gateway GATEWAY [--client-ipv6 IPV6]

Le script :
  1. Collecte les informations système (OS, interfaces, pare-feu, chiffrement…)
  2. Génère un rapport XML au format GlobalProtect HIP v4
  3. Le soumet à https://GATEWAY/ssl-vpn/hipreport.esp

Sans ce rapport, le gateway peut limiter la connectivité VPN.
"""

import sys
import os
import socket
import uuid
import json
import subprocess
import urllib.parse
from datetime import datetime


# ─────────────────────────────────────────────
#  Lecture des arguments openconnect
# ─────────────────────────────────────────────

def parse_args(argv):
    args = {}
    i = 1
    while i < len(argv):
        if argv[i].startswith('--') and i + 1 < len(argv):
            args[argv[i][2:]] = argv[i + 1]
            i += 2
        else:
            i += 1
    return args


# ─────────────────────────────────────────────
#  Collecte d'informations système
# ─────────────────────────────────────────────

def get_os_info():
    """Retourne (nom_os, version, kernel)."""
    os_name = 'Ubuntu'
    os_version = '22.04'
    kernel = '6.0.0'
    try:
        with open('/etc/os-release') as f:
            for line in f:
                if line.startswith('NAME='):
                    os_name = line.split('=', 1)[1].strip().strip('"')
                elif line.startswith('VERSION_ID='):
                    os_version = line.split('=', 1)[1].strip().strip('"')
    except Exception:
        pass
    try:
        kernel = subprocess.check_output(
            ['uname', '-r'], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        pass
    return os_name, os_version, kernel


def get_machine_id():
    """Retourne l'identifiant unique de la machine (UUID).

    Priorité (alignée sur le comportement de GlobalProtect Windows) :
      1. UUID DMI/SMBIOS — `/sys/class/dmi/id/product_uuid`
         Format natif : 4c4c4544-004a-5710-8053-c8c04f383734
         C'est le `host-id` que voit la console Palo Alto (cf. logs
         "gateway-hip-check" → colonne HOST ID).
         Lecture root-only ; OK car hipreport.py est invoqué par
         openconnect via sudo.
      2. dmidecode -s system-uuid    (fallback si /sys non lisible)
      3. /etc/machine-id              (UUID stable mais != SMBIOS)
      4. /var/lib/dbus/machine-id
      5. UUID aléatoire               (dernier recours)
    """
    # 1) DMI / SMBIOS (idéal — c'est ce que Palo Alto attend)
    try:
        with open('/sys/class/dmi/id/product_uuid') as f:
            mid = f.read().strip().lower()
        # Format attendu : 8-4-4-4-12 hex
        if len(mid) == 36 and mid.count('-') == 4:
            return mid
    except Exception:
        pass

    # 2) dmidecode (souvent dispo, nécessite root)
    try:
        out = subprocess.check_output(
            ['dmidecode', '-s', 'system-uuid'],
            text=True, stderr=subprocess.DEVNULL, timeout=3).strip().lower()
        if len(out) == 36 and out.count('-') == 4:
            return out
    except Exception:
        pass

    # 3-4) machine-id (32 hex sans tirets → reformaté)
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path) as f:
                mid = f.read().strip().lower()
            if len(mid) == 32:
                return (f'{mid[:8]}-{mid[8:12]}-{mid[12:16]}'
                        f'-{mid[16:20]}-{mid[20:]}')
            if len(mid) == 36:
                return mid
        except Exception:
            pass

    # 5) Dernier recours — aléatoire (changera à chaque exécution !)
    return str(uuid.uuid4())


def get_interfaces(client_ip):
    """Retourne la liste des interfaces réseau (max 4)."""
    interfaces = []
    try:
        out = subprocess.check_output(
            ['ip', '-o', 'link', 'show'],
            text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[1].rstrip(':').split('@')[0]
            if name == 'lo':
                continue
            mac = '00:00:00:00:00:00'
            if 'link/ether' in line:
                idx = parts.index('link/ether')
                mac = parts[idx + 1]
            interfaces.append({'name': name, 'mac': mac})
    except Exception:
        interfaces = [{'name': 'eth0', 'mac': '00:00:00:00:00:00'}]
    return interfaces[:4]


def check_trend_micro():
    """Détecte Trend Micro Deep Security Agent sur Linux.

    Retourne (installé, version, vendor, product, real_time_protection,
              last_scan_time, defver) ou (False, ...) si absent.

    Trend Micro Deep Security Agent (DSA) sur Linux s'installe dans
    /opt/ds_agent/ et expose les binaires :
      - /opt/ds_agent/dsa_query   : interroge l'état du composant
      - /opt/ds_agent/sendCommand : envoi de commandes
    Le service systemd est 'ds_agent'.
    """
    install_dir   = '/opt/ds_agent'
    dsa_query     = '/opt/ds_agent/dsa_query'
    sendCmd       = '/opt/ds_agent/sendCommand'
    service_name  = 'ds_agent'

    installed = (
        os.path.isdir(install_dir)
        and (os.path.isfile(dsa_query) or os.path.isfile(sendCmd))
    )
    if not installed:
        return False, '', '', '', False, '', ''

    version = '20.0.0.0000'
    real_time = True   # le composant Anti-Malware DSA tourne en RT par défaut
    defver = datetime.now().strftime('%Y%m%d')
    last_scan = datetime.now().strftime('%m/%d/%Y %H:%M:%S')

    # 1) Version via dsa_query
    try:
        out = subprocess.check_output(
            [dsa_query, '-c', 'GetAgentStatus'],
            text=True, stderr=subprocess.DEVNULL, timeout=5)
        for line in out.splitlines():
            ln = line.strip()
            if ln.lower().startswith('component.am.version'):
                version = ln.split(':', 1)[1].strip() or version
            elif ln.lower().startswith('component.am.mode'):
                # mode "on"/"prevent" => protection temps réel active
                mode = ln.split(':', 1)[1].strip().lower()
                real_time = mode not in ('', 'off', 'disabled', 'detect')
            elif ln.lower().startswith('component.am.signatureversion'):
                v = ln.split(':', 1)[1].strip()
                if v and v.lower() != 'none':
                    defver = v
            elif ln.lower().startswith('component.am.lastscan'):
                v = ln.split(':', 1)[1].strip()
                if v and v.lower() != 'none':
                    last_scan = v
    except Exception:
        pass

    # 2) Fallback version : /opt/ds_agent/Version.txt
    if version == '20.0.0.0000':
        for p in ('/opt/ds_agent/Version.txt',
                  '/opt/ds_agent/version.txt',
                  '/opt/ds_agent/lib/version.txt'):
            try:
                with open(p) as f:
                    v = f.read().strip()
                if v:
                    version = v.splitlines()[0].strip()
                    break
            except Exception:
                pass

    # 3) Vérifier que le service tourne — sinon "Is Installed" reste yes
    #    mais on coupe real-time-protection si le daemon est down.
    try:
        rc = subprocess.run(
            ['systemctl', 'is-active', '--quiet', service_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        if rc != 0:
            real_time = False
    except Exception:
        pass

    return (True, version,
            'Trend Micro, Inc.',
            'Trend Micro Deep Security Agent',
            real_time, last_scan, defver)


def check_clamav():
    """Retourne (installé, version, date_def)."""
    for cmd in (['clamscan', '--version'], ['clamdscan', '--version']):
        try:
            out = subprocess.check_output(
                cmd, text=True, stderr=subprocess.DEVNULL)
            version = out.split()[1] if len(out.split()) > 1 else '1.0.0'
            # Tenter de lire la date de définition
            defver = datetime.now().strftime('%Y%m%d')
            try:
                db_out = subprocess.check_output(
                    ['freshclam', '--version'],
                    text=True, stderr=subprocess.DEVNULL)
                # Format: ClamAV 1.0.0/26xxx/Mon Jan 1 00:00:00 2024
                if '/' in db_out:
                    parts = db_out.split('/')
                    if len(parts) > 2:
                        defver = parts[1].strip()
            except Exception:
                pass
            return True, version, defver
        except Exception:
            pass
    return False, '', ''


def check_antimalware():
    """Détection AV unifiée. Priorité : Trend Micro DSA > ClamAV.

    Retourne dict :
      {
        'installed': bool,
        'vendor':    'Trend Micro, Inc.' | 'ClamAV Project' | '',
        'product':   'Trend Micro Deep Security Agent' | 'ClamAV ...' | '',
        'version':   str,
        'defver':    str,
        'real_time': bool,
        'last_scan': str (mm/dd/yyyy HH:MM:SS),
      }
    """
    (tm_ok, tm_ver, tm_vendor, tm_prod,
     tm_rt, tm_scan, tm_def) = check_trend_micro()
    if tm_ok:
        return {
            'installed': True,
            'vendor':    tm_vendor,
            'product':   tm_prod,
            'version':   tm_ver,
            'defver':    tm_def,
            'real_time': tm_rt,
            'last_scan': tm_scan,
        }
    cl_ok, cl_ver, cl_def = check_clamav()
    if cl_ok:
        return {
            'installed': True,
            'vendor':    'ClamAV Project',
            'product':   f'ClamAV {cl_ver}',
            'version':   cl_ver,
            'defver':    cl_def or datetime.now().strftime('%Y%m%d'),
            'real_time': False,
            'last_scan': datetime.now().strftime('%m/%d/%Y %H:%M:%S'),
        }
    return {
        'installed': False, 'vendor': '', 'product': '',
        'version': '', 'defver': '', 'real_time': False, 'last_scan': '',
    }


def check_firewall():
    """Retourne (actif, nom). Teste ufw puis iptables."""
    # UFW
    try:
        out = subprocess.check_output(
            ['ufw', 'status'], text=True, stderr=subprocess.DEVNULL)
        if 'active' in out.lower():
            return True, 'UFW'
    except Exception:
        pass
    # iptables (vérifie si des règles non-vides existent)
    try:
        out = subprocess.check_output(
            ['iptables', '-L', '--line-numbers'],
            text=True, stderr=subprocess.DEVNULL)
        if len(out.strip().splitlines()) > 10:
            return True, 'iptables'
    except Exception:
        pass
    return False, 'iptables'


def check_disk_encryption():
    """Retourne True si un volume LUKS est détecté."""
    try:
        out = subprocess.check_output(
            ['lsblk', '-o', 'NAME,TYPE'],
            text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if 'crypt' in line:
                return True
    except Exception:
        pass
    return False


def check_disk_backup():
    """Retourne True si timeshift ou rsync-backup est configuré."""
    for tool in ('timeshift', 'rsnapshot', 'restic'):
        if subprocess.run(['which', tool], capture_output=True).returncode == 0:
            return True, tool
    return False, ''


# ─────────────────────────────────────────────
#  Construction du rapport HIP XML
# ─────────────────────────────────────────────

def _xml_escape(s):
    return (str(s)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;'))


def build_hip_report(cookie, client_ip, md5, computer, gateway,
                     username='', ipv6='', fake_overrides=None):
    now      = datetime.now().strftime('%m/%d/%Y %H:%M:%S')
    host_id  = get_machine_id()

    # Valeurs OS (utilisées par le filtre Palo Alto "Host Info → OS")
    os_name, os_version, kernel = get_os_info()

    if fake_overrides is not None:
        hostname   = _xml_escape(
            fake_overrides.get('hostname') or computer or socket.gethostname())
        av_installed = fake_overrides.get('antivirus', True)
        av_vendor  = fake_overrides.get('antivirus_vendor', 'Trend Micro, Inc.')
        av_product = fake_overrides.get('antivirus_name',
                                        'Trend Micro Deep Security Agent')
        av_ver     = fake_overrides.get('antivirus_version', '20.0.0.0000')
        av_def     = fake_overrides.get('antivirus_defver',
                                        datetime.now().strftime('%Y%m%d'))
        av_rt      = fake_overrides.get('antivirus_real_time', True)
        av_scan    = fake_overrides.get('antivirus_last_scan', now)
        fw_active  = fake_overrides.get('firewall', True)
        fw_name    = fake_overrides.get('firewall_name', 'UFW')
        has_luks   = fake_overrides.get('encryption', True)
        has_mdm    = fake_overrides.get('mdm', True)
        mdm_name   = fake_overrides.get('mdm_name', 'Microsoft Intune')
        has_backup = fake_overrides.get('backup', False)
        bk_name    = fake_overrides.get('backup_name', 'timeshift')
        interfaces = [{'name': 'eth0', 'mac': '00:00:00:00:00:00'}]
        # Le filtre Palo Alto "OS Contains Linux" lit la valeur <os>
        os_label   = fake_overrides.get(
            'os_label', f'Linux {os_name} {os_version}')
        os_vendor  = fake_overrides.get('os_vendor', 'Linux')
        print('[HIP] Mode FAKE — valeurs simulées utilisées.', file=sys.stderr)
    else:
        hostname = _xml_escape(computer or socket.gethostname())
        av = check_antimalware()
        av_installed = av['installed']
        av_vendor    = av['vendor']
        av_product   = av['product']
        av_ver       = av['version']
        av_def       = av['defver']
        av_rt        = av['real_time']
        av_scan      = av['last_scan'] or now
        fw_active, fw_name     = check_firewall()
        has_luks               = check_disk_encryption()
        has_mdm, mdm_name      = False, ''
        has_backup, bk_name    = check_disk_backup()
        interfaces             = get_interfaces(client_ip)
        os_label  = f'Linux {os_name} {os_version}'
        os_vendor = 'Linux'

    # ── Interfaces réseau ──────────────────
    ifaces_xml = ''
    for ifc in interfaces:
        ifaces_xml += f'''    <entry name="{_xml_escape(ifc['name'])}">
      <description>{_xml_escape(ifc['name'])}</description>
      <mac-address>{_xml_escape(ifc['mac'])}</mac-address>
      <ip-address>
        <entry name="{_xml_escape(client_ip)}"/>
      </ip-address>
    </entry>\n'''

    # ── Anti-Malware ───────────────────────
    # Syntaxe simplifiée Palo Alto HIP (cf. exemple officiel) :
    #   <vendor>...</vendor>
    #   <name>...</name>
    #   <product-version>...</product-version>
    #   <real-time-protection>yes|no</real-time-protection>
    #   <definition-version>...</definition-version>
    #   <last-scan-time>MM/DD/YYYY HH:MM:SS</last-scan-time>
    # Vendor + Name matchent le HIP Object Anti-Malware (Vendor / Product).
    if av_installed:
        defver = av_def or datetime.now().strftime('%Y%m%d')
        rt_str = 'yes' if av_rt else 'no'
        am_list = f'''      <list>
        <entry>
          <vendor>{_xml_escape(av_vendor)}</vendor>
          <name>{_xml_escape(av_product)}</name>
          <product-version>{_xml_escape(av_ver)}</product-version>
          <real-time-protection>{rt_str}</real-time-protection>
          <definition-version>{_xml_escape(defver)}</definition-version>
          <last-scan-time>{_xml_escape(av_scan)}</last-scan-time>
        </entry>
      </list>'''
    else:
        am_list = '      <list/>'

    # ── Host Info (OS / host-name / host-id / interfaces) ──────────────────
    # Reproduit la structure attendue par PAN-OS / GP Windows :
    #   client-version → os → os-vendor → domain → host-name → host-id
    #   → network-interface[…]
    # Le <host-id> et <host-name> apparaissent ICI (dans host-info) en plus
    # du top-level — c'est ce qui alimente les colonnes HOST ID / HOST NAME
    # de la console Palo Alto (cf. screenshot gateway-hip-check).
    host_info_xml = f'''      <client-version>6.0.0-1</client-version>
      <os>{_xml_escape(os_label)}</os>
      <os-vendor>{_xml_escape(os_vendor)}</os-vendor>
      <domain></domain>
      <host-name>{hostname}</host-name>
      <host-id>{_xml_escape(host_id)}</host-id>
      <network-interface>
{ifaces_xml}      </network-interface>'''

    # ── Pare-feu (syntaxe simplifiée : name + status) ──────────────────────
    fw_state = 'yes' if fw_active else 'no'
    fw_list  = f'''      <list>
        <entry>
          <name>{_xml_escape(fw_name)}</name>
          <status>{fw_state}</status>
        </entry>
      </list>'''

    # ── Chiffrement disque (cf. exemple officiel : name + status) ──────────
    if has_luks:
        enc_list = '''      <list>
        <entry>
          <name>LUKS</name>
          <status>yes</status>
        </entry>
      </list>'''
    else:
        enc_list = '      <list/>'

    # ── Sauvegarde ────────────────────────
    if has_backup:
        bk_list = f'''      <list>
        <entry>
          <name>{_xml_escape(bk_name)}</name>
          <status>yes</status>
        </entry>
      </list>'''
    else:
        bk_list = '      <list/>'

    # ── MDM ────────────────────────────────
    if has_mdm:
        mdm_list = f'''      <list>
        <entry>
          <name>{_xml_escape(mdm_name)}</name>
          <status>yes</status>
        </entry>
      </list>'''
    else:
        mdm_list = '      <list/>'

    # ── Assemblage final ──────────────────────────────────────────────────
    # Format aligné sur la doc Palo Alto fournie :
    #   • <hip-report> SANS attribut name="..."
    #   • Déclaration XML (encoding UTF-8)
    #   • Ordre canonique : md5-sum → user-name → domain → host-name → host-id
    #                      → ip-address → ipv6-address → generate-time
    #                      → hip-report-version → categories
    #   • Catégories en MINUSCULES avec tirets
    #   • Antivirus émis sous "antivirus" ET "anti-malware" (compat PAN-OS)
    report = f"""<?xml version="1.0" encoding="UTF-8"?>
<hip-report>
  <md5-sum>{_xml_escape(md5)}</md5-sum>
  <user-name>{_xml_escape(username)}</user-name>
  <domain></domain>
  <host-name>{hostname}</host-name>
  <host-id>{_xml_escape(host_id)}</host-id>
  <ip-address>{_xml_escape(client_ip)}</ip-address>
  <ipv6-address>{_xml_escape(ipv6)}</ipv6-address>
  <generate-time>{now}</generate-time>
  <hip-report-version>4</hip-report-version>
  <categories>
    <entry name="host-info">
{host_info_xml}
    </entry>
    <entry name="antivirus">
{am_list}
    </entry>
    <entry name="anti-malware">
{am_list}
    </entry>
    <entry name="disk-backup">
{bk_list}
    </entry>
    <entry name="disk-encryption">
{enc_list}
    </entry>
    <entry name="firewall">
{fw_list}
    </entry>
    <entry name="patch-management">
      <list/>
    </entry>
    <entry name="data-loss-prevention">
      <list/>
    </entry>
    <entry name="mobile-device-management">
{mdm_list}
    </entry>
  </categories>
</hip-report>"""
    return report


# ─────────────────────────────────────────────
#  Point d'entrée
# ─────────────────────────────────────────────

def parse_cookie_fields(cookie_str):
    """Parse l'authcookie URL-encodé retourné par openconnect.

    Format : authcookie=...&portal=...&user=...&domain=...&computer=...
    """
    import urllib.parse
    fields = {}
    for part in cookie_str.split('&'):
        if '=' in part:
            k, _, v = part.partition('=')
            fields[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
    return fields


def get_user_config():
    """Lit la config GP Connect même quand le script tourne en root (sudo).

    sudo ne change pas HOME mais SUDO_USER contient l'utilisateur d'origine.
    """
    import pwd
    sudo_user = os.environ.get('SUDO_USER', '')
    if sudo_user:
        try:
            home = pwd.getpwnam(sudo_user).pw_dir
            path = os.path.join(home, '.config', 'gp-connect', 'config.json')
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    # Fallback : répertoire courant
    try:
        path = os.path.expanduser('~/.config/gp-connect/config.json')
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def save_session_context(ctx, path='/tmp/.gp-current-authcookie'):
    """Sauvegarde le contexte de session (authcookie, gateway, etc.)
    dans un fichier 0600.

    Permet au "Diag HIP" de re-soumettre le rapport via la session
    courante sans devoir extraire les credentials d'openconnect.
    Le fichier est écrit par root (sudo) ; le fallback _on_diagnose_hip
    le lit aussi en root via l'option helper.
    """
    try:
        # Écriture atomique : tmp + rename, et chmod 0600
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(ctx, f, indent=2)
        os.chmod(tmp, 0o600)
        os.rename(tmp, path)
        # Lisible aussi par le user d'origine (sudo) pour que
        # gp_connect.py puisse le relire sans sudo.
        sudo_user = os.environ.get('SUDO_USER', '')
        if sudo_user:
            try:
                import pwd
                pw = pwd.getpwnam(sudo_user)
                os.chown(path, pw.pw_uid, pw.pw_gid)
            except Exception:
                pass
        print(f'[HIP] ✔ Contexte session sauvegardé → {path}',
              file=sys.stderr)
    except Exception as e:
        print(f'[HIP] ⚠ Impossible de sauvegarder le contexte : {e}',
              file=sys.stderr)


def _flatten_gp_cookie_form(cookie_str, client_ip=None, report_xml=None):
    """Champs POST plats ssl-vpn/* (comme openconnect, pas cookie=…)."""
    fields = {'client-role': 'global-protect-full'}
    for part in (cookie_str or '').split('&'):
        if '=' in part:
            k, _, v = part.partition('=')
            fields[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
    if client_ip:
        fields['client-ip'] = client_ip
    if report_xml is not None:
        fields['report'] = report_xml
    return fields


def verify_post_to_gateway(server, cookie_str, client_ip, computer,
                           report_xml, verify=False):
    """POST direct du rapport HIP au gateway et capture la réponse brute.

    Utilisé uniquement quand GP_HIP_VERIFY_POST=1 est défini : permet
    d'obtenir le body de la réponse PAN-OS (souvent absent des logs
    d'openconnect, qui ne fait que "HIP report submission failed" sans
    le contenu XML d'erreur).

    NB : ce POST est en plus de celui d'openconnect — PAN-OS écrase
    juste l'ancien rapport, donc pas d'effet de bord. Utile pour
    capturer un éventuel <response status="error"><msg>...</msg></response>.
    """
    if not server:
        print('[HIP] verify-post : server inconnu — skip.', file=sys.stderr)
        return
    try:
        import ssl
        import urllib.request
        url = f'https://{server}/ssl-vpn/hipreport.esp'
        data = urllib.parse.urlencode(
            _flatten_gp_cookie_form(cookie_str, client_ip=client_ip,
                                    report_xml=report_xml)
        ).encode('utf-8')
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url, data=data, method='POST',
            headers={'User-Agent': 'PAN GlobalProtect',
                     'Content-Type': 'application/x-www-form-urlencoded'})
        print(f'[HIP] verify-post → POST {url} ({len(data)} octets)',
              file=sys.stderr)
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            print(f'[HIP] verify-post HTTP {resp.status} '
                  f'({len(body)} octets) :', file=sys.stderr)
            for ln in body.splitlines():
                print(f'[HIP] verify-post   {ln}', file=sys.stderr)
    except Exception as e:
        print(f'[HIP] verify-post ⚠ erreur : {e}', file=sys.stderr)


def main():
    # ── Debug : afficher les arguments reçus ────────────────────────────
    print(f'[HIP] Args reçus : {sys.argv[1:]}', file=sys.stderr)

    args      = parse_args(sys.argv)
    cookie    = args.get('cookie', '')
    client_ip = args.get('client-ip', '')
    md5       = args.get('md5', '')
    ipv6      = args.get('client-ipv6', '')
    gateway   = args.get('gateway', '')
    # openconnect v9 passe --client-os au lieu de --computer
    client_os = args.get('client-os', 'Mac')

    # ── Extraire user et computer depuis le cookie URL-encodé ───────────
    # Format : authcookie=...&portal=...&user=...&computer=...
    cookie_fields = parse_cookie_fields(cookie)
    username = cookie_fields.get('user', '')
    computer = (args.get('computer', '')          # présent dans certaines versions
                or cookie_fields.get('computer', '')
                or socket.gethostname())

    # Compléter avec la config si nécessaire
    cfg = get_user_config()
    if not username:
        username = cfg.get('last_username', '')

    print(f'[HIP] Génération du rapport HIP', file=sys.stderr)
    print(f'[HIP]   IP client   : {client_ip}', file=sys.stderr)
    print(f'[HIP]   MD5 attendu : {md5}', file=sys.stderr)
    print(f'[HIP]   Utilisateur : {username}', file=sys.stderr)
    print(f'[HIP]   Ordinateur  : {computer}', file=sys.stderr)
    print(f'[HIP]   Gateway     : {gateway or "(non transmis)"}',
          file=sys.stderr)

    # ── Sauvegarder le contexte pour le bouton "Diag HIP" en mode tunnel ─
    # Permet à gp_connect.py de re-soumettre le rapport HIP à la passerelle
    # avec l'authcookie courant, sans avoir à le ré-extraire d'openconnect.
    ctx_path = os.environ.get('GP_HIP_CONTEXT_FILE',
                              '/tmp/.gp-current-authcookie')
    save_session_context({
        'cookie':     cookie,
        'authcookie': cookie_fields.get('authcookie', ''),
        'portal':     cookie_fields.get('portal', ''),
        'user':       username,
        'domain':     cookie_fields.get('domain', ''),
        'computer':   computer,
        'client_ip':  client_ip,
        'client_ipv6': ipv6,
        'md5':        md5,
        'gateway':    gateway,
        'client_os':  client_os,
        'saved_at':   datetime.now().isoformat(timespec='seconds'),
    }, path=ctx_path)

    # ── Mode fake : template ou valeurs simulées ────────────────────────
    env_mode      = os.environ.get('GP_HIP_MODE', '')
    template_path = os.environ.get('GP_HIP_TEMPLATE', '')
    hip_mode_cfg  = cfg.get('hip_mode', 'builtin')

    if env_mode == 'fake' and template_path and os.path.isfile(template_path):
        # ── Mode fake avec template XML édité par l'utilisateur ──────────
        print(f'[HIP]   Mode       : FAKE (template : {template_path})',
              file=sys.stderr)
        import re as _re
        with open(template_path) as f:
            report_xml = f.read()
        now = datetime.now().strftime('%m/%d/%Y %H:%M:%S')
        # Mettre à jour les champs dynamiques
        def _upd(tag, val, xml):
            return _re.sub(
                rf'<{tag}>[^<]*</{tag}>',
                f'<{tag}>{val}</{tag}>',
                xml, count=1)
        if client_ip:
            report_xml = _upd('ip-address',    client_ip, report_xml)
        if md5:
            report_xml = _upd('md5-sum',       md5,       report_xml)
        if username:
            report_xml = _upd('user-name',     username,  report_xml)
        report_xml = _upd('generate-time', now, report_xml)
        print(f'[HIP] ✔ Template fake appliqué (ip={client_ip}, md5={md5[:8]}…)',
              file=sys.stderr)
    elif env_mode == 'fake' or hip_mode_cfg == 'fake':
        # ── Mode fake sans template : utiliser les valeurs de la config ──
        # Valeurs par défaut : OS Linux + exemple d'antivirus courant.
        print('[HIP]   Mode       : FAKE (valeurs config)', file=sys.stderr)
        fake_overrides = {
            'hostname':            cfg.get('hip_fake_hostname', ''),
            'os_label':            cfg.get('hip_fake_os_label', ''),
            'os_vendor':           cfg.get('hip_fake_os_vendor', 'Linux'),
            'firewall':            cfg.get('hip_fake_firewall', False),
            'firewall_name':       cfg.get('hip_fake_firewall_name', 'UFW'),
            'antivirus':           cfg.get('hip_fake_antivirus', True),
            'antivirus_vendor':    cfg.get('hip_fake_antivirus_vendor',
                                           'Trend Micro, Inc.'),
            'antivirus_name':      cfg.get('hip_fake_antivirus_name',
                                           'Trend Micro Deep Security Agent'),
            'antivirus_version':   cfg.get('hip_fake_antivirus_version',
                                           '20.0.0.0000'),
            'antivirus_defver':    cfg.get('hip_fake_antivirus_defver',
                                           datetime.now().strftime('%Y%m%d')),
            'antivirus_real_time': cfg.get('hip_fake_antivirus_real_time', True),
            'antivirus_last_scan': cfg.get('hip_fake_antivirus_last_scan',
                                           datetime.now().strftime(
                                               '%m/%d/%Y %H:%M:%S')),
            'encryption':          cfg.get('hip_fake_encryption', True),
            'mdm':                 cfg.get('hip_fake_mdm', True),
            'mdm_name':            cfg.get('hip_fake_mdm_name',
                                           'Microsoft Intune'),
            'backup':              cfg.get('hip_fake_backup', False),
            'backup_name':         cfg.get('hip_fake_backup_name', 'timeshift'),
        }
        # os_label vide => calculé automatiquement depuis /etc/os-release
        if not fake_overrides['os_label']:
            fake_overrides.pop('os_label')
        report_xml = build_hip_report(
            cookie, client_ip, md5, computer, '', username, ipv6,
            fake_overrides=fake_overrides)
    else:
        # ── Mode normal : détection automatique ──────────────────────────
        print(f'[HIP]   Mode       : {hip_mode_cfg}', file=sys.stderr)
        report_xml = build_hip_report(
            cookie, client_ip, md5, computer, '', username, ipv6)

    # ⚠️ Écrire le rapport XML sur stdout → openconnect le soumet au gateway
    print(report_xml)
    sys.stdout.flush()

    print('[HIP] ✔ Rapport HIP généré et transmis à openconnect.', file=sys.stderr)

    # ── POST de vérification (optionnel) ────────────────────────────────
    # Active uniquement si GP_HIP_VERIFY_POST=1 : fait un POST direct au
    # gateway en doublon de celui d'openconnect, pour capturer le body
    # complet de la réponse PAN-OS (logs souvent muets en cas d'échec
    # côté HIP Object matching).
    if os.environ.get('GP_HIP_VERIFY_POST', '') == '1':
        verify_server = (gateway
                         or args.get('server', '')
                         or cookie_fields.get('portal', ''))
        cookie_str = cookie  # déjà URL-encodé tel que reçu d'openconnect
        verify_post_to_gateway(
            verify_server, cookie_str, client_ip, computer, report_xml,
            verify=False)

    sys.exit(0)   # Toujours 0


if __name__ == '__main__':
    main()
