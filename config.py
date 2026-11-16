import scapy.all as scapy
import requests
import time
import socket
import concurrent.futures
import sys
import os
import json
import ssl
import datetime
import ipaddress
import zlib
import html
import re
import unicodedata
import random
import base64
import binascii
import hashlib
import hmac
import uuid
from urllib.parse import urlparse

# ويندوز: الطرفية افتراضياً cp1252/cp437 فتنهار الطباعة عند أول حرف عربي أو
# إطار Unicode؛ نعيد ضبط stdout/stderr على UTF-8 قبل أي طباعة.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError, OSError):
        pass
os.environ.setdefault('PYTHONIOENCODING', 'utf-8')
try:
    if os.name == 'nt':
        os.system('')  # يفعّل معالجة ANSI VT في console ويندوز (ألوان واضحة بدل أكواد)
except OSError:
    pass

from arabic_tools import fix_ar

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ---------------- طبقة تشفير البيانات الحساسة (IP الجهاز، السجلات) ----------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:  # احتياطي: نستخدم AES-GCM إن توفرت، وإلا نمنع التخزين الصريح
    AESGCM = None
    CRYPTO_AVAILABLE = False



VAULT_PREFIX = b"GRV1"
VAULT_FILE = os.path.expanduser("~/.ghost_radar/vault.key")


NO_EXTERNAL = os.environ.get('GHOST_NO_EXTERNAL', '0').strip() in ('1', 'true', 'yes')
GHOST_PROXY = os.environ.get('GHOST_PROXY', '').strip()

_SESSION = requests.Session()
if GHOST_PROXY:
    _SESSION.proxies.update({'http': GHOST_PROXY, 'https': GHOST_PROXY})
_SESSION.trust_env = not GHOST_PROXY

# مساحة الأسماء المحلية لا تُرسل لخدمات خارجية أبداً (تمنع كوكيعة/تسريب الشبكة)
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
    '169.254.0.0/16', '100.64.0.0/10', '::1/128', 'fc00::/7', 'fe80::/10')]

GREEN = '\033[92m'
RED = '\033[91m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# ---------------- نظام اللغات الداخلي الاحتياطي (ar / en / tr) ----------------
SESSION_DATA = {
    "started_at": datetime.datetime.now().isoformat(),
    "network_scans": [],
    "website_scans": [],
    "port_scans": []
}

HISTORY_FILE = "ghost_radar_history.json"

# ---------------- الدوال الاستخباراتية ----------------

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "SMB", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP"
}

EXTENDED_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPCBind", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 194: "IRC", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD",
    587: "SMTP-Submission", 631: "IPP", 636: "LDAPS", 873: "Rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel-SSL", 2181: "Zookeeper", 2222: "SSH-Alt",
    3000: "Dev-Server", 3128: "Squid-Proxy", 3306: "MySQL", 3389: "RDP",
    5000: "UPnP/Flask", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6660: "IRC", 6666: "IRC", 6667: "IRC", 7001: "WebLogic",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9000: "PHP-FPM/Portainer", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB", 50000: "SAP"
}

MAX_CUSTOM_PORTS = 5000

