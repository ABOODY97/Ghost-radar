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


from config import *

def sanitize_text(value, max_len=200):
    """ينظف أي نص قادم من مصدر خارجي قبل عرضه أو حفظه:
    يزيل تسلسلات ANSI/تحكم الطرفية ويحده بطول آمن."""
    if value is None:
        return ""
    text = str(value)
    text = text.replace('\x1b', '').replace('\u009b', '')
    text = ''.join(ch for ch in text if unicodedata.category(ch) not in ('Cc', 'Cf') or ch in '\t')
    text = re.sub(r'[\x00-\x1f\x7f]', '', text)
    return text[:max_len]

_DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(\.[A-Za-z0-9_-]{1,63})*\.?[A-Za-z]{2,63}$')

def validate_domain(raw):
    """يتحقق من أن المدخل دومين/هوست صالح (يمنع URL injection والحقن)."""
    if not raw:
        return None
    host = raw.strip().lower()
    if '://' in host:
        parsed = urlparse(host)
        host = parsed.hostname or ''
    host = host.split('/')[0].split(':')[0].strip('.')
    if not host or len(host) > 253:
        return None
    if _DOMAIN_RE.match(host) or _is_safe_ip(host):
        return host
    return None

def _is_safe_ip(value):
    """يتحقق أن القيمة عنوان IP صالح (IPv4/IPv6) دون أي رموز إضافية."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def validate_cidr(raw):
    """يتحقق أن المدخل نطاق شبكة صغير ومعقول قبل إرساله لـ Scapy."""
    if not raw:
        return None
    try:
        network = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        return None
    if not isinstance(network, ipaddress.IPv4Network) or network.num_addresses > 65536:
        return None
    return str(network)

def parse_port_input(raw):
    """يحلل مدخلات المستخدم لنطاق المنافذ"""
    ports = set()
    raw = raw.strip()
    if not raw:
        return None
    try:
        for part in raw.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                s, e = part.split('-')
                s, e = int(s.strip()), int(e.strip())
                s = max(1, s)
                e = min(65535, e)
                if s > e:
                    s, e = e, s
                ports.update(range(s, e + 1))
            elif part.isdigit():
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
    except ValueError:
        return None
    return sorted(ports) if ports else None

