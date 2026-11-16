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

def external_egress_allowed() -> bool:
    """هل يُسمح بالاتصال بالخدمات الخارجية في الجلسة الحالية؟"""
    return not NO_EXTERNAL

def external_lookup_allowed(ip_or_domain: str) -> bool:
    """ينفي إرسال بيانات أنماط الشبكة المحلية إلى qualquer خدمة."""
    if not external_egress_allowed():
        return False
    try:
        if _is_safe_ip(ip_or_domain):
            addr = ipaddress.ip_address(ip_or_domain)
        else:
            host = resolve_host(ip_or_domain)
            if not host:
                return False
            addr = ipaddress.ip_address(host)
        return not any(addr in net for net in _PRIVATE_NETS)
    except (ValueError, RuntimeError, socket.gaierror):
        return False

def external_get(url, **kwargs):
    """GET فقط عبر طبقة التحكم (بروكسي اختياري). يرمي RuntimeError لو منع الخارجي."""
    if not external_egress_allowed():
        raise RuntimeError('external egress disabled')
    kwargs.setdefault('timeout', 6)
    kwargs.setdefault('headers', ghost_headers())
    return _SESSION.get(url, **kwargs)


def resolve_host(host):
    """يحوّل الهوست إلى IPv4 بشكل آمن.
    إن وُجد بروكسي، نستخدم DoH عبر البروكسي (لا يستعلم مزود الإنترنت عن النطاق)،
    وإن كان GHOST_NO_EXTERNAL فعّالاً نرفض حل أسماء خارجية تماماً."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not external_egress_allowed():
        # وضع العزل: لا DNS خارجي ولا اتصال، لا شيء يستدعي كشف النطاق
        raise socket.gaierror(-2, 'external egress disabled')
    if GHOST_PROXY:
        # DoH يعتمد على requests فقط، لا حاجة لمكتبة dnspython هنا
        try:
            answers = _ProxyDNSResolver(GHOST_PROXY).resolve(host, 'A', lifetime=5)
            for a in answers:
                val = str(a)
                if _is_safe_ip(val):
                    return val
            raise RuntimeError('DoH returned no usable A record')
        except (requests.RequestException, ValueError, RuntimeError) as exc:
            # لا نتراجع لـDNS المحلي صامتاً: ذلك يسرّب النطاق لمزود الإنترنت
            raise RuntimeError('DoH resolution failed over proxy') from exc
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        return infos[0][4][0]
    except socket.gaierror:
        return None

class _ProxyDNSResolver:
    """يحل سجلات DNS عبر HTTP(S) DoH (عبر البروكسي نفسه) بدل UDP المحلية:
    لا يرسل استعلاماً لمزود الإنترنت ولا يكشف النطاق للمزوّد المحلي."""
    def __init__(self, proxy):
        self.proxy = proxy

    def resolve(self, domain, rtype, lifetime=5):
        resp = _SESSION.get(
            'https://cloudflare-dns.com/dns-query',
            params={'name': domain, 'type': rtype},
            headers={'Accept': 'application/dns-json'},
            timeout=lifetime,
            proxies={'http': self.proxy, 'https': self.proxy},
        )
        data = resp.json()
        return [_DnsAnswer(a.get('data', '')) for a in data.get('Answer', [])]


class _DnsAnswer:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


