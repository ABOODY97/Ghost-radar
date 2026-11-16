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

def get_local_mac():
    """يجلب MAC الحقيقي للواجهة النشطة من إعدادات النظام المحلية (بدون أي حزم)."""
    local_ip = get_local_ip()
    if not local_ip:
        return None
    try:
        _iface = scapy.conf.route.route(local_ip)[1]
        if _iface:
            mac = scapy.get_if_hwaddr(_iface)
            if mac and mac != '00:00:00:00:00:00':
                return mac
    except Exception:
        pass
    return None


def random_mac():
    """MAC محلي الإدارة (Locally Administered) عشوائي — يكسر تتبع هوية الجهاز في الطبقة 2."""
    return "02:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(5))


def ghost_delay(mean=0.35):
    """تأخير عشوائي (Poisson) يحوّل رشقات الحزم إلى حركة موزعة طبيعياً."""
    if stealth_active:
        time.sleep(random.expovariate(1.0 / mean))


_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

def ghost_headers(extra=None):
    """ترويسات عشوائية تشبه متصفحاً عادياً — تمنع بصمة User-Agent الثابتة."""
    headers = {
        'User-Agent': random.choice(_USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
        'Accept-Language': random.choice(['en-US,en;q=0.9', 'ar,en-US;q=0.8', 'tr;q=0.9,en;q=0.7']),
        'Cache-Control': 'no-cache',
    }
    if extra:
        headers.update(extra)
    return headers


def ghost_arp_sweep(network, timeout=2):
    """مسح ARP من الطبقة 2 مع اتساق كامل بين عناوين الإطار.

    psrc يبقى عنوان الواجهة الحقيقي (ARP مبني على الربط، وعنوان غريب
    يُصنّف spoofing فوراً)، لكن MAC المصدر في Ethernet وفي hwsrc يحملان
    نفس القيمة العشوائية المحلية، والتشويش يأتي من التجزئة والإيقاع
    والترتيب العشوائي لا من تناقض الحقول."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return []
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 256:
        hosts = random.sample(hosts, 256)
    random.shuffle(hosts)
    found = []
    local_ip = get_local_ip()
    real_mac = (get_local_mac() or '').lower()
    # دفعة كبيرة + timeout متوازٍ: كانت 16 مضيفاً/دفعة × 2s تسلسلياً = 32s لنطاق /24
    # (وكان أول أمر في القائمة يبدو "معلّقاً"). الآن 6 دفعات فقط وكل دفعة متوازية.
    batch = 48 if len(hosts) > 48 else 16
    for i in range(0, len(hosts), batch):
        chunk = hosts[i:i + batch]
        # عنوان MAC وهمي واحد يُوضع في ترويسة Ethernet وفي hwsrc معاً
        # (كان hwsrc تلقائياً يظهر MAC الحقيقي فينتج تناقض يكشفك).
        # MAC الإدارة المحلية (02:) مقبول كعنوان عشوائي للخصوصية في أنظمة
        # التشغيل الحديثة، والردود تُمسك بوضع "promisc" في srp وتُعيد توجيهها
        # للواجهة الحقيقية محلياً، لذا يعمل على Wi-Fi أيضاً.
        ghost_mac = random_mac()
        pkt = scapy.Ether(src=ghost_mac, dst="ff:ff:ff:ff:ff:ff") / \
            scapy.ARP(hwsrc=ghost_mac, hwdst="00:00:00:00:00:00",
                      psrc=local_ip or None, pdst=chunk)
        answered, _ = scapy.srp(pkt, timeout=min(timeout, 1.5), verbose=False, retry=0)
        for _s, recv in answered:
            if not _is_safe_ip(recv.psrc):
                continue
            # لا نُدرج عنواننا الحقيقي كـ"جهاز" إذا طابق MAC الواجهة
            if real_mac and str(recv.hwsrc).lower() == real_mac:
                continue
            found.append((recv.psrc, sanitize_text(str(recv.hwsrc), 32)))
        ghost_delay(0.4)
    return found

# ---------------- أكواد الألوان ----------------
