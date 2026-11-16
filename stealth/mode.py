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

stealth_active = False
_real_getaddrinfo = socket.getaddrinfo

STEALTH_PORTS = [80, 443, 8080, 8443, 53, 123, 5353]

# ---------------- سياسة الخصوصية للاستعلامات الخارجية ----------------
# يجري تمرير كل طلبات الكشف الخارجي (crt.sh / NVD / macvendors / geo) عبر هذه الطبقة:
#  - GHOST_NO_EXTERNAL=1 => لا يتصل بأي خدمة خارجية إطلاقاً (الخصوصية المطلقة)
#  - GHOST_PROXY=socks5h://127.0.0.1:9050 => يمر عبر Tor
def _ghost_getaddrinfo(host, port, *args, **kwargs):
    """يختار عنواناً عشوائياً من DNS إذا كان للهدف عدة عناوين (تشتيت الأنماط)."""
    results = _real_getaddrinfo(host, port, *args, **kwargs)
    if stealth_active and len(results) > 1:
        return [random.choice(results)]
    return results


def enable_ghost_mode():
    """يفعّل وضع الشبح.

    لا نغلف socket.socket إطلاقاً (يحفظ سلامة TLS/HTTP). التشويش من طبقة
    الحزم: SYN خام، MAC شبح ثابت، Timestamp متدرّج، ومسح مجزأ عشوائياً.
    كما يخفّي اسم العملية فعلياً عبر setproctitle إن توفر."""
    global stealth_active
    stealth_active = True
    socket.getaddrinfo = _ghost_getaddrinfo
    _set_ghost_proc_title()

def disable_ghost_mode():
    """يعيد الإعداد الأصلي عند الخروج (بدون آثار)."""
    global stealth_active
    stealth_active = False
    socket.getaddrinfo = _real_getaddrinfo


def _set_ghost_proc_title():
    """يغيّر كل تايتل العملية الحقيقي (argv + /proc/PID/cmdline + ps).
    يستخدم setproctitle إن كانت مثبتة؛ prctl وحده يغيّر الاسم المختصر فقط
    فيبقى سطر cmdline كاملاً ظاهراً، لذلك لا نغشّ ونكتفي به."""
    try:
        import setproctitle
        setproctitle.setproctitle('ghostradar')  # اسم محايد لا يحمل مسار السكريبت أو اسمه
        return True
    except ImportError:
        return False


def toggle_ghost_mode():
    """يبدّل وضع الشبح من داخل القائمة ويعيد الحالة الجديدة."""
    if stealth_active:
        disable_ghost_mode()
        return False
    enable_ghost_mode()
    return True


