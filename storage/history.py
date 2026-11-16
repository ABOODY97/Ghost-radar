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

def _encrypt_blob(obj) -> str:
    """يشفّر أي كائن JSON بـ AES-256-GCM قبل كتابته (لا يظهر IP/شبكة كنص صريح)."""
    payload = json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    if CRYPTO_AVAILABLE and _VAULT_KEY:
        return encrypt_value(payload)
    # بدون تشفير متاح: نرفض الكتابة الصريحة (خصوصية على الحساب) إلا بإذن صريح
    if os.environ.get('GHOST_PLAINTEXT_FILES', '0').strip() in ('1', 'true', 'yes'):
        return payload
    raise RuntimeError('crypto unavailable: refusing to write plaintext')


def _decrypt_blob(token: str):
    """يفك تشفير ملف؛ يدعم أيضاً ملفات JSON القديمة للترقية."""
    if not token:
        return None
    if token.lstrip().startswith('{'):
        try:
            return json.loads(token)
        except json.JSONDecodeError:
            return None
    plain = decrypt_value(token.strip())
    if not plain:
        return None
    try:
        return json.loads(plain)
    except json.JSONDecodeError:
        return None


def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return _decrypt_blob(f.read())
        except (OSError, ValueError):
            return None
    return None


def save_history(devices):
    data = {
        "last_scan": datetime.datetime.now().isoformat(),
        "devices": redact_local_identity(devices, get_local_ip())
    }
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            f.write(_encrypt_blob(data))
        try:
            os.chmod(HISTORY_FILE, 0o600)
        except OSError:
            pass
    except (OSError, RuntimeError):
        pass

def compare_history(current_devices, previous, local_ip=None):
    """يقارن بحيث تُعامل عناوين جهازك المقنّعة في السجل كعنوانك الحقيقي،
    فلا إنذار كاذب "جهاز جديد"."""
    if not previous:
        return set(), set()
    if local_ip is None:
        local_ip = get_local_ip()
    prev_devices = _unredact_local_identity(previous.get("devices", {}), local_ip)
    prev_ips = set(prev_devices.keys())
    curr_ips = set(current_devices.keys())
    new_ips = curr_ips - prev_ips
    missing_ips = prev_ips - curr_ips
    return new_ips, missing_ips

# ---------------- فحص شهادات SSL/TLS ----------------

