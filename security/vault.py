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

def _stable_machine_id():
    """معرّف جهاز **ثابت** لا يتغير عند تبديل Wi-Fi/Ethernet أو MAC Randomization:
    يعتمد على منصة النظام + مضيف ثابت (MachineGuid على Windows / machine-id على Linux).
    uuid.getnode() لا يُستخدم إطلاقاً لأنه يتغيّر مع واجهة الشبكة."""
    ident = []
    try:
        if os.name == 'nt':
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Cryptography") as k:
                ident.append(str(winreg.QueryValueEx(k, "MachineGuid")[0]))
        else:
            for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
                if os.path.exists(path):
                    ident.append(open(path, encoding='utf-8').read().strip())
                    break
    except (OSError, ImportError, PermissionError):
        pass
    if not ident:
        # احتياطي أخير: هوست ثابت لا يمسه تغيير الشبكة
        ident.append(socket.gethostname())
    ident.append(sys.platform)
    return '|'.join(ident).encode('utf-8', errors='ignore')


def _machine_secret_legacy():
    """بصمة الإصدار السابق (تتضمن uuid.getnode) — تُستخدم فقط لترقية مفتاح قديم
    حتى لا يفقد المستخدم القدرة على فك تشفير ملفاته السابقة."""
    parts = [
        os.environ.get('USERNAME') or os.environ.get('USER') or '',
        os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME') or '',
        str(uuid.getnode()),
        sys.platform,
    ]
    return '|'.join(parts).encode('utf-8', errors='ignore')


def _machine_secret():
    """سر الجهاز المستخدم لربط مفتاح الخزنة بالجهاز (لا يُكتب على القرص)."""
    return _stable_machine_id()


def _write_vault_key(key: bytes):
    """يكتب المفتاح مقفلاً بـHMAC الجهاز مع صلاحيات 0600."""
    tag = hmac.new(_machine_secret(), key, hashlib.sha256).digest()
    with open(VAULT_FILE, 'wb') as f:
        f.write(base64.b64encode(key + tag))
    try:
        os.chmod(VAULT_FILE, 0o600)
    except OSError:
        pass


def _load_or_create_vault_key():
    """ينشئ/يقرأ مفتاح الخزنة ويتحقق من HMAC مربوط بالجهاز.
    يدعم الترقية من بصمة الإصدار القديمة (uuid.getnode) إلى البصمة الثابتة
    دون فقدان أي بيانات مشفّرة سابقاً: إذا نجح التحقق القديم نُعيد قفل نفس
    المفتاح بالبصمة الثابتة ونحفظه."""
    if not CRYPTO_AVAILABLE:
        return None
    try:
        os.makedirs(os.path.dirname(VAULT_FILE), mode=0o700, exist_ok=True)
    except (OSError, PermissionError):
        return None
    if os.path.exists(VAULT_FILE):
        try:
            raw = base64.b64decode(open(VAULT_FILE, 'rb').read())
            key, tag = raw[:-32], raw[-32:]
            expected = hmac.new(_machine_secret(), key, hashlib.sha256).digest()
            if hmac.compare_digest(tag, expected):
                return key
            # ترقية: هل مفتاح قديم بصمة uuid.getnode؟
            legacy = hmac.new(_machine_secret_legacy(), key, hashlib.sha256).digest()
            if hmac.compare_digest(tag, legacy):
                _write_vault_key(key)
                return key
            return None  # المفتاح منُسوخ من جهاز آخر أو مُعادلة
        except (OSError, ValueError, binascii.Error):
            return None
    key = os.urandom(32)
    try:
        _write_vault_key(key)
    except OSError:
        return None
    return key


_VAULT_KEY = _load_or_create_vault_key()


def encrypt_value(plaintext: str) -> str:
    """يُشفّر نصاً (مثل IP الجهاز) بـ AES-256-GCM؛ يرجع base64 مع nonce."""
    if not plaintext:
        return ""
    if not CRYPTO_AVAILABLE or not _VAULT_KEY:
        raise RuntimeError('crypto unavailable')
    nonce = os.urandom(12)
    ct = AESGCM(_VAULT_KEY).encrypt(nonce, plaintext.encode('utf-8'), None)
    return base64.b64encode(VAULT_PREFIX + nonce + ct).decode('ascii')


def decrypt_value(token: str) -> str:
    """يفكّ تشفير قيمة أنشأها encrypt_value على نفس الجهاز."""
    if not token:
        return ""
    try:
        raw = base64.b64decode(token)
        if not raw.startswith(VAULT_PREFIX):
            return ""
        nonce, ct = raw[4:16], raw[16:]
        return AESGCM(_VAULT_KEY).decrypt(nonce, ct, None).decode('utf-8')
    except Exception:
        return ""


def mask_ip(ip: str) -> str:
    """يعيد تمثيلاً مقنّعاً للـ IP (يُخفي الرقم الأخير) للعرض/التقارير."""
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            parts = ip.split('.')
            return '.'.join(parts[:3] + ['x'])
        return str(addr.exploded[:12]) + '::/x'
    except ValueError:
        return 'unknown'


def redact_local_identity(devices: dict, local_ip) -> dict:
    """يستبدل عنوان جهازك (IP/MAC) في نتائج المسح قبل حفظها في التقرير/السجل،
    فيبقى جهازك غير قابل للتمييز داخل بيانات التقرير، ويحتفظ اسم "you" فقط.
    يعيد نسخة جديدة ولا يعدّل القاموس الأصلي."""
    if not isinstance(devices, dict):
        return devices
    result = {}
    for ip, info in devices.items():
        if ip == local_ip:
            result[mask_ip(ip)] = {
                "mac": "xx:xx:xx:xx:xx:xx",
                "vendor": "This device",
                "hostname": "this-device",
                "os": (info or {}).get("os", ""),
            }
        else:
            result[ip] = info
    return result

# ---------------- وضع الشبح (Ghost Mode) ----------------

def _unredact_local_identity(devices: dict, local_ip) -> dict:
    """عكس redact_local_identity عند القراءة: السجل يخزّن جهازك مقنّعاً
    (192.168.x.x)، فنعيد له عنوانه الحقيقي قبل المقارنة حتى لا يظهر
    "جهازاً جديداً" في كل فحص. يعيد نسخة جديدة."""
    if not isinstance(devices, dict) or not local_ip:
        return dict(devices or {})
    masked = mask_ip(local_ip)
    result = {}
    for ip, info in devices.items():
        if ip == masked:
            result[local_ip] = info
        else:
            result[ip] = info
    return result


