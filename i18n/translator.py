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

CURRENT_LANG = 'ar'
LANGUAGES = {}

try:
    with open('language.json', 'r', encoding='utf-8') as f:
        LANGUAGES = json.load(f)
except FileNotFoundError:
    LANGUAGES = DEFAULT_LANGUAGES

# ---------------- أدوات التحقق الأمني ----------------

LANG_CHOICES = {'1': 'ar', '2': 'en', '3': 'tr'}

_BRACE_RE = re.compile(r'\{([^{}]*)\}')


def _format_template(text, args):
    """يعوّض {0}/{1} وأيضاً {} بتقويم الوضع: القالب {} يحتاج ترقيماً صريحاً
    لـstr.format، وإلا انفجر IndexError أثناء الطباعة (سابقاً أبلغ عن
    "فشل حفظ التقرير" بعد أن حُفظ JSON فعلاً)."""
    idx = [-1]

    def _sub(m):
        spec = m.group(1)
        if spec == '':
            idx[0] += 1
            return str(args[idx[0]]) if idx[0] < len(args) else m.group(0)
        return m.group(0)

    text = _BRACE_RE.sub(_sub, text)
    try:
        return text.format(*args)
    except (IndexError, KeyError, ValueError):
        return text


def _t(key, *args):
    """دالة الترجمة: تجلب النص من JSON وإلا من القاموس الداخلي."""
    text = LANGUAGES.get(CURRENT_LANG, {}).get(key)
    if not text:
        text = DEFAULT_LANGUAGES.get(CURRENT_LANG, {}).get(key, key)
    if args and '{' in text:
        text = _format_template(text, args)
    if CURRENT_LANG == 'ar':
        return fix_ar(text)
    return text

def choose_language(prompt_text):
    """يعرض قائمة اللغات الثلاث ويحدّث CURRENT_LANG."""
    global CURRENT_LANG
    print(f"{CYAN}\n1. {fix_ar('عربي')}{RESET}")
    print(CYAN + "2. English" + RESET)
    print(CYAN + "3. Türkçe" + RESET)
    choice = input(YELLOW + prompt_text + RESET).strip()
    if choice in LANG_CHOICES:
        CURRENT_LANG = LANG_CHOICES[choice]
        return True
    return False

# ---------------- بيانات الجلسة (للتقارير) ----------------
