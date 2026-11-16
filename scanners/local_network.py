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

def get_vendor(mac_address):
    if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac_address):
        return "Unknown"
    second_char = mac_address[1].lower()
    if second_char in ['2', '6', 'a', 'e']:
        return "Randomized (Private MAC)"
    if not external_egress_allowed():
        return "Offline (no external)"
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = external_get(url, timeout=2)
        if response.status_code == 200:
            return sanitize_text(response.text, 60)
        return "Unknown"
    except (requests.RequestException, RuntimeError):
        return "Offline / Error"

def get_os_fingerprint(ip):
    """بصمة TTL عبر ICMP على الطبقة الثالثة فقط (نفس منطق scan_single_port):
    الإطار بـMAC وهمي كان يجعل الحزم تُرسل لكن الردود تُوجّه لـMAC الحقيقي،
    فيضيع الرد ويتحول كل جهاز محلي إلى Filtered/No Ping."""
    if not _is_safe_ip(ip):
        return "Invalid IP"
    try:
        frame = scapy.IP(dst=ip, ttl=random.choice([64, 128])) / scapy.ICMP()
        response = scapy.sr1(frame, timeout=1, verbose=False)
    except (OSError, scapy.Scapy_Exception):
        return "Filtered / No Ping"
    if response and response.haslayer(scapy.IP):
        ttl = response[scapy.IP].ttl
        if ttl <= 64: return f"Linux / Android / Apple (TTL:{ttl})"
        elif ttl <= 128: return f"Windows PC (TTL:{ttl})"
        else: return f"Router / Network (TTL:{ttl})"
    return "Filtered / No Ping"

def get_hostname(ip):
    """يحاول جلب اسم الجهاز عبر Reverse DNS محلياً فقط.
    Reverse DNS لعنوان عام يذهب لمزود الإنترنت (PTR خارج البروكسي)، فنرفضه
    إلا إن كان الوضع للشبكة الخاصة أو السماح الخارجي صريحاً."""
    if not _is_safe_ip(ip):
        return "Unknown"
    try:
        addr = ipaddress.ip_address(ip)
        is_private = addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return "Unknown"
    if not is_private and not external_egress_allowed():
        return "Unknown"
    if not is_private and GHOST_PROXY:
        # نتجنب PTR عبر DNS المحلي تحت بروكسي (لا يمر عبر البروكسي)
        return "Unknown"
    try:
        return sanitize_text(socket.gethostbyaddr(ip)[0], 120) or "Unknown"
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"

# ---------------- اكتشاف الأجهزة المتصلة بنفس الشبكة ----------------

def get_local_ip():
    """يجلب الأيبي المحلي لجهازك"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()

def get_local_network():
    """يخمّن نطاق شبكتك المحلية (CIDR)."""
    local_ip = get_local_ip()
    if not local_ip:
        return None, None
    prefix = 24
    try:
        for route in scapy.conf.route.routes:
            net, msk, out_ip = route[0], route[1], route[4]
            if out_ip == local_ip and net != 0 and msk not in (0, 0xFFFFFFFF):
                prefix = max(prefix, bin(msk).count("1"))
                break
    except Exception:
        pass
    network = ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)
    return str(network), local_ip

def discover_devices(network, timeout=2):
    """مسح ARP في وضع الشبح: عينة عشوائية + دفعات صغيرة + فاصل عشوائي."""
    found = ghost_arp_sweep(network, timeout=timeout)
    devices = {}
    for ip, mac in found:
        devices[ip] = mac
    return sorted(devices.items(), key=lambda item: ipaddress.ip_address(item[0]))

def show_connected_devices():
    """يعرض أيبيات الأجهزة المتصلة بشبكتك كقائمة مرقّمة."""
    network, local_ip = get_local_network()
    if not network:
        print(RED + _t("net_auto_fail") + RESET)
        return None
    print(YELLOW + _t("net_detecting", network) + RESET)
    found = discover_devices(network)
    others = [d for d in found if d[0] != local_ip]
    if not others:
        print(RED + _t("devices_none") + RESET)
    if local_ip and local_ip not in dict(found):
        found.append((local_ip, "-"))
        found.sort(key=lambda item: ipaddress.ip_address(item[0]))
    print(GREEN + _t("devices_title", len(found)) + RESET)
    print("--------------------------------------------------")
    for index, (ip_addr, mac_addr) in enumerate(found, 1):
        tag = f"  <- {_t('devices_you')}" if ip_addr == local_ip else ""
        print(f"  {YELLOW}{index:>2}{RESET}. {CYAN}{ip_addr:<16}{RESET} {mac_addr}{GREEN}{tag}{RESET}")
    print("--------------------------------------------------")
    return found

# ---------------- سجل الفحوصات السابقة (لاكتشاف الأجهزة الجديدة) ----------------

