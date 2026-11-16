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

def banner_capture_allowed():
    """جلب البصمة يحتاج اتصال TCP كامل، وهو الوحيد الذي يكشف IP الحقيقي.
    يُمنع تلقائياً في وضع الشبح ما لم يُسمح صراحةً بـ GHOST_ALLOW_BANNER=1."""
    if os.environ.get('GHOST_NO_BANNER', '0').strip() in ('1', 'true', 'yes'):
        return False
    if stealth_active and os.environ.get('GHOST_ALLOW_BANNER', '0').strip() not in ('1', 'true', 'yes'):
        return False
    return True


def grab_banner(ip, port):
    """يحاول جلب بصمة الخدمة (يُتجاوز في وضع الشبح — اتصال كامل = كشف IP)."""
    if not banner_capture_allowed():
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, port))
        if port in (80, 8080, 8000, 8081, 8888, 3000):
            request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode())
            data = s.recv(2048).decode(errors='ignore')
            s.close()
            for line in data.split('\r\n'):
                if line.lower().startswith('server:'):
                    return line.split(':', 1)[1].strip()
            return None
        else:
            data = s.recv(256)
            s.close()
            if data:
                return sanitize_text(data.decode(errors='ignore'), 200).strip()
            return None
    except Exception:
        return None

def check_cve(banner_text):
    """يستعلم عن ثغرات معروفة من قاعدة NVD الرسمية"""
    if not banner_text or len(banner_text) < 3 or not external_egress_allowed():
        return []
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": banner_text[:100], "resultsPerPage": 5}
        resp = external_get(url, params=params, timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            results = []
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'Unknown')
                if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
                    continue
                descs = cve.get('descriptions', [])
                desc_text = next((d.get('value', '') for d in descs if d.get('lang') == 'en'), '')
                results.append((cve_id, sanitize_text(desc_text, 140)))
            return results
        elif resp.status_code in (403, 429):
            return "RATE_LIMITED"
    except (requests.RequestException, ValueError, RuntimeError):
        pass
    return []

# عدّاد Timestamp متقدم لكل هدف يحاكي ترقي الساعة الطبيعية (TSval)
_TS_CACHE = {}


def _next_tsval(target_key):
    """TSval حقيقي متراكم (كل ميكروثانية/ms) بدل ثابت 0،0 — لا يعطي بصمة اصطناعية."""
    last = _TS_CACHE.get(target_key)
    now_ms = int(time.time() * 1000) & 0xFFFFFFFF
    if last is None or now_ms < last:
        val = now_ms
    else:
        val = (last + random.randint(50, 900)) & 0xFFFFFFFF
    _TS_CACHE[target_key] = val
    return val


def _realistic_tcp_options(tsval):
    """خيارات TCP مشابهة لـ Linux/Windows الحديثة، مع طول نافذة متغير
    و MSS/WScale غير ثابتين، فلا يظهر توقيع програмمي مميز."""
    mss = random.choice([1460, 1460, 1440, 1412])
    wscale = random.choice([7, 7, 6, 8])
    if random.random() < 0.5:
        return [('MSS', mss), ('SAckOK', b''), ('Timestamp', (tsval, 0)), ('NOP', None), ('WScale', wscale)]
    return [('MSS', mss), ('SAckOK', b''), ('Timestamp', (tsval, 0)), ('NOP', None), ('NOP', None), ('WScale', wscale)]


def _random_window():
    """window عشوائي من قيم مألوفة في المتصفحات/أنظمة التشغيل."""
    return random.choice([64240, 65535, 14600, 29200, 28960, 50240, 64860, 62727])


def scan_single_port(ip, port):
    """مسح SYN خام (Half-open) على الطبقة الثالثة فقط — بلا Ether وهمي.

    لماذا بلا طبقة 2؟ لا يمكن تزوير MAC المصدر مع الاحتفاظ بالIP الحقيقي
    محلياً دون كسر مسار العودة: الهدف يوجّه الرد حسب جدول ARP إلى MAC
    الحقيقي، بينما srp1 يطابق إطار الرد على MAC المصدر المُرسل، فيرفض كل
    الردود ويُصنّف الكل FILTERED (هذا ما حدث مع الراوتر المحلي). نترك
    النظام يُكمل الطبقة 2 بشكل متسق عبر sr1.
    التشويش يبقى في الطبقة 3: Timestamp متدرّج، نافذة عشوائية، خيارات متنوعة."""
    ghost_delay(0.08)
    try:
        local_ip = get_local_ip()
        if not local_ip:
            return (port, "ERROR")
        tsval = _next_tsval(ip)

        tcp = scapy.TCP(
            sport=random.randint(32768, 60999), dport=port, flags='S',
            seq=random.randint(1, 2**32 - 1),
            window=_random_window(), options=_realistic_tcp_options(tsval))

        frame = scapy.IP(src=local_ip, dst=ip, ttl=random.choice([64, 64, 128])) / tcp
        resp = scapy.sr1(frame, timeout=1.0 + random.uniform(0, 0.4), verbose=False)

        if resp and resp.haslayer(scapy.TCP):
            flags = resp[scapy.TCP].flags
            if (flags & 0x12) == 0x12:   # SYN-ACK => مفتوح
                _send_ghost_rst(ip, resp)
                return (port, "OPEN")
            if flags & 0x04:             # RST => مغلق
                return (port, "CLOSED")
        return (port, "FILTERED")
    except (OSError, scapy.Scapy_Exception):
        return (port, "ERROR")


def _send_ghost_rst(ip, synack):
    """إغلاق طبيعي: RST فوري برقم تسلسل صحيح (seq=ack) عبر الطبقة 3،
    فيتعامل النظام مع الطبقة 2 بتناسق، ويبدو الإغلاق كعميل رفض الاتصال لا nmap."""
    try:
        rst = scapy.IP(dst=ip, ttl=random.choice([64, 128])) / \
            scapy.TCP(sport=synack[scapy.TCP].dport, dport=synack[scapy.TCP].sport,
                      flags='R', seq=synack[scapy.TCP].ack)
        scapy.send(rst, verbose=False)
    except (OSError, scapy.Scapy_Exception, AttributeError, KeyError):
        pass

def port_scanner(target, ports_to_scan):
    domain = validate_domain(target)
    if not domain:
        print(RED + _t("port_bad_target") + RESET)
        return
    try:
        target_ip = resolve_host(domain)
    except (socket.gaierror, RuntimeError):
        target_ip = None
    if not target_ip:
        print(RED + _t("port_bad_target") + RESET)
        return
    print(YELLOW + _t("port_scanning", target_ip, len(ports_to_scan)) + RESET)
    # وضع الشبح: ترتيب عشوائي + خيوط أقل + تجزئة على دفعات — يكسر بصمة "مسح متزامن"
    ports_shuffled = list(ports_to_scan)
    random.shuffle(ports_shuffled)
    scan_results = []
    batch_size = 120
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        for i in range(0, len(ports_shuffled), batch_size):
            batch = ports_shuffled[i:i + batch_size]
            futures = {executor.submit(scan_single_port, target_ip, port): port for port in batch}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result: scan_results.append(result)
            ghost_delay(1.2)

    print(GREEN + _t("port_done") + RESET)
    print("-------------------------------------------------------------------------")
    scan_results.sort(key=lambda x: x[0])
    quick_mode = len(ports_to_scan) <= 20
    port_names = COMMON_PORTS if quick_mode else EXTENDED_PORTS
    open_ports_info = []
    for port, status in scan_results:
        service_name = port_names.get(port, "Unknown")
        if status == "OPEN":
            banner = grab_banner(target_ip, port)
            banner_display = f" | {_t('banner_found')}: {banner}" if banner else ""
            print(f"Port {CYAN}{port:<5}{RESET} | {GREEN}[ OPEN ]{RESET} -> {service_name}{banner_display}")
            open_ports_info.append({"port": port, "service": service_name, "banner": banner})
        elif status == "FILTERED":
            print(f"Port {CYAN}{port:<5}{RESET} | {YELLOW}[ FILTERED ]{RESET} -> {service_name + _t('port_protected')}")
        elif status == "CLOSED" and quick_mode:
            print(f"Port {CYAN}{port:<5}{RESET} | {RED}[ CLOSED ]{RESET} -> {service_name}")
    print("-------------------------------------------------------------------------")

    banners_to_check = [p for p in open_ports_info if p["banner"]][:10]
    if banners_to_check:
        print(CYAN + _t("cve_checking") + RESET)
        for p in banners_to_check:
            cves = check_cve(p["banner"])
            if cves == "RATE_LIMITED":
                print(YELLOW + _t("cve_rate_limited") + RESET)
                break
            elif cves:
                print(RED + _t("cve_found", p["banner"]) + RESET)
                for cve_id, desc in cves:
                    print(f"    - {cve_id}: {desc}")
                p["cves"] = [c[0] for c in cves]
            time.sleep(6)

    SESSION_DATA["port_scans"].append({
        "target": target_ip,
        "timestamp": datetime.datetime.now().isoformat(),
        "open_ports": open_ports_info
    })

# ---------------- توليد التقارير ----------------

