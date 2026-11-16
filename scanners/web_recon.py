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

def _open_tls_socket(domain, port=443, timeout=4):
    """يفتح مقبس TLS لـget_ssl_info عبر البروكسي فقط.
    - GHOST_NO_EXTERNAL=1 => ممنوع
    - بروكسي مضبوط => SOCKS/HTTP عبر PySocks (rdns=True) فلا يرى الهدف IP الحقيقي
    - بدون بروكسي في وضع الشبح => ممنوع افتراضياً (يكشف IP + SNI)، مع إمكانية
      السماح الصريح عبر GHOST_ALLOW_DIRECT_TLS=1
    يرجع (sock, 'proxy'/'direct'/'blocked')، ويرمي RuntimeError عند فشل البروكسي.
    """
    if not external_egress_allowed():
        return None, 'blocked'
    ctx = ssl.create_default_context()
    if GHOST_PROXY:
        if not GHOST_PROXY.lower().startswith(('socks', 'http://', 'https://')):
            return None, 'blocked'
        try:
            import socks  # PySocks
            u = urlparse(GHOST_PROXY)
            # ثوابت المكتبة بدل أرقام مُقحمة (مثلاً socks4:// كان سيفشل)
            scheme = (u.scheme or '').lower()
            if scheme in ('socks5', 'socks5h'):
                ptype = socks.SOCKS5
            elif scheme in ('socks4', 'socks4a'):
                ptype = socks.SOCKS4
            elif scheme in ('http', 'https'):
                ptype = socks.HTTP
            else:
                return None, 'blocked'
            s = socks.socksocket()
            s.set_proxy(ptype, u.hostname or '127.0.0.1', u.port or 1080, rdns=True)
            s.settimeout(timeout)
            s.connect((domain, port))
            return ctx.wrap_socket(s, server_hostname=domain), 'proxy'
        except (ImportError, OSError) as exc:
            raise RuntimeError('proxy unavailable') from exc
    if stealth_active and os.environ.get('GHOST_ALLOW_DIRECT_TLS', '0').strip() not in ('1', 'true', 'yes'):
        return None, 'blocked'
    sock = socket.create_connection((domain, port), timeout=timeout)
    return ctx.wrap_socket(sock, server_hostname=domain), 'direct'


def get_ssl_info(domain, port=443):
    try:
        ssock, route = _open_tls_socket(domain, port)
        if ssock is None:
            return {'blocked': True}
        with ssock:
            cert = ssock.getpeercert()
            protocol = ssock.version()
        issuer_parts = dict(x[0] for x in cert.get('issuer', []))
        issuer = issuer_parts.get('organizationName', issuer_parts.get('commonName', 'Unknown'))
        not_after = cert.get('notAfter')
        expire_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc)
        days_left = (expire_date - datetime.datetime.now(datetime.timezone.utc)).days
        return {
            "issuer": issuer,
            "expires": expire_date.strftime('%Y-%m-%d'),
            "days_left": days_left,
            "protocol": protocol
        }
    except (OSError, ssl.SSLError, ValueError, RuntimeError):
        return None

# ---------------- سجلات DNS ----------------

def get_dns_records(domain):
    """سجلات DNS مع احترام سياسة الخروج:
    - GHOST_NO_EXTERNAL=1 => لا استعلام إطلاقاً (حماية خصوصية صارمة)
    - وجود بروكسي => DoH عبر البروكسي (لا استعلام UDP محلي للـ ISP)
    - بدون بروكسي => resolver محلي (لا نقل发包 خارجي لكن ISP يرى الاستعلامات)"""
    if not external_egress_allowed():
        raise RuntimeError('external egress disabled')
    if GHOST_PROXY:
        # DoH يعتمد على requests فقط — لا يحتاج مكتبة dnspython
        resolver = _ProxyDNSResolver(GHOST_PROXY)
    elif DNS_AVAILABLE:
        resolver = dns.resolver
    else:
        return None
    records = {}
    for rtype in ['MX', 'NS', 'TXT']:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=5)
            values = []
            for r in answers:
                value = str(r).strip()
                # عناوين NS/MX تأتي بنقطة نهاية؛ نزيلها ونقنع الأمان
                values.append(sanitize_text(value.rstrip('.'), 200))
            records[rtype] = values
        except Exception:
            records[rtype] = []
    return records

# ---------------- اكتشاف النطاقات الفرعية عبر Certificate Transparency ----------------

def get_subdomains(domain):
    try:
        if not external_lookup_allowed(domain):
            return []
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = external_get(url, timeout=10)
        if resp.status_code == 200 and resp.text.strip():
            data = resp.json()
            subs = set()
            for entry in data:
                name_value = entry.get('name_value', '')
                for n in name_value.split('\n'):
                    n = n.strip().lower()
                    if n and n.endswith('.' + domain) and '*' not in n:
                        if _DOMAIN_RE.match(n):
                            subs.add(n)
            return sorted(subs)
    except (requests.RequestException, ValueError):
        pass
    return []

def scan_website(url):
    domain = validate_domain(url)
    if not domain:
        print(RED + _t("web_bad_domain") + RESET)
        return
    print(YELLOW + _t("web_scanning", domain) + RESET)
    scan_record = {"domain": domain, "timestamp": datetime.datetime.now().isoformat()}
    try:
        try:
            target_ip = resolve_host(domain)
        except RuntimeError:
            print(RED + _t("external_blocked") + RESET)
            return
        if not target_ip:
            print(RED + _t("web_bad_domain") + RESET)
            return
        geo_data = {}
        if external_lookup_allowed(target_ip):
            try:
                geo_response = external_get(f"https://ip-api.io/json/{target_ip}", timeout=5)
                geo_data = geo_response.json() if geo_response.status_code == 200 else {}
            except (requests.RequestException, ValueError, RuntimeError):
                geo_data = {}
        country = sanitize_text(geo_data.get("country_name", "Unknown"), 80)
        city = sanitize_text(geo_data.get("city", "Unknown"), 80)
        isp = sanitize_text(geo_data.get("organisation", "Unknown"), 120)

        # الاتصال بالموقع المستهدف يمر عبر طبقة الخروج نفسها (بروكسي/منع)
        scheme_used = 'https'
        try:
            response = external_get('https://' + domain, timeout=5, allow_redirects=True)
        except requests.exceptions.SSLError:
            # خادم محلي/قديم على المنفذ 80 فقط: احتياطي على HTTP
            response = external_get('http://' + domain, timeout=5, allow_redirects=True)
            scheme_used = 'http'
        headers = response.headers

        print(GREEN + _t("web_success") + RESET)
        print("---------------------------------------------------------")
        print(f"[{CYAN}Target IP{RESET}] {target_ip}")
        print(f"[{CYAN}Location{RESET}] {country}, {city}")
        print(f"[{CYAN}ISP / Hosting{RESET}] {isp}")
        print("---------------------------------------------------------")

        status_color = GREEN if response.status_code == 200 else RED
        print(f"[{status_color}{response.status_code}{RESET}] HTTP Status Code")
        server = sanitize_text(headers.get('Server', 'Unknown / Hidden'), 100)
        print(f"[{CYAN}Server WAF{RESET}] {server}")

        sec_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
        missing = [h for h in sec_headers if h not in headers]
        if missing:
            print(f"[{RED}Vulnerability{RESET}] Missing Security Headers: {', '.join(missing)}")
        else:
            print(f"[{GREEN}Security{RESET}] Strong Security Headers.")
        print("---------------------------------------------------------")

        print(f"[{CYAN}Scheme{RESET}] {scheme_used}")
        scan_record.update({
            "ip": target_ip, "scheme": scheme_used,
            "country": country, "city": city, "isp": isp,
            "status_code": response.status_code, "server": server,
            "missing_security_headers": missing
        })

        # ---- شهادة SSL/TLS ----
        print(CYAN + _t("ssl_info_title") + RESET)
        ssl_info = get_ssl_info(domain)
        if ssl_info and ssl_info.get('blocked'):
            print(RED + _t("ssl_proxy_blocked") + RESET)
        elif ssl_info:
            print(f"  {_t('ssl_issuer')}: {ssl_info['issuer']}")
            print(f"  {_t('ssl_expires')}: {ssl_info['expires']}  ({_t('ssl_days_left')}: {ssl_info['days_left']})")
            print(f"  {_t('ssl_protocol')}: {ssl_info['protocol']}")
            if ssl_info['days_left'] < 0:
                print(RED + _t("ssl_expired_warning") + RESET)
            elif ssl_info['days_left'] < 15:
                print(YELLOW + _t("ssl_expiring_soon") + RESET)
            scan_record["ssl"] = ssl_info
        else:
            print(YELLOW + _t("ssl_unavailable") + RESET)

        # ---- سجلات DNS ----
        print(CYAN + _t("dns_title") + RESET)
        try:
            dns_records = get_dns_records(domain)
        except RuntimeError:
            dns_records = None
            print(RED + _t("external_blocked") + RESET)
        if dns_records is None and external_egress_allowed():
            print(YELLOW + _t("dns_missing_lib") + RESET)
        elif dns_records is None:
            pass  # تمت طباعة رسالة الحظر أعلاه
        else:
            for rtype, vals in dns_records.items():
                display_vals = ', '.join(vals) if vals else _t("dns_none")
                print(f"  {rtype}: {display_vals}")
            scan_record["dns"] = dns_records

        # ---- نطاقات فرعية ----
        print(YELLOW + _t("subs_title") + RESET)
        subs = get_subdomains(domain)
        if subs:
            print(GREEN + _t("subs_found", len(subs)) + RESET)
            for s in subs[:30]:
                print(f"  - {s}")
            if len(subs) > 30:
                print(f"  ... (+{len(subs) - 30})")
            scan_record["subdomains"] = subs
        else:
            print(YELLOW + _t("subs_none") + RESET)

        SESSION_DATA["website_scans"].append(scan_record)

    except socket.gaierror:
        print(RED + _t("web_bad_domain") + RESET)
    except RuntimeError as exc:
        print(RED + _t("external_blocked") + RESET)
        if 'DoH' in str(exc):
            print(YELLOW + _t("doh_failed") + RESET)
    except (requests.exceptions.RequestException, ValueError) as e:
        print(RED + _t("web_conn_fail", sanitize_text(e, 200)) + RESET)

