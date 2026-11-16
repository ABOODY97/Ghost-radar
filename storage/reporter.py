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

def unseal_report_file(path):
    """يفك تشفير تقرير HTML/JSON أو ملف السجل الذي كتبه البرنامج.
    - ‏JSON (أو سجل قديم بنص صريح): يعيد dict.
    - ‏HTML: يستخرج الحزمة المشفّرة بعلاقة داخل صفحة التقرير ويفكها ويعيد HTML نصي.
    يعيد None إذا كان المفتاح مختلفاً/الملف تالفاً."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
    except OSError:
        return None
    if not content:
        return None
    if content.lstrip().startswith('{'):
        return _decrypt_blob(content)
    m = re.search(r'const DATA_[0-9a-f]+ = "([A-Za-z0-9+/=]*)"', content)
    if not m or not m.group(1):
        return None
    plain = decrypt_value(m.group(1))
    if not plain:
        return None
    try:
        return zlib.decompress(base64.b64decode(plain)).decode('utf-8')
    except (ValueError, zlib.error, UnicodeDecodeError):
        return None

def _h(value):
    """يهرّب أي قيمة قبل حقنها في HTML (يمنع XSS من بيانات الشبكة/البصمات)."""
    return html.escape(str(value if value is not None else ''), quote=True)

def generate_html_report(data):
    ts = data.get("started_at", "")
    html = f"""<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="UTF-8">
<title>Ghost Radar Report</title>
<style>
  body {{ background:#0d1117; color:#c9d1d9; font-family: 'Segoe UI', Tahoma, sans-serif; padding:20px; }}
  h1 {{ color:#39ff88; }}
  h2 {{ color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:6px; margin-top:30px; }}
  h3 {{ color:#e3b341; }}
  table {{ width:100%; border-collapse: collapse; margin-top:10px; }}
  th, td {{ border:1px solid #30363d; padding:8px; text-align:right; }}
  th {{ background:#161b22; color:#39ff88; }}
  .warn {{ color:#f85149; }}
  .ok {{ color:#3fb950; }}
  .section {{ background:#161b22; padding:15px; border-radius:8px; margin-bottom:20px; }}
</style>
</head>
<body>
<h1>&#128123; Ghost Radar &mdash; تقرير الفحص</h1>
<p>تاريخ بدء الجلسة: {_h(ts)}</p>
"""

    if data.get("network_scans"):
        html += '<div class="section"><h2>فحص الشبكة المحلية</h2>'
        for scan in data["network_scans"]:
            html += f"<p>وقت الفحص: {_h(scan.get('timestamp', ''))} — عدد الأجهزة: {len(scan.get('devices', {}))}</p>"
            html += "<table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>OS</th></tr>"
            for ip, info in scan.get("devices", {}).items():
                html += f"<tr><td>{_h(ip)}</td><td>{_h(info.get('mac', ''))}</td><td>{_h(info.get('vendor', ''))}</td><td>{_h(info.get('hostname', ''))}</td><td>{_h(info.get('os', ''))}</td></tr>"
            html += "</table>"
            if scan.get("new_devices"):
                html += f'<p class="warn">أجهزة جديدة: {_h(", ".join(scan["new_devices"]))}</p>'
        html += "</div>"

    if data.get("website_scans"):
        html += '<div class="section"><h2>فحوصات المواقع</h2>'
        for scan in data["website_scans"]:
            html += f"<h3>{_h(scan.get('domain', ''))}</h3>"
            html += f"<p>IP: {_h(scan.get('ip', ''))} | {_h(scan.get('country', ''))}, {_h(scan.get('city', ''))} | ISP: {_h(scan.get('isp', ''))}</p>"
            html += f"<p>HTTP Status: {_h(scan.get('status_code', ''))} | Server: {_h(scan.get('server', ''))}</p>"
            missing = scan.get("missing_security_headers", [])
            if missing:
                html += f'<p class="warn">Missing Headers: {_h(", ".join(missing))}</p>'
            ssl_info = scan.get("ssl")
            if ssl_info:
                cls = "warn" if ssl_info.get("days_left", 999) < 15 else "ok"
                html += f'<p class="{cls}">SSL: {_h(ssl_info.get("issuer", ""))} — expires {_h(ssl_info.get("expires", ""))} ({_h(ssl_info.get("days_left", ""))} days)</p>'
            subs = scan.get("subdomains", [])
            if subs:
                html += f"<p>Subdomains found: {len(subs)}</p><ul>"
                for s in subs[:50]:
                    html += f"<li>{_h(s)}</li>"
                html += "</ul>"
        html += "</div>"

    if data.get("port_scans"):
        html += '<div class="section"><h2>فحوصات المنافذ</h2>'
        for scan in data["port_scans"]:
            html += f"<h3>{_h(scan.get('target', ''))}</h3>"
            html += "<table><tr><th>Port</th><th>Service</th><th>Banner</th><th>Known CVEs</th></tr>"
            for p in scan.get("open_ports", []):
                cves = ", ".join(p.get("cves", [])) if p.get("cves") else "-"
                html += f"<tr><td>{_h(p.get('port', ''))}</td><td>{_h(p.get('service', ''))}</td><td>{_h(p.get('banner') or '-')}</td><td>{_h(cves)}</td></tr>"
            html += "</table>"
        html += "</div>"

    html += "</body></html>"
    return html

def export_report():
    if not (SESSION_DATA["network_scans"] or SESSION_DATA["website_scans"] or SESSION_DATA["port_scans"]):
        print(RED + _t("report_empty") + RESET)
        return
    print(YELLOW + _t("report_generating") + RESET)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    json_path = f"ghost_radar_report_{timestamp}.json"
    html_path = f"ghost_radar_report_{timestamp}.html"
    try:
        # JSON مشفّر: لا يظهر أي IP/شبكة كنص صريح على القرص
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(_encrypt_blob(SESSION_DATA))
        # HTML مشفّر أيضاً: محتوى التقرير يُشفّر قبل حقنه في القالب
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(generate_encrypted_html_report(SESSION_DATA))
        for path in (json_path, html_path):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        print(GREEN + _t("report_saved", json_path, html_path) + RESET)
    except (OSError, RuntimeError) as e:
        print(RED + f"[-] Error saving report: {sanitize_text(e, 200)}" + RESET)


def unseal_report_menu():
    """يفك تشفير تقرير/سجل مكتوب في المجلد الحالي ويكتب نسخة صريحة معه."""
    import glob
    candidates = sorted(glob.glob('ghost_radar_report_*.json') +
                        glob.glob('ghost_radar_report_*.html') + [HISTORY_FILE])
    if not candidates:
        print(RED + _t("unseal_none") + RESET)
        return
    print(CYAN + _t("unseal_list") + RESET)
    for index, path in enumerate(candidates, 1):
        print(f"  {index}. {path}")
    raw = input(BLUE + _t("unseal_prompt") + RESET).strip()
    if not raw.isdigit() or not (1 <= int(raw) <= len(candidates)):
        print(RED + _t("invalid_choice") + RESET)
        return
    src = candidates[int(raw) - 1]
    data = unseal_report_file(src)
    if data is None:
        print(RED + _t("unseal_fail") + RESET)
        return
    base, ext = os.path.splitext(src)
    out_path = f"{base}_decrypted{ext or '.json'}"
    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            if isinstance(data, str):
                f.write(data)
            else:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        print(GREEN + _t("unseal_ok", out_path) + RESET)
    except OSError as e:
        print(RED + f"[-] {sanitize_text(e, 200)}" + RESET)

def generate_encrypted_html_report(data) -> str:
    """HTML قابل للفتح في المتصفح لكن محتواه مشفّر AES-256-GCM ومضغوط.
    لا تُكتب أي IP/MAC/نطاق كنص صريح في الملف. يفك التشفير من المتصفح بمفتاح
    الخزنة ثم يُعرض التقرير داخل iframe معزول (sandbox) عبر srcDoc — لا
    innerHTML ولا تنفيذ scripts في صفحة الملف الأصلية (حتى لو تلاعب أحد بالمحتوى).
    إن لم يتوفر التشفير يُكتب ملف إشعار بدون أي بيانات، ولا يُسقط أي بيانات كاملة."""
    inner = generate_html_report(data)
    payload = base64.b64encode(zlib.compress(inner.encode('utf-8'), 9)).decode('ascii')
    sealed_ok = True
    try:
        sealed = encrypt_value(payload)
    except RuntimeError:
        # لا بيانات إطلاقاً بدون تشفير
        sealed = ''
        sealed_ok = False
        payload = ''
    uid = uuid.uuid4().hex
    sealed_ok_js = 'true' if sealed_ok else 'false'
    return f'''<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head><meta charset="UTF-8"><title>Ghost Radar &mdash; Encrypted Report</title>
<style>body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',Tahoma,sans-serif;padding:20px}}
.sec{{background:#161b22;padding:20px;border-radius:8px;max-width:760px;margin:40px auto;text-align:center}}
button{{background:#238636;color:#fff;border:0;padding:10px 22px;border-radius:6px;font-size:15px;cursor:pointer}}
.out{{text-align:right;margin-top:20px}} .err{{color:#f85149}} input{{padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;width:100%;max-width:420px}}
</style></head>
<body><div class="sec">
<h1>&#128123; Ghost Radar</h1>
<p>هذا التقرير مشفّر (AES-256-GCM). لا يحتوي الملف على أي عناوين IP/MAC أو نطاقات كاملة.</p>
<p>أدخل مفتاح الخزنة (Base64 من الملف <code>~/.ghost_radar/vault.key</code>، السطر الأول) لفك التشفير:</p>
<input id="k-{uid}" placeholder="vault key (base64)" autocomplete="off">
<p><button onclick="unseal_{uid}()">فك التشفير وعرض التقرير</button></p>
<p class="err" id="e-{uid}"></p>
<iframe id="o-{uid}" sandbox="" style="width:100%;height:70vh;border:1px solid #30363d;border-radius:6px;background:#0d1117;margin-top:16px"></iframe>
</div>
<script>
const DATA_{uid} = "{sealed}";
const SEALED_OK_{uid} = {sealed_ok_js};
async function unseal_{uid}() {{
  const out = document.getElementById("o-{uid}");
  const err = document.getElementById("e-{uid}");
  err.textContent = "";
  if (!SEALED_OK_{uid}) {{
    err.textContent = "التقرير غير مشفّر (cryptography غير متوفرة) ولم تُكتب أي بيانات. ثبّت cryptography وأعد التوليد.";
    return;
  }}
  try {{
    const b64 = document.getElementById("k-{uid}").value.trim();
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const keyBytes = raw.slice(0, 32);
    const blob = Uint8Array.from(atob(DATA_{uid}), c => c.charCodeAt(0));
    if (String.fromCharCode(...blob.slice(0,4)) !== "GRV1") throw new Error("bad format");
    const nonce = blob.slice(4,16), ct = blob.slice(16);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const plain = new Uint8Array(await crypto.subtle.decrypt({{name:"AES-GCM", iv:nonce}}, key, ct));
    const b64z = new TextDecoder().decode(plain);
    const bytes = Uint8Array.from(atob(b64z), c => c.charCodeAt(0));
    const htmlText = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"))).text();
    // عرض في iframe معزول بالكامل: لا scripts ولا وصول للأصل الأم
    out.srcdoc = htmlText;
  }} catch (e) {{ err.textContent = "مفتاح غير صحيح أو ملف تالف."; }}
}}
</script>
</body></html>'''

# ---------------- البرنامج الرئيسي ----------------

