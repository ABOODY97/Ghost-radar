import scapy.all as scapy
import requests
import time
import socket
import concurrent.futures
import sys
import os
import json
from arabic_tools import fix_ar

# ---------------- أكواد الألوان ----------------
GREEN = '\033[92m'
RED = '\033[91m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# ---------------- نظام اللغات الداخلي الاحتياطي ----------------
DEFAULT_LANGUAGES = {
    "ar": {
        "menu_1": "1. فحص الشبكة المحلية (Network Scanner - ARP)",
        "menu_2": "2. فحص موقع/سيرفر خارجي (Website/Server Banner Grabbing)",
        "menu_3": "3. فحص المنافذ المفتوحة (Deep Port Scanner)",
        "menu_4": "4. تغيير اللغة ",
        "menu_5": "5. خروج من الرادار (Exit)",
        "prompt_choice": "\nاختر نوع الرادار (1-5): ",
        "invalid_choice": "[-] اختيار غير صالح. جرب مرة أخرى.",
        "goodbye": "\n[+] تم إنهاء الجلسة بنجاح. وداعاً يا Aboody!",
        "net_prompt": "أدخل نطاق الشبكة للفحص الشامل (مثال: 192.168.1.1/24): ",
        "net_scan": "\n[*] جاري مسح الشبكة وإجراء التحليل العميق لـ {}... يرجى الانتظار.",
        "net_off": "[-] هذا الأيبي {} غير نشط أو غير موجود",
        "net_found": "\n[+] تم العثور على {} أجهزة. جاري تحليل البصمات...",
        "web_prompt": "أدخل رابط الموقع أو الأيبي للسيرفر (مثال: google.com): ",
        "port_prompt": "أدخل الأيبي أو رابط الموقع لفحص منافذه (مثال: 192.168.1.1): "
    },
    "en": {
        "menu_1": "1. Local Network Scanner (ARP)",
        "menu_2": "2. Website/Server Scanner (Banner Grabbing)",
        "menu_3": "3. Deep Port Scanner",
        "menu_4": "4. Change Language ",
        "menu_5": "5. Exit Radar",
        "prompt_choice": "\nChoose Radar Type (1-5): ",
        "invalid_choice": "[-] Invalid choice. Try again.",
        "goodbye": "\n[+] Session ended successfully. Goodbye Aboody!",
        "net_prompt": "Enter network range to scan (e.g., 192.168.1.1/24): ",
        "net_scan": "\n[*] Scanning and analyzing {}... Please wait.",
        "net_off": "[-] IP {} is offline or unreachable.",
        "net_found": "\n[+] Found {} devices. Analyzing fingerprints...",
        "web_prompt": "Enter website URL or Server IP (e.g., google.com): ",
        "port_prompt": "Enter IP or URL for port scan (e.g., 192.168.1.1): "
    }
}

CURRENT_LANG = 'ar'
LANGUAGES = {}

try:
    with open('language.json', 'r', encoding='utf-8') as f:
        LANGUAGES = json.load(f)
except FileNotFoundError:
    LANGUAGES = DEFAULT_LANGUAGES

def _t(key):
    """دالة الترجمة تجلب النص، وإذا لم تجده في JSON تبحث في القاموس الداخلي"""
    text = LANGUAGES.get(CURRENT_LANG, {}).get(key)
    if not text:
        text = DEFAULT_LANGUAGES.get(CURRENT_LANG, {}).get(key, key)
        
    if CURRENT_LANG == 'ar':
        return fix_ar(text)
    return text

# ---------------- الدوال الاستخباراتية ----------------

def get_vendor(mac_address):
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text
        else:
            second_char = mac_address[1].lower()
            if second_char in ['2', '6', 'a', 'e']:
                return "Randomized (Private MAC)"
            return "Unknown"
    except:
        return "Offline / Error"

def get_os_fingerprint(ip):
    packet = scapy.IP(dst=ip) / scapy.ICMP()
    response = scapy.sr1(packet, timeout=1, verbose=False)
    if response and response.haslayer(scapy.IP):
        ttl = response[scapy.IP].ttl
        if ttl <= 64: return f"Linux / Android / Apple (TTL:{ttl})"
        elif ttl <= 128: return f"Windows PC (TTL:{ttl})"
        else: return f"Router / Network (TTL:{ttl})"
    return "Filtered / No Ping"

def scan_website(url):
    domain = url.replace("https://", "").replace("http://", "").split('/')[0]
    if not url.startswith('http'):
        url = 'https://' + url
    print(YELLOW + fix_ar(f"\n[*] جاري إرسال طلب استطلاع إلى {domain}...") + RESET)
    try:
        target_ip = socket.gethostbyname(domain)
        geo_url = f"http://ip-api.com/json/{target_ip}"
        geo_response = requests.get(geo_url).json()
        country = geo_response.get("country", "Unknown")
        city = geo_response.get("city", "Unknown")
        isp = geo_response.get("isp", "Unknown")

        response = requests.get(url, timeout=5)
        headers = response.headers
        
        print(GREEN + fix_ar("\n[+] تم اختراق واجهة السيرفر وجمع البيانات بنجاح!") + RESET)
        print("---------------------------------------------------------")
        print(f"[{CYAN}Target IP{RESET}] {target_ip}")
        print(f"[{CYAN}Location{RESET}] {country}, {city}")
        print(f"[{CYAN}ISP / Hosting{RESET}] {isp}")
        print("---------------------------------------------------------")
        
        status_color = GREEN if response.status_code == 200 else RED
        print(f"[{status_color}{response.status_code}{RESET}] HTTP Status Code")
        server = headers.get('Server', 'Unknown / Hidden')
        print(f"[{CYAN}Server WAF{RESET}] {server}")
        
        sec_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
        missing = [h for h in sec_headers if h not in headers]
        if missing:
            print(f"[{RED}Vulnerability{RESET}] Missing Security Headers: {', '.join(missing)}")
        else:
            print(f"[{GREEN}Security{RESET}] Strong Security Headers.")
        print("---------------------------------------------------------")
    except socket.gaierror:
        print(RED + fix_ar("[-] خطأ: الدومين غير صحيح أو لا يمكن تحويله إلى IP.") + RESET)
    except requests.exceptions.RequestException as e:
        print(RED + fix_ar(f"[-] فشل الاتصال بالسيرفر: {e}") + RESET)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "SMB", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP"
}

def scan_single_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        timeout_limit = 1.5
        s.settimeout(timeout_limit)
        start_time = time.time()
        result = s.connect_ex((ip, port))
        end_time = time.time()
        s.close()
        time_taken = end_time - start_time
        if result == 0: return (port, "OPEN")
        elif time_taken >= (timeout_limit - 0.2): return (port, "FILTERED")
        else: return (port, "CLOSED")
    except socket.timeout: return (port, "FILTERED")
    except Exception: return (port, "ERROR")

def port_scanner(target):
    domain = target.replace("https://", "").replace("http://", "").split('/')[0]
    try:
        target_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print(RED + fix_ar("[-] خطأ: لا يمكن تحويل الهدف إلى IP.") + RESET)
        return
    print(YELLOW + fix_ar(f"\n[*] جاري توجيه رادار المنافذ لاختراق دفاعات {target_ip}...") + RESET)
    scan_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_single_port, target_ip, port): port for port in COMMON_PORTS.keys()}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result: scan_results.append(result)
    
    print(GREEN + fix_ar("\n[+] اكتمل المسح التكتيكي! تحليل المنافذ:") + RESET)
    print("-------------------------------------------------------------------------")
    scan_results.sort(key=lambda x: x[0])
    for port, status in scan_results:
        service_name = COMMON_PORTS[port]
        if status == "OPEN":
            print(f"Port {CYAN}{port:<4}{RESET} | {GREEN}[ OPEN ]{RESET} -> {fix_ar(service_name)}")
        elif status == "FILTERED":
            print(f"Port {CYAN}{port:<4}{RESET} | {YELLOW}[ FILTERED ]{RESET} -> {fix_ar(service_name + ' (محمي)')}")
        elif status == "CLOSED":
            print(f"Port {CYAN}{port:<4}{RESET} | {RED}[ CLOSED ]{RESET} -> {fix_ar(service_name)}")
    print("-------------------------------------------------------------------------")


# ---------------- البرنامج الرئيسي ----------------

def main():
    global CURRENT_LANG

    if os.name != 'nt' and os.geteuid() != 0:
        print(RED + fix_ar("[-] يرجى تشغيل السكريبت بصلاحيات Root (sudo) لضمان عمل Scapy بشكل صحيح.") + RESET)
        sys.exit(1)

    start_time = time.time()
    
    print(CYAN + """
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
          R  A  D  A  R   V 1.0              
           -= FROM ABOODY =-                 
    """ + RESET)

    # اختيار اللغة عند التشغيل
    print(BLUE + fix_ar("1. عربي") + RESET)
    print(BLUE + "2. English" + RESET)
    while True:
        lang_choice = input(YELLOW + "(1/2): " + RESET).strip()
        if lang_choice == '1':
            CURRENT_LANG = 'ar'
            break
        elif lang_choice == '2':
            CURRENT_LANG = 'en'
            break

    try:
        while True:
            print(BLUE + "\n" + _t("menu_1"))
            print(BLUE + _t("menu_2"))
            print(BLUE + _t("menu_3"))
            print(YELLOW + _t("menu_4"))
            print(RED + _t("menu_5") + RESET)
            
            choice = input(YELLOW + _t("prompt_choice") + RESET).strip().lower()

            if choice in ['5', 'exit', 'quit', 'q']:
                break
            
            elif choice == '4':
                print(CYAN + "\n1. عربي" + RESET)
                print(CYAN + "2. English" + RESET)
                sub_lang = input(YELLOW + "Choose / اختر (1/2): " + RESET).strip()
                if sub_lang == '1':
                    CURRENT_LANG = 'ar'
                    print(GREEN + fix_ar("\n[+] تم التبديل إلى اللغة العربية!") + RESET)
                elif sub_lang == '2':
                    CURRENT_LANG = 'en'
                    print(GREEN + "\n[+] Switched to English successfully!" + RESET)
            
            elif choice == '1':
                target = input(BLUE + _t("net_prompt") + RESET)
                print(YELLOW + _t("net_scan").format(target) + RESET)
                
                arp_request = scapy.ARP(pdst=target)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                answered, _ = scapy.srp(broadcast / arp_request, timeout=2, verbose=False)
                
                if len(answered) == 0:
                    print(RED + _t("net_off").format(target) + RESET)
                    continue

                print(GREEN + _t("net_found").format(len(answered)) + RESET)
                print("-----------------------------------------------------------------------------------------")
                print(f"{'IP Address':<16} | {'MAC Address':<18} | {'OS Fingerprint (TTL)':<28} | {'Vendor'}")
                print("-----------------------------------------------------------------------------------------")
                for element in answered:
                    ip_addr = element[1].psrc
                    mac_addr = element[1].hwsrc
                    os_info = get_os_fingerprint(ip_addr)
                    vendor_info = get_vendor(mac_addr)
                    vendor_color = RED if "Randomized" in vendor_info else YELLOW
                    print(f"{CYAN}{ip_addr:<16}{RESET} | {mac_addr:<18} | {GREEN}{os_info:<28}{RESET} | {vendor_color}{vendor_info}{RESET}")
                    time.sleep(0.5)
                print("-----------------------------------------------------------------------------------------")

            elif choice == '2':
                target_url = input(BLUE + _t("web_prompt") + RESET)
                scan_website(target_url)

            elif choice == '3':
                target_ip = input(BLUE + _t("port_prompt") + RESET)
                port_scanner(target_ip)

            else:
                print(RED + _t("invalid_choice") + RESET)

    except KeyboardInterrupt:
        print(YELLOW + fix_ar("\n\n[!] تم رصد إشارة Ctrl+C! جاري إيقاف الرادار وإخفاء الآثار...") + RESET)
    
    finally:
        elapsed_time = round(time.time() - start_time, 2)
        print(GREEN + _t("goodbye").replace("!", f" ({elapsed_time}s)!") + RESET)
        sys.exit(0)

if __name__ == "__main__":
    main()