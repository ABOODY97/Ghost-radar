"""Ghost Radar modular entry point."""
import importlib
import config as config
import i18n.defaults as i18n_defaults
import i18n.translator as i18n_translator
import security.validators as security_validators
import security.vault as security_vault
import security.egress as security_egress
import stealth.mode as stealth_mode
import stealth.network_stealth as stealth_network_stealth
import scanners.local_network as scanners_local_network
import scanners.web_recon as scanners_web_recon
import scanners.port_scanner as scanners_port_scanner
import storage.history as storage_history
import storage.reporter as storage_reporter

_modules = [
    config,
    i18n_defaults,
    i18n_translator,
    security_validators,
    security_vault,
    security_egress,
    stealth_mode,
    stealth_network_stealth,
    scanners_local_network,
    scanners_web_recon,
    scanners_port_scanner,
    storage_history,
    storage_reporter,
]
_shared = {}
for _module in _modules:
    _shared.update({name: value for name, value in vars(_module).items() if not name.startswith('__')})
for _module in _modules:
    _module.__dict__.update(_shared)
globals().update(_shared)
def main():
    global CURRENT_LANG

    # تفعيل وضع الشبح قبل أي عملية شبكية
    enable_ghost_mode()

    if os.name != 'nt' and os.geteuid() != 0:
        print(RED + "[-] يرجى تشغيل السكريبت بصلاحيات Root (sudo) لضمان عمل Scapy بشكل صحيح. | Please run with root (sudo). | Lütfen root (sudo) ile çalıştırın." + RESET)
        sys.exit(1)

    start_time = time.time()

    print(CYAN + """
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
          R  A  D  A  R   V 5.0              
           -= FROM ABOODY =-                 
    """ + RESET)

    try:
        while not choose_language("(1/2/3): "):
            pass

        while True:
            print(BLUE + "\n" + _t("menu_1"))
            print(BLUE + _t("menu_2"))
            print(BLUE + _t("menu_3"))
            print(CYAN + _t("menu_4"))
            print(YELLOW + _t("menu_5"))
            print(RED + _t("menu_6") + RESET)
            print(GREEN + _t("menu_7") + f"  [{'ON' if stealth_active else 'OFF'}]" + RESET)
            mode_tag = "NO-EXTERNAL" if NO_EXTERNAL else ("TOR/PROXY" if GHOST_PROXY else "direct")
            my_ip = get_local_ip()
            id_tag = mask_ip(my_ip) if my_ip else "n/a"
            vault_tag = "AES-256-GCM" if (CRYPTO_AVAILABLE and _VAULT_KEY) else "PLAINTEXT-OFF"
            print(f"    {CYAN}egress: {mode_tag} | device: {id_tag} | vault: {vault_tag}{RESET}")
            print(YELLOW + _t("menu_8"))

            choice = input(YELLOW + _t("prompt_choice") + RESET).strip().lower()

            if choice in ['6', 'exit', 'quit', 'q']:
                break

            elif choice == '7':
                print(GREEN + _t("ghost_on") if toggle_ghost_mode() else YELLOW + _t("ghost_off") + RESET)
                print(CYAN + _t("ghost_egress_note") + RESET)

            elif choice == '5':
                if choose_language("Choose / اختر / Seçin (1/2/3): "):
                    print(GREEN + _t("lang_switched") + RESET)

            elif choice == '8':
                unseal_report_menu()

            elif choice == '1':
                print(CYAN + _t("net_mode_prompt") + RESET)
                net_mode = input(YELLOW + "\n> " + RESET).strip()
                if net_mode == '1':
                    show_connected_devices()
                    continue

                target = input(BLUE + _t("net_prompt") + RESET).strip()
                _local_warn = not target
                if not target:
                    target, _local_ip = get_local_network()
                else:
                    target = validate_cidr(target)
                if not target:
                    print(RED + _t("net_auto_fail" if _local_warn else "invalid_choice") + RESET)
                    continue
                print(YELLOW + _t("net_scan", target) + RESET)

                # مسح خفي: دفعات عشوائية بدل بث نطاق واحد مرئي
                found_list = discover_devices(target, timeout=2)

                if not found_list:
                    print(RED + _t("net_off", target) + RESET)
                    continue

                print(GREEN + _t("net_found", len(found_list)) + RESET)
                print("---------------------------------------------------------------------------------------------------------")
                print(f"{'IP Address':<16} | {'MAC Address':<18} | {'OS Fingerprint (TTL)':<28} | {'Hostname':<20} | {'Vendor'}")
                print("---------------------------------------------------------------------------------------------------------")
                current_devices = {}
                for ip_addr, mac_addr in found_list:
                    if not _is_safe_ip(ip_addr):
                        continue
                    os_info = sanitize_text(get_os_fingerprint(ip_addr), 60)
                    ghost_delay(0.9)
                    vendor_info = sanitize_text(get_vendor(mac_addr), 60)
                    hostname = sanitize_text(get_hostname(ip_addr), 120)
                    vendor_color = RED if "Randomized" in vendor_info else YELLOW
                    print(f"{CYAN}{ip_addr:<16}{RESET} | {mac_addr:<18} | {GREEN}{os_info:<28}{RESET} | {hostname:<20} | {vendor_color}{vendor_info}{RESET}")
                    current_devices[ip_addr] = {"mac": sanitize_text(str(mac_addr), 32), "vendor": vendor_info, "hostname": hostname, "os": os_info}
                    time.sleep(0.5)
                print("---------------------------------------------------------------------------------------------------------")

                previous = load_history()
                new_ips, missing_ips = compare_history(current_devices, previous, get_local_ip())
                if previous:
                    if new_ips:
                        print(RED + _t("new_device") + RESET)
                        for ip in new_ips:
                            print(f"    -> {ip} ({current_devices[ip]['mac']})")
                    if missing_ips:
                        print(YELLOW + _t("missing_device") + RESET)
                        for ip in missing_ips:
                            print(f"    -> {ip}")
                # إخفاء هوية جهازك قبل التخزين في السجل/التقرير
                safe_devices = redact_local_identity(current_devices, get_local_ip())
                save_history(safe_devices)
                SESSION_DATA["network_scans"].append({
                    "timestamp": datetime.datetime.now().isoformat(),
                    "devices": safe_devices,
                    "new_devices": list(new_ips)
                })

            elif choice == '2':
                target_url = input(BLUE + _t("web_prompt") + RESET)
                scan_website(target_url)

            elif choice == '3':
                print(CYAN + _t("port_target_mode") + RESET)
                target_mode = input(YELLOW + "\n> " + RESET).strip()
                if target_mode == '2':
                    found_devices = show_connected_devices()
                    if not found_devices:
                        continue
                    pick = input(BLUE + _t("pick_device") + RESET).strip()
                    if pick.isdigit() and 1 <= int(pick) <= len(found_devices):
                        target_ip = found_devices[int(pick) - 1][0]
                    elif pick and (validate_domain(pick) or _is_safe_ip(pick.strip('[]'))):
                        target_ip = pick
                    else:
                        print(RED + _t("invalid_choice") + RESET)
                        continue
                else:
                    target_ip = input(BLUE + _t("port_prompt") + RESET)
                    if not (validate_domain(target_ip) or _is_safe_ip(target_ip.strip('[]'))):
                        print(RED + _t("port_bad_target") + RESET)
                        continue
                print(_t("port_profile_prompt"))
                profile_choice = input(YELLOW + "\n> " + RESET).strip()
                if profile_choice == '2':
                    ports_to_scan = list(EXTENDED_PORTS.keys())
                elif profile_choice == '3':
                    custom_raw = input(BLUE + _t("port_custom_prompt") + RESET)
                    ports_to_scan = parse_port_input(custom_raw)
                    if not ports_to_scan:
                        print(RED + _t("invalid_choice") + RESET)
                        continue
                    if len(ports_to_scan) > MAX_CUSTOM_PORTS:
                        ports_to_scan = ports_to_scan[:MAX_CUSTOM_PORTS]
                        print(YELLOW + _t("port_limited", MAX_CUSTOM_PORTS) + RESET)
                else:
                    ports_to_scan = list(COMMON_PORTS.keys())
                port_scanner(target_ip, ports_to_scan)

            elif choice == '4':
                export_report()

            else:
                print(RED + _t("invalid_choice") + RESET)

    except KeyboardInterrupt:
        print(YELLOW + _t("ctrl_c") + RESET)
    except EOFError:
        # stdin مغلق/موجّه: بدون هذا يظهر traceback قبيح بدل رسالة واضحة
        print(YELLOW + _t("eof_exit") + RESET)

    finally:
        disable_ghost_mode()
        elapsed_time = round(time.time() - start_time, 2)
        print(GREEN + _t("goodbye").replace("!", f" ({elapsed_time}s)!") + RESET)
        sys.exit(0)


if __name__ == "__main__":
    main()
