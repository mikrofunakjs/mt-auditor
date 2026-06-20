#!/usr/bin/env python3

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils import (
    info, ok, warn, error, kritikal, section,
    GREEN, RED, YELLOW, CYAN, MAGENTA, BLUE,
    BOLD, DIM, RST, BANNER, LEGAL, validate_ip, timestamp
)
from core.scanner import scan_subnet, quick_scan
from core.port_audit import audit_ports
from core.service_detect import detect_services
from core.cred_test import test_creds
from core.bruteforce import bruteforce_ssh, bruteforce_api
from core.config_parser import parse_and_report
from core.user_audit import audit_users, check_active_sessions
from core.firewall_analyze import analyze_firewall
from core.infra_inspect import inspect_infrastructure
from core.stress import stress_menu
from core.hotspot_exploit import hotspot_menu


def main_menu():
    legal_check()

    target_ip = get_target()

    while True:
        print(f"\n{BOLD}MAIN MENU{RST}")
        print(f"  Target: {CYAN}{target_ip}{RST}")
        print()
        print(f"  {YELLOW}1{RST}) Quick Audit (Recon + Cred Test + Analisis)")
        print(f"  {YELLOW}2{RST}) Full Exploit (Recon -> Exploit -> Post-Exploit -> Report)")
        print(f"  {YELLOW}3{RST}) Recon Only (Scan + Port + Service Detect)")
        print(f"  {YELLOW}4{RST}) Credential Brute Force")
        print(f"  {YELLOW}5{RST}) Stress Test Menu")
        print(f"  {YELLOW}6{RST}) Hotspot Exploit (WiFi Voucher)")
        print(f"  {YELLOW}7{RST}) Ganti Target IP")
        print(f"  {YELLOW}0{RST}) Exit")
        print()

        try:
            choice = input(f"{GREEN}Pilih > {RST}").strip()
        except KeyboardInterrupt:
            print(f"\n{RED}[!] Exit.{RST}")
            sys.exit(0)

        if choice == "0":
            print(f"\n{CYAN}[*] Sampai jumpa!{RST}")
            sys.exit(0)

        elif choice == "1":
            run_quick_audit(target_ip)

        elif choice == "2":
            run_full_exploit(target_ip)

        elif choice == "3":
            run_recon(target_ip)

        elif choice == "4":
            run_bruteforce(target_ip)

        elif choice == "5":
            stress_menu(target_ip)

        elif choice == "6":
            run_hotspot_exploit(target_ip)

        elif choice == "7":
            target_ip = get_target()

        else:
            warn(f"Pilihan tidak valid: {choice}")


def legal_check():
    print(BANNER)
    print(LEGAL)
    print(f"{YELLOW}{'─'*58}{RST}")
    while True:
        try:
            ans = input(f"\n{YELLOW}[?] Anda setuju & bertanggung jawab? (ya/tidak): {RST}").strip().lower()
            if ans in ("ya", "y", "yes"):
                break
            elif ans in ("tidak", "n", "no"):
                print(f"{RED}[!] Dibatalkan oleh user.{RST}")
                sys.exit(0)
        except KeyboardInterrupt:
            print(f"\n{RED}[!] Dibatalkan.{RST}")
            sys.exit(0)
    print()


def get_target():
    while True:
        try:
            ip = input(f"{YELLOW}[?] Target IP / Subnet > {RST}").strip()
            if not ip:
                continue
            if "/" in ip:
                from core.utils import validate_subnet
                if validate_subnet(ip):
                    info(f"Subnet: {ip}")
                    return ip
                else:
                    error("Subnet tidak valid.")
            elif validate_ip(ip):
                info(f"Target: {ip}")
                return ip
            else:
                error("IP tidak valid.")
        except KeyboardInterrupt:
            print(f"\n{RED}[!] Exit.{RST}")
            sys.exit(0)


def run_quick_audit(target_ip):
    section("QUICK AUDIT")

    services_found = []
    credentials_found = []

    if "/" in target_ip:
        mikrotik_hosts = scan_subnet(target_ip)
        if not mikrotik_hosts:
            warn("Tidak ada MikroTik terdeteksi, scan host pertama yang hidup...")
            time.sleep(1)
            return
        target_ip = mikrotik_hosts[0]["ip"]
        info(f"Menggunakan MikroTik pertama: {target_ip}")

    open_ports = audit_ports(target_ip)
    if open_ports:
        services_found = detect_services(target_ip, open_ports)

    if services_found:
        credentials_found = test_creds(target_ip, services_found)

    if credentials_found:
        info("Menganalisis konfigurasi (post-exploit) ...")
        time.sleep(0.5)
        parse_and_report(target_ip, credentials_found, services_found)

    generate_audit_summary(target_ip, open_ports, services_found, credentials_found)


def run_full_exploit(target_ip):
    section("FULL EXPLOIT MODE")

    services_found = []
    credentials_found = []

    if "/" in target_ip:
        mikrotik_hosts = scan_subnet(target_ip)
        if not mikrotik_hosts:
            error("Tidak ada MikroTik terdeteksi.")
            return
        target_ip = mikrotik_hosts[0]["ip"]
        info(f"Menggunakan MikroTik pertama: {target_ip}")

    open_ports = audit_ports(target_ip, timeout=1.5)
    if open_ports:
        services_found = detect_services(target_ip, open_ports)

    if services_found:
        credentials_found = test_creds(target_ip, services_found)

    if credentials_found:
        info("Login berhasil — menjalankan Post-Exploit modules ...")
        time.sleep(1)

        parse_and_report(target_ip, credentials_found, services_found)
        audit_users(target_ip, credentials_found, services_found)
        check_active_sessions(target_ip, credentials_found, services_found)
        analyze_firewall(target_ip, credentials_found, services_found)
        inspect_infrastructure(target_ip, credentials_found, services_found)

        if any(p["port"] in [80, 443] for p in open_ports):
            print()
            info("Port HTTP/HTTPS terbuka — menjalankan Hotspot Exploit...")
            time.sleep(0.5)
            from core.hotspot_exploit import login_page_analyzer
            login_page_analyzer(target_ip, any(p["port"] == 443 for p in open_ports))
    else:
        warn("Login gagal — hanya menjalankan recon.")
        ok("Gunakan menu (4) untuk brute force credential.")

    generate_audit_summary(target_ip, open_ports, services_found, credentials_found)


def run_recon(target_ip):
    section("RECON MODE")

    services_found = []

    if "/" in target_ip:
        mikrotik_hosts = scan_subnet(target_ip)
        if not mikrotik_hosts:
            return
        target_ip = mikrotik_hosts[0]["ip"]
        info(f"Menggunakan MikroTik pertama: {target_ip}")

    open_ports = audit_ports(target_ip)
    if open_ports:
        services_found = detect_services(target_ip, open_ports)

    generate_audit_summary(target_ip, open_ports, services_found, [])


def run_bruteforce(target_ip):
    section("BRUTE FORCE MENU")

    if "/" in target_ip:
        error("Brute force hanya untuk single IP, bukan subnet.")
        return

    print(f"  Target: {CYAN}{target_ip}{RST}")
    print()
    print(f"  {YELLOW}1{RST}) SSH Brute Force")
    print(f"  {YELLOW}2{RST}) API Brute Force")
    print(f"  {YELLOW}0{RST}) Kembali")
    print()

    try:
        choice = input(f"{GREEN}Pilih > {RST}").strip()
    except KeyboardInterrupt:
        return

    if choice == "1":
        username = input("  Username (default: admin): ").strip() or "admin"
        wordlist = input("  Wordlist file (default: common_passwords.txt): ").strip() or "common_passwords.txt"
        threads = input("  Threads (default: 5): ").strip() or "5"
        result = bruteforce_ssh(
            target_ip, 22, username,
            wordlist_file=wordlist,
            max_threads=int(threads)
        )
        if result:
            ok(f"Credential valid: {result['username']}:{result['password']}")

    elif choice == "2":
        username = input("  Username (default: admin): ").strip() or "admin"
        port = int(input("  API Port (default: 8728): ").strip() or "8728")
        wordlist = input("  Wordlist file (default: common_passwords.txt): ").strip() or "common_passwords.txt"
        threads = input("  Threads (default: 5): ").strip() or "5"
        result = bruteforce_api(
            target_ip, port, username,
            wordlist_file=wordlist,
            max_threads=int(threads)
        )
        if result:
            ok(f"Credential valid: {result['username']}:{result['password']}")


def run_hotspot_exploit(target_ip):
    section("HOTSPOT EXPLOIT")

    if "/" in target_ip:
        mikrotik_hosts = scan_subnet(target_ip)
        if not mikrotik_hosts:
            error("Tidak ada host terdeteksi.")
            return
        target_ip = mikrotik_hosts[0]["ip"]
        info(f"Menggunakan: {target_ip}")

    open_ports = audit_ports(target_ip)
    services_found = []
    credentials_found = []

    if open_ports:
        services_found = detect_services(target_ip, open_ports)

    if services_found:
        info("Mencoba login dengan default credential...")
        credentials_found = test_creds(target_ip, services_found)

    hotspot_menu(target_ip, open_ports, credentials_found)


def generate_audit_summary(ip, open_ports, services, credentials):
    section("AUDIT SUMMARY")

    total_issues = 0
    findings = []

    if not open_ports:
        ok("Tidak ada port terbuka — host mungkin mati atau firewall sangat ketat.")
        return

    port_bahaya = [p for p in open_ports if p["port"] in [21, 23, 80, 443, 8291, 8728, 8729]]
    if port_bahaya:
        total_issues += 1
        findings.append(f"{len(port_bahaya)} port berbahaya terbuka (FTP, Telnet, WebFig, Winbox, API)")

    if credentials:
        total_issues += 1
        findings.append(f"Kredensial default/lemah ditemukan: {len(credentials)} akun")

    if findings:
        warn(f"Ditemukan {total_issues} isu keamanan:")
        for f in findings:
            print(f"    {RED}-> {f}{RST}")
        print()
        print(f"  {YELLOW}REKOMENDASI:{RST}")
        if any(p["port"] in [21, 23] for p in open_ports):
            print(f"    - Nonaktifkan FTP dan Telnet (gunakan SSH saja)")
        if any(p["port"] in [8291] for p in open_ports):
            print(f"    - Batasi Winbox hanya dari IP tertentu (MAC-based filtering)")
        if any(p["port"] in [8728, 8729] for p in open_ports):
            print(f"    - Nonaktifkan API jika tidak dipakai, atau batasi akses")
        if credentials:
            print(f"    - Ganti semua default password segera!")
        if not credentials and any(p["port"] in [22, 8728] for p in open_ports):
            print(f"    - Gunakan password kuat (min 12 char, campuran)")
    else:
        ok("Tidak ditemukan isu kritis dari quick scan.")
        if any(p["port"] in [22, 443] for p in open_ports):
            info("Port SSH/HTTPS terbuka — pastikan pakai password kuat & non-standar.")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Dibatalkan.{RST}")
        sys.exit(0)
