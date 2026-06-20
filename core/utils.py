import os
import sys
import time
import socket
import ipaddress
import subprocess
from datetime import datetime

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"

BANNER = f"""
{GREEN}{BOLD}
╔══════════════════════════════════════════════════════╗
║  █▀▄▀█  ▀█▀  ▄▄   █▀█  ▀▄▀  █▄░█  █▀▀  ▀█▀  █▄▀  ║
║  █░▀░█  ░█░  ░░   █▀▀  █░█  █░▀█  ██▄  ░█░  █░█  ║
║                                                      ║
║     {YELLOW}MikroTik Security Auditor v1.0{RST}{GREEN}{BOLD}                   ║
║     {DIM}RT/RW Net Pentest Toolkit{RST}{GREEN}{BOLD}                        ║
╚══════════════════════════════════════════════════════╝{RST}

"""

LEGAL = f"""{RED}[!] PERINGATAN HUKUM{RST}
Tools ini hanya boleh digunakan pada jaringan yang ANDA MILIKI SENDIRI
atau jaringan di mana Anda MENDAPAT IZIN TERTULIS dari pemiliknya.

Penggunaan tanpa izin adalah TINDAK PIDANA yang melanggar:
- UU ITE No. 19 Tahun 2016 Pasal 30 & 46 (Indonesia)
- Computer Fraud and Abuse Act (Internasional)

{DIM}Dengan melanjutkan, Anda bertanggung jawab penuh atas penggunaan tools ini.{RST}
"""

MIKROTIK_OUI = [
    "D4:CA:6D", "4C:5E:0C", "6C:3B:6B", "00:0C:42",
    "E4:8D:8C", "CC:2D:E0", "B8:69:F4", "74:4D:28",
    "2C:C8:1B", "08:55:31", "DC:2C:6E", "C4:AD:34",
    "64:D1:54", "78:9A:18", "0C:27:24", "B0:BE:76",
]

MIKROTIK_MNDP_MULTICAST = "224.0.0.1"
MNDP_PORT = 5678
MNDP_MAGIC = b"\x00\x00"


def legal_check():
    print(BANNER)
    print(LEGAL)
    print(f"{YELLOW}{'─'*58}{RST}")
    try:
        ans = input(f"\n{YELLOW}[?] Anda setuju & bertanggung jawab? (ya/tidak): {RST}").strip().lower()
        if ans not in ("ya", "y", "yes"):
            print(f"{RED}[!] Dibatalkan oleh user.{RST}")
            sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Dibatalkan.{RST}")
        sys.exit(0)
    print()


def info(msg):
    print(f"{BLUE}[*]{RST} {msg}")


def ok(msg):
    print(f"{GREEN}[+]{RST} {msg}")


def warn(msg):
    print(f"{YELLOW}[!]{RST} {msg}")


def error(msg):
    print(f"{RED}[-]{RST} {msg}")


def kritikal(msg):
    print(f"{RED}{BOLD}[!!] KRITIS: {msg}{RST}")


def section(title):
    print(f"\n{CYAN}{'─'*55}{RST}")
    print(f"{CYAN}{BOLD}  {title}{RST}")
    print(f"{CYAN}{'─'*55}{RST}\n")


def validate_ip(ip_str):
    try:
        return str(ipaddress.ip_address(ip_str))
    except ValueError:
        return None


def validate_subnet(subnet_str):
    try:
        net = ipaddress.ip_network(subnet_str, strict=False)
        return str(net)
    except ValueError:
        return None


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def save_report(filename, content):
    os.makedirs("reports", exist_ok=True)
    filepath = os.path.join("reports", filename)
    with open(filepath, "w") as f:
        f.write(content)
    ok(f"Laporan disimpan: reports/{filename}")
    return filepath


def ping_host(ip, timeout=1):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False


def get_arp_table():
    hosts = []
    try:
        result = subprocess.run(
            ["ip", "neigh"], capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "lladdr":
                hosts.append({"ip": parts[0], "mac": parts[3].upper()})
    except Exception:
        pass
    return hosts


def check_mikrotik_mac(mac):
    if not mac:
        return False
    prefix = mac.upper()[:8]
    return any(prefix.upper() == oui.upper() for oui in MIKROTIK_OUI)
