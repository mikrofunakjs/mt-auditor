import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import (
    ping_host, get_arp_table, check_mikrotik_mac,
    info, ok, warn, error, section, validate_subnet, get_local_ip,
    CYAN, RST
)

MIKROTIK_PORTS = [80, 443, 8291, 8728, 8729, 21, 22, 23]


def cek_port_mikrotik(ip, port, timeout=1):
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def scan_single_host(ip, fast=True):
    host = {
        "ip": ip,
        "alive": False,
        "is_mikrotik": False,
        "mikrotik_evidence": [],
        "mac": None,
    }

    if not ping_host(ip, timeout=1):
        return host

    host["alive"] = True

    arp_table = get_arp_table()
    for entry in arp_table:
        if entry["ip"] == ip:
            host["mac"] = entry["mac"]
            break

    if host["mac"] and check_mikrotik_mac(host["mac"]):
        host["is_mikrotik"] = True
        host["mikrotik_evidence"].append(f"MAC OUI: {host['mac']}")

    open_ports = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(cek_port_mikrotik, ip, p, 0.8): p for p in MIKROTIK_PORTS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    if open_ports:
        host["mikrotik_evidence"].append(f"Port terbuka: {open_ports}")
        if any(p in [8291, 8728, 8729] for p in open_ports):
            host["is_mikrotik"] = True
        if 80 in open_ports or 443 in open_ports:
            host["mikrotik_evidence"].append("WebFig/HTTPS mungkin aktif")

    return host


def scan_subnet(target):
    section(f"SCAN SUBNET: {target}")

    net = validate_subnet(target)
    if not net:
        error(f"Subnet tidak valid: {target}")
        return []

    info(f"Scanning {net} ...")
    hosts = list(ipaddress.ip_network(net, strict=False).hosts())
    target_list = [str(h) for h in hosts[:256]]
    target_list.append(str(hosts[0]).rsplit(".", 1)[0] + ".1")

    target_list = list(dict.fromkeys(target_list))

    alive_hosts = []
    mikrotik_hosts = []

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(scan_single_host, ip): ip for ip in target_list}
        done = 0
        total = len(target_list)

        for future in as_completed(futures):
            ip = futures[future]
            done += 1
            try:
                result = future.result()
                if result["alive"]:
                    alive_hosts.append(result)
                    if result["is_mikrotik"]:
                        mikrotik_hosts.append(result)
                        marker = " [MikroTik]"
                    else:
                        marker = ""
                    ok(f"Host ditemukan: {ip}{marker}")
            except Exception as e:
                pass

    print()
    ok(f"Total host hidup: {len(alive_hosts)}")
    if mikrotik_hosts:
        ok(f"MikroTik terdeteksi: {len(mikrotik_hosts)}")
        for mt in mikrotik_hosts:
            print(f"    {CYAN}{mt['ip']}{RST} MAC: {mt.get('mac', '?')}")
            for ev in mt["mikrotik_evidence"]:
                print(f"      {ev}")
    else:
        warn("Tidak ada MikroTik terdeteksi di subnet ini.")

    return mikrotik_hosts


def quick_scan():
    local_ip = get_local_ip()
    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
    info(f"Menggunakan subnet lokal: {subnet}")
    return scan_subnet(subnet)
