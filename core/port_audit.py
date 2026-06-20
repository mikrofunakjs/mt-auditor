import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import info, ok, warn, error, section, GREEN, YELLOW, RED, CYAN, RST

PORTS_MIKROTIK = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP (WebFig)",
    443: "HTTPS (WebFig SSL)",
    53: "DNS",
    161: "SNMP",
    123: "NTP",
    139: "NetBIOS",
    445: "SMB",
    514: "Syslog",
    1194: "OpenVPN",
    1723: "PPTP",
    2000: "Bandwidth Test",
    5060: "SIP",
    5678: "MNDP",
    8080: "HTTP Proxy",
    8291: "Winbox",
    8728: "API",
    8729: "API-SSL",
}

PORTS_STANDARD = list(PORTS_MIKROTIK.keys())


def scan_port(ip, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            service = PORTS_MIKROTIK.get(port, f"port-{port}")
            return {"port": port, "service": service, "open": True}
        return None
    except Exception:
        return None


def audit_ports(ip, ports=None, timeout=1.0, max_workers=20):
    section(f"PORT AUDIT: {ip}")

    if ports is None:
        ports = PORTS_STANDARD

    info(f"Scanning {len(ports)} port MikroTik pada {ip} ...")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda x: x["port"])

    print()
    if not results:
        warn("Tidak ada port terdeteksi (mungkin host mati atau firewall ketat).")
        return results

    berbahaya = [8291, 8728, 8729, 21, 23, 80]
    count_berbahaya = 0

    for r in results:
        port = r["port"]
        svc = r["service"]
        if port in berbahaya:
            color = RED
            count_berbahaya += 1
        else:
            color = GREEN
        print(f"  {color}{port:>6}/tcp{'}': <10} {svc}{RST}")

    print()
    ok(f"Total port terbuka: {len(results)}")
    if count_berbahaya > 0:
        warn(f"{count_berbahaya} port berbahaya terdeteksi!")

    return results
