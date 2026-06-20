import socket
import ssl
from .utils import info, ok, warn, error, section, GREEN, RED, YELLOW, RST

SERVICE_SIGNATURES = {
    "SSH": b"SSH",
    "Telnet": b"Telnet",
    "FTP": b"FTP",
    "SMTP": b"SMTP",
    "HTTP": b"HTTP",
}


def grab_banner(ip, port, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if port == 443 or port == 8729:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ssock = ctx.wrap_socket(sock, server_hostname=ip)
                ssock.settimeout(2.0)
                data = ssock.recv(1024)
                ssock.close()
            except Exception:
                sock.close()
                return None
        else:
            try:
                if port == 80 or port == 8080:
                    sock.send(b"GET / HTTP/1.0\r\n\r\n")
                sock.settimeout(1.5)
                data = sock.recv(1024)
                sock.close()
            except Exception:
                sock.close()
                return None

        if not data:
            return None

        banner = data[:200]
        try:
            text = banner.decode("utf-8", errors="ignore").strip()
            text = text.replace("\r\n", " ").replace("\n", " ")
        except Exception:
            text = repr(banner)

        return text[:200]
    except Exception:
        return None


def identify_service(ip, port, banner):
    if not banner:
        return "unknown"

    banner_upper = banner.upper()

    if port == 8291:
        return "Winbox"
    if port == 8728 or port == 8729:
        return "MikroTik API"

    if port == 22 or "SSH" in banner_upper:
        return "SSH Server"
    if port == 23 or "TELNET" in banner_upper:
        return "Telnet Server"
    if port == 21 or "FTP" in banner_upper:
        return "FTP Server"
    if port == 80 or port == 8080 or port == 443:
        if "RouterOS" in banner:
            return "MikroTik WebFig"
        if "HTTP" in banner_upper or "HTML" in banner_upper:
            return "HTTP Server"
        return "Web Server (unknown)"

    for sig, name in SERVICE_SIGNATURES.items():
        if sig.encode() in banner.encode("utf-8", errors="ignore"):
            return f"{name} (signature match)"

    return "unknown"


def detect_services(ip, open_ports):
    section(f"SERVICE DETECTION: {ip}")
    info(f"Mendeteksi service pada {len(open_ports)} port terbuka ...")

    results = []
    for entry in open_ports:
        port = entry["port"]
        info(f"  Port {port}/tcp ...", end="")
        banner = grab_banner(ip, port)
        service = identify_service(ip, port, banner or "")

        result = {
            "port": port,
            "service": service,
            "banner": banner,
        }

        if service != "unknown":
            ok(f" -> {service}")
        else:
            warn(f" -> Tidak teridentifikasi")

        results.append(result)

    return results
