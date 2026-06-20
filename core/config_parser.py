import time
from .utils import (
    info, ok, warn, error, kritikal, section,
    GREEN, RED, YELLOW, CYAN, RST, BOLD, DIM, save_report, timestamp
)


def connect_api(ip, port, username, password):
    try:
        from librouteros import connect
    except ImportError:
        error("librouteros tidak terinstall. Run: pip install librouteros")
        return None
    try:
        api = connect(host=ip, port=port, username=username, password=password, timeout=8)
        return api
    except Exception as e:
        error(f"Gagal konek API: {e}")
        return None


def export_config(api):
    info("Mengexport full config via API ...")
    try:
        cmd = api("/export")
        lines = []
        for row in cmd:
            lines.append(row)
        return lines
    except Exception as e:
        error(f"Export gagal: {e}")
        return []


def parse_and_report(ip, credentials, services_found):
    section(f"KONFIGURASI ANALYZER: {ip}")

    cred = credentials[0] if credentials else None
    if not cred:
        error("Butuh kredensial valid untuk analisis konfigurasi.")
        return

    has_api = any(s["port"] in [8728, 8729] for s in services_found)
    api_port = 8728
    if has_api:
        for s in services_found:
            if s["port"] in [8728, 8729]:
                api_port = s["port"]
                break
    else:
        error("API port tidak terbuka.")
        return

    api = connect_api(ip, api_port, cred["username"], cred["password"])
    if not api:
        return

    ok(f"Terhubung ke MikroTik API pada {ip}:{api_port}")

    config_data = export_config(api)

    try:
        api.close()
    except Exception:
        pass

    if not config_data:
        warn("Tidak bisa export config, mencoba resource individual ...")
        api2 = connect_api(ip, api_port, cred["username"], cred["password"])
        if api2:
            findings = check_individual_resources(api2)
            api2.close()
            return findings
        return

    report_lines = []
    report_lines.append(f"# MikroTik Security Audit Report")
    report_lines.append(f"# Target: {ip}")
    report_lines.append(f"# Waktu: {timestamp()}")
    report_lines.append(f"#")
    report_lines.append("")

    findings = {
        "issues": [],
        "warnings": [],
        "info": [],
    }

    config_text = ""
    for line in config_data:
        if isinstance(line, str):
            config_text += line + "\n"
        else:
            text = line.get("ret", line.get("message", str(line)))
            config_text += text if isinstance(text, str) else str(text)

    rules = config_text.split("\n")
    report_lines.append("## Full Config (ringkasan)")
    report_lines.append("")
    for line in rules[:500]:
        report_lines.append(f"  {line}")

    check_common_issues(config_text, findings)

    report_lines.append("")
    report_lines.append("## Temuan")
    report_lines.append("")

    if findings["issues"]:
        for f in findings["issues"]:
            kritikal(f)
            report_lines.append(f"[KRITIS] {f}")

    if findings["warnings"]:
        for f in findings["warnings"]:
            warn(f)
            report_lines.append(f"[WARNING] {f}")

    if findings["info"]:
        for f in findings["info"]:
            info(f)
            report_lines.append(f"[INFO] {f}")

    filename = f"{ip}_{timestamp()}.txt"
    save_report(filename, "\n".join(report_lines))

    return findings


def check_common_issues(config_text, findings):
    config_lower = config_text.lower()

    if "add chain=input action=accept" in config_lower:
        findings["issues"].append("Firewall INPUT chain: ACCEPT dari ANY! Sangat berbahaya.")

    if "add chain=forward action=accept" in config_lower:
        findings["warnings"].append("Firewall FORWARD chain: ACCEPT all traffic.")

    if "password=\"\"" in config_text or "password=''" in config_text:
        findings["issues"].append("Ditemukan user dengan password KOSONG!")

    if "password=\"admin\"" in config_lower or "password='admin'" in config_lower:
        findings["issues"].append("Password user masih 'admin' (default)!")

    if "password=\"1234" in config_lower or "password=\"123456" in config_lower:
        findings["issues"].append("Password user terlalu lemah (1234/123456)!")

    if "allow-remote-requests=yes" in config_lower:
        findings["warnings"].append("DNS: allow-remote-requests=yes (bisa DNS amplification attack)")

    if "/ip service enable 0" in config_lower or "name=telnet" in config_lower and "disabled=no" in config_lower:
        findings["warnings"].append("Telnet service mungkin aktif (tidak aman!)")

    if "/ip service enable 4" in config_lower or "name=ftp" in config_lower and "disabled=no" in config_lower:
        findings["warnings"].append("FTP service mungkin aktif (tidak aman!)")

    if "name=api" in config_lower and "disabled=no" in config_lower:
        findings["info"].append("API service aktif. Pastikan hanya accessible dari LAN.")

    if "name=winbox" in config_lower and "disabled=no" in config_lower:
        findings["info"].append("Winbox service aktif.")

    if "address-pool=dhcp" in config_lower:
        findings["info"].append("DHCP server aktif.")

    if "/ip firewall nat" not in config_lower:
        findings["info"].append("Tidak ada NAT rules ditemukan (mungkin default config).")

    if "add action=masquerade" not in config_lower:
        findings["warnings"].append("Masquerade tidak ditemukan — client mungkin tidak bisa akses internet.")


def check_individual_resources(api):
    findings = {"issues": [], "warnings": [], "info": []}

    try:
        users = api("/user/print")
        info(f"User ditemukan: {len(users)}")
        for u in users:
            name = u.get("name", "?")
            group = u.get("group", "?")
            disabled = u.get("disabled", "false")
            if name == "admin" and disabled != "true":
                findings["warnings"].append(f"User 'admin' aktif dengan group '{group}'")
            print(f"  {CYAN}User: {name:<15} Group: {group:<10} Disabled: {disabled}{RST}")
    except Exception as e:
        warn(f"Gagal membaca /user: {e}")

    try:
        services = api("/ip/service/print")
        for svc in services:
            name = svc.get("name", "?")
            disabled = svc.get("disabled", "true")
            port = svc.get("port", "?")
            if name in ("telnet", "ftp") and disabled != "true":
                findings["warnings"].append(f"Service {name} aktif di port {port}!")
    except Exception:
        pass

    return findings
