import os
import sys
import socket
import time
from .utils import (
    info, ok, warn, error, kritikal, section,
    GREEN, RED, YELLOW, CYAN, RST, BOLD
)

WORDLIST_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists")


def load_wordlist(filename):
    path = os.path.join(WORDLIST_DIR, filename)
    credentials = []
    if not os.path.exists(path):
        return credentials
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                user, pwd = line.split(":", 1)
                credentials.append((user.strip(), pwd.strip()))
    return credentials


def try_ssh(ip, port, username, password, timeout=5):
    try:
        import paramiko
    except ImportError:
        return None

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip, port=port, username=username, password=password,
            timeout=timeout, allow_agent=False, look_for_keys=False,
            banner_timeout=5
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return None


def try_api(ip, port, username, password, timeout=5):
    try:
        from librouteros import connect
    except ImportError:
        return None

    try:
        api = connect(
            host=ip, port=port, username=username,
            password=password, timeout=timeout
        )
        api.close()
        return True
    except Exception:
        return False


def try_http(ip, port, username, password, timeout=5, ssl=False):
    try:
        import requests
    except ImportError:
        return None

    try:
        scheme = "https" if ssl else "http"
        url = f"{scheme}://{ip}:{port}/"
        r = requests.get(url, auth=(username, password), timeout=timeout, verify=False)
        if r.status_code == 200:
            return True
        if r.status_code == 401:
            return False
        return None
    except Exception:
        return None


def test_creds(ip, services_found):
    section(f"CREDENTIAL TESTER: {ip}")
    info("Memuat wordlist default MikroTik ...")

    credentials = load_wordlist("mikrotik_defaults.txt")
    info(f"{len(credentials)} kombinasi username:password dimuat.\n")

    has_ssh = any(s["port"] == 22 for s in services_found)
    has_api = any(s["port"] == 8728 for s in services_found)
    has_api_ssl = any(s["port"] == 8729 for s in services_found)
    has_http = any(s["port"] == 80 for s in services_found)
    has_https = any(s["port"] == 443 for s in services_found)

    successful = []

    for username, password in credentials:
        results = []
        prefix = f"  {username}:{password[:8]:<8}"

        if has_ssh:
            ok_ssh = f"? SSH({prefix})"  # placeholder
            ...
        # TODO: Skip for now, continue below

    # Simplify: test all services
    for username, password in credentials:
        cred_str = f"{username}:{password}"
        print(f"  {DIM}[*] Testing {cred_str:<25}{RST}", end="")

        success_services = []

        if has_ssh:
            r = try_ssh(ip, 22, username, password)
            if r is True:
                success_services.append("SSH")
            elif r is False:
                print(f"\r{CYAN}  [x] {cred_str:<20} -> SSH: auth failed{RST}")
            else:
                pass

        if has_api:
            r = try_api(ip, 8728, username, password)
            if r:
                success_services.append("API")

        if has_api_ssl:
            r = try_api(ip, 8729, username, password)
            if r:
                success_services.append("API-SSL")

        if has_http:
            r = try_http(ip, 80, username, password)
            if r is True:
                success_services.append("WebFig(HTTP)")
            elif r is False:
                pass

        if has_https:
            r = try_http(ip, 443, username, password, ssl=True)
            if r is True:
                success_services.append("WebFig(HTTPS)")
            elif r is False:
                pass

        if success_services:
            print(f"\r{GREEN}{BOLD}  [✓] BERHASIL! {cred_str:<20} -> {', '.join(success_services)}{RST}")
            successful.append({
                "username": username,
                "password": password,
                "services": success_services,
            })
        else:
            print(f"\r{DIM}  [-] {cred_str:<20} -> Gagal{RST}")

        time.sleep(0.1)  # rate limit

    print()
    if successful:
        kritikal(f"{len(successful)} credential ditemukan!")
        for s in successful:
            print(f"    {RED}Username: {s['username']}, Password: {s['password']}{RST}")
            print(f"    Service: {', '.join(s['services'])}")
    else:
        ok("Tidak ada default credential yang berfungsi.")

    return successful


def quick_cred_check(ip, username, password):
    results = []
    info(f"Quick check: {username}:{password} pada {ip}")

    if try_ssh(ip, 22, username, password):
        ok("SSH: Berhasil!")
        results.append("SSH")

    if try_api(ip, 8728, username, password):
        ok("API: Berhasil!")
        results.append("API")

    if try_http(ip, 80, username, password):
        ok("WebFig HTTP: Berhasil!")
        results.append("WebFig")

    return results
