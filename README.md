# MikroTik Security Auditor v1.0

Toolkit audit keamanan MikroTik untuk RT/RW Net. Cari celah lalu amankan.

> **Peringatan:** Hanya gunakan pada jaringan milik sendiri!

## Alur Kerja

```
RECON → EXPLOIT → POST-EXPLOIT
```

## Fitur (10 Core + 9 Hotspot Exploit)

| # | Core Modul | Fungsi |
|---|-----------|--------|
| 1 | Subnet Scanner | Ping sweep + deteksi MikroTik (MAC OUI, MNDP, port signature) |
| 2 | Port Auditor | Scan 20 port khas MikroTik (multithread) |
| 3 | Service Detector | Fingerprint service: SSH/API/WebFig/Winbox/FTP/Telnet |
| 4 | Credential Tester | Default/weak password via SSH + API + HTTP |
| 5 | Brute Forcer | Brute force SSH & MikroTik API multithread |
| 6 | Config Parser | Export full config via API + auto analisis isu keamanan |
| 7 | User Auditor | Audit user list + cek password strength + active sessions |
| 8 | Firewall Analyzer | Analisis INPUT/FORWARD/NAT rules + deteksi miskonfigurasi |
| 9 | Infra Inspector | DNS, DHCP, PPPoE, Hotspot server, Interfaces |
| 10 | Stress Tester | TCP connect flood, HTTP GET flood, Slowloris simulator |

### Hotspot Exploit (WiFi Voucher) — 9 Attack Vectors

| # | Sub-Modul | Vektor Serangan |
|---|-----------|----------------|
| 1 | Login Page Analyzer | HTTP vs HTTPS, Captcha, CSRF token, open redirect, sensitive endpoints, REST API probe |
| 2 | HTTP Sniff Test | Deteksi kredensial plaintext + panduan ARP spoof + bettercap |
| 3 | Walled Garden Bypass | DNS tunnel, DoH bypass, TCP direct test, domain whitelist enumeration |
| 4 | Voucher Bruteforce | Pattern analysis (sequential, date, dictionary, random) + multithread POST |
| 5 | Trial MAC Bypass | MAC rotation script + trial endpoint detector |
| 6 | Session Hijack | Cookie analysis (Secure, HttpOnly) + replay attack scenario |
| 7 | API Voucher Generator | Via librouteros: buat voucher, list profiles, active sessions, cookies |
| 8 | Winbox File Read | CVE-2018-14847: directory traversal baca user.dat tanpa auth |
| 9 | REST API Probe | RouterOS v7+ /rest/ endpoint enumeration + config export |

## Quick Install

### Termux (Android)
```bash
git clone https://github.com/mikrofunakjs/mt-auditor.git
cd mt-auditor
bash install.sh    # auto-install dependencies
bash run.sh        # jalankan tools
```

### Linux Desktop
```bash
git clone https://github.com/mikrofunakjs/mt-auditor.git
cd mt-auditor
bash install.sh    # pilih opsi [2]
bash run.sh
```

## Manual Install (Termux)

```bash
# Step 1: cryptography + Rust (binary, no compile needed)
pkg install python-cryptography rust binutils -y

# Step 2: sisanya via pip
pip install paramiko requests librouteros rich

# Step 3: jalankan
python mt.py
```

## Menu CLI

```
[1] Quick Audit (Recon + Cred Test + Analisis)
[2] Full Exploit (Recon -> Exploit -> Post-Exploit -> Report)
[3] Recon Only (Scan + Port + Service Detect)
[4] Credential Brute Force
[5] Stress Test Menu
[6] Ganti Target IP
[0] Exit
```

## Struktur

```
mt-auditor/
├── mt.py              # CLI menu utama (6 option + hotspot sub-menu)
├── install.sh         # Auto-installer (Termux & Linux)
├── run.sh             # Quick run + dependency check
├── core/
│   ├── scanner.py     # Subnet scanner + MikroTik detection
│   ├── port_audit.py  # Port scanner 20 port khas
│   ├── service_detect.py  # Service banner grab + fingerprint
│   ├── cred_test.py   # Default/weak password tester
│   ├── bruteforce.py  # SSH & API brute force
│   ├── config_parser.py   # MikroTik config export + analyzer
│   ├── user_audit.py  # User enumeration + weakness check
│   ├── firewall_analyze.py # Firewall rule audit
│   ├── infra_inspect.py    # DNS/DHCP/PPP/Hotspot inspection
│   ├── stress.py      # TCP/HTTP flood + Slowloris
│   └── hotspot_exploit.py  # 9 WiFi voucher attack vectors
├── wordlists/
│   ├── mikrotik_defaults.txt  # 25 default MikroTik passwords
│   └── common_passwords.txt   # 50 weak passwords
├── reports/           # Output laporan audit
├── requirements.txt
├── README.md
└── .gitignore
```

## License

For educational & authorized security testing only.
