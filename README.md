# MikroTik Security Auditor v1.0

Toolkit audit keamanan MikroTik untuk RT/RW Net. Cari celah lalu amankan.

> **Peringatan:** Hanya gunakan pada jaringan milik sendiri!

## Alur Kerja

```
RECON → EXPLOIT → POST-EXPLOIT
```

## Fitur (10 Modul)

| # | Modul | Fungsi |
|---|-------|--------|
| 1 | Subnet Scanner | Ping sweep + deteksi MikroTik (MAC OUI, port signature) |
| 2 | Port Auditor | Scan 20 port khas MikroTik |
| 3 | Service Detector | Fingerprint service (SSH/API/WebFig/Winbox) |
| 4 | Credential Tester | Cek default/weak password via SSH, API, HTTP |
| 5 | Brute Forcer | Brute force SSH & API multithread |
| 6 | Config Parser | Export & analisis konfig via MikroTik API |
| 7 | User Auditor | Audit user + cek password strength |
| 8 | Firewall Analyzer | Analisis firewall rules (INPUT, FORWARD, NAT) |
| 9 | Infra Inspector | DNS, DHCP, PPP, Hotspot, Interface |
| 10 | Stress Tester | TCP flood, HTTP flood, Slowloris simulator |

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
├── mt.py              # CLI menu utama
├── install.sh         # Auto-installer (Termux & Linux)
├── run.sh             # Quick run
├── core/
│   ├── scanner.py     # Subnet scanner
│   ├── port_audit.py  # Port scanner
│   ├── service_detect.py
│   ├── cred_test.py   # Password tester
│   ├── bruteforce.py  # SSH/API brute force
│   ├── config_parser.py
│   ├── user_audit.py
│   ├── firewall_analyze.py
│   ├── infra_inspect.py
│   └── stress.py      # Stress tester
├── wordlists/
│   ├── mikrotik_defaults.txt
│   └── common_passwords.txt
├── reports/           # Output laporan
└── requirements.txt
```

## License

For educational & authorized security testing only.
