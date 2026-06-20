#!/bin/bash
# MikroTik Security Auditor - Installer
# Jalankan: bash install.sh

RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
RST='\033[0m'

echo -e "${GREEN}${BOLD}"
echo "  ╔════════════════════════════════════════════╗"
echo "  ║  MikroTik Security Auditor v1.0           ║"
echo "  ║  Installer Script                         ║"
echo "  ╚════════════════════════════════════════════╝"
echo -e "${RST}"

echo -e "${CYAN}[*] Deteksi environment ...${RST}"

IS_TERMUX=false
if [ -d /data/data/com.termux/files/usr ]; then
    IS_TERMUX=true
    echo -e "${GREEN}[+] Termux terdeteksi${RST}"
else
    echo -e "${YELLOW}[!] Bukan Termux — diasumsikan Linux desktop/server${RST}"
fi

echo ""
echo -e "${CYAN}[*] Update package manager ...${RST}"

if $IS_TERMUX; then
    pkg update -y 2>/dev/null || apt update -y 2>/dev/null || true
else
    if command -v apt &>/dev/null; then
        sudo apt update -y
    fi
fi

echo ""
echo -e "${CYAN}[*] Install Python & pip ...${RST}"

if $IS_TERMUX; then
    pkg install python python-pip -y 2>/dev/null || apt install python python-pip -y 2>/dev/null || true
fi

echo ""
echo -e "${BOLD}${YELLOW}Pilih metode install:${RST}"
echo ""
echo -e "  ${GREEN}1${RST}) Termux — pkg binary + pip (recommended)"
echo -e "  ${GREEN}2${RST}) Linux — pip semua + build tools"
echo -e "  ${GREEN}3${RST}) Tampilkan perintah manual"
echo ""

read -p "$(echo -e "${YELLOW}Pilih [1/2/3] (default: 1): ${RST}")" METHOD
METHOD=${METHOD:-1}

if [ "$METHOD" = "3" ]; then
    echo ""
    echo -e "${CYAN}=== Perintah Manual ===${RST}"
    echo ""
    if $IS_TERMUX; then
        echo "  pkg install python-cryptography rust binutils -y"
        echo "  pip install paramiko requests librouteros rich"
    else
        echo "  sudo apt install python3-dev build-essential libssl-dev -y"
        echo "  pip install cryptography paramiko requests librouteros rich"
    fi
    echo ""
    echo "# Jalankan:"
    echo "  cd $(pwd) && python mt.py"
    exit 0
fi

echo ""

if $IS_TERMUX && [ "$METHOD" != "2" ]; then
    echo -e "${CYAN}[*] Install cryptography via pkg (binary, NO Rust)...${RST}"
    echo -e "  -> pkg install python-cryptography"

    PKG_OK=true
    pkg install python-cryptography -y 2>/dev/null || {
        apt install python-cryptography -y 2>/dev/null || {
            PKG_OK=false
        }
    }

    if ! $PKG_OK; then
        echo ""
        echo -e "${RED}[!] GAGAL: python-cryptography tidak ditemukan di repo pkg.${RST}"
        echo -e "  Coba: ${CYAN}termux-change-repo${RST} (pilih mirror terdekat)"
        echo -e "  Lalu: ${CYAN}pkg update && pkg install python-cryptography${RST}"
        exit 1
    fi

    echo -e "${GREEN}[+] cryptography terinstall (binary)${RST}"

    echo ""
    echo -e "${CYAN}[*] Install Rust compiler (buat bcrypt & pynacl)...${RST}"
    pkg install rust binutils -y 2>/dev/null || apt install rust binutils -y 2>/dev/null || {
        echo -e "${YELLOW}[!] Rust gagal terinstall via pkg, coba manual:${RST}"
        echo -e "    ${CYAN}pkg install rust binutils${RST}"
        exit 1
    }
    echo -e "${GREEN}[+] Rust compiler terinstall${RST}"

    echo ""
    echo -e "${CYAN}[*] Install paramiko + requests via pip ...${RST}"
    pip install paramiko requests 2>/dev/null || pip3 install paramiko requests
else
    echo -e "${CYAN}[*] Install via pip (Linux) ...${RST}"
    echo -e "  -> Install build tools dulu ..."
    if command -v apt &>/dev/null; then
        sudo apt install python3-dev build-essential libssl-dev -y 2>/dev/null || true
    fi
    echo -e "  -> pip install cryptography paramiko requests ..."
    pip install cryptography paramiko requests 2>/dev/null || pip3 install cryptography paramiko requests
fi

echo ""
echo -e "${CYAN}[*] Install librouteros + rich (pip) ...${RST}"
pip install librouteros rich 2>/dev/null || pip3 install librouteros rich

echo ""
echo -e "${GREEN}${BOLD}=============================================${RST}"
echo -e "${GREEN}${BOLD}  INSTALL BERHASIL!${RST}"
echo -e "${GREEN}${BOLD}=============================================${RST}"
echo ""
echo -e "  Jalankan:  ${CYAN}bash run.sh${RST}"
echo -e "  Atau:      ${CYAN}python mt.py${RST}"
echo ""
