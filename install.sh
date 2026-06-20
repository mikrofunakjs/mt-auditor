#!/bin/bash
# MikroTik Security Auditor - Installer
# Jalankan: bash install.sh

set -e

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
if [ -d /data/data/com.termux ]; then
    IS_TERMUX=true
    echo -e "${GREEN}[+] Termux terdeteksi${RST}"
else
    echo -e "${YELLOW}[!] Bukan Termux — diasumsikan Linux desktop/server${RST}"
fi

echo ""
echo -e "${CYAN}[*] Update package manager ...${RST}"

if $IS_TERMUX; then
    apt update -y 2>/dev/null || true
    apt upgrade -y 2>/dev/null || true
else
    if command -v apt &>/dev/null; then
        sudo apt update -y
    elif command -v yum &>/dev/null; then
        sudo yum update -y
    fi
fi

echo ""
echo -e "${CYAN}[*] Install Python3 & pip ...${RST}"

if $IS_TERMUX; then
    apt install python3 python3-pip -y 2>/dev/null || true
else
    command -v python3 &>/dev/null || sudo apt install python3 python3-pip -y
fi

echo ""
echo -e "${BOLD}${YELLOW}Pilih metode install:${RST}"
echo ""
echo -e "  ${GREEN}1${RST}) Termux — pakai pkg + pip (otomatis)"
echo -e "  ${GREEN}2${RST}) Linux — pip semua"
echo -e "  ${GREEN}3${RST}) Manual — cuma tampilkan perintah"
echo ""

read -p "$(echo -e "${YELLOW}Pilih [1/2/3] (default: auto): ${RST}")" METHOD
METHOD=${METHOD:-0}

if [ "$METHOD" = "3" ]; then
    echo ""
    echo -e "${CYAN}=== Perintah Manual ===${RST}"
    echo ""
    if $IS_TERMUX; then
        echo "  pkg install python3-cryptography python3-paramiko python3-requests -y"
    else
        echo "  sudo apt install python3-dev build-essential libssl-dev -y"
    fi
    echo "  pip install librouteros rich"
    echo "  pip install paramiko requests"
    echo ""
    echo "# Jalankan:"
    echo "  cd $(pwd) && python mt.py"
    exit 0
fi

echo ""
echo -e "${CYAN}[*] Install dependencies ...${RST}"

if $IS_TERMUX && [ "$METHOD" != "2" ]; then
    echo -e "  -> Via pkg (binary pre-compiled)..."
    apt install python3-cryptography python3-paramiko python3-requests -y 2>/dev/null || {
        echo -e "${YELLOW}[!] pkg gagal, fallback ke pip...${RST}"
        pip install paramiko requests
    }
else
    echo -e "  -> Via pip ..."
    pip install paramiko requests
fi

echo ""
echo -e "  -> Install librouteros + rich (pip) ..."
pip install librouteros rich

echo ""
echo -e "${GREEN}${BOLD}=============================================${RST}"
echo -e "${GREEN}${BOLD}  INSTALL BERHASIL!${RST}"
echo -e "${GREEN}${BOLD}=============================================${RST}"
echo ""
echo -e "  Jalankan:  ${CYAN}bash run.sh${RST}"
echo -e "  Atau:      ${CYAN}python mt.py${RST}"
echo ""
