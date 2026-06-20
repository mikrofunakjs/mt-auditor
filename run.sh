#!/bin/bash
# MikroTik Security Auditor - Quick Run
# Jalankan: bash run.sh

cd "$(dirname "$0")"

GREEN='\033[92m'
RED='\033[91m'
RST='\033[0m'

check_python() {
    if command -v python3 &>/dev/null; then
        echo "python3"
    elif command -v python &>/dev/null; then
        echo "python"
    else
        echo ""
    fi
}

PYTHON=$(check_python)

if [ -z "$PYTHON" ]; then
    echo -e "${RED}[-] Python tidak ditemukan! Jalankan install.sh dulu.${RST}"
    exit 1
fi

check_deps() {
    $PYTHON -c "from core.utils import info, BANNER; print('OK')" 2>/dev/null || {
        echo -e "${RED}[-] Library belum terinstall atau import gagal.${RST}"
        echo -e "${RED}    Jalankan: bash install.sh${RST}"
        exit 1
    }
}

check_deps

exec $PYTHON mt.py "$@"
