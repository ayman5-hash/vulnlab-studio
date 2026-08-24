#!/usr/bin/env bash

check() {
    NAME="$1"
    PORT="$2"

    if curl -s --connect-timeout 1 \
        "http://127.0.0.1:$PORT" \
        >/dev/null 2>&1
    then
        printf "[ONLINE]  %-22s :%s\n" "$NAME" "$PORT"
    else
        printf "[OFFLINE] %-22s :%s\n" "$NAME" "$PORT"
    fi
}

echo "=========================================="
echo " VulnLab Services"
echo "=========================================="

check "Security Studio" 3000
check "Scanner API" 8000
check "Vulnerable Target" 8080
check "Controlled RFI Server" 9000
