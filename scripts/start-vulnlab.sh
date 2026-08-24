#!/usr/bin/env bash

set -e

ROOT="/opt/vulnlab"
LOG_DIR="$ROOT/logs"

mkdir -p "$LOG_DIR"

echo "=========================================="
echo "             VulnLab Studio"
echo "=========================================="

start_if_free() {
    PORT="$1"
    NAME="$2"
    COMMAND="$3"
    LOGFILE="$4"
    PIDFILE="$5"

    if ss -lnt | grep -q ":${PORT} "; then
        echo "[SKIP] $NAME already listening on :$PORT"
        return
    fi

    bash -c "$COMMAND" > "$LOGFILE" 2>&1 &

    echo $! > "$PIDFILE"

    echo "[STARTED] $NAME on :$PORT"
}


start_if_free \
8080 \
"Vulnerable Target" \
"cd $ROOT/vulnerable-app && source .venv/bin/activate && python3 app.py" \
"$LOG_DIR/target.log" \
"$LOG_DIR/target.pid"


start_if_free \
9000 \
"Controlled RFI Server" \
"cd $ROOT/resource-server && python3 -m http.server 9000 --bind 127.0.0.1" \
"$LOG_DIR/rfi.log" \
"$LOG_DIR/rfi.pid"


start_if_free \
8000 \
"Scanner API" \
"cd $ROOT/scanner && source .venv/bin/activate && uvicorn app.main:app --host 127.0.0.1 --port 8000" \
"$LOG_DIR/scanner.log" \
"$LOG_DIR/scanner.pid"


start_if_free \
3000 \
"Security Studio" \
"cd $ROOT/frontend && npm run dev -- --hostname 127.0.0.1 --port 3000" \
"$LOG_DIR/frontend.log" \
"$LOG_DIR/frontend.pid"


sleep 3

echo
echo "=========================================="
echo "Dashboard:  http://127.0.0.1:3000"
echo "Scanner:    http://127.0.0.1:8000"
echo "API Docs:   http://127.0.0.1:8000/docs"
echo "Target:     http://127.0.0.1:8080"
echo "RFI:        http://127.0.0.1:9000"
echo "=========================================="
