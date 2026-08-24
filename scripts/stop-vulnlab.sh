#!/usr/bin/env bash

ROOT="/opt/vulnlab"
PID_DIR="$ROOT/logs"

for service in target rfi scanner frontend
do
    PIDFILE="$PID_DIR/$service.pid"

    if [ ! -f "$PIDFILE" ]; then
        continue
    fi

    PID=$(cat "$PIDFILE")

    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        echo "[STOPPED] $service ($PID)"
    fi

    rm -f "$PIDFILE"
done

echo "VulnLab stopped."
