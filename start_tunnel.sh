#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# Tenda Guard Pro - start_tunnel.sh
# Keeps a Cloudflare quick tunnel running so you can open the app from anywhere,
# including abroad. A quick tunnel gets a NEW address every time it starts, so
# this script emails the new address to the "Send alerts to" mailbox each time.
#
# One-time setup:
#   pkg install cloudflared
#   chmod +x start_tunnel.sh
#   Settings > Email alerts must be filled in (same mailbox receives the link).
#
# Run:   ./start_tunnel.sh        (autostart.sh starts it for you)
# Stop:  kill "$(cat tunnel.pid)"
# =============================================================================

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$APP_DIR/logs"
LOG="$LOG_DIR/tunnel.log"
PID_FILE="$APP_DIR/tunnel.pid"
URL_FILE="$APP_DIR/tunnel_url.txt"

cd "$APP_DIR" || exit 1
mkdir -p "$LOG_DIR"

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "cloudflared is missing. Run: pkg install cloudflared"
  exit 1
fi

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" >/dev/null 2>&1; then
  echo "Tunnel supervisor already running (PID $(cat "$PID_FILE"))."
  exit 0
fi
echo $$ > "$PID_FILE"

PORT="$(python -c "import json; print(json.load(open('config.json'))['server']['port'])" 2>/dev/null || echo 5000)"

if command -v termux-wake-lock >/dev/null 2>&1; then
  termux-wake-lock
fi

cleanup() { [ -n "$CF_PID" ] && kill "$CF_PID" 2>/dev/null; rm -f "$PID_FILE"; exit 0; }
trap cleanup INT TERM

while true; do
  : > "$LOG"
  cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >> "$LOG" 2>&1 &
  CF_PID=$!

  URL=""
  for _ in $(seq 1 60); do
    URL="$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$LOG" | head -1)"
    [ -n "$URL" ] && break
    kill -0 "$CF_PID" 2>/dev/null || break
    sleep 1
  done

  if [ -n "$URL" ]; then
    echo "$URL" > "$URL_FILE"
    echo "$(date '+%F %T') tunnel up: $URL"
    python "$APP_DIR/tunnel_notify.py" "$URL" >> "$LOG_DIR/notify.log" 2>&1
  else
    echo "$(date '+%F %T') no tunnel address yet, retrying"
  fi

  wait "$CF_PID"
  echo "$(date '+%F %T') tunnel stopped, restarting in 5 seconds"
  sleep 5
done
