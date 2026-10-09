#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# Tenda Guard Pro - autostart.sh
# Starts the Flask app in the background inside Termux. Safe to run repeatedly:
# it does nothing if the app is already running.
#
# One-time setup:
#   pkg install python
#   chmod +x autostart.sh start_boot.sh
# =============================================================================

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$APP_DIR/guard.pid"
LOG_DIR="$APP_DIR/logs"

cd "$APP_DIR" || exit 1
mkdir -p "$LOG_DIR"

if command -v termux-wake-lock >/dev/null 2>&1; then
  termux-wake-lock
fi

if ! python -c "import flask, requests" >/dev/null 2>&1; then
  echo "Installing Python dependencies..."
  pip install flask requests >> "$LOG_DIR/install.log" 2>&1 || {
    echo "Dependency install failed. See $LOG_DIR/install.log"
    exit 1
  }
fi

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" >/dev/null 2>&1; then
  echo "Tenda Guard Pro is already running (PID $(cat "$PID_FILE"))."
  exit 0
fi

nohup python app.py >> "$LOG_DIR/app.log" 2>&1 &
echo $! > "$PID_FILE"
echo "Tenda Guard Pro started (PID $!). Open http://127.0.0.1:5000"
