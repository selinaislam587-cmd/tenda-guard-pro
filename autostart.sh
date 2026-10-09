#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# Tenda Guard Pro - start_boot.sh
# Launches the app when the phone boots, using the Termux:Boot add-on.
#
# Setup:
#   1. Install the Termux:Boot app and open it once.
#   2. Copy the project to ~/tenda-guard-pro (or change APP_DIR below).
#   3. mkdir -p ~/.termux/boot
#      cp start_boot.sh ~/.termux/boot/tenda-guard.sh
#      chmod +x ~/.termux/boot/tenda-guard.sh
# =============================================================================

APP_DIR="$HOME/tenda-guard-pro"

termux-wake-lock

# Give the phone time to join Wi-Fi before the first router poll.
sleep 20

if [ -x "$APP_DIR/autostart.sh" ]; then
  "$APP_DIR/autostart.sh" >> "$APP_DIR/boot.log" 2>&1
else
  echo "autostart.sh not found or not executable in $APP_DIR" >> "$HOME/tenda-guard-boot-error.log"
fi
