#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# Tenda Guard Pro - router_probe.sh
# Tries the Tenda F3 login directly with curl and reports what the router does.
# curl tolerates the router's odd HTTP headers, so this shows the real behaviour.
#
#   pkg install curl
#   chmod +x router_probe.sh
#   ./router_probe.sh                 (router at 192.168.0.1)
#   ./router_probe.sh 192.168.0.1
#
# Nothing is saved. The password is typed hidden. Cookie values are never printed
# unless you run:  SHOW=1 ./router_probe.sh   (do that privately, never paste it).
# =============================================================================

IP="${1:-192.168.0.1}"
command -v curl >/dev/null 2>&1 || { echo "curl is missing. Run: pkg install curl"; exit 1; }

printf 'Router admin password (hidden, not saved): '
read -r -s PW
echo
[ -n "$PW" ] || { echo "No password entered."; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
LIST="/goform/getQos?modules=onlineList"

enc() {
  case "$1" in
    base64) printf '%s' "$PW" | base64 | tr -d '\n' ;;
    md5)    printf '%s' "$PW" | md5sum | cut -d' ' -f1 ;;
    plain)  printf '%s' "$PW" ;;
  esac
}

show_headers() {
  tr -d '\r' < "$1" | awk '
    NR==1 { print "   status: " $0 }
    tolower($0) ~ /^location:/ { print "   " $0 }
    tolower($0) ~ /^set-cookie:/ {
      line=$0; sub(/^[Ss]et-[Cc]ookie: */, "", line)
      name=line; sub(/=.*/, "", name)
      val=line; sub(/^[^=]*=/, "", val); sub(/;.*/, "", val)
      print "   set-cookie: " name " (" length(val) " chars)"
    }
    NR>1 && $0 != "" && $0 !~ /:/ { print "   MALFORMED header line seen" }'
}

check_list() {
  curl -s -i --max-time 8 "$@" "http://$IP$LIST" -o "$TMP/list.txt"
  status="$(head -1 "$TMP/list.txt" | tr -d '\r')"
  count="$(grep -oiE '([0-9a-f]{2}[:-]){5}[0-9a-f]{2}' "$TMP/list.txt" | sort -u | wc -l | tr -d ' ')"
  moved="$(grep -ciE 'moved to a new location|login\.html' "$TMP/list.txt")"
  echo "   device list: $status , devices found: $count , login page: $([ "$moved" -gt 0 ] && echo yes || echo no)"
  [ "$count" -gt 0 ]
}


form_encode() {
  curl -s -o /dev/null -w '%{url_effective}' -G --data-urlencode "password=$1" --max-time 1 "http://127.0.0.1:9/" 2>/dev/null | sed 's/^[^?]*?//'
}

raw_post() {
  # Plain bash socket request. Keeps broken header lines that curl may throw away.
  local host="${IP%%:*}" port="${IP#*:}" body="$1"
  [ "$port" = "$IP" ] && port=80
  exec 3<>"/dev/tcp/$host/$port" 2>/dev/null || return 1
  printf 'POST /login/Auth HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\n\r\n%s' "$IP" "${#body}" "$body" >&3
  timeout 6 cat <&3 > "$TMP/raw.txt"
  exec 3<&- 3>&-
  return 0
}

raw_cookie() {
  tr -d '\r' < "$TMP/raw.txt" | awk 'tolower($0) ~ /^set-cookie:/ { line=$0; sub(/^[Ss]et-[Cc]ookie: */, "", line); sub(/;.*/, "", line); print line; exit }'
}

WORKING=""
echo "Probing http://$IP ..."
echo
echo "== Login page"
curl -s --max-time 8 "http://$IP/login.html" -o "$TMP/login.html"
echo "   size: $(wc -c < "$TMP/login.html") bytes"
tr -d '\r\n' < "$TMP/login.html" | grep -oiE '<form[^>]*>.{0,400}' | head -1 | cut -c1-500 | sed 's/^/   form: /'
echo

for kind in base64 md5 plain; do
  val="$(enc "$kind")"
  echo "== Password sent as $kind"

  echo " A) POST /login/Auth  password only"
  rm -f "$TMP/jar"
  curl -s -i --max-time 8 -c "$TMP/jar" --data-urlencode "password=$val" "http://$IP/login/Auth" -o "$TMP/h.txt"
  show_headers "$TMP/h.txt"
  if check_list -b "$TMP/jar"; then
    echo "   >>> WORKS: POST /login/Auth with password only ($kind)"
    WORKING="POST password-only ($kind)"
    [ "$SHOW" = "1" ] && grep -v '^#' "$TMP/jar" | awk 'NF>=7 {print "   cookie to paste in Settings: " $6 "=" $7}'
  fi

  echo " B) POST /login/Auth  username + password"
  rm -f "$TMP/jar"
  curl -s -i --max-time 8 -c "$TMP/jar" --data-urlencode "username=admin" --data-urlencode "password=$val" "http://$IP/login/Auth" -o "$TMP/h.txt"
  show_headers "$TMP/h.txt"
  if check_list -b "$TMP/jar"; then
    echo "   >>> WORKS: POST /login/Auth with username+password ($kind)"
    WORKING="POST username+password ($kind)"
  fi

  echo " D) raw socket POST  password only (keeps broken headers)"
  if raw_post "$(form_encode "$val")"; then
    show_headers "$TMP/raw.txt"
    RAWC="$(raw_cookie)"
    if [ -n "$RAWC" ] && check_list -H "Cookie: $RAWC"; then
      echo "   >>> WORKS: raw socket POST with password only ($kind) , cookie name: ${RAWC%%=*}"
      WORKING="raw socket POST password-only ($kind)"
      [ "$SHOW" = "1" ] && echo "   cookie to paste in Settings: $RAWC"
    elif [ -z "$RAWC" ]; then
      echo "   no Set-Cookie in the raw reply"
    fi
  else
    echo "   (raw sockets are not available in this shell)"
  fi

  echo " C) cookie only  ecos_pw=<$kind>"
  if check_list -H "Cookie: ecos_pw=$val"; then
    echo "   >>> WORKS: cookie ecos_pw=<$kind> without any login request"
    WORKING="cookie only ($kind)"
    [ "$SHOW" = "1" ] && echo "   cookie to paste in Settings: ecos_pw=$val"
  fi
  echo
done

echo "== Summary"
if [ -n "$WORKING" ]; then
  echo "Last working method: $WORKING"
else
  echo "No method returned a device list."
  echo "Check: can you log in at http://$IP in a browser with this exact password?"
fi
echo "Copy everything above (it contains no passwords) and send it."
