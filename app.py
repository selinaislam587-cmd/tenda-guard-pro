#!/usr/bin/env python3
# =============================================================================
# Tenda Guard Pro - app.py
# Flask backend for managing a Tenda F3 router (default 192.168.0.1).
#
# Run:   pip install flask requests && python app.py
# Open:  http://127.0.0.1:5000
# =============================================================================

import hashlib
import json
import os
import re
import smtplib
import ssl
import threading
import time
from datetime import datetime
from email.message import EmailMessage

import requests
from flask import Flask, jsonify, render_template, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

SPEED_PRESETS = {"1k": 1, "512k": 512, "1m": 1024, "max": 0}
TRUST_DURATIONS_DAYS = {"1": 1, "7": 7, "30": 30, "unlimited": 0}
THROTTLE_KBPS = 1
UNLIMITED_KBPS = 0

DEFAULT_CONFIG = {
    "auto_throttle": False,
    "poll_interval": 10,
    "server": {"host": "127.0.0.1", "port": 5000},
    "router": {
        "ip": "192.168.0.1",
        "username": "admin",
        "password": "",
        "limit_param": "list",
        "limit_template": "{name}\t{mac}\t{up}\t{down}\t{ip}",
    },
    "email": {"sender": "", "app_password": "", "target": ""},
    "trusted_devices": {},
    "limits": {},
    "pending_throttle": [],
    "notified_macs": [],
}

cfg_lock = threading.RLock()
runtime = {
    "devices": [],
    "router_online": False,
    "last_poll": 0,
    "last_error": "",
    "mail_error": "",
    "mail_backoff_until": 0,
    "started_at": time.time(),
}


# -----------------------------------------------------------------------------
# Configuration storage
# -----------------------------------------------------------------------------
def deep_merge(base, extra):
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config():
    data = json.loads(json.dumps(DEFAULT_CONFIG))
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
                deep_merge(data, json.load(handle))
        except (OSError, ValueError):
            pass
    return data


cfg = load_config()


def save_config():
    with cfg_lock:
        tmp_path = CONFIG_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle, indent=2)
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, CONFIG_PATH)


# -----------------------------------------------------------------------------
# Parsing helpers
# -----------------------------------------------------------------------------
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_KEYS = ["mac", "devMac", "macAddr", "macAddress", "MAC", "hwaddr"]
IP_KEYS = ["ip", "devIp", "ipAddr", "ipAddress", "IP"]
NAME_KEYS = ["hostName", "hostname", "devName", "deviceName", "name", "devHostName", "remark"]


def normalize_mac(value):
    digits = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(digits) != 12:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()


def pick(item, keys):
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return str(item[key])
    return ""


def find_dict_list(node):
    if isinstance(node, list):
        if node and all(isinstance(entry, dict) for entry in node):
            return node
        for entry in node:
            found = find_dict_list(entry)
            if found:
                return found
    elif isinstance(node, dict):
        for value in node.values():
            found = find_dict_list(value)
            if found:
                return found
    return []


def parse_devices(text):
    devices = []
    seen = set()
    try:
        data = json.loads(text)
    except ValueError:
        data = None

    if data is not None:
        for item in find_dict_list(data):
            mac = normalize_mac(pick(item, MAC_KEYS))
            if not mac or mac in seen:
                continue
            seen.add(mac)
            devices.append({
                "mac": mac,
                "ip": pick(item, IP_KEYS),
                "name": pick(item, NAME_KEYS) or "Unknown device",
            })
        return devices

    for line in text.splitlines():
        mac_match = MAC_RE.search(line)
        if not mac_match:
            continue
        mac = normalize_mac(mac_match.group(0))
        if not mac or mac in seen:
            continue
        seen.add(mac)
        ip_match = IP_RE.search(line)
        name = ""
        for token in re.split(r"[\t,;|]+", line):
            token = token.strip()
            if token and not MAC_RE.fullmatch(token) and not IP_RE.fullmatch(token) and not token.isdigit():
                name = token
                break
        devices.append({
            "mac": mac,
            "ip": ip_match.group(0) if ip_match else "",
            "name": name or "Unknown device",
        })
    return devices


# -----------------------------------------------------------------------------
# Router client
# -----------------------------------------------------------------------------
class RouterClient:
    def __init__(self):
        self.session = requests.Session()
        self.lock = threading.Lock()

    def base_url(self):
        return "http://{}".format(cfg["router"]["ip"])

    def login(self):
        password = cfg["router"].get("password", "")
        if not password:
            return False
        digest = hashlib.md5(password.encode("utf-8")).hexdigest()
        try:
            self.session.post(
                self.base_url() + "/login/Auth",
                data={"username": cfg["router"].get("username", "admin"), "password": digest},
                timeout=6,
                allow_redirects=False,
            )
            return True
        except requests.RequestException:
            return False

    def send(self, method, path, **kwargs):
        response = None
        for attempt in (1, 2):
            response = self.session.request(
                method, self.base_url() + path, timeout=6, allow_redirects=False, **kwargs
            )
            location = response.headers.get("Location", "").lower()
            needs_login = response.status_code in (401, 403) or (
                response.status_code in (301, 302) and "login" in location
            )
            if needs_login and attempt == 1 and cfg["router"].get("password"):
                self.login()
                continue
            break
        return response

    def get_devices(self):
        with self.lock:
            response = self.send("GET", "/goform/getNetDeviceList", params={"random": time.time()})
            response.raise_for_status()
            return parse_devices(response.text)

    def set_limit(self, device, kbps):
        template = cfg["router"].get("limit_template", DEFAULT_CONFIG["router"]["limit_template"])
        try:
            line = template.format(
                name=device.get("name", "device"),
                mac=device["mac"],
                ip=device.get("ip", ""),
                up=kbps,
                down=kbps,
            )
        except (KeyError, IndexError, ValueError):
            return False
        payload = {cfg["router"].get("limit_param", "list"): line}
        try:
            with self.lock:
                response = self.send("POST", "/goform/SetOnlineDevList", data=payload)
            return response is not None and response.ok
        except requests.RequestException:
            return False

    def reboot(self):
        try:
            with self.lock:
                response = self.send("POST", "/goform/SysToolReboot", data={})
            return response is not None and response.ok
        except (requests.ConnectionError, requests.ReadTimeout):
            return True
        except requests.RequestException:
            return False


router = RouterClient()


# -----------------------------------------------------------------------------
# Email alerts
# -----------------------------------------------------------------------------
def email_configured():
    mail = cfg["email"]
    return bool(mail.get("sender") and mail.get("app_password") and mail.get("target"))


def send_email(subject, body):
    mail = cfg["email"]
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = mail["sender"]
    message["To"] = mail["target"]
    message.set_content(body)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=20) as server:
        server.login(mail["sender"], mail["app_password"].replace(" ", ""))
        server.send_message(message)


def alert_worker(device):
    subject = "Tenda Guard Pro: unrecognized device throttled"
    body = (
        "An unrecognized device was limited to 1 Kbps.\n\n"
        "Name: {name}\nMAC: {mac}\nIP: {ip}\nTime: {when}\n\n"
        "Open Tenda Guard Pro to trust this device or keep it throttled."
    ).format(
        name=device.get("name", "Unknown"),
        mac=device["mac"],
        ip=device.get("ip") or "Unknown",
        when=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    try:
        send_email(subject, body)
        with cfg_lock:
            runtime["mail_error"] = ""
    except Exception as exc:  # network, auth or SMTP failure: allow a later retry
        with cfg_lock:
            runtime["mail_error"] = str(exc)
            runtime["mail_backoff_until"] = time.time() + 300
            if device["mac"] in cfg["notified_macs"]:
                cfg["notified_macs"].remove(device["mac"])
                save_config()


def notify_step(devices):
    if not email_configured() or time.time() < runtime["mail_backoff_until"]:
        return
    for device in devices:
        mac = device["mac"]
        with cfg_lock:
            if mac in cfg["trusted_devices"] or mac in cfg["notified_macs"]:
                continue
            if cfg["limits"].get(mac) != THROTTLE_KBPS:
                continue
            cfg["notified_macs"].append(mac)
            save_config()
        threading.Thread(target=alert_worker, args=(device,), daemon=True).start()


# -----------------------------------------------------------------------------
# Throttle engine
# -----------------------------------------------------------------------------
def apply_limit(device, kbps):
    if router.set_limit(device, kbps):
        with cfg_lock:
            cfg["limits"][device["mac"]] = kbps
            if device["mac"] in cfg["pending_throttle"] and kbps == THROTTLE_KBPS:
                cfg["pending_throttle"].remove(device["mac"])
            save_config()
        return True
    return False


def run_expiry():
    now = time.time()
    with cfg_lock:
        changed = False
        for mac, info in list(cfg["trusted_devices"].items()):
            expires_at = info.get("expires_at")
            if expires_at and expires_at <= now:
                del cfg["trusted_devices"][mac]
                cfg["limits"].pop(mac, None)
                if mac not in cfg["pending_throttle"]:
                    cfg["pending_throttle"].append(mac)
                if mac in cfg["notified_macs"]:
                    cfg["notified_macs"].remove(mac)
                changed = True
        if changed:
            save_config()


def throttle_step(devices):
    with cfg_lock:
        auto = cfg["auto_throttle"]
        trusted = set(cfg["trusted_devices"].keys())
        limits = dict(cfg["limits"])
        pending = set(cfg["pending_throttle"])
    for device in devices:
        mac = device["mac"]
        if mac in trusted:
            if mac not in limits:
                apply_limit(device, UNLIMITED_KBPS)
            continue
        if mac in pending or (auto and mac not in limits):
            apply_limit(device, THROTTLE_KBPS)


def run_cycle():
    run_expiry()
    try:
        devices = router.get_devices()
    except requests.RequestException as exc:
        with cfg_lock:
            runtime["router_online"] = False
            runtime["last_error"] = str(exc)
        return
    with cfg_lock:
        runtime["devices"] = devices
        runtime["router_online"] = True
        runtime["last_error"] = ""
        runtime["last_poll"] = time.time()
    throttle_step(devices)
    notify_step(devices)


def worker_loop():
    while True:
        try:
            run_cycle()
        except Exception as exc:  # keep the watchdog alive whatever happens
            with cfg_lock:
                runtime["last_error"] = str(exc)
        time.sleep(max(3, int(cfg.get("poll_interval", 10))))


def start_worker():
    thread = threading.Thread(target=worker_loop, name="guard-worker", daemon=True)
    thread.start()
    return thread


# -----------------------------------------------------------------------------
# Flask app
# -----------------------------------------------------------------------------
app = Flask(__name__)


def body():
    return request.get_json(silent=True) or {}


def fail(message, status=400):
    return jsonify({"ok": False, "error": message}), status


def snapshot():
    now = time.time()
    with cfg_lock:
        trusted = cfg["trusted_devices"]
        limits = cfg["limits"]
        devices_out = []
        throttled = 0
        online_macs = set()
        for device in runtime["devices"]:
            mac = device["mac"]
            online_macs.add(mac)
            info = trusted.get(mac)
            limit = limits.get(mac)
            is_throttled = limit is not None and limit > 0
            if is_throttled:
                throttled += 1
            devices_out.append({
                "mac": mac,
                "ip": device.get("ip", ""),
                "name": info["name"] if info else device.get("name", "Unknown device"),
                "hostname": device.get("name", ""),
                "limit_kbps": limit,
                "throttled": is_throttled,
                "trusted": info is not None,
                "expires_at": info.get("expires_at") if info else None,
            })
        trusted_out = []
        for mac, info in trusted.items():
            expires_at = info.get("expires_at")
            trusted_out.append({
                "mac": mac,
                "name": info.get("name", mac),
                "added_at": info.get("added_at"),
                "expires_at": expires_at,
                "seconds_left": max(0, int(expires_at - now)) if expires_at else None,
                "online": mac in online_macs,
            })
        return {
            "ok": True,
            "router_ip": cfg["router"]["ip"],
            "router_online": runtime["router_online"],
            "last_poll": runtime["last_poll"],
            "last_error": runtime["last_error"],
            "mail_error": runtime["mail_error"],
            "auto_throttle": cfg["auto_throttle"],
            "devices": devices_out,
            "trusted": trusted_out,
            "metrics": {
                "connected": len(devices_out),
                "throttled": throttled,
                "trusted": len(trusted_out),
                "pending": len(cfg["pending_throttle"]),
                "uptime_seconds": int(now - runtime["started_at"]),
            },
        }


def find_device(mac):
    with cfg_lock:
        for device in runtime["devices"]:
            if device["mac"] == mac:
                return dict(device)
    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/data", methods=["GET"])
def api_data():
    return jsonify(snapshot())


@app.route("/api/toggle-autothrottle", methods=["POST"])
def api_toggle_autothrottle():
    payload = body()
    with cfg_lock:
        if "enabled" in payload:
            cfg["auto_throttle"] = bool(payload["enabled"])
        else:
            cfg["auto_throttle"] = not cfg["auto_throttle"]
        save_config()
        state = cfg["auto_throttle"]
    return jsonify({"ok": True, "auto_throttle": state})


@app.route("/api/trust-device", methods=["POST"])
def api_trust_device():
    payload = body()
    mac = normalize_mac(payload.get("mac"))
    if not mac:
        return fail("A valid MAC address is required.")
    duration = str(payload.get("duration", "unlimited")).lower()
    if duration not in TRUST_DURATIONS_DAYS:
        return fail("Duration must be 1, 7, 30 or unlimited.")
    live = find_device(mac) or {"mac": mac, "name": "device", "ip": ""}
    name = str(payload.get("name") or "").strip()[:60] or live.get("name") or mac
    days = TRUST_DURATIONS_DAYS[duration]
    now = time.time()

    if not apply_limit(live, UNLIMITED_KBPS):
        return fail("The router did not accept the speed change. Check the router connection.", 502)

    with cfg_lock:
        cfg["trusted_devices"][mac] = {
            "name": name,
            "added_at": int(now),
            "expires_at": int(now + days * 86400) if days else None,
        }
        if mac in cfg["pending_throttle"]:
            cfg["pending_throttle"].remove(mac)
        if mac in cfg["notified_macs"]:
            cfg["notified_macs"].remove(mac)
        save_config()
    return jsonify({"ok": True})


@app.route("/api/untrust-device", methods=["POST"])
def api_untrust_device():
    mac = normalize_mac(body().get("mac"))
    if not mac:
        return fail("A valid MAC address is required.")
    with cfg_lock:
        if mac not in cfg["trusted_devices"]:
            return fail("That device is not on the trusted list.", 404)
        del cfg["trusted_devices"][mac]
        cfg["limits"].pop(mac, None)
        if mac not in cfg["notified_macs"]:
            cfg["notified_macs"].append(mac)
        save_config()
    live = find_device(mac)
    throttled_now = bool(live and apply_limit(live, THROTTLE_KBPS))
    if not throttled_now:
        with cfg_lock:
            if mac not in cfg["pending_throttle"]:
                cfg["pending_throttle"].append(mac)
            save_config()
    return jsonify({"ok": True, "throttled_now": throttled_now})


@app.route("/api/set-speed", methods=["POST"])
def api_set_speed():
    payload = body()
    mac = normalize_mac(payload.get("mac"))
    preset = str(payload.get("preset", "")).lower()
    if not mac:
        return fail("A valid MAC address is required.")
    if preset not in SPEED_PRESETS:
        return fail("Preset must be 1k, 512k, 1m or max.")
    device = find_device(mac)
    if not device:
        return fail("That device is not connected right now.", 404)
    if not apply_limit(device, SPEED_PRESETS[preset]):
        return fail("The router did not accept the speed change.", 502)
    with cfg_lock:
        if mac not in cfg["notified_macs"]:
            cfg["notified_macs"].append(mac)
        if mac in cfg["pending_throttle"]:
            cfg["pending_throttle"].remove(mac)
        save_config()
    return jsonify({"ok": True})


@app.route("/api/panic-lock", methods=["POST"])
def api_panic_lock():
    with cfg_lock:
        trusted = set(cfg["trusted_devices"].keys())
        targets = [dict(d) for d in runtime["devices"] if d["mac"] not in trusted]
    done = 0
    failed = 0
    for device in targets:
        if apply_limit(device, THROTTLE_KBPS):
            done += 1
            with cfg_lock:
                if device["mac"] not in cfg["notified_macs"]:
                    cfg["notified_macs"].append(device["mac"])
                save_config()
        else:
            failed += 1
    return jsonify({"ok": failed == 0, "throttled": done, "failed": failed})


@app.route("/api/reboot", methods=["POST"])
def api_reboot():
    if not runtime["router_online"]:
        return fail("The router is not reachable, so it cannot be rebooted.", 502)
    if not router.reboot():
        return fail("The router rejected the reboot command.", 502)
    with cfg_lock:
        cfg["limits"] = {}
        runtime["router_online"] = False
        save_config()
    return jsonify({"ok": True})


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    run_cycle()
    return jsonify(snapshot())


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    with cfg_lock:
        mail = cfg["email"]
        return jsonify({
            "ok": True,
            "sender": mail.get("sender", ""),
            "target": mail.get("target", ""),
            "password_set": bool(mail.get("app_password")),
            "router_ip": cfg["router"]["ip"],
            "router_password_set": bool(cfg["router"].get("password")),
        })


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    payload = body()
    email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    sender = str(payload.get("sender", "")).strip()
    target = str(payload.get("target", "")).strip()
    if sender and not email_re.match(sender):
        return fail("Sender email is not a valid address.")
    if target and not email_re.match(target):
        return fail("Target email is not a valid address.")
    with cfg_lock:
        cfg["email"]["sender"] = sender
        cfg["email"]["target"] = target
        new_password = str(payload.get("app_password", "")).strip()
        if new_password:
            cfg["email"]["app_password"] = new_password
        router_password = payload.get("router_password")
        if isinstance(router_password, str) and router_password.strip():
            cfg["router"]["password"] = router_password.strip()
        router_ip = str(payload.get("router_ip", "")).strip()
        if router_ip:
            cfg["router"]["ip"] = router_ip
        runtime["mail_backoff_until"] = 0
        save_config()
    return jsonify({"ok": True})


@app.route("/api/test-email", methods=["POST"])
def api_test_email():
    if not email_configured():
        return fail("Save the sender, app password and target email first.")
    try:
        send_email(
            "Tenda Guard Pro: test email",
            "Email alerts are working. Sent at {}.".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
    except Exception as exc:
        return fail("Email failed: {}".format(exc), 502)
    return jsonify({"ok": True})


if __name__ == "__main__":
    start_worker()
    app.run(
        host=cfg["server"].get("host", "127.0.0.1"),
        port=int(cfg["server"].get("port", 5000)),
        threaded=True,
        use_reloader=False,
    )
