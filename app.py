#!/usr/bin/env python3
# =============================================================================
# Tenda Guard Pro - app.py  (v2)
#
# Flask backend for monitoring and throttling devices on a Tenda F3 router.
#
#   * Router login: session cookie handling with three login strategies, login
#     page detection, automatic re-login and backoff.
#   * /stream: Server-Sent Events push of live snapshots.
#   * Sticky device registry: a failed or empty poll never drops the list to 0.
#   * Web login, CSRF protection, rate limiting and security headers, because
#     this app is meant to be exposed through a Cloudflare Tunnel.
#
# Run:  pip install flask requests && python app.py
# =============================================================================

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import ssl
import threading
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from urllib.parse import urlparse

import requests
from flask import (Flask, Response, jsonify, redirect, render_template, request,
                   session, url_for)
from flask.sessions import SecureCookieSessionInterface
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

SPEED_PRESETS = {"1k": 1, "512k": 512, "1m": 1024, "max": 0}
TRUST_DURATIONS_DAYS = {"1": 1, "7": 7, "30": 30, "unlimited": 0}
THROTTLE_KBPS = 1
UNLIMITED_KBPS = 0
MAX_STREAM_CLIENTS = 12
MAX_KNOWN_DEVICES = 300
MIN_WEB_PASSWORD_LENGTH = 10

DEFAULT_CONFIG = {
    "auto_throttle": False,
    "poll_interval": 5,
    "stream_interval": 4,
    "device_grace_seconds": 45,
    "empty_confirmations": 3,
    "server": {"host": "127.0.0.1", "port": 5000},
    "web": {"password_hash": "", "secret_key": "", "session_hours": 72, "trust_proxy": True},
    "router": {
        "ip": "192.168.0.1",
        "username": "admin",
        "password": "",
        "devices_endpoint": "/goform/getQos",
        "fallback_endpoints": ["/goform/getOnlineList", "/goform/getNetDeviceList"],
        "limit_endpoint": "/goform/setQos",
        "limit_param": "list",
        "limit_template": "{name}\t{mac}\t{up}\t{down}\t{ip}",
    },
    "email": {"sender": "", "app_password": "", "target": ""},
    "trusted_devices": {},
    "limits": {},
    "pending_throttle": [],
    "notified_macs": [],
    "known_devices": {},
}

cfg_lock = threading.RLock()
cycle_lock = threading.Lock()
runtime = {
    "router_online": False,
    "stale": True,
    "auth_error": False,
    "last_poll": time.time(),
    "last_error": "",
    "mail_error": "",
    "mail_backoff_until": 0,
    "empty_streak": 0,
    "started_at": time.time(),
}
registry = {}


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
            backup = CONFIG_PATH + ".broken-" + str(int(time.time()))
            try:
                os.replace(CONFIG_PATH, backup)
            except OSError:
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
# Live update bus (wakes every SSE client when state changes)
# -----------------------------------------------------------------------------
class Bus:
    def __init__(self):
        self.cond = threading.Condition()
        self.version = 0

    def publish(self):
        with self.cond:
            self.version += 1
            self.cond.notify_all()


bus = Bus()


# -----------------------------------------------------------------------------
# Parsing helpers
# -----------------------------------------------------------------------------
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_KEYS = ["qosListMac", "mac", "devMac", "macAddr", "macAddress", "MAC", "hwaddr"]
IP_KEYS = ["qosListIP", "ip", "devIp", "devIP", "ipAddr", "ipAddress", "IP"]
UP_LIMIT_KEYS = ["qosListUpLimit", "upLimit"]
DOWN_LIMIT_KEYS = ["qosListDownLimit", "downLimit"]
NAME_KEYS = ["qosListRemark", "qosListHostname", "hostName", "hostname", "devName",
             "deviceName", "name", "devHostName", "remark"]
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}(:\d{1,5})?$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def to_int(value):
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return None


def normalize_mac(value):
    digits = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(digits) != 12:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()


def pick(item, keys):
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return str(item[key]).strip()
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
                "name": pick(item, NAME_KEYS)[:60] or "Unknown device",
                "up_limit": to_int(pick(item, UP_LIMIT_KEYS)),
                "down_limit": to_int(pick(item, DOWN_LIMIT_KEYS)),
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
                name = token[:60]
                break
        devices.append({
            "mac": mac,
            "ip": ip_match.group(0) if ip_match else "",
            "name": name or "Unknown device",
        })
    return devices


# -----------------------------------------------------------------------------
# Router client with authentication
# -----------------------------------------------------------------------------
class RouterAuthError(Exception):
    """The router wants a login and we could not provide a working one."""


class RouterFormatError(Exception):
    """The router answered, but not with a device list we can read."""


MOVED_HINTS = ("moved to a new location", "this document has moved", "object moved")


def looks_like_login(resp):
    if resp is None:
        return False
    if resp.status_code in (401, 403):
        return True
    location = resp.headers.get("Location", "").lower()
    head = (resp.text or "")[:1500].lower()
    if 300 <= resp.status_code < 400:
        return "login" in location or "login" in head or not location
    if any(hint in head for hint in MOVED_HINTS):
        return True
    stripped = head.lstrip()
    if stripped and stripped[0] not in "[{" and "login.html" in head:
        return True
    if "<html" in head or "<!doctype" in head:
        return "login" in head or 'type="password"' in head or "type='password'" in head
    return False


BUILTIN_ENDPOINTS = [
    ("/goform/getQos", {"modules": "onlineList"}),
    ("/goform/getOnlineList", {}),
    ("/goform/getNetDeviceList", {}),
]
AUTH_COOKIE = "ecos_pw"
PASSWORD_KINDS = ("base64", "md5", "plain")


def encode_password(kind, password):
    if kind == "base64":
        return base64.b64encode(password.encode("utf-8")).decode("ascii")
    if kind == "md5":
        return hashlib.md5(password.encode("utf-8")).hexdigest()
    return password


class RouterClient:
    """Talks to the Tenda F3 web server (ecos firmware family).

    Verified facts (from public research on this firmware family):
      * login endpoint is POST /login/Auth
      * the session cookie is named ecos_pw
      * device data comes from /goform/getQos with modules=onlineList
      * the password is Base64 on many F3 revisions and MD5 on others, so all
        encodings are tried and the one that works is remembered.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        with self.lock:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "Mozilla/5.0 (TendaGuardPro)", "Accept": "*/*"})
            self.winner = None
            self.endpoint = None
            self.inline_pw = None
            self.fail_count = 0
            self.backoff_until = 0
            self.last_login = {}
            self.last_fetch = []

    # ---- basics ----
    def host(self):
        return cfg["router"]["ip"]

    def base_url(self):
        return "http://" + self.host()

    def password(self):
        return os.environ.get("TGP_ROUTER_PASSWORD") or cfg["router"].get("password", "")

    def raw(self, method, path, **kwargs):
        headers = kwargs.get("headers", {})
        if "Referer" not in headers:
            headers["Referer"] = self.base_url() + "/index.html"
        if "Origin" not in headers:
            headers["Origin"] = self.base_url()
        kwargs["headers"] = headers
        return self.session.request(
            method, self.base_url() + path, timeout=(4, 8), allow_redirects=False, **kwargs
        )

    # ---- device list ----
    def endpoint_specs(self):
        specs = list(BUILTIN_ENDPOINTS)
        known = [path for path, _ in specs]
        extra = [cfg["router"].get("devices_endpoint", "")] + list(cfg["router"].get("fallback_endpoints", []))
        for path in extra:
            if path and path not in known:
                specs.append((path, {}))
                known.append(path)
        if self.endpoint:
            specs.sort(key=lambda spec: 0 if spec[0] == self.endpoint else 1)
        return specs

    def fetch_devices(self):
        """Tries every known device-list page. Returns (path, response) of the first
        usable one, otherwise the last response seen."""
        last = (None, None)
        login_hit = None
        trail = []
        for path, params in self.endpoint_specs():
            query = dict(params)
            query["random"] = "%.6f" % time.time()
            if self.inline_pw:
                data = dict(params)
                data["password"] = self.inline_pw
                resp = self.raw("POST", path, params={"random": query["random"]}, data=data)
            else:
                resp = self.raw("GET", path, params=query)
            login_like = looks_like_login(resp)
            trail.append((path, resp.status_code, login_like))
            last = (path, resp)
            if login_like and login_hit is None:
                login_hit = (path, resp)
            if resp.status_code == 404 or login_like:
                continue
            self.last_fetch = trail
            return path, resp
        self.last_fetch = trail
        return login_hit or last

    def session_valid(self):
        path, resp = self.fetch_devices()
        return resp is not None and resp.status_code == 200 and not looks_like_login(resp)

    def get_devices(self):
        with self.lock:
            path, resp = self.fetch_devices()
            if looks_like_login(resp):
                self.login()
                path, resp = self.fetch_devices()
                if looks_like_login(resp):
                    raise RouterAuthError("The router still shows its login page after signing in.")
            if resp is None or resp.status_code == 404:
                raise RouterFormatError(
                    "The router has none of the known device-list pages (HTTP 404). "
                    "Use Settings > Test router connection.")
            resp.raise_for_status()
            self.endpoint = path
            devices = parse_devices(resp.text)
            body_text = (resp.text or "").strip()
            if not devices and body_text and body_text not in ("[]", "{}") and not MAC_RE.search(body_text):
                try:
                    json.loads(body_text)
                except ValueError:
                    raise RouterFormatError(
                        "Unexpected reply from the router: {}".format(" ".join(body_text[:80].split())))
            return devices

    # ---- login ----
    def discover_login(self):
        """Reads the router's own login page to learn field names, form targets and hints."""
        info = {"page_status": None, "actions": [], "user_field": "", "pass_field": "", "hidden": {},
                "js_urls": [], "hints": [], "kinds": list(PASSWORD_KINDS), "scripts_read": 0}
        try:
            page = self.raw("GET", "/login.html")
        except requests.RequestException:
            return info
        info["page_status"] = page.status_code
        html = page.text or ""
        if page.status_code != 200 or not html:
            return info
        for tag in re.findall(r"<form[^>]*>", html, re.I):
            match = re.search(r"action\s*=\s*[\"']([^\"']*)", tag, re.I)
            if match and match.group(1) and not match.group(1).startswith("#"):
                info["actions"].append(match.group(1) if match.group(1).startswith("/") else "/" + match.group(1))
        for tag in re.findall(r"<input[^>]*>", html, re.I):
            name = re.search(r"name\s*=\s*[\"']([^\"']+)", tag, re.I)
            kind = re.search(r"type\s*=\s*[\"']([^\"']+)", tag, re.I)
            value = re.search(r"value\s*=\s*[\"']([^\"']*)", tag, re.I)
            if not name:
                continue
            kind = kind.group(1).lower() if kind else "text"
            if kind == "password" and not info["pass_field"]:
                info["pass_field"] = name.group(1)
            elif kind == "text" and not info["user_field"]:
                info["user_field"] = name.group(1)
            elif kind == "hidden":
                info["hidden"][name.group(1)] = value.group(1) if value else ""
        blob = html
        for src_url in re.findall(r"<script[^>]+src\s*=\s*[\"']([^\"']+)", html, re.I)[:5]:
            if src_url.startswith("http"):
                continue
            path = src_url if src_url.startswith("/") else "/" + src_url
            try:
                script = self.raw("GET", path)
            except requests.RequestException:
                continue
            if script.status_code == 200:
                blob += "\n" + script.text[:300000]
                info["scripts_read"] += 1
        for url in re.findall(r"[\"'](/[A-Za-z0-9_./\-]*(?:login|Login|auth|Auth)[A-Za-z0-9_./\-]*)[\"']", blob):
            if url not in info["js_urls"] and not url.endswith((".html", ".js", ".css")):
                info["js_urls"].append(url)
        for line in blob.splitlines():
            if re.search(r"ecos_pw|base64|md5|btoa|login/Auth", line, re.I) and len(info["hints"]) < 8:
                cleaned = " ".join(line.split())[:180]
                if cleaned and cleaned not in info["hints"]:
                    info["hints"].append(cleaned)
        has_b64 = bool(re.search(r"base64|btoa", blob, re.I))
        has_md5 = bool(re.search(r"md5", blob, re.I))
        if has_md5 and not has_b64:
            info["kinds"] = ["md5", "base64", "plain"]
        return info

    def login_candidates(self, user, password, disc):
        kinds = disc["kinds"]
        paths = []
        for path in disc["actions"] + ["/login/Auth"] + disc["js_urls"]:
            if path and path not in paths:
                paths.append(path)
        paths = paths[:3]
        fieldsets = []
        if disc["user_field"] or disc["pass_field"]:
            fieldsets.append((disc["user_field"] or "username", disc["pass_field"] or "password"))
        for pair in [("username", "password"), ("user", "pass")]:
            if pair not in fieldsets:
                fieldsets.append(pair)
        fieldsets = fieldsets[:2]

        def post_data(user_key, pass_key, kind):
            data = dict(disc["hidden"])
            data[user_key] = user
            data[pass_key] = encode_password(kind, password)
            return data

        first_path = paths[0]
        first_user, first_pass = fieldsets[0]
        candidates = []
        for kind in kinds:
            candidates.append({"label": "POST {} {}/{} password={}".format(first_path, first_user, first_pass, kind),
                               "cookie": None, "post": (first_path, post_data(first_user, first_pass, kind)), "inline": None})
        for kind in kinds:
            candidates.append({"label": "cookie {}={} + POST {}".format(AUTH_COOKIE, kind, first_path),
                               "cookie": (AUTH_COOKIE, encode_password(kind, password)),
                               "post": (first_path, post_data(first_user, first_pass, kind)), "inline": None})
        for kind in kinds:
            candidates.append({"label": "cookie {}={} only".format(AUTH_COOKIE, kind),
                               "cookie": (AUTH_COOKIE, encode_password(kind, password)), "post": None, "inline": None})
        for kind in kinds:
            candidates.append({"label": "password sent with each request ({})".format(kind),
                               "cookie": None, "post": None, "inline": encode_password(kind, password)})
        for path in paths:
            for user_key, pass_key in fieldsets:
                for kind in kinds:
                    label = "POST {} {}/{} password={}".format(path, user_key, pass_key, kind)
                    if any(c["label"] == label for c in candidates):
                        continue
                    candidates.append({"label": label, "cookie": None,
                                       "post": (path, post_data(user_key, pass_key, kind)), "inline": None})
        return candidates[:30]

    def login(self):
        if time.time() < self.backoff_until:
            raise RouterAuthError("Waiting a moment before the next router login attempt.")
        password = self.password()
        if not password:
            raise RouterAuthError("The router asked for a login but no admin password is saved. Add it in Settings.")
        user = cfg["router"].get("username", "admin") or "admin"
        domain = self.host().split(":")[0]
        discovery = self.discover_login()
        candidates = self.login_candidates(user, password, discovery)
        if self.winner:
            candidates = [self.winner] + [c for c in candidates if c["label"] != self.winner["label"]]

        attempts = []
        errors = 0
        for candidate in candidates:
            self.session.cookies.clear()
            self.inline_pw = candidate["inline"]
            if candidate["cookie"]:
                self.session.cookies.set(candidate["cookie"][0], candidate["cookie"][1], domain=domain, path="/")
            outcome = ""
            valid = False
            try:
                if candidate["post"]:
                    reply = self.raw("POST", candidate["post"][0], data=candidate["post"][1])
                    outcome = "POST {}".format(reply.status_code)
                valid = self.session_valid()
                outcome += (" , " if outcome else "") + ("list OK" if valid else "still login page")
            except requests.RequestException as exc:
                errors += 1
                outcome = "network error {}".format(exc.__class__.__name__)
            attempts.append({"label": candidate["label"], "result": outcome})
            if valid:
                self.winner = candidate
                self.fail_count = 0
                self.last_login = {"discovery": discovery, "attempts": attempts, "ok": True}
                return True
            self.inline_pw = None

        self.session.cookies.clear()
        self.last_login = {"discovery": discovery, "attempts": attempts, "ok": False}
        if attempts and errors == len(attempts):
            raise requests.ConnectionError("every login attempt failed to connect")
        self.fail_count += 1
        if self.fail_count >= 3:
            self.backoff_until = time.time() + min(600, 60 * self.fail_count)
        raise RouterAuthError("Router login failed. Use Settings > Test router connection to see why.")

    # ---- actions ----
    def call(self, method, path, **kwargs):
        with self.lock:
            if self.inline_pw and method == "POST" and isinstance(kwargs.get("data"), dict):
                kwargs["data"] = dict(kwargs["data"], password=self.inline_pw)
            resp = self.raw(method, path, **kwargs)
            if looks_like_login(resp):
                self.login()
                resp = self.raw(method, path, **kwargs)
                if looks_like_login(resp):
                    raise RouterAuthError("The router rejected the request after signing in.")
            return resp

    def limit_matches(self, mac, kbps):
        """Reads the router back. True when it agrees (or does not report limits)."""
        try:
            devices = self.get_devices()
        except (RouterAuthError, RouterFormatError, requests.RequestException):
            return True
        for device in devices:
            if device["mac"] != mac:
                continue
            reported = [v for v in (device.get("up_limit"), device.get("down_limit")) if v is not None]
            if not reported:
                return True
            return any(v > 0 for v in reported) == (kbps > 0)
        return True

    def set_limit(self, device, kbps):
        template = cfg["router"].get("limit_template", DEFAULT_CONFIG["router"]["limit_template"])
        try:
            line = template.format(
                name=device.get("name", "device"), mac=device["mac"], ip=device.get("ip", ""), up=kbps, down=kbps)
        except (KeyError, IndexError, ValueError):
            return False
        payload = {cfg["router"].get("limit_param", "list"): line}
        endpoint = cfg["router"].get("limit_endpoint") or "/goform/setQos"
        try:
            resp = self.call("POST", endpoint, data=payload)
            if not resp.ok:
                return False
            time.sleep(0.6)
            return self.limit_matches(device["mac"], kbps)
        except (requests.RequestException, RouterAuthError):
            return False

    def reboot(self):
        try:
            resp = self.call("POST", "/goform/SysToolReboot", data={})
            return resp.ok
        except (requests.ConnectionError, requests.ReadTimeout):
            return True
        except (requests.RequestException, RouterAuthError):
            return False

    # ---- diagnostics ----
    def diagnose(self):
        """Human readable report of what the router does. Never includes passwords or cookie values."""
        lines = []
        with self.lock:
            lines.append("Router: {}".format(self.host()))
            lines.append("Admin password saved: {}".format("yes" if self.password() else "NO"))
            try:
                path, resp = self.fetch_devices()
            except requests.RequestException as exc:
                return lines + ["Cannot connect: {}".format(exc.__class__.__name__),
                                "Check the router address and that this phone is on the router's Wi-Fi."]
            for trail_path, status, login_like in self.last_fetch:
                lines.append("Try {} -> HTTP {}{}".format(trail_path, status, " (login page)" if login_like else ""))
            snippet = " ".join((resp.text or "")[:140].split()) if resp is not None else ""
            lines.append("Last reply starts with: {}".format(snippet or "(empty)"))
            if resp is not None and looks_like_login(resp):
                try:
                    self.login()
                except (RouterAuthError, requests.RequestException) as exc:
                    lines.append("Login result: FAILED ({})".format(str(exc)[:120]))
                else:
                    lines.append("Login result: OK using: {}".format(self.winner["label"]))
                report = self.last_login
                disc = report.get("discovery", {})
                lines.append("Router login page: HTTP {} , form actions {} , user field {} , password field {} , scripts read {}".format(
                    disc.get("page_status"), disc.get("actions") or "none", disc.get("user_field") or "?",
                    disc.get("pass_field") or "?", disc.get("scripts_read")))
                for hint in disc.get("hints", [])[:8]:
                    lines.append("  login script: {}".format(hint))
                for item in report.get("attempts", [])[:14]:
                    lines.append("  tried: {} -> {}".format(item["label"], item["result"]))
            names = sorted({cookie.name for cookie in self.session.cookies})
            lines.append("Cookies held: {}".format(", ".join(names) or "none"))
            try:
                devices = self.get_devices()
                lines.append("Devices found now: {}".format(len(devices)))
            except (RouterAuthError, RouterFormatError, requests.RequestException) as exc:
                lines.append("Device list still failing: {}".format(str(exc)[:160]))
        return lines


router = RouterClient()


# -----------------------------------------------------------------------------
# Device registry: keeps the list stable through failed or empty polls
# -----------------------------------------------------------------------------
def load_registry():
    now = time.time()
    for mac, info in cfg.get("known_devices", {}).items():
        registry[mac] = {"name": info.get("name", "Unknown device"), "ip": info.get("ip", ""), "last_seen": now}
    runtime["last_poll"] = now


def visible_devices(now=None):
    now = now or time.time()
    grace = max(15, int(cfg.get("device_grace_seconds", 45)))
    shown = []
    for mac, entry in registry.items():
        recent = now - entry["last_seen"] <= grace
        frozen = runtime["stale"] and entry["last_seen"] >= runtime["last_poll"] - grace
        if recent or frozen:
            shown.append({"mac": mac, "name": entry["name"], "ip": entry["ip"]})
    shown.sort(key=lambda d: (d["name"].lower(), d["mac"]))
    return shown


def remember_devices(devices):
    with cfg_lock:
        changed = False
        for device in devices:
            record = {"name": device["name"], "ip": device["ip"]}
            if cfg["known_devices"].get(device["mac"]) != record:
                cfg["known_devices"][device["mac"]] = record
                changed = True
        if len(cfg["known_devices"]) > MAX_KNOWN_DEVICES:
            ranked = sorted(cfg["known_devices"], key=lambda m: registry.get(m, {}).get("last_seen", 0))
            for mac in ranked[: len(cfg["known_devices"]) - MAX_KNOWN_DEVICES]:
                cfg["known_devices"].pop(mac, None)
                registry.pop(mac, None)
            changed = True
        if changed:
            save_config()


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
            runtime["mail_error"] = str(exc)[:200]
            runtime["mail_backoff_until"] = time.time() + 300
            if device["mac"] in cfg["notified_macs"]:
                cfg["notified_macs"].remove(device["mac"])
                save_config()
        bus.publish()


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
    return changed


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


def mark_failure(message, auth=False):
    with cfg_lock:
        runtime["router_online"] = False
        runtime["stale"] = True
        runtime["auth_error"] = auth
        runtime["last_error"] = message[:240]


def poll_once():
    run_expiry()
    try:
        devices = router.get_devices()
    except RouterAuthError as exc:
        mark_failure(str(exc), auth=True)
        bus.publish()
        return
    except RouterFormatError as exc:
        mark_failure(str(exc))
        bus.publish()
        return
    except requests.RequestException as exc:
        mark_failure("Cannot reach the router: {}".format(exc.__class__.__name__))
        bus.publish()
        return

    now = time.time()
    with cfg_lock:
        runtime["router_online"] = True
        runtime["auth_error"] = False
        runtime["last_error"] = ""
        had_devices = bool(visible_devices(now))
        if not devices and had_devices and runtime["empty_streak"] < int(cfg.get("empty_confirmations", 3)):
            runtime["empty_streak"] += 1
            runtime["last_error"] = "The router returned an empty list. Keeping the last known devices."
            suspicious = True
        else:
            suspicious = False
            runtime["empty_streak"] = 0
            for device in devices:
                registry[device["mac"]] = {"name": device["name"], "ip": device["ip"], "last_seen": now}
            runtime["stale"] = False
            runtime["last_poll"] = now
    bus.publish()
    if suspicious:
        return
    remember_devices(devices)
    throttle_step(devices)
    notify_step(devices)
    bus.publish()


def run_cycle(blocking=True):
    if not cycle_lock.acquire(blocking=blocking):
        return False
    try:
        poll_once()
    finally:
        cycle_lock.release()
    return True


def worker_loop():
    while True:
        try:
            run_cycle()
        except Exception as exc:  # keep the watchdog alive whatever happens
            mark_failure("Unexpected error: {}".format(exc))
            bus.publish()
        time.sleep(max(3, int(cfg.get("poll_interval", 5))))


def start_worker():
    thread = threading.Thread(target=worker_loop, name="guard-worker", daemon=True)
    thread.start()
    return thread


# -----------------------------------------------------------------------------
# Web security setup
# -----------------------------------------------------------------------------
class CookieInterface(SecureCookieSessionInterface):
    """Marks the session cookie Secure automatically when served over HTTPS."""

    def get_cookie_secure(self, app):
        return request.is_secure


def init_web_security():
    changed = False
    with cfg_lock:
        web = cfg["web"]
        if not web.get("secret_key"):
            web["secret_key"] = secrets.token_hex(32)
            changed = True
        env_password = os.environ.get("TGP_WEB_PASSWORD", "")
        if env_password and (not web.get("password_hash") or not check_password_hash(web["password_hash"], env_password)):
            web["password_hash"] = generate_password_hash(env_password)
            changed = True
        elif not web.get("password_hash"):
            generated = secrets.token_urlsafe(9)
            web["password_hash"] = generate_password_hash(generated)
            changed = True
            print("=" * 62, flush=True)
            print(" Tenda Guard Pro: first run web password", flush=True)
            print(" Password: {}".format(generated), flush=True)
            print(" Change it in Settings after signing in.", flush=True)
            print("=" * 62, flush=True)
        if changed:
            save_config()


app = Flask(__name__)
init_web_security()
app.secret_key = cfg["web"]["secret_key"]
app.session_interface = CookieInterface()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="tgp_session",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(cfg["web"].get("session_hours", 72))),
    MAX_CONTENT_LENGTH=64 * 1024,
)
if cfg["web"].get("trust_proxy", True):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

login_attempts = {}
PUBLIC_ENDPOINTS = {"login", "static"}


def body():
    return request.get_json(silent=True) or {}


def fail(message, status=400):
    return jsonify({"ok": False, "error": message}), status


def origin_ok():
    origin = request.headers.get("Origin")
    if not origin:
        return True
    if origin == "null":
        return False
    return urlparse(origin).netloc == request.host


@app.before_request
def guard():
    session["auth"] = True
    return None
    if request.endpoint in PUBLIC_ENDPOINTS:
        if request.method == "POST" and not origin_ok():
            return fail("Cross-site request blocked.", 403)
        return None
    if not session.get("auth"):
        if request.path.startswith("/api/") or request.path == "/stream" or request.method != "GET":
            return fail("Sign in required.", 401)
        return redirect(url_for("login"))
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not origin_ok():
            return fail("Cross-site request blocked.", 403)
        token = request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(token, session.get("csrf", "")):
            return fail("Security token mismatch. Reload the page.", 403)
    return None


@app.after_request
def secure_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.endpoint != "static" and "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("auth"):
            return redirect(url_for("index"))
        return render_template("login.html", error="")
    now = time.time()
    ip = request.remote_addr or "unknown"
    record = login_attempts.setdefault(ip, {"fails": 0, "until": 0})
    if record["until"] > now:
        wait = int(record["until"] - now)
        return render_template("login.html", error="Too many attempts. Try again in {} seconds.".format(wait)), 429
    password = request.form.get("password", "")
    if check_password_hash(cfg["web"]["password_hash"], password):
        login_attempts.pop(ip, None)
        session.clear()
        session.permanent = True
        session["auth"] = True
        session["csrf"] = secrets.token_urlsafe(24)
        return redirect(url_for("index"))
    record["fails"] += 1
    if record["fails"] >= 5:
        record["until"] = now + 300
        record["fails"] = 0
    if len(login_attempts) > 500:
        for key in [k for k, v in login_attempts.items() if v["until"] < now and v["fails"] == 0]:
            login_attempts.pop(key, None)
    time.sleep(0.6)
    return render_template("login.html", error="Incorrect password."), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


# -----------------------------------------------------------------------------
# Snapshot and streaming
# -----------------------------------------------------------------------------
def snapshot():
    now = time.time()
    with cfg_lock:
        trusted = cfg["trusted_devices"]
        limits = cfg["limits"]
        devices_out = []
        throttled = 0
        online_macs = set()
        for device in visible_devices(now):
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
            "server_time": now,
            "router_ip": cfg["router"]["ip"],
            "router_online": runtime["router_online"],
            "stale": runtime["stale"],
            "auth_error": runtime["auth_error"],
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


stream_slots = threading.BoundedSemaphore(MAX_STREAM_CLIENTS)


class EventStream:
    """Iterator that yields an SSE frame on every state change or interval."""

    def __init__(self):
        self.first = True
        self.version = -1
        self.released = False

    def __iter__(self):
        return self

    def frame(self):
        with bus.cond:
            self.version = bus.version
        payload = json.dumps(snapshot(), separators=(",", ":"))
        return "id: {}\nevent: snapshot\ndata: {}\n\n".format(self.version, payload)

    def __next__(self):
        if self.first:
            self.first = False
            return "retry: 3000\n\n" + self.frame()
        interval = max(2, int(cfg.get("stream_interval", 4)))
        with bus.cond:
            bus.cond.wait_for(lambda: bus.version != self.version, timeout=interval)
        return self.frame()

    def close(self):
        if not self.released:
            self.released = True
            stream_slots.release()


@app.route("/stream")
def stream():
    if not stream_slots.acquire(blocking=False):
        return fail("Too many live connections. Close another tab and retry.", 429)
    response = Response(EventStream(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache, no-transform"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response


# -----------------------------------------------------------------------------
# REST API
# -----------------------------------------------------------------------------
def find_device(mac):
    with cfg_lock:
        for device in visible_devices():
            if device["mac"] == mac:
                return dict(device)
    return None


@app.route("/")
def index():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return render_template("index.html", csrf=session["csrf"])


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
    bus.publish()
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
    bus.publish()
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
    bus.publish()
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
    bus.publish()
    return jsonify({"ok": True})


@app.route("/api/panic-lock", methods=["POST"])
def api_panic_lock():
    with cfg_lock:
        trusted = set(cfg["trusted_devices"].keys())
        targets = [d for d in visible_devices() if d["mac"] not in trusted]
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
    bus.publish()
    return jsonify({"ok": failed == 0, "throttled": done, "failed": failed,
                    "error": "{} device(s) could not be throttled.".format(failed) if failed else ""})


@app.route("/api/reboot", methods=["POST"])
def api_reboot():
    if not runtime["router_online"]:
        return fail("The router is not reachable, so it cannot be rebooted.", 502)
    if not router.reboot():
        return fail("The router rejected the reboot command.", 502)
    with cfg_lock:
        cfg["limits"] = {}
        runtime["router_online"] = False
        runtime["stale"] = True
        save_config()
    bus.publish()
    return jsonify({"ok": True})


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    run_cycle(blocking=False)
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
            "router_password_set": bool(router.password()),
        })


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    payload = body()
    sender = str(payload.get("sender", "")).strip()
    target = str(payload.get("target", "")).strip()
    router_ip = str(payload.get("router_ip", "")).strip()
    if sender and not EMAIL_RE.match(sender):
        return fail("Sender email is not a valid address.")
    if target and not EMAIL_RE.match(target):
        return fail("Target email is not a valid address.")
    if router_ip and not HOST_RE.match(router_ip):
        return fail("Router address must look like 192.168.0.1.")
    reset_router = False
    with cfg_lock:
        cfg["email"]["sender"] = sender
        cfg["email"]["target"] = target
        new_password = str(payload.get("app_password", "")).strip()
        if new_password:
            cfg["email"]["app_password"] = new_password
        router_password = payload.get("router_password")
        if isinstance(router_password, str) and router_password.strip():
            cfg["router"]["password"] = router_password.strip()
            reset_router = True
        if router_ip and router_ip != cfg["router"]["ip"]:
            cfg["router"]["ip"] = router_ip
            reset_router = True
        runtime["mail_backoff_until"] = 0
        save_config()
    if reset_router:
        router.reset()
        threading.Thread(target=run_cycle, daemon=True).start()
    bus.publish()
    return jsonify({"ok": True})


@app.route("/api/change-password", methods=["POST"])
def api_change_password():
    payload = body()
    current = str(payload.get("current", ""))
    new = str(payload.get("new", ""))
    if not check_password_hash(cfg["web"]["password_hash"], current):
        return fail("Your current password is incorrect.", 403)
    if len(new) < MIN_WEB_PASSWORD_LENGTH:
        return fail("Use at least {} characters for the new password.".format(MIN_WEB_PASSWORD_LENGTH))
    with cfg_lock:
        cfg["web"]["password_hash"] = generate_password_hash(new)
        cfg["web"]["secret_key"] = secrets.token_hex(32)
        save_config()
        app.secret_key = cfg["web"]["secret_key"]
    session.clear()
    session.permanent = True
    session["auth"] = True
    session["csrf"] = secrets.token_urlsafe(24)
    return jsonify({"ok": True, "csrf": session["csrf"]})


@app.route("/api/diagnose", methods=["POST"])
def api_diagnose():
    try:
        lines = router.diagnose()
    except Exception as exc:  # report instead of crashing the request
        lines = ["Diagnosis failed: {}".format(str(exc)[:160])]
    return jsonify({"ok": True, "lines": lines})


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
        return fail("Email failed: {}".format(str(exc)[:160]), 502)
    return jsonify({"ok": True})


load_registry()

if __name__ == "__main__":
    start_worker()
    app.run(
        host=cfg["server"].get("host", "127.0.0.1"),
        port=int(cfg["server"].get("port", 5000)),
        threaded=True,
        use_reloader=False,
    )
