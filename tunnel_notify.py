#!/usr/bin/env python3
"""Emails the current Cloudflare tunnel address.

Usage: python tunnel_notify.py https://something.trycloudflare.com

Reads the Gmail settings saved by the app in config.json. Exits quietly when
email is not configured. It never prints passwords.
"""
import json
import os
import smtplib
import ssl
import sys
from datetime import datetime
from email.message import EmailMessage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")


def load_mail_settings(path=CONFIG_PATH):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle).get("email", {})
    except (OSError, ValueError):
        return {}


def build_message(url, mail):
    message = EmailMessage()
    message["Subject"] = "Tenda Guard Pro: your remote access link"
    message["From"] = mail["sender"]
    message["To"] = mail["target"]
    message.set_content(
        "Your router control page is reachable here:\n\n{}\n\n"
        "Sign in with your Tenda Guard Pro password.\n"
        "This address changes whenever the tunnel restarts, and a new email is sent each time.\n"
        "Sent {}.".format(url, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    return message


def send(url, path=CONFIG_PATH):
    mail = load_mail_settings(path)
    if not (mail.get("sender") and mail.get("app_password") and mail.get("target")):
        print("Email is not configured, skipping the link email.")
        return False
    message = build_message(url, mail)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=20) as server:
        server.login(mail["sender"], mail["app_password"].replace(" ", ""))
        server.send_message(message)
    print("Link email sent.")
    return True


if __name__ == "__main__":
    if len(sys.argv) != 2 or not sys.argv[1].startswith("https://"):
        print("Usage: python tunnel_notify.py https://your-tunnel-address")
        sys.exit(2)
    try:
        send(sys.argv[1])
    except Exception as exc:  # network or Gmail problem: report, never crash the supervisor
        print("Could not send the link email: {}".format(str(exc)[:160]))
        sys.exit(1)
