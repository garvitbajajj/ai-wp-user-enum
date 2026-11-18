"""WordPress user-enumeration techniques (deterministic, no AI).

Each function takes an HttpClient + target base URL and returns a list of user
dicts {username, display_name?, user_id?} plus an evidence string. Network and
parsing errors are caught and surfaced, never raised to the caller.

Techniques:
  1. REST API      GET /wp-json/wp/v2/users           -> JSON user objects
  2. Author archive GET /?author=N (redirect leaks slug)
  3. Login-error oracle (confirm a candidate username is valid)
"""
from __future__ import annotations

import re
import secrets

from requests import RequestException

from .http_client import HttpClient

_AUTHOR_SLUG_RE = re.compile(r"/author/([^/?#\"']+)")
_BODY_AUTHOR_CLASS_RE = re.compile(r"author-([A-Za-z0-9_.-]+)")


# ---------------------------------------------------------------------------
# 1. REST API
# ---------------------------------------------------------------------------
def rest_api_users(client: HttpClient, target: str) -> tuple[list[dict], str]:
    """Enumerate via the unauthenticated REST users endpoint.

    Tries the pretty-permalink route first, then the plain ?rest_route fallback
    so it works regardless of the site's permalink settings. Follows pagination.
    """
    candidates = [
        f"{target}/wp-json/wp/v2/users",
        f"{target}/?rest_route=/wp/v2/users",
    ]
    for base in candidates:
        users: list[dict] = []
        try:
            page, total_pages = 1, 1
            while page <= total_pages:
                sep = "&" if "?" in base else "?"
                url = f"{base}{sep}per_page=100&page={page}"
                resp = client.get(url)
                if resp.status_code != 200:
                    break
                try:
                    data = resp.json()
                except ValueError:
                    break
                if not isinstance(data, list):
                    break
                for obj in data:
                    users.append({
                        "username": obj.get("slug", ""),
                        "display_name": obj.get("name"),
                        "user_id": obj.get("id"),
                    })
                total_pages = int(resp.headers.get("X-WP-TotalPages", 1) or 1)
                page += 1
            if users:
                return users, f"{base} returned {len(users)} user object(s) without authentication"
        except RequestException as exc:
            return [], f"request to {base} failed: {exc}"
    return [], f"no users returned from REST endpoint ({candidates[0]})"


# ---------------------------------------------------------------------------
# 2. Author archive routing
# ---------------------------------------------------------------------------
def author_archive_users(
    client: HttpClient, target: str, max_ids: int = 10
) -> tuple[list[dict], str]:
    """Probe /?author=N; a redirect to /author/<slug>/ leaks the user's login.

    Stops early after 3 consecutive ids return nothing useful.
    """
    found: list[dict] = []
    misses = 0
    last_err = None
    for uid in range(1, max_ids + 1):
        try:
            resp = client.get(f"{target}/?author={uid}", allow_redirects=False)
        except RequestException as exc:
            last_err = str(exc)
            misses += 1
            if misses >= 3:
                break
            continue

        slug = None
        if resp.status_code in (301, 302, 307, 308):
            m = _AUTHOR_SLUG_RE.search(resp.headers.get("Location", ""))
            if m:
                slug = m.group(1)
        if slug is None and resp.status_code == 200:
            # Permalinks may be plain: fall back to parsing the archive page.
            m = _AUTHOR_SLUG_RE.search(resp.text) or _BODY_AUTHOR_CLASS_RE.search(resp.text)
            if m:
                slug = m.group(1)

        if slug:
            found.append({"username": slug, "user_id": uid})
            misses = 0
        else:
            misses += 1
            if misses >= 3 and found:
                break

    if found:
        return found, f"?author=N redirects leaked {len(found)} username(s) via /author/<slug>/"
    msg = "no usernames leaked via author archives"
    if last_err:
        msg += f" (last error: {last_err})"
    return [], msg


# ---------------------------------------------------------------------------
# 3. Login-error oracle
# ---------------------------------------------------------------------------
def wp_login(client: HttpClient, target: str, username: str, password: str):
    """POST credentials to wp-login.php. Returns the raw Response.

    Sets the test cookie WordPress requires, else it short-circuits with a
    "Cookies are blocked" error instead of the real auth result.
    """
    client.session.cookies.set("wordpress_test_cookie", "WP Cookie check")
    data = {
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": f"{target}/wp-admin/",
        "testcookie": "1",
    }
    return client.post(f"{target}/wp-login.php", data=data, allow_redirects=False)


def confirm_username_via_login(client: HttpClient, target: str, username: str) -> dict:
    """Use WordPress's distinct login errors to prove a username exists.

    Valid user + wrong password -> "the password you entered ... is incorrect".
    Unknown user                -> "is not registered" / "Invalid username".
    """
    wrong = "x" + secrets.token_hex(8)
    try:
        resp = wp_login(client, target, username, wrong)
    except RequestException as exc:
        return {"username": username, "status": "error", "evidence": str(exc)}

    text = resp.text.lower()
    if "the password you entered" in text:
        return {"username": username, "status": "valid",
                "evidence": "login error distinguishes a wrong password (user exists)"}
    if "is not registered" in text or "invalid username" in text:
        return {"username": username, "status": "invalid",
                "evidence": "login error reports username not registered"}
    return {"username": username, "status": "unknown",
            "evidence": "login response did not match a known error pattern"}
