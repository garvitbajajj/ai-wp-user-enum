"""Unit tests for the enumeration + brute-force logic (HTTP fully mocked).

Run: pytest -q
"""
import responses

from src.bruteforce import bruteforce_login
from src.enumerators import (author_archive_users, confirm_username_via_login,
                             rest_api_users)
from src.findings import Findings
from src.http_client import HttpClient

BASE = "http://wp.test"


def _client():
    return HttpClient(timeout=5)


@responses.activate
def test_rest_api_parses_users():
    responses.add(
        responses.GET, f"{BASE}/wp-json/wp/v2/users",
        json=[
            {"id": 1, "slug": "admin", "name": "Administrator"},
            {"id": 2, "slug": "editor1", "name": "Editor One"},
        ],
        headers={"X-WP-TotalPages": "1"}, status=200,
    )
    users, ev = rest_api_users(_client(), BASE)
    names = sorted(u["username"] for u in users)
    assert names == ["admin", "editor1"]
    assert users[0]["user_id"] == 1
    assert "without authentication" in ev


@responses.activate
def test_rest_api_falls_back_to_rest_route():
    responses.add(responses.GET, f"{BASE}/wp-json/wp/v2/users", status=404)
    responses.add(
        responses.GET, f"{BASE}/", json=[{"id": 1, "slug": "admin", "name": "Admin"}],
        headers={"X-WP-TotalPages": "1"}, status=200,
    )
    users, _ = rest_api_users(_client(), BASE)
    assert [u["username"] for u in users] == ["admin"]


@responses.activate
def test_author_archive_leaks_slug_via_redirect():
    responses.add(
        responses.GET, f"{BASE}/", status=302,
        headers={"Location": f"{BASE}/author/adminuser/"},
    )
    users, ev = author_archive_users(_client(), BASE, max_ids=1)
    assert users and users[0]["username"] == "adminuser"
    assert users[0]["user_id"] == 1
    assert "author" in ev


@responses.activate
def test_login_error_oracle_valid_user():
    responses.add(
        responses.POST, f"{BASE}/wp-login.php", status=200,
        body="<strong>Error:</strong> The password you entered for the username "
             "<strong>admin</strong> is incorrect.",
    )
    res = confirm_username_via_login(_client(), BASE, "admin")
    assert res["status"] == "valid"


@responses.activate
def test_login_error_oracle_invalid_user():
    responses.add(
        responses.POST, f"{BASE}/wp-login.php", status=200,
        body="<strong>Error:</strong> The username <strong>ghost</strong> "
             "is not registered on this site.",
    )
    res = confirm_username_via_login(_client(), BASE, "ghost")
    assert res["status"] == "invalid"


@responses.activate
def test_bruteforce_finds_password():
    # First attempt (wrong) fails with 200; second (admin123) succeeds with a 302.
    responses.add(responses.POST, f"{BASE}/wp-login.php", status=200, body="incorrect")
    responses.add(
        responses.POST, f"{BASE}/wp-login.php", status=302,
        headers={"Location": f"{BASE}/wp-admin/"},
    )
    res = bruteforce_login(_client(), BASE, "admin", ["wrong", "admin123"], delay=0)
    assert res["success"] is True
    assert res["password"] == "admin123"
    assert res["attempts"] == 2


@responses.activate
def test_bruteforce_exhausts_list():
    responses.add(responses.POST, f"{BASE}/wp-login.php", status=200, body="incorrect")
    res = bruteforce_login(_client(), BASE, "admin", ["nope"], delay=0)
    assert res["success"] is False
    assert res["password"] is None


def test_findings_merge_and_dedupe():
    f = Findings(target=BASE)
    f.record_technique("rest_api", "/users",
                       [{"username": "admin", "user_id": 1, "display_name": "Admin"}], "ev1")
    f.record_technique("author_archive", "/?author=1",
                       [{"username": "admin", "user_id": 1}], "ev2")
    assert len(f.users) == 1
    assert sorted(f.users["admin"].sources) == ["author_archive", "rest_api"]
    f.confirm_user("admin", True)
    assert f.users["admin"].confirmed is True
