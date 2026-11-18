"""CLI entry point.

Usage:
    python -m src.main --target http://localhost:8080          # AI agent (default)
    python -m src.main --target http://localhost:8080 --no-ai  # deterministic only
"""
from __future__ import annotations

import sys

from .bruteforce import bruteforce_login, load_passwords
from .config import Config, parse_config
from .enumerators import (author_archive_users, confirm_username_via_login,
                          rest_api_users)
from .findings import Findings
from .http_client import HttpClient
from . import agent, report


def run_deterministic(config: Config, client: HttpClient, findings: Findings) -> None:
    """Fixed enumeration pipeline — no AI. Also the fallback when the agent can't run."""
    # 1. REST API first (highest-signal technique).
    users, ev = rest_api_users(client, config.target)
    findings.record_technique("rest_api", "/wp-json/wp/v2/users", users, ev)

    # 2. Author-archive fallback / corroboration.
    a_users, a_ev = author_archive_users(client, config.target, config.max_author_ids)
    findings.record_technique("author_archive", "/?author=N", a_users, a_ev)

    if not findings.users:
        return  # nothing to confirm or brute-force

    # 3. Admin is user id 1 if present, else the first discovered user.
    admin = next((u for u in findings.users.values() if u.user_id == 1), None)
    admin_name = (admin or next(iter(findings.users.values()))).username

    # 4. Confirm via login-error oracle.
    res = confirm_username_via_login(client, config.target, admin_name)
    is_valid = res["status"] == "valid"
    findings.confirm_user(admin_name, is_valid)
    findings.record_technique("login_error_oracle", f"wp-login.php?log={admin_name}",
                              [], f"{admin_name}: {res['status']} — {res['evidence']}",
                              status="confirmed" if is_valid else res["status"])

    # 5. Brute-force the admin with the common-password list.
    try:
        pws = load_passwords(config.passwords_file)
    except OSError as exc:
        findings.record_technique("bruteforce", config.passwords_file, [],
                                  error=f"could not read password list: {exc}")
        return
    bf = bruteforce_login(client, config.target, admin_name, pws, config.delay)
    findings.set_bruteforce(admin_name, bf)


def main(argv: list[str] | None = None) -> int:
    # Ensure non-ASCII report glyphs (box drawing, check marks) don't crash on
    # Windows' legacy cp1252 console.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    config = parse_config(argv)
    client = HttpClient(timeout=config.timeout)

    mode = "ai" if config.use_ai else "deterministic"
    findings = Findings(target=config.target, mode=mode)

    if config.use_ai:
        try:
            agent.run(config, client, findings)
        except agent.AgentUnavailable as exc:
            report.console.print(
                f"[yellow]AI agent unavailable ({exc}); "
                f"falling back to deterministic pipeline.[/]")
            findings.mode = "deterministic (fallback)"
            run_deterministic(config, client, findings)
    else:
        run_deterministic(config, client, findings)

    data = findings.to_dict()
    if config.json_out:                 # write the deliverable first
        report.write_json(data, config.json_out)
    report.render_cli(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
