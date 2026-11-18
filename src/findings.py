"""Shared result model. Both the deterministic pipeline and the AI agent feed
into one Findings object, so JSON / CLI output is identical either way.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class User:
    username: str
    display_name: str | None = None
    user_id: int | None = None
    sources: list[str] = field(default_factory=list)
    confirmed: bool = False  # proven valid via login-error oracle


class Findings:
    def __init__(self, target: str, mode: str = "deterministic"):
        self.target = target
        self.mode = mode
        self.techniques: list[dict] = []
        self.users: dict[str, User] = {}   # keyed by username
        self.admin: dict | None = None
        self.ai_summary: str | None = None

    def record_technique(
        self,
        technique: str,
        detail: str,
        found: list[dict] | None = None,
        evidence: str | None = None,
        error: str | None = None,
    ) -> list[str]:
        """Log a technique run and merge any users it discovered.

        `found` is a list of {username, display_name?, user_id?}.
        Returns the list of usernames discovered by this call.
        """
        found = found or []
        names: list[str] = []
        for item in found:
            name = (item.get("username") or "").strip()
            if not name:
                continue
            names.append(name)
            u = self.users.get(name) or User(username=name)
            u.display_name = u.display_name or item.get("display_name")
            if u.user_id is None:
                u.user_id = item.get("user_id")
            if technique not in u.sources:
                u.sources.append(technique)
            self.users[name] = u
        self.techniques.append({
            "technique": technique,
            "detail": detail,
            "found": names,
            "evidence": evidence,
            "error": error,
        })
        return names

    def confirm_user(self, username: str, confirmed: bool) -> None:
        u = self.users.get(username)
        if u:
            u.confirmed = confirmed or u.confirmed

    def set_bruteforce(self, username: str, result: dict) -> None:
        self.admin = {"username": username, "bruteforce": result}

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "users": [
                {
                    "username": u.username,
                    "display_name": u.display_name,
                    "user_id": u.user_id,
                    "sources": u.sources,
                    "confirmed": u.confirmed,
                }
                for u in self.users.values()
            ],
            "techniques": self.techniques,
            "admin": self.admin,
            "ai_summary": self.ai_summary,
        }
