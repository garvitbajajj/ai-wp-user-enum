"""Output rendering: a human-readable CLI report (rich) and structured JSON."""
from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def render_cli(data: dict) -> None:
    console.print()
    console.rule(f"[bold]WordPress User Enumeration[/] — {data['target']}")
    console.print(f"mode: [cyan]{data['mode']}[/]\n")

    users = data.get("users", [])
    if users:
        table = Table(title=f"Discovered users ({len(users)})", show_lines=False)
        table.add_column("ID", justify="right", style="dim")
        table.add_column("Username", style="bold green")
        table.add_column("Display name")
        table.add_column("Found via")
        table.add_column("Confirmed", justify="center")
        for u in users:
            table.add_row(
                str(u.get("user_id") if u.get("user_id") is not None else "-"),
                u.get("username", ""),
                u.get("display_name") or "-",
                ", ".join(u.get("sources", [])) or "-",
                "✓" if u.get("confirmed") else "",
            )
        console.print(table)
    else:
        console.print("[yellow]No users discovered.[/]")

    # Technique evidence
    console.print("\n[bold]Techniques[/]")
    for t in data.get("techniques", []):
        status = "[red]error[/]" if t.get("error") else (
            "[green]hit[/]" if t.get("found") else "[yellow]miss[/]")
        console.print(f"  • {t['technique']} [{status}] — {t.get('evidence') or t.get('error') or ''}")

    # Brute-force
    admin = data.get("admin")
    if admin:
        bf = admin["bruteforce"]
        if bf.get("success"):
            console.print(Panel.fit(
                f"[bold red]ADMIN LOGIN CRACKED[/]\n"
                f"user: [bold]{admin['username']}[/]\n"
                f"password: [bold]{bf['password']}[/]  (attempt {bf['attempts']})",
                border_style="red"))
        else:
            console.print(f"\n[bold]Brute-force[/] against [bold]{admin['username']}[/]: "
                          f"[yellow]no hit[/] ({bf['evidence']})")

    if data.get("ai_summary"):
        console.print(Panel(data["ai_summary"], title="AI Summary Report",
                            border_style="cyan"))
    console.print()


def to_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def write_json(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_json(data))
    console.print(f"[dim]JSON written to {path}[/]")
