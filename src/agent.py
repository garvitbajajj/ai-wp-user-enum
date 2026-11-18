"""AI agent layer (Claude Agent SDK).

The agent is the "brain": it decides which enumeration technique to try, reads
the structured evidence each returns, confirms the admin user, orders the
brute-force, and writes the final summary. The "muscle" (actual HTTP work) stays
in enumerators.py / bruteforce.py, exposed to the agent as in-process MCP tools.

Requires Node.js (the SDK drives a bundled Claude Code CLI) and an authenticated
Claude session — either a Claude Pro/Max subscription login (`claude setup-token`)
or ANTHROPIC_API_KEY. If the runtime or auth is missing, run() raises
AgentUnavailable and the caller falls back to the deterministic pipeline.
"""
from __future__ import annotations

import asyncio

from .bruteforce import bruteforce_login, load_passwords
from .config import Config
from .enumerators import author_archive_users, confirm_username_via_login, rest_api_users
from .findings import Findings
from .http_client import HttpClient

# Built-in Claude Code tools we never want this agent to touch — it only needs
# the wpenum MCP tools below.
_BLOCKED_BUILTINS = [
    "Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit",
    "Glob", "Grep", "WebFetch", "WebSearch", "TodoWrite", "Task",
]

SYSTEM_PROMPT = """You are a WordPress user-enumeration agent running an AUTHORIZED
security test against a self-hosted, intentionally vulnerable instance.

Your goal: discover valid WordPress usernames, identify the administrator, and
attempt a small common-password brute-force against that admin account.

You have these tools (use only these):
- rest_api_users: query the unauthenticated REST users endpoint.
- author_archive_users: probe ?author=N redirects that leak usernames.
- confirm_username: prove a candidate username is valid via the login-error oracle.
- bruteforce_admin: try a short common-password list against one username.

Strategy:
1. Start with rest_api_users (highest signal). If it finds users, you may skip
   author_archive_users unless you want corroboration; if it finds nothing, fall
   back to author_archive_users.
2. The administrator is almost always user id 1 / the first account. Optionally
   confirm it with confirm_username.
3. Call bruteforce_admin exactly once on the admin username.
4. Finish with a concise 4-6 sentence summary: which technique(s) worked, the
   usernames found, the admin, the brute-force outcome, and the security risk
   this exposure poses. Do not invent data not returned by the tools.
"""


class AgentUnavailable(RuntimeError):
    pass


def _fmt(users: list[dict], evidence: str) -> str:
    if not users:
        return f"No users found. {evidence}"
    lines = [f"- {u.get('username')} (id={u.get('user_id')}, name={u.get('display_name')})"
             for u in users]
    return evidence + "\n" + "\n".join(lines)


def _build_tools(client: HttpClient, config: Config, findings: Findings):
    from claude_agent_sdk import tool

    @tool("rest_api_users", "Enumerate users via the WordPress REST API "
          "(/wp-json/wp/v2/users), unauthenticated.", {})
    async def t_rest(args):
        users, ev = rest_api_users(client, config.target)
        findings.record_technique("rest_api", "/wp-json/wp/v2/users", users, ev)
        return {"content": [{"type": "text", "text": _fmt(users, ev)}]}

    @tool("author_archive_users", "Probe /?author=N; redirects to /author/<slug>/ "
          "leak usernames.", {})
    async def t_author(args):
        users, ev = author_archive_users(client, config.target, config.max_author_ids)
        findings.record_technique("author_archive", "/?author=N", users, ev)
        return {"content": [{"type": "text", "text": _fmt(users, ev)}]}

    @tool("confirm_username", "Confirm a username exists via the wp-login.php "
          "error oracle.", {"username": str})
    async def t_confirm(args):
        res = confirm_username_via_login(client, config.target, args["username"])
        findings.confirm_user(args["username"], res["status"] == "valid")
        findings.record_technique("login_error_oracle",
                                  f"wp-login.php?log={args['username']}",
                                  [], f"{args['username']}: {res['status']} — {res['evidence']}")
        return {"content": [{"type": "text", "text": f"{args['username']}: {res['status']} ({res['evidence']})"}]}

    @tool("bruteforce_admin", "Try a short common-password list against one "
          "username on wp-login.php.", {"username": str})
    async def t_brute(args):
        pws = load_passwords(config.passwords_file)
        res = bruteforce_login(client, config.target, args["username"], pws, config.delay)
        findings.set_bruteforce(args["username"], res)
        return {"content": [{"type": "text", "text": res["evidence"]}]}

    return [t_rest, t_author, t_confirm, t_brute]


async def _run_async(config: Config, client: HttpClient, findings: Findings) -> None:
    from claude_agent_sdk import (
        AssistantMessage, ClaudeAgentOptions, ResultMessage, TextBlock,
        create_sdk_mcp_server, query,
    )

    server = create_sdk_mcp_server("wpenum", "1.0.0",
                                   tools=_build_tools(client, config, findings))
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        model=config.model,
        mcp_servers={"wpenum": server},
        allowed_tools=[
            "mcp__wpenum__rest_api_users",
            "mcp__wpenum__author_archive_users",
            "mcp__wpenum__confirm_username",
            "mcp__wpenum__bruteforce_admin",
        ],
        disallowed_tools=_BLOCKED_BUILTINS,
        permission_mode="bypassPermissions",
        max_turns=16,
    )
    prompt = (f"Authorized target: {config.target}\n"
              f"Enumerate the WordPress users, identify the admin, and run the "
              f"common-password brute-force. Then summarize.")

    summary = None
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock) and block.text.strip():
                    summary = block.text
        elif isinstance(message, ResultMessage):
            if getattr(message, "result", None):
                summary = message.result
    findings.ai_summary = summary


def run(config: Config, client: HttpClient, findings: Findings) -> None:
    """Run the agent. Raises AgentUnavailable if the runtime/auth isn't ready.

    Auth is handled by the SDK: it uses a Claude Pro/Max subscription login
    (`claude setup-token`) or ANTHROPIC_API_KEY, whichever is present. We don't
    pre-check a specific one — a missing/invalid session surfaces as a runtime
    error below and falls back to the deterministic pipeline.
    """
    try:
        import claude_agent_sdk  # noqa: F401
    except ImportError as exc:
        raise AgentUnavailable(f"claude-agent-sdk not installed: {exc}") from exc
    try:
        asyncio.run(_run_async(config, client, findings))
    except AgentUnavailable:
        raise
    except Exception as exc:  # Node missing / not authenticated / API error -> fall back
        raise AgentUnavailable(f"agent runtime error: {exc}") from exc
