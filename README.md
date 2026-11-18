# AI-Driven WordPress User Enumeration Tool

An autonomous security tool that enumerates valid WordPress user accounts from a
configurable target, confirms the administrator, and attempts a small
common-password brute-force — orchestrated by an AI agent (Claude Agent SDK).

> **Ethics / scope:** Use this **only** against intentionally-vulnerable or
> self-hosted WordPress instances you are authorized to test. A local Docker
> target is bundled. Do **not** point it at production or third-party sites.

---

## Approach and reasoning

WordPress leaks usernames by default through several vectors. Rather than hard-code
one, the tool implements three real techniques and separates **"muscle" from
"brain"**:

- **Muscle (deterministic):** the actual HTTP techniques live in plain, unit-tested
  Python functions. They always work the same way and need no API key.
- **Brain (AI agent):** a Claude agent decides *which* technique to run, reads the
  structured evidence each returns, confirms the admin, orders the brute-force, and
  writes a human summary. The agent only ever acts through the tools we expose — it
  never gets a shell or filesystem access.

This split is deliberate: the security-critical logic is deterministic and testable,
while the AI adds genuine value (strategy + interpretation + reporting) without being
a single point of failure. If the AI runtime or API key is missing, the tool
**falls back to a fixed deterministic pipeline** and still runs end-to-end.

### Enumeration techniques

| # | Technique | How it leaks usernames |
|---|-----------|------------------------|
| 1 | **REST API** | `GET /wp-json/wp/v2/users` returns user objects (`id`, `slug`, `name`) unauthenticated. `slug` ≈ the login. Falls back to `/?rest_route=/wp/v2/users` when pretty permalinks are off; follows pagination. |
| 2 | **Author archive routing** | `GET /?author=N` 301/302-redirects to `/author/<slug>/`, leaking the login even when REST is locked down. Falls back to parsing the archive page when permalinks are plain. |
| 3 | **Login-error oracle** | `wp-login.php` returns *different* errors for a valid username + wrong password ("the password you entered…") vs. an unknown user ("is not registered"). Used to **confirm** a candidate user exists. |

After the admin username is known, **brute-force** (`bruteforce.py`) replays a short
common-password list against `wp-login.php`, handling WordPress's required test
cookie and detecting success via the post-login redirect / `wordpress_logged_in` cookie.

---

## Architecture

```
          ┌─────────────┐
 CLI ───▶ │  main.py     │  parse config, pick mode, render output
          └──────┬──────┘
                 │ use_ai?
        ┌────────┴─────────┐
        ▼                  ▼
   agent.py           run_deterministic()      ← same functions, no AI
 (Claude Agent SDK)        │
   exposes tools ──────────┤
        │                  │
        ▼                  ▼
   enumerators.py   bruteforce.py       ← the three techniques + brute-force
        │                  │
        └───────┬──────────┘
                ▼
          http_client.py   (shared session: retries, timeout, generic UA)
                ▼
           findings.py     (one result model; CLI + JSON render from it)
                ▼
            report.py      (rich CLI table + structured JSON)
```

| Module | Responsibility |
|--------|----------------|
| `config.py` | Resolve settings from CLI flags → `.env`/env vars. |
| `http_client.py` | One `requests.Session` with retries, timeout, generic User-Agent. |
| `enumerators.py` | The three enumeration techniques + the `wp_login` helper. |
| `bruteforce.py` | Common-password login attempts against one user. |
| `findings.py` | Shared result model; merges/dedupes users across techniques. |
| `agent.py` | Claude Agent SDK: wraps the above as MCP tools, runs the agent loop. |
| `report.py` | Human CLI report (rich) + JSON output. |
| `main.py` | Orchestration, AI-vs-deterministic selection, graceful fallback. |

### Agent design

The agent (`agent.py`) registers four in-process MCP tools — `rest_api_users`,
`author_archive_users`, `confirm_username`, `bruteforce_admin` — via
`create_sdk_mcp_server`, and runs `query()` with a system prompt describing the
mission and strategy. Each tool calls the deterministic function and records results
into a shared `Findings` object, so the structured output is identical in AI and
deterministic modes. Built-in Claude Code tools (Bash, Read, Write, …) are
disallowed; the agent can only use the four wpenum tools.

---

## Setup

### 1. Bring up the vulnerable target (Docker)

```bash
docker compose up -d      # WordPress on http://localhost:8090 + MariaDB
./seed.sh                 # install WP (admin/admin123) + seed users with posts
```

`seed.sh` creates `admin` (password `admin123`, intentionally in the wordlist),
`editor1`, and `author1`, each with a published post so they appear in the REST
endpoint and author archives.

### 2. Install the tool

```bash
python -m venv .venv
. .venv/Scripts/activate        # Windows;  source .venv/bin/activate on macOS/Linux
pip install -r requirements.txt
cp .env.example .env            # set ANTHROPIC_API_KEY for AI mode (optional)
```

**AI mode requires [Node.js](https://nodejs.org/) 18+** (the Claude Agent SDK drives a
bundled Claude Code CLI subprocess) plus **one** of:

- a **Claude Pro/Max subscription** login — run `claude setup-token` once (no API
  credits needed), or
- an **`ANTHROPIC_API_KEY`** in `.env`.

`--no-ai` mode needs none of this and always runs.

---

## Usage

```bash
# Deterministic pipeline (no API key / Node needed)
python -m src.main --target http://localhost:8090 --no-ai

# Full AI agent (default), also writing JSON
python -m src.main --target http://localhost:8090 --json results.json

# Config via env instead of flags
export WP_TARGET_URL=http://localhost:8090
python -m src.main
```

Key flags: `--target/-t`, `--ai`/`--no-ai`, `--model`, `--max-author-ids`,
`--passwords`, `--delay`, `--timeout`, `--json`. Target is also read from
`WP_TARGET_URL`, model from `WP_ENUM_MODEL`.

### Example output (abridged)

```
───────── WordPress User Enumeration — http://localhost:8090 ─────────
mode: ai

        Discovered users (3)
 ID  Username  Display name    Found via               Confirmed
  1  admin     Administrator   rest_api, author_archive    ✓
  2  editor1   Editor One      rest_api
  3  author1   Author One      rest_api

Techniques
  • rest_api [hit] — /wp-json/wp/v2/users returned 3 user object(s) …
  • author_archive [hit] — ?author=N redirects leaked 3 username(s) …
  • login_error_oracle [hit] — admin: valid — login error distinguishes …

╭──────────────────────────────╮
│ ADMIN LOGIN CRACKED          │
│ user: admin                  │
│ password: admin123 (attempt 4)│
╰──────────────────────────────╯
```

---

## Testing

```bash
pytest -q        # 8 tests, HTTP fully mocked (no live server needed)
```

`tests/test_enumerators.py` covers each technique (REST parse + permalink fallback,
author-archive redirect, both login-oracle branches), the brute-force success /
exhaustion paths, and the findings merge/dedupe — all with `responses`-mocked HTTP,
so the suite is fast and deterministic.

---

## Limitations and trade-offs

- **`slug` ≈ login, not guaranteed.** The REST `slug` (user_nicename) usually equals
  the login but an admin can change it; treat REST usernames as high-confidence, not
  certain. The login-error oracle is used to confirm.
- **Hardening defeats these vectors.** Security plugins (or `disable REST users`,
  blocked author archives, generic login errors) will reduce hits — by design; the
  tool reports misses rather than guessing.
- **Brute-force is a proof-of-concept.** Short list, serial, with a delay. It is not a
  real cracker and will trip rate-limiting / lockout plugins (intentionally).
- **AI mode needs Node + an API key.** Mitigated by the deterministic fallback so the
  tool always runs end-to-end.
- **No WAF/stealth evasion.** Requests are straightforward and identify with a generic
  User-Agent; this is an authorized-testing tool, not an evasion framework.

---

## Project layout

```
ai-wp-user-enum/
├── docker-compose.yml      # vulnerable WP + DB target
├── seed.sh                 # headless WP install + seed users
├── requirements.txt
├── .env.example
├── wordlists/common-passwords.txt
├── src/
│   ├── config.py  http_client.py  findings.py
│   ├── enumerators.py  bruteforce.py
│   ├── agent.py   report.py   main.py
└── tests/test_enumerators.py
```
