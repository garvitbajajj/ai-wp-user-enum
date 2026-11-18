"""Configuration: resolved from CLI flags, with .env / environment as fallback."""
from __future__ import annotations

import argparse
import os
from dataclasses import dataclass

from dotenv import load_dotenv

DEFAULT_MODEL = "claude-opus-5-5"


@dataclass
class Config:
    target: str
    use_ai: bool
    model: str
    max_author_ids: int
    passwords_file: str
    delay: float
    timeout: float
    json_out: str | None


def parse_config(argv: list[str] | None = None) -> Config:
    load_dotenv()  # populate os.environ from a local .env if present

    p = argparse.ArgumentParser(
        prog="wp-user-enum",
        description="AI-driven WordPress user enumeration (authorized testing only).",
    )
    p.add_argument(
        "-t", "--target",
        default=os.getenv("WP_TARGET_URL"),
        help="Target WordPress base URL (or set WP_TARGET_URL).",
    )
    ai = p.add_mutually_exclusive_group()
    ai.add_argument("--ai", dest="use_ai", action="store_true", default=True,
                    help="Use the AI agent to orchestrate + summarize (default).")
    ai.add_argument("--no-ai", dest="use_ai", action="store_false",
                    help="Run the deterministic pipeline only (no API key needed).")
    p.add_argument("--model", default=os.getenv("WP_ENUM_MODEL", DEFAULT_MODEL),
                   help=f"Model for the agent (default: {DEFAULT_MODEL}).")
    p.add_argument("--max-author-ids", type=int, default=10,
                   help="Highest ?author=N id to probe (default: 10).")
    p.add_argument("--passwords", dest="passwords_file",
                   default="wordlists/common-passwords.txt",
                   help="Password list for brute-force.")
    p.add_argument("--delay", type=float, default=0.3,
                   help="Seconds between brute-force attempts (default: 0.3).")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="Per-request timeout in seconds (default: 10).")
    p.add_argument("--json", dest="json_out", default=None,
                   help="Also write structured results to this JSON file.")

    args = p.parse_args(argv)
    if not args.target:
        p.error("no target: pass --target URL or set WP_TARGET_URL")
    args.target = args.target.rstrip("/")
    return Config(
        target=args.target,
        use_ai=args.use_ai,
        model=args.model,
        max_author_ids=args.max_author_ids,
        passwords_file=args.passwords_file,
        delay=args.delay,
        timeout=args.timeout,
        json_out=args.json_out,
    )
