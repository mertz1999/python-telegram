#!/usr/bin/env python3
"""Point Telegram at the relay without exposing credentials as CLI arguments."""

from __future__ import annotations

import json
import os
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def main() -> int:
    try:
        token = required_env("TELEGRAM_BOT_TOKEN")
        secret = required_env("TELEGRAM_WEBHOOK_SECRET")
        public_url = required_env("RELAY_PUBLIC_URL").rstrip("/")
        path = os.environ.get("RELAY_WEBHOOK_PATH", "/telegram/webhook").strip()
        parsed = urlsplit(public_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("RELAY_PUBLIC_URL must be a complete HTTPS origin")
        if not path.startswith("/") or "?" in path:
            raise ValueError("RELAY_WEBHOOK_PATH must be an absolute path")
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    payload = json.dumps(
        {
            "url": f"{public_url}{path}",
            "secret_token": secret,
            "drop_pending_updates": False,
        }
    ).encode()
    request = Request(
        f"https://api.telegram.org/bot{token}/setWebhook",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=15, context=ssl.create_default_context()) as response:
            result = json.load(response)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Telegram webhook update failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    if result.get("ok") is not True:
        description = str(result.get("description") or "Telegram rejected the request")[:200]
        print(f"Telegram webhook update failed: {description}", file=sys.stderr)
        return 1
    print(f"Telegram webhook now points to {parsed.hostname}; queued updates were preserved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
