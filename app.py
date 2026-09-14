#!/usr/bin/env python3
"""Secure Telegram-to-AgentFA webhook relay for a WSGI hosting platform."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import socket
import ssl
import time
from dataclasses import dataclass
from functools import lru_cache
from http import HTTPStatus
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from gunicorn.app.base import BaseApplication


LOGGER = logging.getLogger("agentfa.telegram_relay")
SECRET_HEADER = "X-Telegram-Bot-Api-Secret-Token"
RELAY_AUTH_HEADER = "X-AgentFA-Relay-Auth"
RELAY_AUTH_CONTEXT = b"agentfa-telegram-relay-auth-v1"
OUTBOUND_PATH_PREFIX = "/telegram/api/"
OUTBOUND_METHODS = {
    "answerCallbackQuery",
    "sendMediaGroup",
    "sendMessage",
    "sendPhoto",
    "setMyCommands",
}
DEFAULT_MAX_BODY_BYTES = 1_048_576


class ConfigurationError(ValueError):
    """Raised when required relay configuration is invalid."""


class PayloadError(ValueError):
    """Raised when a request is not a valid Telegram update."""


class UpstreamError(RuntimeError):
    """Raised when PaaSta does not accept an update."""

    def __init__(self, message: str, *, status: int = HTTPStatus.BAD_GATEWAY) -> None:
        super().__init__(message)
        self.status = status


class TelegramAPIError(RuntimeError):
    """Raised when Telegram rejects webhook configuration."""


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent forwarding the webhook secret to a redirected host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class RelayConfig:
    upstream_url: str
    webhook_secret: str
    bot_token: str = ""
    webhook_path: str = "/telegram/webhook"
    forward_timeout_seconds: float = 7.0
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES

    @classmethod
    def from_env(cls) -> "RelayConfig":
        config = cls(
            upstream_url=os.environ.get("UPSTREAM_WEBHOOK_URL", "").strip(),
            webhook_secret=os.environ.get("TELEGRAM_WEBHOOK_SECRET", "").strip(),
            bot_token=os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
            webhook_path=os.environ.get("RELAY_WEBHOOK_PATH", "/telegram/webhook").strip(),
            forward_timeout_seconds=_env_float(
                "FORWARD_TIMEOUT_SECONDS", 7.0, minimum=0.5, maximum=20.0
            ),
            max_body_bytes=_env_int(
                "MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES, minimum=1024, maximum=10_485_760
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        parsed = urlsplit(self.upstream_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ConfigurationError("UPSTREAM_WEBHOOK_URL must be a complete HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ConfigurationError("UPSTREAM_WEBHOOK_URL must not contain credentials, query, or fragment")
        if not self.webhook_secret:
            raise ConfigurationError("TELEGRAM_WEBHOOK_SECRET is required")
        if not self.webhook_path.startswith("/") or "?" in self.webhook_path:
            raise ConfigurationError("RELAY_WEBHOOK_PATH must be an absolute path without a query")


@dataclass(frozen=True)
class WebhookSetupConfig:
    enabled: bool
    admin_token: str
    bot_token: str
    relay_public_url: str

    @classmethod
    def from_env(cls) -> "WebhookSetupConfig":
        config = cls(
            enabled=_env_bool("SETUP_ENDPOINT_ENABLED", False),
            admin_token=os.environ.get("SETUP_ADMIN_TOKEN", "").strip(),
            bot_token=os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
            relay_public_url=os.environ.get("RELAY_PUBLIC_URL", "").strip().rstrip("/"),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.enabled:
            return
        if len(self.admin_token) < 32:
            raise ConfigurationError("SETUP_ADMIN_TOKEN must contain at least 32 characters")
        if ":" not in self.bot_token:
            raise ConfigurationError("TELEGRAM_BOT_TOKEN is required")
        parsed = urlsplit(self.relay_public_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ConfigurationError("RELAY_PUBLIC_URL must be a complete HTTPS origin")


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, str(default)).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


@lru_cache(maxsize=1)
def get_config() -> RelayConfig:
    return RelayConfig.from_env()


@lru_cache(maxsize=1)
def get_setup_config() -> WebhookSetupConfig:
    return WebhookSetupConfig.from_env()


def parse_update(raw_body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayloadError("request body must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("update_id"), int):
        raise PayloadError("request body must be a Telegram Update object")
    return payload


def secrets_match(provided: str, expected: str) -> bool:
    return bool(provided) and hmac.compare_digest(provided.encode(), expected.encode())


def derive_relay_auth(bot_token: str) -> str:
    """Derive a relay-only credential without transmitting the bot token."""
    token = bot_token.strip()
    if not token:
        return ""
    return hmac.new(token.encode(), RELAY_AUTH_CONTEXT, hashlib.sha256).hexdigest()


def forward_update(
    raw_body: bytes,
    config: RelayConfig,
    *,
    opener: Callable[..., Any] | None = None,
) -> int:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        SECRET_HEADER: config.webhook_secret,
        "User-Agent": "AgentFA-Telegram-Relay/1.0",
    }
    relay_auth = derive_relay_auth(config.bot_token)
    if relay_auth:
        headers[RELAY_AUTH_HEADER] = relay_auth
    request = Request(
        config.upstream_url,
        data=raw_body,
        method="POST",
        headers=headers,
    )
    open_request = opener or build_opener(
        HTTPSHandler(context=ssl.create_default_context()), NoRedirectHandler()
    ).open
    try:
        with open_request(request, timeout=config.forward_timeout_seconds) as response:
            status = int(response.status)
            response.read(4096)
    except HTTPError as exc:
        raise UpstreamError(f"PaaSta rejected the update with HTTP {exc.code}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise UpstreamError(
            "PaaSta did not respond before the forwarding deadline",
            status=HTTPStatus.GATEWAY_TIMEOUT,
        ) from exc
    except (URLError, OSError) as exc:
        reason = exc.reason if isinstance(exc, URLError) else exc
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise UpstreamError(
                "PaaSta did not respond before the forwarding deadline",
                status=HTTPStatus.GATEWAY_TIMEOUT,
            ) from exc
        raise UpstreamError("PaaSta could not be reached") from exc
    if not 200 <= status < 300:
        raise UpstreamError(f"PaaSta rejected the update with HTTP {status}")
    return status


def configure_telegram_webhook(
    relay_config: RelayConfig,
    setup_config: WebhookSetupConfig,
    *,
    opener: Callable[..., Any] | None = None,
) -> str:
    webhook_url = f"{setup_config.relay_public_url}{relay_config.webhook_path}"
    body = json.dumps(
        {
            "url": webhook_url,
            "secret_token": relay_config.webhook_secret,
            "drop_pending_updates": False,
        }
    ).encode()
    request = Request(
        f"https://api.telegram.org/bot{setup_config.bot_token}/setWebhook",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    open_request = opener or build_opener(
        HTTPSHandler(context=ssl.create_default_context()), NoRedirectHandler()
    ).open
    try:
        with open_request(request, timeout=15) as response:
            response_body = response.read(16_384)
            status = int(response.status)
    except HTTPError as exc:
        raise TelegramAPIError(f"Telegram rejected setup with HTTP {exc.code}") from exc
    except (URLError, OSError, TimeoutError, socket.timeout) as exc:
        raise TelegramAPIError("Telegram could not be reached") from exc
    if not 200 <= status < 300:
        raise TelegramAPIError(f"Telegram rejected setup with HTTP {status}")
    try:
        result = json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelegramAPIError("Telegram returned an invalid response") from exc
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise TelegramAPIError("Telegram rejected webhook setup")
    return webhook_url


def get_telegram_webhook_info(
    setup_config: WebhookSetupConfig,
    *,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    request = Request(
        f"https://api.telegram.org/bot{setup_config.bot_token}/getWebhookInfo",
        method="GET",
        headers={"Accept": "application/json"},
    )
    open_request = opener or build_opener(
        HTTPSHandler(context=ssl.create_default_context()), NoRedirectHandler()
    ).open
    try:
        with open_request(request, timeout=15) as response:
            response_body = response.read(16_384)
            status = int(response.status)
    except HTTPError as exc:
        raise TelegramAPIError(f"Telegram rejected diagnostics with HTTP {exc.code}") from exc
    except (URLError, OSError, TimeoutError, socket.timeout) as exc:
        raise TelegramAPIError("Telegram could not be reached") from exc
    if not 200 <= status < 300:
        raise TelegramAPIError(f"Telegram rejected diagnostics with HTTP {status}")
    try:
        payload = json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelegramAPIError("Telegram returned an invalid response") from exc
    if not isinstance(payload, dict):
        raise TelegramAPIError("Telegram returned an invalid response")
    result = payload.get("result")
    if payload.get("ok") is not True or not isinstance(result, dict):
        raise TelegramAPIError("Telegram rejected diagnostics")
    return result


def forward_telegram_api(
    method: str,
    raw_body: bytes,
    bot_token: str,
    *,
    opener: Callable[..., Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = Request(
        f"https://api.telegram.org/bot{bot_token}/{method}",
        data=raw_body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    open_request = opener or build_opener(
        HTTPSHandler(context=ssl.create_default_context()), NoRedirectHandler()
    ).open
    try:
        with open_request(request, timeout=15) as response:
            response_body = response.read(65_536)
            status = int(response.status)
    except HTTPError as exc:
        response_body = exc.read(65_536)
        status = int(exc.code)
    except (URLError, OSError, TimeoutError, socket.timeout) as exc:
        raise TelegramAPIError("Telegram could not be reached") from exc
    try:
        payload = json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelegramAPIError("Telegram returned an invalid response") from exc
    if not isinstance(payload, dict):
        raise TelegramAPIError("Telegram returned an invalid response")
    return status, payload


def check_agentfa_connection(config: RelayConfig) -> dict[str, Any]:
    update_id = 2_000_000_000 + (int(time.time()) % 100_000_000)
    raw_body = json.dumps({"update_id": update_id}, separators=(",", ":")).encode()
    started = time.monotonic()
    try:
        upstream_status = forward_update(raw_body, config)
    except UpstreamError as exc:
        latency_ms = round((time.monotonic() - started) * 1000)
        error = (
            "timeout"
            if exc.status == HTTPStatus.GATEWAY_TIMEOUT
            else "unreachable_or_rejected"
        )
        return {
            "ok": False,
            "latency_ms": latency_ms,
            "error": error,
        }
    return {
        "ok": True,
        "status": upstream_status,
        "latency_ms": round((time.monotonic() - started) * 1000),
        "upstream_host": urlsplit(config.upstream_url).hostname,
    }


def check_telegram_connection(
    config: RelayConfig,
    setup_config: WebhookSetupConfig,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        webhook_info = get_telegram_webhook_info(setup_config)
    except TelegramAPIError:
        return {
            "ok": False,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "error": "unreachable_or_rejected",
        }

    webhook_url = webhook_info.get("url")
    if not isinstance(webhook_url, str):
        webhook_url = ""
    expected_url = f"{setup_config.relay_public_url}{config.webhook_path}"
    webhook_matches_relay = bool(webhook_url) and secrets_match(webhook_url, expected_url)
    return {
        "ok": True,
        "latency_ms": round((time.monotonic() - started) * 1000),
        "webhook_configured": bool(webhook_url),
        "webhook_matches_relay": webhook_matches_relay,
        "webhook_host": urlsplit(webhook_url).hostname if webhook_url else None,
        "pending_update_count": webhook_info.get("pending_update_count"),
        "last_error_date": webhook_info.get("last_error_date"),
        "last_error_message": webhook_info.get("last_error_message"),
    }


def json_response(
    start_response: Callable[..., Any], status: int, payload: dict[str, Any]
) -> Iterable[bytes]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    status_code = HTTPStatus(status)
    start_response(
        f"{status_code.value} {status_code.phrase}",
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
        ],
    )
    return [body]


def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "GET").upper()

    try:
        config = get_config()
    except ConfigurationError as exc:
        LOGGER.error("Invalid relay configuration: %s", exc)
        return json_response(start_response, HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False})

    if method == "GET" and path == "/healthz":
        return json_response(start_response, HTTPStatus.OK, {"ok": True})
    if method == "POST" and path.startswith(OUTBOUND_PATH_PREFIX):
        bot_token = config.bot_token
        if ":" not in bot_token:
            return json_response(start_response, HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False})
        supplied_secret = environ.get("HTTP_X_AGENTFA_RELAY_SECRET", "")
        supplied_relay_auth = environ.get("HTTP_X_AGENTFA_RELAY_AUTH", "")
        if not (
            secrets_match(supplied_secret, config.webhook_secret)
            or secrets_match(supplied_relay_auth, derive_relay_auth(bot_token))
        ):
            return json_response(start_response, HTTPStatus.UNAUTHORIZED, {"ok": False})
        telegram_method = path.removeprefix(OUTBOUND_PATH_PREFIX)
        if telegram_method not in OUTBOUND_METHODS:
            return json_response(start_response, HTTPStatus.NOT_FOUND, {"ok": False})
        try:
            content_length = int(environ.get("CONTENT_LENGTH", ""))
        except (TypeError, ValueError):
            return json_response(start_response, HTTPStatus.LENGTH_REQUIRED, {"ok": False})
        if content_length <= 0 or content_length > config.max_body_bytes:
            return json_response(
                start_response, HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False}
            )
        raw_body = environ["wsgi.input"].read(content_length)
        try:
            payload = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return json_response(
                start_response, HTTPStatus.UNPROCESSABLE_ENTITY, {"ok": False}
            )
        if not isinstance(payload, dict):
            return json_response(
                start_response, HTTPStatus.UNPROCESSABLE_ENTITY, {"ok": False}
            )
        try:
            status, response_payload = forward_telegram_api(
                telegram_method, raw_body, bot_token
            )
        except TelegramAPIError:
            LOGGER.warning("Telegram outbound proxy failed for method=%s", telegram_method)
            return json_response(start_response, HTTPStatus.BAD_GATEWAY, {"ok": False})
        return json_response(start_response, status, response_payload)
    if path in {"/admin/setup-webhook", "/admin/test-connections"}:
        if method != "POST":
            return json_response(start_response, HTTPStatus.NOT_FOUND, {"ok": False})
        try:
            setup_config = get_setup_config()
        except ConfigurationError as exc:
            LOGGER.error("Invalid setup endpoint configuration: %s", exc)
            return json_response(start_response, HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False})
        if not setup_config.enabled:
            return json_response(start_response, HTTPStatus.NOT_FOUND, {"ok": False})
        authorization = environ.get("HTTP_AUTHORIZATION", "")
        expected_authorization = f"Bearer {setup_config.admin_token}"
        if not secrets_match(authorization, expected_authorization):
            return json_response(start_response, HTTPStatus.UNAUTHORIZED, {"ok": False})
        if path == "/admin/test-connections":
            telegram = check_telegram_connection(config, setup_config)
            agentfa = check_agentfa_connection(config)
            connections_ok = bool(
                telegram.get("ok")
                and telegram.get("webhook_matches_relay")
                and agentfa.get("ok")
            )
            return json_response(
                start_response,
                HTTPStatus.OK,
                {
                    "ok": connections_ok,
                    "connections": {
                        "telegram": telegram,
                        "agentfa": agentfa,
                    },
                },
            )
        try:
            webhook_url = configure_telegram_webhook(config, setup_config)
        except TelegramAPIError as exc:
            LOGGER.warning("Webhook setup failed: %s", exc)
            return json_response(start_response, HTTPStatus.BAD_GATEWAY, {"ok": False})
        LOGGER.info("Telegram webhook configured for relay_host=%s", urlsplit(webhook_url).hostname)
        return json_response(
            start_response,
            HTTPStatus.OK,
            {"ok": True, "webhook_host": urlsplit(webhook_url).hostname},
        )
    if method != "POST" or path != config.webhook_path:
        return json_response(start_response, HTTPStatus.NOT_FOUND, {"ok": False})

    supplied_secret = environ.get("HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN", "")
    if not secrets_match(supplied_secret, config.webhook_secret):
        return json_response(start_response, HTTPStatus.UNAUTHORIZED, {"ok": False})

    try:
        content_length = int(environ.get("CONTENT_LENGTH", ""))
    except (TypeError, ValueError):
        return json_response(start_response, HTTPStatus.LENGTH_REQUIRED, {"ok": False})
    if content_length <= 0 or content_length > config.max_body_bytes:
        return json_response(start_response, HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False})

    raw_body = environ["wsgi.input"].read(content_length)
    try:
        update = parse_update(raw_body)
        forward_update(raw_body, config)
    except PayloadError:
        return json_response(start_response, HTTPStatus.UNPROCESSABLE_ENTITY, {"ok": False})
    except UpstreamError as exc:
        LOGGER.warning("Forward failed for update_id=%s: %s", update.get("update_id"), exc)
        return json_response(start_response, exc.status, {"ok": False})

    LOGGER.info("Forwarded update_id=%s", update["update_id"])
    return json_response(start_response, HTTPStatus.OK, {"ok": True})


class StandaloneApplication(BaseApplication):
    def __init__(self, app: Callable[..., Any], options: dict[str, Any] | None = None) -> None:
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self) -> None:
        for key, value in self.options.items():
            if key in self.cfg.settings and value is not None:
                self.cfg.set(key.lower(), value)

    def load(self) -> Callable[..., Any]:
        return self.application


if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        config = get_config()
    except ConfigurationError as exc:
        raise SystemExit(f"Invalid configuration: {exc}") from exc
    LOGGER.info("Starting relay for upstream_host=%s", urlsplit(config.upstream_url).hostname)
    port = _env_int("PORT", 8080, minimum=1, maximum=65535)
    StandaloneApplication(
        application,
        {
            "bind": f"0.0.0.0:{port}",
            "workers": _env_int("WEB_CONCURRENCY", 2, minimum=1, maximum=8),
            "threads": _env_int("WEB_THREADS", 4, minimum=1, maximum=32),
            "timeout": 30,
            "accesslog": "-",
            "errorlog": "-",
        },
    ).run()
