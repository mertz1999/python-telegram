from __future__ import annotations

import io
import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import app


class FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int) -> bytes:
        return b'{"ok":true}'


class RelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = app.RelayConfig(
            upstream_url="https://agentfaai.ir/api/bots/telegram/webhook",
            webhook_secret="test_secret-123",
        )

    def tearDown(self) -> None:
        app.get_config.cache_clear()
        app.get_setup_config.cache_clear()

    def test_config_rejects_non_https_upstream(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            app.RelayConfig(
                upstream_url="http://internal.example/webhook",
                webhook_secret="secret",
            ).validate()

    def test_secret_comparison(self) -> None:
        self.assertTrue(app.secrets_match("test_secret-123", "test_secret-123"))
        self.assertFalse(app.secrets_match("", "test_secret-123"))
        self.assertFalse(app.secrets_match("wrong", "test_secret-123"))

    def test_parse_update(self) -> None:
        self.assertEqual(app.parse_update(b'{"update_id":42}')["update_id"], 42)
        for raw_body in (b"[]", b'{"message":{}}', b"not-json"):
            with self.subTest(raw_body=raw_body), self.assertRaises(app.PayloadError):
                app.parse_update(raw_body)

    def test_forward_preserves_body_and_adds_secret(self) -> None:
        raw_body = json.dumps({"update_id": 42, "message": {"text": "/start"}}).encode()
        captured = {}

        def opener(request, **kwargs):
            captured["request"] = request
            captured["kwargs"] = kwargs
            return FakeResponse()

        self.assertEqual(app.forward_update(raw_body, self.config, opener=opener), 200)
        request = captured["request"]
        self.assertEqual(request.data, raw_body)
        self.assertEqual(request.get_header("X-telegram-bot-api-secret-token"), "test_secret-123")
        self.assertEqual(captured["kwargs"]["timeout"], 7.0)

    def test_upstream_http_error_becomes_retryable_error(self) -> None:
        def opener(request, **_kwargs):
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO())

        with self.assertRaisesRegex(app.UpstreamError, "HTTP 401"):
            app.forward_update(b'{"update_id":42}', self.config, opener=opener)

    def test_configure_webhook_uses_relay_url_and_shared_secret(self) -> None:
        setup_config = app.WebhookSetupConfig(
            enabled=True,
            admin_token="a" * 32,
            bot_token="123456:telegram-token-value",
            relay_public_url="https://relay.example.com",
        )
        captured = {}

        def opener(request, **kwargs):
            captured["request"] = request
            captured["kwargs"] = kwargs
            return FakeResponse()

        webhook_url = app.configure_telegram_webhook(
            self.config, setup_config, opener=opener
        )
        request_body = json.loads(captured["request"].data)
        self.assertEqual(webhook_url, "https://relay.example.com/telegram/webhook")
        self.assertEqual(request_body["url"], webhook_url)
        self.assertEqual(request_body["secret_token"], self.config.webhook_secret)
        self.assertFalse(request_body["drop_pending_updates"])
        self.assertEqual(captured["kwargs"]["timeout"], 15)

    def test_wsgi_health_and_authorization(self) -> None:
        environment = {
            "UPSTREAM_WEBHOOK_URL": self.config.upstream_url,
            "TELEGRAM_WEBHOOK_SECRET": self.config.webhook_secret,
        }
        with patch.dict(os.environ, environment, clear=False):
            app.get_config.cache_clear()
            health_status, health_body = call_app("GET", "/healthz")
            unauthorized_status, _ = call_app(
                "POST", "/telegram/webhook", body=b'{"update_id":42}'
            )
        app.get_config.cache_clear()
        self.assertEqual(health_status, "200 OK")
        self.assertEqual(json.loads(health_body), {"ok": True})
        self.assertEqual(unauthorized_status, "401 Unauthorized")

    def test_wsgi_forwards_valid_update(self) -> None:
        environment = {
            "UPSTREAM_WEBHOOK_URL": self.config.upstream_url,
            "TELEGRAM_WEBHOOK_SECRET": self.config.webhook_secret,
        }
        with patch.dict(os.environ, environment, clear=False), patch.object(
            app, "forward_update", return_value=200
        ) as forward:
            app.get_config.cache_clear()
            status, body = call_app(
                "POST",
                "/telegram/webhook",
                body=b'{"update_id":42}',
                secret=self.config.webhook_secret,
            )
        app.get_config.cache_clear()
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(body), {"ok": True})
        forward.assert_called_once()

    def test_setup_endpoint_is_disabled_by_default(self) -> None:
        environment = {
            "UPSTREAM_WEBHOOK_URL": self.config.upstream_url,
            "TELEGRAM_WEBHOOK_SECRET": self.config.webhook_secret,
            "SETUP_ENDPOINT_ENABLED": "false",
        }
        with patch.dict(os.environ, environment, clear=False):
            app.get_config.cache_clear()
            app.get_setup_config.cache_clear()
            status, _ = call_app("POST", "/admin/setup-webhook")
        self.assertEqual(status, "404 Not Found")

    def test_setup_endpoint_requires_separate_admin_token(self) -> None:
        environment = setup_environment(self.config)
        with patch.dict(os.environ, environment, clear=False):
            app.get_config.cache_clear()
            app.get_setup_config.cache_clear()
            status, _ = call_app("POST", "/admin/setup-webhook")
        self.assertEqual(status, "401 Unauthorized")

    def test_setup_endpoint_configures_webhook_without_returning_secrets(self) -> None:
        environment = setup_environment(self.config)
        webhook_url = "https://relay.example.com/telegram/webhook"
        with patch.dict(os.environ, environment, clear=False), patch.object(
            app, "configure_telegram_webhook", return_value=webhook_url
        ) as configure:
            app.get_config.cache_clear()
            app.get_setup_config.cache_clear()
            status, body = call_app(
                "POST",
                "/admin/setup-webhook",
                authorization=f"Bearer {environment['SETUP_ADMIN_TOKEN']}",
            )
        response = json.loads(body)
        self.assertEqual(status, "200 OK")
        self.assertEqual(response, {"ok": True, "webhook_host": "relay.example.com"})
        self.assertNotIn(self.config.webhook_secret, body.decode())
        self.assertNotIn(environment["TELEGRAM_BOT_TOKEN"], body.decode())
        configure.assert_called_once()


def setup_environment(config: app.RelayConfig) -> dict[str, str]:
    return {
        "UPSTREAM_WEBHOOK_URL": config.upstream_url,
        "TELEGRAM_WEBHOOK_SECRET": config.webhook_secret,
        "SETUP_ENDPOINT_ENABLED": "true",
        "SETUP_ADMIN_TOKEN": "separate-admin-token-value-123456",
        "TELEGRAM_BOT_TOKEN": "123456:telegram-token-value",
        "RELAY_PUBLIC_URL": "https://relay.example.com",
    }


def call_app(
    method: str,
    path: str,
    *,
    body: bytes = b"",
    secret: str = "",
    authorization: str = "",
):
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    if secret:
        environ["HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN"] = secret
    if authorization:
        environ["HTTP_AUTHORIZATION"] = authorization
    response_body = b"".join(app.application(environ, start_response))
    return captured["status"], response_body


if __name__ == "__main__":
    unittest.main()
