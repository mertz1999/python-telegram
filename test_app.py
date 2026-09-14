from __future__ import annotations

import io
import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import app


class FakeResponse:
    def __init__(self, status: int = 200, body: bytes = b'{"ok":true}') -> None:
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int) -> bytes:
        return self.body


class RelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = app.RelayConfig(
            upstream_url="https://agentfaai.ir/api/bots/telegram/webhook",
            webhook_secret="test_secret-123",
            bot_token="123456:telegram-token",
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
        self.assertEqual(
            request.get_header("X-agentfa-relay-auth"),
            app.derive_relay_auth(self.config.bot_token),
        )
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

    def test_telegram_diagnostics_returns_webhook_info(self) -> None:
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
            return FakeResponse(
                body=json.dumps(
                    {
                        "ok": True,
                        "result": {
                            "url": "https://relay.example.com/telegram/webhook",
                            "pending_update_count": 0,
                        },
                    }
                ).encode()
            )

        result = app.get_telegram_webhook_info(setup_config, opener=opener)
        self.assertEqual(result["pending_update_count"], 0)
        self.assertTrue(captured["request"].full_url.endswith("/getWebhookInfo"))
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

    def test_forward_telegram_api_preserves_json_payload(self) -> None:
        raw_body = b'{"chat_id":"42","text":"hello"}'
        captured = {}

        def opener(request, **kwargs):
            captured["request"] = request
            captured["kwargs"] = kwargs
            return FakeResponse(body=b'{"ok":true,"result":{"message_id":7}}')

        status, payload = app.forward_telegram_api(
            "sendMessage", raw_body, "123456:telegram-token", opener=opener
        )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(captured["request"].data, raw_body)
        self.assertTrue(captured["request"].full_url.endswith("/sendMessage"))
        self.assertEqual(captured["kwargs"]["timeout"], 15)

    def test_wsgi_outbound_proxy_requires_secret_and_allows_known_method(self) -> None:
        environment = {
            "UPSTREAM_WEBHOOK_URL": self.config.upstream_url,
            "TELEGRAM_WEBHOOK_SECRET": self.config.webhook_secret,
            "TELEGRAM_BOT_TOKEN": "123456:telegram-token",
        }
        body = b'{"chat_id":"42","text":"hello"}'
        with patch.dict(os.environ, environment, clear=False), patch.object(
            app,
            "forward_telegram_api",
            return_value=(200, {"ok": True, "result": {"message_id": 7}}),
        ) as forward:
            app.get_config.cache_clear()
            unauthorized_status, _ = call_app(
                "POST", "/telegram/api/sendMessage", body=body
            )
            status, response = call_app(
                "POST",
                "/telegram/api/sendMessage",
                body=body,
                relay_secret=self.config.webhook_secret,
            )
            derived_status, _ = call_app(
                "POST",
                "/telegram/api/sendMessage",
                body=body,
                relay_auth=app.derive_relay_auth(environment["TELEGRAM_BOT_TOKEN"]),
            )
            unsupported_status, _ = call_app(
                "POST",
                "/telegram/api/deleteWebhook",
                body=b"{}",
                relay_secret=self.config.webhook_secret,
            )

        self.assertEqual(unauthorized_status, "401 Unauthorized")
        self.assertEqual(status, "200 OK")
        self.assertTrue(json.loads(response)["ok"])
        self.assertEqual(derived_status, "200 OK")
        self.assertEqual(unsupported_status, "404 Not Found")
        self.assertEqual(forward.call_count, 2)
        forward.assert_called_with("sendMessage", body, environment["TELEGRAM_BOT_TOKEN"])

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

    def test_diagnostics_endpoint_is_disabled_by_default(self) -> None:
        environment = {
            "UPSTREAM_WEBHOOK_URL": self.config.upstream_url,
            "TELEGRAM_WEBHOOK_SECRET": self.config.webhook_secret,
            "SETUP_ENDPOINT_ENABLED": "false",
        }
        with patch.dict(os.environ, environment, clear=False):
            app.get_config.cache_clear()
            app.get_setup_config.cache_clear()
            status, _ = call_app("POST", "/admin/test-connections")
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

    def test_diagnostics_endpoint_requires_admin_token(self) -> None:
        environment = setup_environment(self.config)
        with patch.dict(os.environ, environment, clear=False):
            app.get_config.cache_clear()
            app.get_setup_config.cache_clear()
            status, _ = call_app("POST", "/admin/test-connections")
        self.assertEqual(status, "401 Unauthorized")

    def test_diagnostics_endpoint_reports_both_connections_safely(self) -> None:
        environment = setup_environment(self.config)
        telegram_result = {
            "ok": True,
            "latency_ms": 20,
            "webhook_configured": True,
            "webhook_matches_relay": True,
            "webhook_host": "relay.example.com",
            "pending_update_count": 0,
            "last_error_date": None,
            "last_error_message": None,
        }
        agentfa_result = {
            "ok": True,
            "status": 200,
            "latency_ms": 30,
            "upstream_host": "agentfaai.ir",
        }
        with (
            patch.dict(os.environ, environment, clear=False),
            patch.object(app, "check_telegram_connection", return_value=telegram_result),
            patch.object(app, "check_agentfa_connection", return_value=agentfa_result),
        ):
            app.get_config.cache_clear()
            app.get_setup_config.cache_clear()
            status, body = call_app(
                "POST",
                "/admin/test-connections",
                authorization=f"Bearer {environment['SETUP_ADMIN_TOKEN']}",
            )
        response = json.loads(body)
        self.assertEqual(status, "200 OK")
        self.assertTrue(response["ok"])
        self.assertEqual(response["connections"]["telegram"], telegram_result)
        self.assertEqual(response["connections"]["agentfa"], agentfa_result)
        self.assertNotIn(self.config.webhook_secret, body.decode())
        self.assertNotIn(environment["TELEGRAM_BOT_TOKEN"], body.decode())


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
    relay_secret: str = "",
    relay_auth: str = "",
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
    if relay_secret:
        environ["HTTP_X_AGENTFA_RELAY_SECRET"] = relay_secret
    if relay_auth:
        environ["HTTP_X_AGENTFA_RELAY_AUTH"] = relay_auth
    if authorization:
        environ["HTTP_AUTHORIZATION"] = authorization
    response_body = b"".join(app.application(environ, start_response))
    return captured["status"], response_body


if __name__ == "__main__":
    unittest.main()
