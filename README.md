# AgentFA Telegram webhook relay

This small WSGI service receives Telegram webhook updates on a server Telegram
can reach and forwards the unchanged JSON body to AgentFA on PaaSta.

```text
Telegram
  -> https://your-relay-domain.example/telegram/webhook
  -> this service
  -> https://agentfaai.ir/api/bots/telegram/webhook
  -> AgentFA bot handler
```

It is intentionally not a general-purpose proxy. The upstream is one fixed
HTTPS URL, redirects are rejected, request bodies are size-limited, and message
bodies and secrets are never logged.

## Deployment variables

Configure these variables on the hosting platform:

| Variable | Required | Value |
| --- | --- | --- |
| `UPSTREAM_WEBHOOK_URL` | yes | `https://agentfaai.ir/api/bots/telegram/webhook` |
| `TELEGRAM_WEBHOOK_SECRET` | yes | Same value as `MESSENGER_TELEGRAM_WEBHOOK_SECRET` on PaaSta |
| `RELAY_WEBHOOK_PATH` | no | `/telegram/webhook` |
| `FORWARD_TIMEOUT_SECONDS` | no | `7` |
| `MAX_BODY_BYTES` | no | `1048576` |
| `WEB_CONCURRENCY` | no | `2` |
| `WEB_THREADS` | no | `4` |

The platform should run:

```bash
python app.py
```

The application binds to `0.0.0.0:$PORT`, defaulting to port `8080`. The public
domain must provide a valid HTTPS certificate.

After deployment, check:

```bash
curl --fail --silent --show-error https://your-relay-domain.example/healthz
```

## Point Telegram at the relay

Run the helper from a secure machine. It preserves Telegram's queued updates:

```bash
export TELEGRAM_BOT_TOKEN='replace-securely'
export TELEGRAM_WEBHOOK_SECRET='same-secret-as-paasta'
export RELAY_PUBLIC_URL='https://your-relay-domain.example'
python3 set_webhook.py
unset TELEGRAM_BOT_TOKEN TELEGRAM_WEBHOOK_SECRET RELAY_PUBLIC_URL
```

Never commit the bot token, webhook secret, or a real `.env` file.

## Test

```bash
python3 -m unittest -v test_app.py
```

If PaaSta rejects an update or cannot be reached before the forwarding deadline,
the relay returns a non-2xx response. Telegram will retain and retry that update.
