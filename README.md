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

AgentFA also sends Telegram Bot API calls back through the relay because its
PaaSta runtime cannot reach `api.telegram.org` directly:

```text
AgentFA
  -> https://your-relay-domain.example/telegram/api/<allowed-method>
  -> Telegram Bot API
```

The same service can optionally relay AgentFA's Gemini requests when PaaSta
cannot reach Google's Gemini API directly:

```text
AgentFA
  -> https://your-relay-domain.example/gemini/v1beta/models/<allowed-model>:generateContent
  -> https://generativelanguage.googleapis.com/v1beta/models/<allowed-model>:generateContent
```

It is intentionally not a general-purpose proxy. Each upstream is fixed,
redirects are rejected, request bodies are size-limited, Gemini models and
operations are allowlisted, and message bodies, prompts, and secrets are never
logged.

## Deployment variables

Configure these variables on the hosting platform:

| Variable | Required | Value |
| --- | --- | --- |
| `UPSTREAM_WEBHOOK_URL` | yes | `https://agentfaai.ir/api/bots/telegram/webhook` |
| `TELEGRAM_WEBHOOK_SECRET` | yes | Legacy webhook secret retained for backward compatibility; setup now registers a derived Telegram-compatible secret |
| `RELAY_WEBHOOK_PATH` | no | `/telegram/webhook` |
| `FORWARD_TIMEOUT_SECONDS` | no | `7` |
| `MAX_BODY_BYTES` | no | `1048576` |
| `WEB_CONCURRENCY` | no | `2` |
| `WEB_THREADS` | no | `4` |
| `SETUP_ENDPOINT_ENABLED` | no | `false`; temporarily set to `true` to enable HTTP setup |
| `SETUP_ADMIN_TOKEN` | for HTTP setup | A separate random value of at least 32 characters |
| `TELEGRAM_BOT_TOKEN` | yes | Token issued by Telegram `@BotFather`; used for setup, diagnostics, and outbound Bot API forwarding |
| `RELAY_PUBLIC_URL` | for HTTP setup | Public HTTPS origin of this relay |
| `GEMINI_RELAY_ENABLED` | no | `false`; explicitly set to `true` to enable the Gemini route |
| `GEMINI_RELAY_API_KEYS` | when Gemini is enabled | JSON array or comma-separated allowlist of the same Gemini API keys configured in AgentFA |
| `GEMINI_ALLOWED_MODELS` | no | Comma-separated model allowlist; defaults to `gemini-3.5-flash-lite` |
| `GEMINI_FORWARD_TIMEOUT_SECONDS` | no | Google request timeout; defaults to `125` and is capped at `300` |
| `GEMINI_MAX_BODY_BYTES` | no | Gemini request limit; defaults to `20971520` (20 MiB) |
| `GEMINI_MAX_RESPONSE_BYTES` | no | Gemini response limit; defaults to `10485760` (10 MiB) |
| `WORKER_TIMEOUT_SECONDS` | no | Gunicorn worker timeout; defaults to `150` so Gemini calls can complete |

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

Configure AgentFA on PaaSta with
`MESSENGER_TELEGRAM_API_BASE_URL=https://your-relay-domain.example/telegram/api`.
Both services must use the same Telegram bot token. They derive separate values
for relay authentication and Telegram webhook verification, so
`TELEGRAM_WEBHOOK_SECRET` does not also need to be synchronized with AgentFA.
The previous shared-secret headers remain accepted for backward compatibility.
The outbound endpoint accepts only the Bot API methods AgentFA needs and rejects
unauthenticated requests.

## Gemini relay

The Gemini relay is disabled by default. Configure the relay host with:

```env
GEMINI_RELAY_ENABLED=true
GEMINI_RELAY_API_KEYS=["first-key","second-key"]
GEMINI_ALLOWED_MODELS=gemini-3.5-flash-lite
GEMINI_FORWARD_TIMEOUT_SECONDS=125
WORKER_TIMEOUT_SECONDS=150
```

Keep the real values in the hosting platform's secret environment; never put
them in Git. `GEMINI_RELAY_API_KEYS` is both an authentication allowlist and the
set of credentials the route is permitted to forward. Requests with any other
key receive `401`, and unapproved models or operations receive `404`.

After the relay is deployed, set AgentFA's existing Gemini base URL to the
relay origin plus `/gemini`:

```env
GEMINI_BASE_URL=https://your-relay-domain.example/gemini
```

Keep AgentFA's existing `GEMINI_POOL_CONFIG` unchanged. The Google SDK continues
to select a key from that pool and sends it in `X-Goog-Api-Key`; the relay only
accepts it if the same key is present in `GEMINI_RELAY_API_KEYS`. This preserves
AgentFA's key rotation, cooldown handling, usage accounting, and key labels.

Example direct relay check using a key already stored securely in the shell:

```bash
curl --fail --silent --show-error \
  --request POST \
  --header 'Content-Type: application/json' \
  --header "X-Goog-Api-Key: $GEMINI_API_KEY" \
  --data '{"contents":[{"parts":[{"text":"Reply with OK"}]}]}' \
  https://your-relay-domain.example/gemini/v1beta/models/gemini-3.5-flash-lite:generateContent
```

Only enable this route on a host and for usage that complies with Google's
Gemini API terms and regional availability requirements.

### Protected HTTP setup endpoint

As an alternative to `set_webhook.py`, temporarily configure
`SETUP_ENDPOINT_ENABLED=true` and the three HTTP setup variables above. Then
call the endpoint using its separate administrator token:

```bash
curl --request POST \
  --header "Authorization: Bearer $SETUP_ADMIN_TOKEN" \
  https://your-relay-domain.example/admin/setup-webhook
```

The endpoint reads the Telegram bot token and webhook secret only from the
server environment. It does not accept or return either credential. It calls
Telegram's `setWebhook`, preserves queued updates, and returns only the relay
hostname. Set `SETUP_ENDPOINT_ENABLED=false` and remove `TELEGRAM_BOT_TOKEN`
and `SETUP_ADMIN_TOKEN` from the relay environment after successful setup.

### Protected connection diagnostics

While `SETUP_ENDPOINT_ENABLED=true`, the same administrator token can run a
safe end-to-end connection check:

```bash
curl --request POST \
  --header "Authorization: Bearer $SETUP_ADMIN_TOKEN" \
  https://your-relay-domain.example/admin/test-connections
```

The endpoint calls Telegram's `getWebhookInfo` and sends a signed no-op update
through the configured AgentFA webhook. It reports safe status, latency,
webhook-match, pending-update, and last-error fields without returning any
credential. A successful request can still return HTTP 200 with `"ok":false`;
inspect the separate `connections.telegram` and `connections.agentfa` results.

## Test

```bash
python3 -m unittest -v test_app.py
```

If PaaSta rejects an update or cannot be reached before the forwarding deadline,
the relay returns a non-2xx response. Telegram will retain and retry that update.
