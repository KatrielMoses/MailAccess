# Integrations

## CLI (`pip install mailaccess`)

The fastest integration — install the CLI and point it at any MailAccess instance:

```bash
mailaccess configure set-url http://your-instance:8000
mailaccess configure proxy show
mailaccess investigate target@example.com -o report.stix
mailaccess harvest-emails --domain example.com --use-proxies
```

The deprecated `mailaccess config` alias still works during the transition,
but `configure` is the canonical form. ScrapingAnt proxy routing is managed
separately with `mailaccess configure proxy enable residential|datacenter`
and `mailaccess configure proxy disable`.

---

## Maltego

MailAccess ships a Maltego local transform server that lets you run email investigations directly from the Maltego desktop app without touching the web UI or CLI.

### How it works

The transform server runs at `POST /maltego/email_investigate`. It accepts a standard Maltego TRX XML request containing an `EmailAddress` entity, runs a full MailAccess investigation (synchronously, with a 55-second timeout), and returns Maltego entities derived from the findings.

The endpoint is exempt from `MAILACCESS_API_KEY` authentication — it is designed to be called from the Maltego desktop app on localhost. Restrict it at the network level if your instance is publicly accessible.

### Setup

1. Start MailAccess. On startup it generates a configuration bundle at `maltego/MailAccess.mtz`.
2. Open **Maltego Desktop**.
3. Go to **Import/Export** → **Import Config**.
4. Select `MailAccess.mtz` and complete the import wizard.
5. In the resulting transform settings, verify the **Transform URL** points to your instance:
   ```
   http://localhost:8000/maltego/email_investigate
   ```
6. Restart Maltego.

To run an investigation: drag an `EmailAddress` entity onto the graph, right-click → **Run Transform** → **MailAccess: Investigate Email**.

### Partial results

If the investigation takes longer than 55 seconds, the transform returns whatever findings are available at that point, marked as partial. The full investigation continues in the background and is accessible via the web UI.

---

## Slack

Send a notification to a Slack channel when an investigation completes.

### Setup

1. Create an [incoming webhook](https://api.slack.com/messaging/webhooks) in your Slack workspace.
2. Add to `.env`:
   ```
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
   ```
3. Restart MailAccess.

---

## Discord

Send a notification to a Discord channel when an investigation completes.

### Setup

1. In your Discord server, go to **Server Settings** → **Integrations** → **Webhooks** → **New Webhook**.
2. Copy the webhook URL.
3. Add to `.env`:
   ```
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/.../...
   ```
4. Restart MailAccess.

---

## Generic Webhook

Post investigation results to any HTTP endpoint.

### Setup

Add to `.env`:

```
INTEGRATION_WEBHOOK_URL=https://your-system.example.com/webhook
INTEGRATION_WEBHOOK_SECRET=your-hmac-secret
```

When `INTEGRATION_WEBHOOK_SECRET` is set, MailAccess signs the request body with HMAC-SHA256 and includes the signature in the `X-MailAccess-Signature` header. Verify it on your end:

```python
import hashlib, hmac

def verify(body: bytes, secret: str, header: str) -> bool:
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)
```

The webhook payload is the same JSON structure as `GET /api/report/{id}`.

---

## Pipeline Integration

MailAccess is pipeline-friendly: read target emails from stdin, stream JSONL output, and branch on exit codes in CI/CD scripts.

### stdin batch

```bash
cat emails.txt | mailaccess investigate -
```

Pass `-` as the email argument to read one email address per line from stdin. Each email is investigated sequentially; output is written to stdout in the configured format.

### JSONL streaming

```bash
# Stream all findings as newline-delimited JSON
mailaccess investigate you@example.com --format jsonl

# Filter to critical findings only
mailaccess investigate you@example.com --format jsonl | jq 'select(.severity=="critical")'

# Combine with stdin batch
cat targets.txt | mailaccess investigate - --format jsonl | jq 'select(.severity=="critical")'
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Findings present |
| `2` | Active breaches detected |
| `3` | Error (network, config, or API failure) |

### Example: GitHub Actions step

```yaml
- name: Check email exposure
  run: |
    pip install mailaccess
    mailaccess investigate ${{ secrets.TARGET_EMAIL }} --format jsonl > findings.jsonl
    if [ $? -eq 2 ]; then
      echo "::error::Active breaches detected"
      exit 1
    fi
```
