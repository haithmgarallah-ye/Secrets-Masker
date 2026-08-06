<div align="center">

<!-- Animated title -->
<a href="https://github.com/haithmgarallah-ye/Secrets-Masker">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=40&duration=3000&pause=1000&color=FF6B35&center=true&vCenter=true&repeat=true&width=600&height=80&lines=%F0%9F%94%90+Secret+Masker;Detect.+Redact.+Stay+Safe." alt="Secret Masker" />
</a>

<br/>
<br/>

<!-- Badges -->
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![stdlib only](https://img.shields.io/badge/deps-stdlib%20only-success?style=for-the-badge&logo=checkmarx&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Secrets](https://img.shields.io/badge/Patterns-35%2B%20providers-FF6B35?style=for-the-badge&logo=shield&logoColor=white)
![Layers](https://img.shields.io/badge/Detection-3%20layers-blueviolet?style=for-the-badge)
![Zero config](https://img.shields.io/badge/Config-zero--setup-brightgreen?style=for-the-badge)

<br/>

*A zero-dependency Python library that detects and redacts secrets from any text — before you log, share, or ship it.*

</div>

---

## What is Secret Masker?

**Secret Masker** is a single-file, `stdlib`-only Python module that automatically finds and replaces credentials, tokens, and keys buried in any string — config dumps, log lines, API responses, error messages — so they never reach the wrong eyes.

It uses **three complementary detection layers** to catch what individual regex libraries miss:

| Layer | Method | Example catch |
|-------|--------|---------------|
| **1** | 35+ provider-specific regex patterns | `ghp_...`, `sk-proj-...`, `AKIA...` |
| **2** | Keyword heuristic assignments | `password = "hunter2"`, `api_key: 'abc'` |
| **3** | Shannon entropy analysis | Any high-entropy bare/quoted token |

Each match is replaced with `[SECRETS]`, preserving surrounding context.

---

## Features

- **Zero dependencies** — pure Python standard library, nothing to `pip install`
- **35+ provider patterns** — AWS, GCP, Azure, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid, Discord, OpenAI, Anthropic, JWT, OAuth, SSH keys, private keys, DB connection strings, and more
- **Keyword heuristics** — catches `password =`, `api_key:`, `secret =`, `bearer`, etc. including typos and natural language ("my password is …")
- **Entropy analysis** — fallback layer flags any high-entropy quoted or bare token not caught above
- **Overlap resolution** — regex wins over heuristics wins over entropy; right-to-left replacement keeps indices valid
- **Structured findings** — each detection returns `{type, start, end, snippet}` for auditing or downstream processing
- **Single file** — drop `secrets_masker.py` anywhere and import it instantly

---

## Installation

No package manager needed. Just copy the file:

```bash
# Clone the repo
git clone https://github.com/haithmgarallah-ye/Secrets-Masker.git

# Or download the single file directly
curl -O https://raw.githubusercontent.com/haithmgarallah-ye/Secrets-Masker/main/secrets_masker.py
```

Then place `secrets_masker.py` next to your script and import:

```python
from secrets_masker import mask_secrets
```

> **Requirements:** Python 3.8+ · No third-party packages

---

## Quick Start

```python
from secrets_masker import mask_secrets

text = """
  aws_key   = AKIAIOSFODNN7EXAMPLE
  password  = "super$ecret99"
  token     = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
  db_url    = postgres://admin:hunter2@prod.db.example.com:5432/app
"""

result = mask_secrets(text)
print(result.masked_text)
print(result.findings)
```

**Output:**

```
  aws_key   = [SECRETS]
  password  = "[SECRETS]"
  token     = [SECRETS]
  db_url    = [SECRETS]
```

---

## Demo Output

Running `python secrets_masker.py` against the built-in demo text produces:

```
======================================================================
MASKED TEXT
======================================================================
# === Cloud keys ===
aws_access_key_id     = [SECRETS]
aws_secret_access_key = [SECRETS]
gcp_api_key           = [SECRETS]

# === VCS tokens ===
github_pat        = [SECRETS]
github_oauth      = [SECRETS]
github_app_token  = [SECRETS]
gitlab_token      = [SECRETS]
npm_token         = [SECRETS]

# === Payment ===
stripe_secret     = [SECRETS]
stripe_pub        = [SECRETS]

# === Communication ===
slack_token   = [SECRETS]
slack_webhook = [SECRETS]
twilio_sid    = [SECRETS]
twilio_key    = [SECRETS]
sendgrid      = [SECRETS]
discord_token = [SECRETS]

# === AI / LLM keys ===
openai_legacy = [SECRETS]
openai_new    = [SECRETS]

# === Auth tokens ===
jwt = [SECRETS]
Authorization: [SECRETS]
client_secret = "[SECRETS]"
access_token  = "[SECRETS]"

# === Private keys ===
[SECRETS]
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJFIsBsTV9MriqBuqhoDWMnFfSS...
-----END RSA PRIVATE KEY-----
ssh_pubkey = [SECRETS]

# === Database connection strings ===
postgres_url  = [SECRETS]
mongodb_url   = [SECRETS]

# === Keyword assignments ===
password    = '[SECRETS]'
api_key     = "[SECRETS]"
secret_key  = "[SECRETS]"
passphrase  = "[SECRETS]"

# === Normal text (should NOT be masked) ===
This is a normal sentence with no secrets.
Visit https://example.com for more info.
username = john_doe

======================================================================
FINDINGS  (26 secrets detected)
======================================================================
  TYPE                           CHARS        SNIPPET
  ------------------------------ ----------   ----------------------------------------
  AWS_ACCESS_KEY                   22-42      'AKIAIOSFODNN7EXAMPLE'
  GCP_API_KEY                      71-110     'AIzaSyD-9tSrke72I6gb4h6kmXDI123456789AB'
  GITHUB_TOKEN                    136-176     'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'
  GITHUB_OAUTH_TOKEN              196-236     'gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'
  GITHUB_APP_TOKEN                259-299     'ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'
  GITLAB_TOKEN                    319-339     'glpat-abcdefghijklmnopqrst'
  ...
```

---

## Demo Usage — Common Patterns

Each example below shows the raw input and the masked output produced by `mask_secrets()`.

---

### AWS Access Key

```python
from secrets_masker import mask_secrets

text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
print(mask_secrets(text).masked_text)
# aws_access_key_id = [SECRETS]

text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
print(mask_secrets(text).masked_text)
# aws_secret_access_key = [SECRETS]
```

---

### GCP API Key

```python
text = 'gcp_key = "AIzaSyD-9tSrke72I6gb4h6kmXDI123456789AB"'
print(mask_secrets(text).masked_text)
# gcp_key = "[SECRETS]"
```

---

### Azure Client Secret

```python
text = "AZURE_CLIENT_SECRET=Xy8Q~dKpLmN3rVwZ9aBcTuEfGhIjOqRsPvWx0123"
print(mask_secrets(text).masked_text)
# AZURE_CLIENT_SECRET=[SECRETS]
```

---

### GitHub Tokens

```python
# Personal Access Token (classic)
text = "github_token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
print(mask_secrets(text).masked_text)
# github_token = [SECRETS]

# OAuth token
text = "Authorization: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
print(mask_secrets(text).masked_text)
# Authorization: [SECRETS]

# Fine-grained PAT
text = "token: github_pat_11ABCDE_" + "A" * 82
print(mask_secrets(text).masked_text)
# token: [SECRETS]
```

---

### GitLab Token

```python
text = "GITLAB_TOKEN=glpat-abcdefghijklmnopqrst"
print(mask_secrets(text).masked_text)
# GITLAB_TOKEN=[SECRETS]
```

---

### NPM & PyPI Tokens

```python
text = "NPM_TOKEN=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
print(mask_secrets(text).masked_text)
# NPM_TOKEN=[SECRETS]

text = "PYPI_TOKEN=pypi-AgEIcHlwaS5vcmcAA" + "B" * 50
print(mask_secrets(text).masked_text)
# PYPI_TOKEN=[SECRETS]
```

---

### OpenAI API Key

```python
# New project key format
text = 'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"'
print(mask_secrets(text).masked_text)
# OPENAI_API_KEY = "[SECRETS]"

# Legacy format
text = "key = sk-aBcDeFgHiJkLmNoPqRsT T3BlbkFJ aBcDeFgHiJkLmNoPqRsT".replace(" ", "")
print(mask_secrets(text).masked_text)
# key = [SECRETS]
```

---

### Anthropic API Key

```python
text = "ANTHROPIC_API_KEY=sk-ant-api03-" + "A" * 80
print(mask_secrets(text).masked_text)
# ANTHROPIC_API_KEY=[SECRETS]
```

---

### Stripe Keys

```python
# Secret key
text = 'stripe_secret = "sk_live_<your_stripe_secret_key>"'
print(mask_secrets(text).masked_text)
# stripe_secret = "[SECRETS]"

# Publishable key
text = 'stripe_pub = "pk_test_4eC39HqLyjWDarjtT1zdp7dc"'
print(mask_secrets(text).masked_text)
# stripe_pub = "[SECRETS]"
```

---

### Slack Token & Webhook

```python
# Bot token
text = "SLACK_TOKEN=xoxb-<team_id>-<bot_id>-<token>"
print(mask_secrets(text).masked_text)
# SLACK_TOKEN=[SECRETS]

# Incoming webhook
text = "webhook = https://hooks.slack.com/services/T<workspace>/B<channel>/<token>"
print(mask_secrets(text).masked_text)
# webhook = [SECRETS]
```

---

### Twilio

```python
text = """
TWILIO_ACCOUNT_SID = AC<your_account_sid>
TWILIO_AUTH_TOKEN  = SK00000000000000000000000000000000
"""
print(mask_secrets(text).masked_text)
# TWILIO_ACCOUNT_SID = [SECRETS]
# TWILIO_AUTH_TOKEN  = [SECRETS]
```

---

### SendGrid API Key

```python
text = "SENDGRID_API_KEY=SG.ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopbd"
print(mask_secrets(text).masked_text)
# SENDGRID_API_KEY=[SECRETS]
```

---

### Discord Token & Webhook

```python
# Bot token
text = "DISCORD_TOKEN=MTk4NjIyNDgzNDcxOTI1MjQ4.GkFsE.ok_really_long_secret_xxxxxxxxx"
print(mask_secrets(text).masked_text)
# DISCORD_TOKEN=[SECRETS]

# Webhook URL
text = "hook = https://discord.com/api/webhooks/12345678901234567/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"
print(mask_secrets(text).masked_text)
# hook = [SECRETS]
```

---

### Telegram Bot Token

```python
text = "BOT_TOKEN=1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
print(mask_secrets(text).masked_text)
# BOT_TOKEN=[SECRETS]
```

---

### JWT & Bearer Token

```python
# JWT
jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
text = f"Authorization: Bearer {jwt}"
print(mask_secrets(text).masked_text)
# Authorization: [SECRETS]

# OAuth access token
text = 'access_token = "ya29.a0AfH6SMBx-very-long-google-oauth-token-here"'
print(mask_secrets(text).masked_text)
# access_token = "[SECRETS]"
```

---

### Database Connection Strings

```python
# PostgreSQL
text = "DATABASE_URL=postgres://admin:hunter2@prod.db.example.com:5432/myapp"
print(mask_secrets(text).masked_text)
# DATABASE_URL=[SECRETS]

# MongoDB
text = "MONGO_URI=mongodb+srv://root:S3cr3tP4ss@cluster0.abc.mongodb.net/prod"
print(mask_secrets(text).masked_text)
# MONGO_URI=[SECRETS]

# MySQL
text = "DB_URL=mysql://app_user:Passw0rd!@mysql.internal:3306/users"
print(mask_secrets(text).masked_text)
# DB_URL=[SECRETS]

# Redis
text = "REDIS_URL=redis://:myredispassword@redis.example.com:6379/0"
print(mask_secrets(text).masked_text)
# REDIS_URL=[SECRETS]
```

---

### Private Key & SSH

```python
# RSA private key header
text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
print(mask_secrets(text).masked_text)
# [SECRETS]
# MIIEowIBAAKCAQEA...
# -----END RSA PRIVATE KEY-----

# SSH public key (also detected)
text = "ssh_pubkey = ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC user@host"
print(mask_secrets(text).masked_text)
# ssh_pubkey = [SECRETS]
```

---

### Keyword Heuristics (passwords, api keys, secrets)

```python
# Various assignment styles
text = """
password    = "hunter2"
passwd      = 'Tr0ub4dor&3'
api_key     = abcdefghijklmnopqrstuvwx
api_secret  = "MyS3cr3tV4lue!!"
secret_key  = "django-insecure-abc123xyz"
client_secret = "oauth_client_secret_value"
auth_token  = "Bearer abc123xyz456"
"""
print(mask_secrets(text).masked_text)
# password    = "[SECRETS]"
# passwd      = '[SECRETS]'
# api_key     = [SECRETS]
# api_secret  = "[SECRETS]"
# secret_key  = "[SECRETS]"
# client_secret = "[SECRETS]"
# auth_token  = "[SECRETS]"

# Natural language
text = "my password is Tr0ub4dor&3"
print(mask_secrets(text).masked_text)
# my password is [SECRETS]
```

---

### DigitalOcean Token

```python
text = "DO_TOKEN=dop_v1_" + "a" * 64
print(mask_secrets(text).masked_text)
# DO_TOKEN=[SECRETS]
```

---

### Real-world: .env file dump

```python
env = """
APP_ENV=production
DATABASE_URL=postgres://app:Sup3rS3cr3t@db.prod.internal/myapp
REDIS_URL=redis://:redispass123@redis.prod.internal:6379
SECRET_KEY=django-insecure-v3ryL0ngS3cr3tK3yV4lu3Here!!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_<your_stripe_secret_key>
SENDGRID_API_KEY=SG.ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopbd
SLACK_BOT_TOKEN=xoxb-<team_id>-<bot_id>-<token>
PORT=8080
DEBUG=false
"""
result = mask_secrets(env)
print(result.masked_text)
```

```
APP_ENV=production
DATABASE_URL=[SECRETS]
REDIS_URL=[SECRETS]
SECRET_KEY=[SECRETS]
AWS_ACCESS_KEY_ID=[SECRETS]
AWS_SECRET_ACCESS_KEY=[SECRETS]
STRIPE_SECRET_KEY=[SECRETS]
SENDGRID_API_KEY=[SECRETS]
SLACK_BOT_TOKEN=[SECRETS]
PORT=8080
DEBUG=false
```

> Non-sensitive values (`PORT`, `DEBUG`, `APP_ENV`) pass through untouched.

---

### Real-world: log line sanitisation

```python
import json
from secrets_masker import mask_secrets

log_line = json.dumps({
    "event": "user_login",
    "user_id": 42,
    "api_key": "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "ip": "203.0.113.5"
})

safe_log = mask_secrets(log_line).masked_text
print(safe_log)
# {"event": "user_login", "user_id": 42, "api_key": "[SECRETS]", "ip": "203.0.113.5"}
```

---

### Inspecting findings metadata

```python
result = mask_secrets(
    "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij "
    "password=hunter2ABC!"
)

for f in result.findings:
    print(f["type"], "@", f["start"], "→", f["end"], "|", f["snippet"][:20])

# GITHUB_TOKEN @ 6 → 46 | ghp_ABCDEFGHIJKLMNOP
# PASSWORD     @ 56 → 67 | hunter2ABC!
```

The `findings` list preserves the original detection type and character offsets, useful for audit logs and alerting even though the masked text always shows `[SECRETS]`.

---

## Supported Secret Types

<details>
<summary><strong>Click to expand — all 35+ provider patterns</strong></summary>

| Category | Label | Example format |
|----------|-------|---------------|
| **Cloud** | `AWS_ACCESS_KEY` | `AKIA[A-Z0-9]{16}` |
| **Cloud** | `GCP_API_KEY` | `AIza[...]{35}` |
| **Cloud** | `AZURE_CLIENT_SECRET` | `azure_client_secret = ...` |
| **Cloud** | `AWS_SESSION_TOKEN` | `FwoGZXIvYXdz...` |
| **VCS** | `GITHUB_TOKEN` | `ghp_[...]{36}` |
| **VCS** | `GITHUB_OAUTH_TOKEN` | `gho_[...]{36}` |
| **VCS** | `GITHUB_APP_TOKEN` | `ghu_/ghs_/ghr_[...]{36}` |
| **VCS** | `GITHUB_FINE_GRAINED_TOKEN` | `github_pat_[...]{82}` |
| **VCS** | `GITLAB_TOKEN` | `glpat-[...]{20}` |
| **VCS** | `BITBUCKET_TOKEN` | `bitbucket_token = ...` |
| **VCS** | `NPM_TOKEN` | `npm_[...]{36}` |
| **VCS** | `PYPI_TOKEN` | `pypi-[...]{50+}` |
| **Payment** | `STRIPE_SECRET_KEY` | `sk_live_[...]{24}` |
| **Payment** | `STRIPE_PUBLISHABLE_KEY` | `pk_test_[...]{24}` |
| **Payment** | `STRIPE_RESTRICTED_KEY` | `rk_live_[...]{24}` |
| **Payment** | `PAYPAL_BRAINTREE_TOKEN` | `access_token$production$...` |
| **Messaging** | `SLACK_TOKEN` | `xoxb-...` |
| **Messaging** | `SLACK_WEBHOOK` | `hooks.slack.com/services/...` |
| **Messaging** | `TWILIO_API_KEY` | `SK[0-9a-f]{32}` |
| **Messaging** | `TWILIO_ACCOUNT_SID` | `AC[a-z0-9]{32}` |
| **Messaging** | `SENDGRID_API_KEY` | `SG.[...]{22}.[...]{43}` |
| **Messaging** | `DISCORD_TOKEN` | `[MN][...]{23}.[...]{6}.[...]{27}` |
| **Messaging** | `DISCORD_WEBHOOK` | `discord.com/api/webhooks/...` |
| **Messaging** | `TELEGRAM_BOT_TOKEN` | `[0-9]{10}:[A-Za-z0-9_-]{35}` |
| **Messaging** | `MAILGUN_API_KEY` | `key-[...]{32}` |
| **Messaging** | `MAILCHIMP_API_KEY` | `[0-9a-f]{32}-us[0-9]{2}` |
| **AI / LLM** | `OPENAI_API_KEY` | `sk-proj-...` / `sk-[...]T3BlbkFJ[...]` |
| **AI / LLM** | `ANTHROPIC_API_KEY` | `sk-ant-[...]{80+}` |
| **Auth** | `JWT_TOKEN` | `eyJ[...].eyJ[...].[...]` |
| **Auth** | `BEARER_TOKEN` | `Bearer eyJ...` |
| **Auth** | `OAUTH_CLIENT_SECRET` | `client_secret = ...` |
| **Auth** | `OAUTH_ACCESS_TOKEN` | `access_token = ...` |
| **Keys** | `PRIVATE_KEY` | `-----BEGIN RSA PRIVATE KEY-----` |
| **Keys** | `SSH_PUBLIC_KEY` | `ssh-rsa AAAA...` |
| **Keys** | `CERTIFICATE` | `-----BEGIN CERTIFICATE-----` |
| **Database** | `DB_CONNECTION_STRING` | `postgres://user:pass@host/db` |
| **Infra** | `CLOUDFLARE_API_KEY` | `v1.0-[0-9a-f]{24}-...` |
| **Infra** | `DATADOG_API_KEY` | `datadog_api_key = [0-9a-f]{32}` |
| **Infra** | `HEROKU_API_KEY` | UUID format |
| **Infra** | `DIGITALOCEAN_TOKEN` | `dop_v1_[0-9a-f]{64}` |
| **CI/CD** | `CIRCLECI_TOKEN` | `circle-token: [0-9a-f]{40}` |
| **Heuristic** | keyword match | `api_key = "..."`, `password = '...'` |
| **Entropy** | entropy match | Any high-entropy bare/quoted token |

</details>

---

## API Reference

### `mask_secrets(text: str) -> MaskResult`

The single public function. Runs all three detection layers and returns a `MaskResult`.

```python
from secrets_masker import mask_secrets, MaskResult

result: MaskResult = mask_secrets("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

result.masked_text
# → "token = [SECRETS]"

result.findings
# → [{"type": "GITHUB_TOKEN", "start": 8, "end": 49, "snippet": "ghp_ABCDE..."}]
```

### `MaskResult`

| Attribute | Type | Description |
|-----------|------|-------------|
| `.masked_text` | `str` | Input with all secrets replaced by `[SECRETS]` |
| `.findings` | `list[dict]` | One entry per detected secret, sorted by position |

### Finding dict

| Key | Type | Description |
|-----|------|-------------|
| `type` | `str` | Label e.g. `"AWS_ACCESS_KEY"` |
| `start` | `int` | Character offset (inclusive) in original text |
| `end` | `int` | Character offset (exclusive) in original text |
| `snippet` | `str` | The literal matched value (for audit logs) |

---

## How It Works

```
Input text
    │
    ▼
┌─────────────────────────────────────────────┐
│  Layer 1 — Regex Patterns                   │
│  35+ compiled provider patterns             │
│  Most-specific first; capture group isolates│
│  just the secret value from context         │
└──────────────────────┬──────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────┐
│  Layer 2 — Keyword Heuristics               │
│  Scans for password=, api_key:, secret =    │
│  ~40 keyword variants + typos + nat. lang.  │
│  Only the VALUE is flagged; key preserved   │
└──────────────────────┬──────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────┐
│  Layer 3 — Entropy Analysis                 │
│  Shannon entropy on unclaimed spans only    │
│  Base64 threshold: 3.5 bits/char            │
│  Hex threshold:    3.0 bits/char            │
└──────────────────────┬──────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────┐
│  Overlap Resolution                         │
│  Regex > Heuristic > Entropy                │
│  Stable sort; right-to-left replacement     │
└──────────────────────┬──────────────────────┘
                       │
    ▼
MaskResult(masked_text, findings)
```

---

## Use Cases

- **Safe logging** — pass any structured log line through `mask_secrets()` before writing to stdout/file/Splunk
- **CI/CD sanitisation** — scrub environment dumps before posting to Slack or GitHub comments
- **Data pipelines** — redact before inserting into analytics stores
- **Debug helpers** — print config dicts safely without leaking credentials
- **Security scanning** — use `.findings` metadata for alerts and incident reports

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made with care · zero deps · single file · drop it anywhere

</div>
