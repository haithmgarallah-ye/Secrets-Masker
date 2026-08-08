<div align="center">

<a href="https://github.com/haithmgarallah-ye/Secrets-Masker">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=40&duration=3000&pause=1000&color=FF6B35&center=true&vCenter=true&repeat=true&width=600&height=80&lines=%F0%9F%94%90+Secret+Masker;Detect.+Redact.+Stay+Safe." alt="Secret Masker" />
</a>

<br/><br/>

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

**Secret Masker** is a stdlib-only Python library that automatically finds and replaces credentials, tokens, and keys buried in any string — config dumps, log lines, API responses, error messages — so they never reach the wrong eyes.

It uses **three complementary detection layers**:

| Layer | Method | Example catch |
|-------|--------|---------------|
| **1** | 35+ provider-specific regex patterns | `ghp_...`, `sk-proj-...`, `AKIA...` |
| **2** | Keyword heuristic assignments | `password = "hunter2"`, `api_key: 'abc'` |
| **3** | Shannon entropy analysis | Any high-entropy bare/quoted token |

Each match is replaced with `[SECRETS]`, preserving surrounding context.

---

## Installation

```bash
pip install secrets-masker
```

```python
from secretsmasker import mask_secrets
```

> **Requirements:** Python 3.8+ · No third-party packages · Zero setup

<details>
<summary>Install from source</summary>

```bash
git clone https://github.com/haithmgarallah-ye/Secrets-Masker.git
cd Secrets-Masker
pip install .
```

</details>

---

## Quick Start

```python
from secretsmasker import mask_secrets

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

## Run the Demo

```bash
pip install secrets-masker
python demo_masker.py
```

---

## Features

- **Zero dependencies** — pure Python standard library
- **35+ provider patterns** — AWS, GCP, Azure, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid, Discord, OpenAI, Anthropic, JWT, OAuth, SSH keys, private keys, DB connection strings, and more
- **Keyword heuristics** — catches `password =`, `api_key:`, `secret =`, `bearer`, etc. including natural language ("my password is …")
- **Entropy analysis** — fallback layer flags any high-entropy token not caught above
- **Overlap resolution** — regex wins over heuristics wins over entropy; right-to-left replacement keeps indices valid
- **Structured findings** — each detection returns `{type, start, end, snippet}` for auditing

---

## API Reference

### `mask_secrets(text: str) -> MaskResult`

```python
from secretsmasker import mask_secrets, MaskResult

result: MaskResult = mask_secrets("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

result.masked_text   # "token = [SECRETS]"
result.findings      # [{"type": "GITHUB_TOKEN", "start": 8, "end": 49, "snippet": "ghp_..."}]
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

## Common Patterns

### .env file

```python
from secretsmasker import mask_secrets

env = """
DATABASE_URL=postgres://app:Sup3rS3cr3t@db.prod.internal/myapp
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
PORT=8080
DEBUG=false
"""
print(mask_secrets(env).masked_text)
# DATABASE_URL=[SECRETS]
# AWS_ACCESS_KEY_ID=[SECRETS]
# AWS_SECRET_ACCESS_KEY=[SECRETS]
# PORT=8080
# DEBUG=false
```

### Log sanitisation

```python
import json
from secretsmasker import mask_secrets

log = json.dumps({
    "event": "user_login",
    "user_id": 42,
    "api_key": "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
    "ip": "203.0.113.5"
})
print(mask_secrets(log).masked_text)
# {"event": "user_login", "user_id": 42, "api_key": "[SECRETS]", "ip": "203.0.113.5"}
```

### Inspect findings

```python
result = mask_secrets("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij password=hunter2")

for f in result.findings:
    print(f["type"], "@", f["start"], "->", f["end"], "|", f["snippet"][:20])
# GITHUB_TOKEN @ 6 -> 46 | ghp_ABCDEFGHIJKLMNOP
# PASSWORD     @ 54 -> 61 | hunter2
```

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
| **VCS** | `NPM_TOKEN` | `npm_[...]{36}` |
| **VCS** | `PYPI_TOKEN` | `pypi-[...]{50+}` |
| **Payment** | `STRIPE_SECRET_KEY` | `sk_live_[...]{24}` |
| **Payment** | `STRIPE_PUBLISHABLE_KEY` | `pk_test_[...]{24}` |
| **Payment** | `STRIPE_RESTRICTED_KEY` | `rk_live_[...]{24}` |
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
| **Infra** | `DIGITALOCEAN_TOKEN` | `dop_v1_[0-9a-f]{64}` |
| **Infra** | `HEROKU_API_KEY` | UUID format |
| **Heuristic** | keyword match | `api_key = "..."`, `password = '...'` |
| **Entropy** | entropy match | Any high-entropy bare/quoted token |

</details>

---

## How It Works

```
Input text
    │
    ▼
┌─────────────────────────────────────────────┐
│  Layer 1 — Regex Patterns                   │
│  35+ compiled provider patterns             │
└──────────────────────┬──────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────┐
│  Layer 2 — Keyword Heuristics               │
│  Scans for password=, api_key:, secret =    │
└──────────────────────┬──────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────┐
│  Layer 3 — Entropy Analysis                 │
│  Shannon entropy on unclaimed spans only    │
└──────────────────────┬──────────────────────┘
                       │
    ▼
MaskResult(masked_text, findings)
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made with care · zero deps · drop it anywhere

</div>
