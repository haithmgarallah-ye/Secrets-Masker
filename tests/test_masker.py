"""Tests for secretsmasker — one test per detection layer and major pattern."""
import pytest
from secretsmasker import mask_secrets, MaskResult, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def masked(text: str) -> str:
    return mask_secrets(text).masked_text


def findings(text: str) -> list[dict]:
    return mask_secrets(text).findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class TestPublicAPI:
    def test_returns_mask_result(self):
        result = mask_secrets("hello world")
        assert isinstance(result, MaskResult)

    def test_no_secrets_passthrough(self):
        text = "This is a normal sentence with no secrets."
        assert masked(text) == text

    def test_findings_sorted_by_position(self):
        text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij password=hunter2ABC!"
        fs = findings(text)
        positions = [f["start"] for f in fs]
        assert positions == sorted(positions)

    def test_finding_keys(self):
        fs = findings("AKIAIOSFODNN7EXAMPLE")
        assert fs
        assert set(fs[0].keys()) == {"type", "start", "end", "snippet"}


# ---------------------------------------------------------------------------
# Layer 1 — Regex patterns
# ---------------------------------------------------------------------------

class TestRegexPatterns:
    def test_aws_access_key(self):
        text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        result = mask_secrets(text)
        assert "[SECRETS]" in result.masked_text
        assert result.findings[0]["type"] == "AWS_ACCESS_KEY"
        assert result.findings[0]["snippet"] == "AKIAIOSFODNN7EXAMPLE"

    def test_gcp_api_key(self):
        text = 'gcp_key = "AIzaSyD-9tSrke72I6gb4h6kmXDI123456789AB"'
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "GCP_API_KEY"

    def test_github_pat(self):
        text = "github_token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "GITHUB_TOKEN"

    def test_github_oauth(self):
        text = "Authorization: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "GITHUB_OAUTH_TOKEN"

    def test_github_fine_grained(self):
        text = "token: github_pat_11ABCDE_" + "A" * 82
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "GITHUB_FINE_GRAINED_TOKEN"

    def test_gitlab_token(self):
        text = "GITLAB_TOKEN=glpat-abcdefghijklmnopqrst"
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "GITLAB_TOKEN"

    def test_npm_token(self):
        text = "NPM_TOKEN=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "NPM_TOKEN"

    def test_stripe_secret(self):
        # Split literal to avoid triggering secret scanners in CI/VCS
        text = 'stripe_secret = "sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc"'
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "STRIPE_SECRET_KEY"

    def test_slack_token(self):
        # Split literal to avoid triggering secret scanners in CI/VCS
        text = "SLACK_TOKEN=xoxb-" + "123456789-123456789-abcdefghijklmnop"
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "SLACK_TOKEN"

    def test_sendgrid_key(self):
        text = "SENDGRID_API_KEY=SG.ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopbd"
        result = mask_secrets(text)
        assert "[SECRETS]" in result.masked_text
        # Caught by either the SENDGRID_API_KEY regex or the entropy fallback
        assert result.findings[0]["type"] in ("SENDGRID_API_KEY", "HIGH_ENTROPY_SECRET")

    def test_telegram_bot_token(self):
        text = "BOT_TOKEN=1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "TELEGRAM_BOT_TOKEN"

    def test_openai_project_key(self):
        text = 'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"'
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "OPENAI_API_KEY"

    def test_anthropic_key(self):
        text = "ANTHROPIC_API_KEY=sk-ant-api03-" + "A" * 80
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "ANTHROPIC_API_KEY"

    def test_jwt_token(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        text = f"Authorization: Bearer {jwt}"
        assert "[SECRETS]" in masked(text)

    def test_db_connection_string_postgres(self):
        text = "DATABASE_URL=postgres://admin:hunter2@prod.db.example.com:5432/myapp"
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "DB_CONNECTION_STRING"

    def test_db_connection_string_mongodb(self):
        text = "MONGO_URI=mongodb+srv://root:S3cr3tP4ss@cluster0.abc.mongodb.net/prod"
        assert "[SECRETS]" in masked(text)

    def test_digitalocean_token(self):
        text = "DO_TOKEN=dop_v1_" + "a" * 64
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "DIGITALOCEAN_TOKEN"

    def test_private_key_header(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "PRIVATE_KEY"

    def test_ssh_public_key(self):
        text = "ssh_pubkey = ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC user@host"
        assert "[SECRETS]" in masked(text)
        assert findings(text)[0]["type"] == "SSH_PUBLIC_KEY"


# ---------------------------------------------------------------------------
# Layer 2 — Keyword heuristics
# ---------------------------------------------------------------------------

class TestKeywordHeuristics:
    def test_password_equals(self):
        text = 'password = "hunter2ABC!"'
        result = mask_secrets(text)
        assert "[SECRETS]" in result.masked_text
        assert result.findings[0]["type"] == "PASSWORD"

    def test_passwd_single_quote(self):
        text = "passwd = 'Tr0ub4dor&3abc'"
        assert "[SECRETS]" in masked(text)

    def test_api_key_colon(self):
        text = "api_key: abcdefghijklmnopqrstuvwx"
        assert "[SECRETS]" in masked(text)

    def test_secret_key(self):
        text = 'secret_key = "django-insecure-abc123xyz"'
        assert "[SECRETS]" in masked(text)

    def test_client_secret(self):
        text = 'client_secret = "oauth_client_secret_value"'
        assert "[SECRETS]" in masked(text)

    def test_natural_language(self):
        text = "my password is Tr0ub4dor3abc"
        assert "[SECRETS]" in masked(text)

    def test_variable_name_preserved(self):
        text = 'api_key = "my_super_secret_key_123"'
        result = mask_secrets(text)
        assert result.masked_text.startswith("api_key")
        assert "[SECRETS]" in result.masked_text


# ---------------------------------------------------------------------------
# Layer 3 — Entropy analysis
# ---------------------------------------------------------------------------

class TestEntropyAnalysis:
    def test_high_entropy_quoted_string(self):
        # A truly random-looking base64 token that doesn't match any regex
        token = "xK9mP2vQnRjT8wYcZ5bL0eHuAsDfGhNkMoIpUyWqErBtVlXzJcO"
        text = f'some_var = "{token}"'
        result = mask_secrets(text)
        # High entropy quoted string should be caught
        assert "[SECRETS]" in result.masked_text


# ---------------------------------------------------------------------------
# Overlap resolution & multi-secret text
# ---------------------------------------------------------------------------

class TestOverlapResolution:
    def test_multiple_secrets_in_one_string(self):
        text = (
            "aws_key = AKIAIOSFODNN7EXAMPLE "
            "github = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        )
        result = mask_secrets(text)
        assert result.masked_text.count("[SECRETS]") == 2
        assert len(result.findings) == 2

    def test_non_sensitive_values_pass_through(self):
        text = "PORT=8080\nDEBUG=false\nAPP_ENV=production"
        assert masked(text) == text

    def test_positions_are_consistent(self):
        text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        result = mask_secrets(text)
        f = result.findings[0]
        assert text[f["start"]:f["end"]] == f["snippet"]

    def test_env_file_mixed(self):
        env = (
            "APP_ENV=production\n"
            "DATABASE_URL=postgres://app:Sup3rS3cr3t@db.prod.internal/myapp\n"
            "PORT=8080\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "DEBUG=false\n"
        )
        result = mask_secrets(env)
        assert "APP_ENV=production" in result.masked_text
        assert "PORT=8080" in result.masked_text
        assert "DEBUG=false" in result.masked_text
        assert "postgres://" not in result.masked_text
        assert "AKIAIOSFODNN7EXAMPLE" not in result.masked_text
