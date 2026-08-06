"""
secrets_masker.py — stdlib-only secrets detection and masking utility.

Detection methods:
  1. Regex patterns     — 20+ provider-specific labeled rules (AWS, GitHub, Stripe, JWT, ...)
  2. Keyword heuristics — variable assignments like password=, api_key=, secret=, ...
  3. Entropy analysis   — high-Shannon-entropy strings not caught by the above two

Usage:
    from secrets_masker import mask_secrets

    result = mask_secrets(text)
    print(result.masked_text)   # text with secrets replaced by [SECRETS]
    print(result.findings)      # list of {type, start, end, snippet} dicts
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single detected secret in the input text."""
    type: str     # e.g. "AWS_ACCESS_KEY"
    start: int    # inclusive character offset in the original text
    end: int      # exclusive character offset in the original text
    snippet: str  # the literal matched text (for audit/logging)

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "snippet": self.snippet,
        }


@dataclass
class MaskResult:
    """Return value of mask_secrets()."""
    masked_text: str
    findings: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Regex pattern registry
# Each entry: (label, compiled_pattern)
# ORDER MATTERS: more-specific patterns come first so they win tie-breaks
# when two patterns overlap at the same start position.
# ---------------------------------------------------------------------------

_REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [

    # ── Cloud providers ────────────────────────────────────────────────────
    (
        "AWS_ACCESS_KEY",
        re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
    ),
    (
        "GCP_API_KEY",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    ),
    (
        "AZURE_CLIENT_SECRET",
        re.compile(
            r"(?i)(?:azure|az)[_\-\s]?(?:client[_\-\s]?)?secret"
            r"[\s:=\'\"]+([A-Za-z0-9_\-~.]{32,88})"
        ),
    ),

    # ── Version control tokens ─────────────────────────────────────────────
    (
        "GITHUB_TOKEN",
        re.compile(r"ghp_[0-9A-Za-z]{36}"),
    ),
    (
        "GITHUB_OAUTH_TOKEN",
        re.compile(r"gho_[0-9A-Za-z]{36}"),
    ),
    (
        "GITHUB_APP_TOKEN",
        re.compile(r"(?:ghu|ghs|ghr)_[0-9A-Za-z]{36}"),
    ),
    (
        "GITHUB_FINE_GRAINED_TOKEN",
        re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    ),
    (
        "GITLAB_TOKEN",
        re.compile(r"glpat-[0-9a-zA-Z\-]{20}"),
    ),
    (
        "BITBUCKET_TOKEN",
        re.compile(r"(?i)bitbucket[_\-\s]?(?:token|key|secret)[\s:=\'\"]+([A-Za-z0-9]{20,64})"),
    ),

    # ── Payment processors ─────────────────────────────────────────────────
    (
        "STRIPE_SECRET_KEY",
        re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24}"),
    ),
    (
        "STRIPE_PUBLISHABLE_KEY",
        re.compile(r"pk_(?:live|test)_[0-9a-zA-Z]{24}"),
    ),
    (
        "STRIPE_RESTRICTED_KEY",
        re.compile(r"rk_(?:live|test)_[0-9a-zA-Z]{24}"),
    ),
    (
        "PAYPAL_BRAINTREE_TOKEN",
        re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ),

    # ── Communication & messaging ──────────────────────────────────────────
    (
        "SLACK_TOKEN",
        re.compile(r"xox[baprs]-(?:[0-9A-Za-z]+-){1,4}[0-9A-Za-z]+"),
    ),
    (
        "SLACK_WEBHOOK",
        re.compile(
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"
        ),
    ),
    (
        "TWILIO_API_KEY",
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    ),
    (
        "TWILIO_ACCOUNT_SID",
        re.compile(r"\bAC[a-z0-9]{32}\b"),
    ),
    (
        "SENDGRID_API_KEY",
        re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"),
    ),
    (
        "DISCORD_TOKEN",
        re.compile(r"[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}"),
    ),
    (
        "DISCORD_WEBHOOK",
        re.compile(
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9\-_]{68}"
        ),
    ),
    (
        "TELEGRAM_BOT_TOKEN",
        re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b"),
    ),
    (
        "MAILGUN_API_KEY",
        re.compile(r"key-[0-9a-zA-Z]{32}"),
    ),
    (
        "MAILCHIMP_API_KEY",
        re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ),

    # ── OpenAI / AI providers ──────────────────────────────────────────────
    # Legacy format first (more specific) — must precede generic sk-proj- check
    (
        "OPENAI_API_KEY",
        re.compile(r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"),
    ),
    (
        "OPENAI_API_KEY",
        re.compile(r"sk-proj-[a-zA-Z0-9\-_]{50,}"),
    ),
    (
        "ANTHROPIC_API_KEY",
        re.compile(r"sk-ant-[a-zA-Z0-9\-_]{80,}"),
    ),

    # ── Auth & session tokens ──────────────────────────────────────────────
    # JWT before bearer so the bearer pattern doesn't consume the JWT value
    (
        "JWT_TOKEN",
        re.compile(
            r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*"
        ),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"[Bb]earer\s+[a-zA-Z0-9\-._~+/]{20,}=*"),
    ),
    (
        "OAUTH_CLIENT_SECRET",
        re.compile(
            r"(?i)client[_\-\s]?secret\s*[:=\s\'\"]+([a-zA-Z0-9\-_.~]{16,100})"
        ),
    ),
    (
        "OAUTH_ACCESS_TOKEN",
        re.compile(
            r"(?i)access[_\-\s]?token\s*[:=\s\'\"]+([a-zA-Z0-9\-_.~+/]{20,200})"
        ),
    ),
    (
        "NPM_TOKEN",
        re.compile(r"npm_[A-Za-z0-9]{36}"),
    ),
    (
        "PYPI_TOKEN",
        re.compile(r"pypi-[A-Za-z0-9\-_]{50,}"),
    ),

    # ── Private keys & certificates ────────────────────────────────────────
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+|ENCRYPTED\s+)?PRIVATE KEY-----",
            re.MULTILINE,
        ),
    ),
    (
        "SSH_PUBLIC_KEY",
        re.compile(r"ssh-(?:rsa|ed25519|dss|ecdsa)\s+AAAA[a-zA-Z0-9+/]+=*"),
    ),
    (
        "CERTIFICATE",
        re.compile(r"-----BEGIN CERTIFICATE-----", re.MULTILINE),
    ),

    # ── Database connection strings ────────────────────────────────────────
    # Matches scheme://user:password@host — explicitly excludes http/https
    (
        "DB_CONNECTION_STRING",
        re.compile(
            r"(?i)(?!https?://)(?!ftp://)[a-z][a-z0-9+\-.]{1,20}://[^@\s\"\'<>]+:[^@\s\"\'<>]+@[^\s\"\'<>]+",
        ),
    ),

    # ── Infrastructure & monitoring ────────────────────────────────────────
    (
        "CLOUDFLARE_API_KEY",
        re.compile(r"v1\.0-[0-9a-f]{24}-[0-9a-f]{146}"),
    ),
    (
        "DATADOG_API_KEY",
        re.compile(r"(?i)datadog[_\-\s]?(?:api[_\-\s]?)?key[\s:=\'\"]+([a-f0-9]{32})"),
    ),
    (
        "HEROKU_API_KEY",
        re.compile(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ),
    ),
    (
        "DIGITALOCEAN_TOKEN",
        re.compile(r"dop_v1_[a-f0-9]{64}"),
    ),

    # ── CI / CD & secrets managers ─────────────────────────────────────────
    (
        "CIRCLECI_TOKEN",
        re.compile(r"circle-token\s*[:=]\s*[a-fA-F0-9]{40}"),
    ),
    (
        "AWS_SESSION_TOKEN",
        re.compile(r"FwoGZXIvYXdz[A-Za-z0-9+/=]{100,}"),
    ),
]


# ---------------------------------------------------------------------------
# Keyword heuristics regex
# Matches assignments like:  password = "hunter2"   api_key: 'abc123'
# Also matches natural-language phrases like:  my password is hunter2
# The VALUE group is what gets masked; the variable name is preserved.
# ---------------------------------------------------------------------------

_KEYWORD_HEURISTIC_RE = re.compile(
    r"""
    (?ix)                                   # ignore-case, verbose
    \b                                      # word boundary — prevent partial matches
    (?:
        # ── Passwords & pass-phrases ────────────────────────────────────
        pass(?:w[o0]r?d?|word|wd)          # password, passw0rd, passwrd
        | passwd | paswd | passwrd | pswd | pwd
        | p[@a]ss(?:w[o0]?r?d?)?             # p@ssword, p@ssw0rd, p@ss
        | pass[\s_\-]?(?:phrase|code)      # passphrase, pass_phrase, pass phrase, passcode

        # ── Secrets ──────────────────────────────────────────────────────
        | sec(?:re?t|ert|rit|rte)(?:[\s_\-]?key)?  # secret, secert, secrit, secret_key, secret key

        # ── API keys / secrets / tokens (space/underscore/hyphen separator)
        | api[\s_\-]?(?:key|secret|token)  # api_key, api-key, api key, api_secret, api_token
        | apy[\s_\-]?key                   # apy key (typo)
        | ap[il1][\s_\-]?key              # apl key, ap1 key (typos)

        # ── Auth tokens / keys / secrets ─────────────────────────────────
        | auth[\s_\-]?(?:token|key|secret) # auth_token, auth-token, auth token

        # ── Access / refresh tokens ──────────────────────────────────────
        | access[\s_\-]?token              # access_token, access-token, access token
        | refresh[\s_\-]?token             # refresh_token, refresh-token, refresh token

        # ── Private keys ─────────────────────────────────────────────────
        | priv(?:ate)?[\s_\-]?key          # private_key, private-key, private key, priv_key
        | prvt[\s_\-]?key                  # prvt key (abbrev typo)

        # ── Encryption keys ──────────────────────────────────────────────
        | enc(?:ryp(?:tion)?)?[\s_\-]?key  # encryption_key, enc_key, encryptionkey

        # ── Signing keys / secrets ───────────────────────────────────────
        | sign(?:ing)?[\s_\-]?(?:key|secret)  # signing_key, signing key, sign_secret

        # ── Client secrets ───────────────────────────────────────────────
        | client[\s_\-]?secret             # client_secret, client-secret, client secret

        # ── App secrets / keys ───────────────────────────────────────────
        | app[\s_\-]?(?:secret|key)        # app_secret, app-secret, app secret, app_key

        # ── Credentials ──────────────────────────────────────────────────
        | cred(?:ential)?s?                # credentials, credential, creds, cred

        # ── Bearer ───────────────────────────────────────────────────────
        | bearer
    )
    (?:
        \s*(?:[:\-=]+)\s*               # assignment operators: = : := -- etc.
        | \s+is\s+                      # natural language: "password is X"
        | \s+                           # plain space: "api key VALUE"  ← new
    )
    (?P<quote>["'])?                     # optional opening quote
    (?P<value>
        [A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]{8,256}
    )
    (?P=quote)?                          # matching closing quote
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _detect_keyword_heuristics(text: str) -> list[Finding]:
    """
    Detect secrets by looking for keyword assignments (password=, api_key=, ...).
    Only the VALUE portion is flagged, so the variable name is preserved in output.
    """
    findings: list[Finding] = []
    for m in _KEYWORD_HEURISTIC_RE.finditer(text):
        value_start, value_end = m.span("value")
        value = m.group("value")
        if value:
            findings.append(Finding(
                type="PASSWORD",
                start=value_start,
                end=value_end,
                snippet=value,
            ))
    return findings


# ---------------------------------------------------------------------------
# Entropy analysis
# ---------------------------------------------------------------------------

_BASE64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")

_ENTROPY_MIN_LEN = 20
_ENTROPY_B64_THRESH = 3.5   # bits / char
_ENTROPY_HEX_THRESH = 3.0   # bits / char

# Candidates: quoted strings ≥20 chars  OR  bare alphanumeric tokens ≥20 chars
_ENTROPY_CANDIDATE_RE = re.compile(
    r"""
    (?:
        (?P<q>["'])(?P<quoted>[A-Za-z0-9+/=\-_]{20,})(?P=q)        # quoted
        |
        (?<![A-Za-z0-9])(?P<bare>[A-Za-z0-9+/=\-_]{20,})(?![A-Za-z0-9])  # bare
    )
    """,
    re.VERBOSE,
)


def _shannon_entropy(s: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _overlaps_any(start: int, end: int, spans: set[tuple[int, int]]) -> bool:
    """Return True if [start, end) overlaps with any span in the set."""
    for s, e in spans:
        if start < e and end > s:
            return True
    return False


def _detect_entropy(text: str, already_found: set[tuple[int, int]]) -> list[Finding]:
    """
    Flag high-entropy strings not already covered by regex/keyword detectors.
    already_found: set of (start, end) spans already committed by prior detectors.
    """
    findings: list[Finding] = []
    for m in _ENTROPY_CANDIDATE_RE.finditer(text):
        if m.group("quoted") is not None:
            value = m.group("quoted")
            start, end = m.start("quoted"), m.end("quoted")
        else:
            value = m.group("bare")
            start, end = m.start("bare"), m.end("bare")

        if len(value) < _ENTROPY_MIN_LEN:
            continue

        if _overlaps_any(start, end, already_found):
            continue

        chars = set(value)
        if chars <= _BASE64_CHARS:
            threshold = _ENTROPY_B64_THRESH
        elif chars <= _HEX_CHARS:
            threshold = _ENTROPY_HEX_THRESH
        else:
            continue  # charset not recognisably high-entropy

        if _shannon_entropy(value) >= threshold:
            findings.append(Finding(
                type="HIGH_ENTROPY_SECRET",
                start=start,
                end=end,
                snippet=value,
            ))
    return findings


# ---------------------------------------------------------------------------
# Regex detector
# ---------------------------------------------------------------------------

def _detect_regex(text: str) -> list[Finding]:
    """
    Apply all compiled regex patterns and return a Finding per match.

    When a pattern has a capture group (group 1), only that group's span is
    masked — this preserves surrounding context like variable names or quote
    characters that are part of the pattern but should not be redacted.
    """
    findings: list[Finding] = []
    for label, pattern in _REGEX_PATTERNS:
        for m in pattern.finditer(text):
            # Prefer group 1 when the pattern uses a capture group to isolate
            # just the secret value from its surrounding keyword/assignment.
            if m.lastindex and m.lastindex >= 1 and m.group(1) is not None:
                start, end = m.span(1)
                snippet = m.group(1)
            else:
                start, end = m.start(), m.end()
                snippet = m.group()
            findings.append(Finding(type=label, start=start, end=end, snippet=snippet))
    return findings


# ---------------------------------------------------------------------------
# Overlap resolution
# ---------------------------------------------------------------------------

def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """
    From a list of findings (possibly from multiple detectors), keep only
    non-overlapping ones.

    Strategy: sort by start position ascending. Ties go to the finding that
    appears earlier in the list — regex findings are appended first, so they
    win over keyword/entropy findings when they share the same start position.
    Python's sort is stable, so equal-start findings preserve their original
    insertion order.
    """
    accepted: list[Finding] = []
    occupied: list[tuple[int, int]] = []

    for f in sorted(findings, key=lambda x: x.start):
        overlaps = any(f.start < e and f.end > s for s, e in occupied)
        if not overlaps:
            accepted.append(f)
            occupied.append((f.start, f.end))

    return accepted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def mask_secrets(text: str) -> MaskResult:
    """
    Detect and mask secrets in *text* using three complementary methods:

      1. Regex patterns     — provider-specific rules for 35+ secret types
      2. Keyword heuristics — assignments like password=, api_key=, secret=
      3. Entropy analysis   — high-entropy strings not caught by the above two

    Each secret is replaced in the output by [SECRETS].
    The variable name / surrounding text is preserved.

    Returns a MaskResult with:
      .masked_text  — the input string with all secrets redacted
      .findings     — list of dicts: {type, start, end, snippet}
                      sorted by start position ascending
    """
    if not isinstance(text, str):
        raise TypeError(f"mask_secrets() expects str, got {type(text).__name__}")

    # Phase 1 — regex and keyword detectors
    all_findings: list[Finding] = []
    all_findings.extend(_detect_regex(text))
    all_findings.extend(_detect_keyword_heuristics(text))

    # Phase 2 — build span set for entropy gating
    phase1_spans: set[tuple[int, int]] = {(f.start, f.end) for f in all_findings}

    # Phase 3 — entropy analysis (only on unclaimed spans)
    all_findings.extend(_detect_entropy(text, phase1_spans))

    # Phase 4 — deduplicate / resolve overlaps
    resolved = _resolve_overlaps(all_findings)

    # Phase 5 — mask text right-to-left so indices stay valid
    masked: list[str] = list(text)
    for f in sorted(resolved, key=lambda x: x.start, reverse=True):
        label = "[SECRETS]"
        masked[f.start:f.end] = list(label)

    masked_text = "".join(masked)

    # Phase 6 — build public findings list (sorted by position ascending)
    findings_dicts = [
        f.as_dict()
        for f in sorted(resolved, key=lambda x: x.start)
    ]

    return MaskResult(masked_text=masked_text, findings=findings_dicts)
