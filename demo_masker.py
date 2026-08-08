"""
demo_masker.py — showcase for the `secrets-masker` pip package.

Install:
    pip install secrets-masker

Run:
    python demo_masker.py
"""

from secretsmasker import mask_secrets

# ---------------------------------------------------------------------------
# Demo text covering all major detection layers
# ---------------------------------------------------------------------------
DEMO_TEXT = "my password 'asdasdasdasdasdasdasd' to login to my account"

# ---------------------------------------------------------------------------
# Run masking
# ---------------------------------------------------------------------------
result = mask_secrets(DEMO_TEXT)

SEP = "=" * 70

print(SEP)
print("MASKED TEXT")
print(SEP)
print(result.masked_text)

print()
print(SEP)
print(f"FINDINGS  ({len(result.findings)} secrets detected)")
print(SEP)
print(f"  {'TYPE':<30} {'CHARS':<12} {'SNIPPET'}")
print(f"  {'-'*30} {'-'*10}   {'-'*40}")
for f in result.findings:
    chars = f"{f['start']}-{f['end']}"
    snippet = repr(f['snippet'][:40])
    print(f"  {f['type']:<30} {chars:>10}   {snippet}")
