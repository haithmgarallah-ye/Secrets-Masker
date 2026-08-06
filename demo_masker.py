from secrets_masker import mask_secrets

text = "use my api key [YOUR SECRET] to logon to my server"
result = mask_secrets(text)

print("Original :", text)
print("Masked   :", result.masked_text)
print("Findings :")
for f in result.findings:
    print(f"  - type={f['type']}  snippet={f['snippet']!r}  pos=[{f['start']}:{f['end']}]")
