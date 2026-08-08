# Contributing to Secret Masker

Thank you for your interest in contributing! Contributions of all kinds are welcome — new secret patterns, bug fixes, documentation improvements, and test coverage.

---

## Getting Started

```bash
git clone https://github.com/haithmgarallah-ye/Secrets-Masker.git
cd Secrets-Masker
pip install -e .
```

Run the test suite to make sure everything works before you start:

```bash
python -m pytest tests/
```

---

## Ways to Contribute

### Add a New Secret Pattern

The regex patterns live in `secretsmasker/secrets_masker.py` inside the `SECRET_PATTERNS` list. Each entry is a tuple:

```python
("PATTERN_LABEL", re.compile(r"your_regex_here"))
```

Guidelines:
- The regex must have **exactly one capture group** that isolates the secret value (not surrounding context like `=` or quotes).
- Place the new pattern in the appropriate category block (Cloud, VCS, Payment, etc.).
- Add a corresponding test in `tests/` that covers at least one positive match and one non-match.
- Update the **Supported Secret Types** table in `README.md`.

### Fix a Bug or False Positive

1. Open an issue first to describe the problem.
2. Include the exact input string and the incorrect output.
3. Submit a PR with a regression test that would have caught the bug.

### Improve Documentation

Typo fixes, clearer examples, and better explanations are always welcome. No issue needed — just open a PR.

---

## Pull Request Checklist

- [ ] Tests pass: `python -m pytest tests/`
- [ ] New behaviour is covered by at least one test
- [ ] No new third-party dependencies introduced (stdlib only)
- [ ] `README.md` updated if a new pattern was added

---

## Code Style

- Standard library only — no external dependencies, ever.
- Follow the existing style; there is no formatter enforced, but keep lines under 100 characters.
- Prefer clarity over cleverness.

---

## Reporting Issues

Use the [GitHub issue tracker](https://github.com/haithmgarallah-ye/Secrets-Masker/issues). Include:

- Python version
- Input text that triggered (or failed to trigger) masking
- Expected vs. actual output

---

## License

By contributing you agree that your code will be released under the project's [MIT License](LICENSE).
