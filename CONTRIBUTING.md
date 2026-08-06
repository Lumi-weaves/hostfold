# Contributing to Hostfold

Thank you for helping make small SSH clusters safer and easier to inhabit.

## Development

```console
$ uv sync --dev
$ uv run ruff format .
$ uv run ruff check .
$ uv run pytest
$ uv build
```

Please keep the implementation compatible with Python 3.10 and avoid adding a
runtime dependency when the standard library is sufficient. The copied bundle
installer in `src/hostfold/_install_payload.py` must remain self-contained and
standard-library-only.

## Change principles

- Preserve canonical host names across all views.
- Keep route selection a render-time concern.
- Make private-key assignment explicit and fail closed.
- Do not make remote nodes authorities or key distributors.
- Preserve unrelated user SSH configuration.
- Prefer a bounded, reversible change over a broad rewrite.

Every security-relevant behavior should have a negative test as well as a
happy-path test.

## Test data

Never commit real deployment data. Tests should generate short-lived keys in a
temporary directory. Examples must use reserved domains and clearly invalid
placeholder key material.

## Reporting vulnerabilities

Please follow `SECURITY.md` rather than opening a public issue for a suspected
vulnerability.
