# Contributing to Internal Security Auditor

## Branch Naming

- `feature/description-of-feature` — new functionality
- `fix/description-of-bug` — bug fixes
- `docs/what-you-documented` — documentation only

## Commit Messages

Follow the Conventional Commits spec:

```
feat: add ARP sweep service
fix: handle timeout in nmap scanner
docs: update ARCHITECTURE.md with OUI flow
test: add conftest fixtures for async DB
```

## Before Opening a PR

- [ ] All tests pass: `pytest tests/ -v`
- [ ] No new linting errors: `ruff check .`
- [ ] New features have tests
- [ ] ARCHITECTURE.md updated if design changed

## Code Style

- Type hints on all function signatures
- Docstrings on all public functions
- No business logic in route handlers