# Contributing to ScanMe

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/NightzDev/scanme.git
cd scanme

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install in dev mode with test dependencies
pip install -e ".[dev]"

# Run tests
pytest -v
```

## How to Contribute

### Reporting Bugs

- Use the [Bug Report](https://github.com/NightzDev/scanme/issues/new?template=bug_report.md) issue template.
- Include: Python version, OS, full error traceback, and steps to reproduce.

### Suggesting Features

- Use the [Feature Request](https://github.com/NightzDev/scanme/issues/new?template=feature_request.md) issue template.
- Explain the use case and why it would be useful.

### Pull Requests

1. Fork the repo and create a branch from `main`.
2. Write your code following the existing patterns.
3. Add tests for new functionality.
4. Ensure all tests pass: `pytest -v`
5. Submit a PR with a clear description.

## Code Guidelines

- **Python 3.10+** — use modern syntax (`str | None`, `match/case`, etc.).
- **Async first** — all scan modules use `asyncio` and `aiohttp`.
- **Type hints** — all function signatures should be typed.
- **Module pattern** — new scan modules must inherit from `AsyncScanEngine` and implement `run()`.
- **No external API keys** — the tool should work without any API keys or accounts.

## Adding a New Scan Module

1. Create `scanme/modules/yourmodule.py`.
2. Subclass `AsyncScanEngine`, set `name`, implement `run(target, ui)`.
3. Register it in `scanme/modules/__init__.py` and `scanme/cli.py`.
4. Add tests in `tests/test_modules.py`.

## Adding a New CMS Profile

Edit `scanme/modules/cmsdetect.py` and add a `_p()` call with:
- At least one `DEFINITIVE` or `STRONG` tier check.
- Version extraction patterns when possible.
- An `exclusive_group` if it competes with similar platforms.

## Tests

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=scanme --cov-report=term-missing

# Run specific test file
pytest tests/test_modules.py -v
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
