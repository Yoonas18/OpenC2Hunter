# Contributing to OpenC2Hunter

Thank you for helping make OpenC2Hunter better! 🛡️

## How to Contribute

### 1. Fork & Clone
```bash
git clone https://github.com/YOUR_USERNAME/OpenC2Hunter.git
cd OpenC2Hunter
```

### 2. Set Up Dev Environment
```bash
pip install -r backend/requirements.txt
pip install ruff bandit   # linting & SAST
cd frontend && npm install && cd ..
```

### 3. Make Your Changes
- Keep backend code in `backend/`
- Keep UI changes in `frontend/src/`
- Add/update tests in `backend/tests/test_core.py`

### 4. Run Tests & Linting
```bash
# Unit tests
pytest backend/tests/ -v

# Linter
ruff check backend/ launch.py

# Security scan
bandit -r backend/ -ll -ii
```

All checks must pass before opening a PR.

### 5. Open a Pull Request
- Target the `main` branch
- Describe what you changed and why
- Reference any related issues

## What We Welcome
- 🐛 Bug fixes
- 🔍 New detection signatures (C2, DGA, OSINT sources)
- 🖥️ Dashboard UI improvements
- 📖 Documentation improvements
- 🌐 Additional OS / platform support

## Code Style
- Python: follow [Ruff](https://docs.astral.sh/ruff/) defaults (PEP 8 compatible)
- JavaScript/JSX: standard React conventions
- Keep functions small and focused
- Add a comment for any non-obvious detection logic

## Legal
By contributing, you agree your contributions will be licensed under the [MIT License](LICENSE).

