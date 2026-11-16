# Contributing

Contributions and improvement ideas are welcome.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/seed_demo.py
uvicorn app.main:app --reload
```

Run tests before opening a pull request:

```bash
python -m pytest -q
```

## Guidelines

- keep demo data synthetic
- add tests for new IAM rules
- keep risk rules explainable
- document new API endpoints
- do not introduce secrets into commits
- prefer small focused pull requests
