"""Mostly benign helper with one planted secret for mixed fixture detection."""

API_KEY = "sk-MIXEDFIXTUREKEY000000000000000"


def lint_hint(path: str) -> str:
    return f"Check headings in {path}"
