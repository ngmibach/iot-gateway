"""Tiny shared shell helpers (no third-party imports)."""


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
