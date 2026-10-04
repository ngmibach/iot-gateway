"""Pure helpers for ACL / passwords / allow-list file mutations."""

from __future__ import annotations


def _ensure_trailing_newline(text: str) -> str:
    if not text:
        return ""
    return text if text.endswith("\n") else text + "\n"


def acl_has_user(content: str, user_id: str) -> bool:
    return any(username == user_id for username, _ in _iter_user_blocks(content))


def append_user_acl(
    content: str,
    user_id: str,
    *,
    topic_rw: str | None = None,
    topic_r: str | None = None,
) -> str:
    """Append a new user block (add_new_user.yaml semantics)."""
    body = _ensure_trailing_newline(content)
    if body and not body.endswith("\n\n"):
        body += "\n"
    lines = [f"user {user_id}"]
    if topic_rw:
        lines.append(f"topic readwrite {topic_rw}")
    if topic_r:
        lines.append(f"topic read {topic_r}")
    return body + "\n".join(lines) + "\n"


def replace_user_acl(
    content: str,
    user_id: str,
    *,
    topic_rw: str | None = None,
    topic_r: str | None = None,
) -> str:
    """Replace an existing user block with a fresh one (topics from args only)."""
    without = remove_user_acl(content, user_id)
    return append_user_acl(without, user_id, topic_rw=topic_rw, topic_r=topic_r)


def upsert_user_acl(
    content: str,
    user_id: str,
    *,
    topic_rw: str | None = None,
    topic_r: str | None = None,
) -> str:
    """Insert or replace the ACL block for ``user_id`` (no duplicate users)."""
    if acl_has_user(content, user_id):
        return replace_user_acl(
            content, user_id, topic_rw=topic_rw, topic_r=topic_r
        )
    return append_user_acl(content, user_id, topic_rw=topic_rw, topic_r=topic_r)


def _iter_user_blocks(content: str) -> list[tuple[str | None, list[str]]]:
    """Split ACL into (username|None, lines) blocks. Preamble has username None."""
    blocks: list[tuple[str | None, list[str]]] = []
    current_user: str | None = None
    current: list[str] = []
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("user "):
            blocks.append((current_user, current))
            current_user = stripped[5:].strip()
            current = [line]
        else:
            current.append(line)
    blocks.append((current_user, current))
    return blocks


def update_user_acl(
    content: str,
    user_id: str,
    *,
    add_rw: list[str] | None = None,
    add_r: list[str] | None = None,
    delete_rw: list[str] | None = None,
    delete_r: list[str] | None = None,
) -> str:
    """Port of update_acl.yaml: delete listed rules, then append new ones under user."""
    add_rw = add_rw or []
    add_r = add_r or []
    delete_rw = set(delete_rw or [])
    delete_r = set(delete_r or [])
    blocks = _iter_user_blocks(content)
    found = False
    out: list[str] = []
    for username, lines in blocks:
        if username != user_id:
            out.extend(lines)
            continue
        found = True
        kept: list[str] = []
        for line in lines:
            s = line.strip()
            drop = False
            if s.startswith("topic readwrite "):
                topic = s[len("topic readwrite ") :]
                if topic in delete_rw:
                    drop = True
            elif s.startswith("topic read "):
                topic = s[len("topic read ") :]
                if topic in delete_r:
                    drop = True
            if not drop:
                kept.append(line)
        # Insert new topics immediately after the `user` line
        if not kept:
            kept = [f"user {user_id}\n"]
        head, rest = kept[0], kept[1:]
        inserts: list[str] = []
        for t in add_rw:
            inserts.append(f"topic readwrite {t}\n")
        for t in add_r:
            inserts.append(f"topic read {t}\n")
        out.append(head)
        out.extend(inserts)
        out.extend(rest)
    if not found:
        raise ValueError(f"user {user_id!r} not found in ACL")
    return "".join(out)


def remove_user_acl(content: str, user_id: str) -> str:
    blocks = _iter_user_blocks(content)
    out: list[str] = []
    removed = False
    for username, lines in blocks:
        if username == user_id:
            removed = True
            continue
        out.extend(lines)
    if not removed:
        raise ValueError(f"user {user_id!r} not found in ACL")
    text = "".join(out)
    # Collapse excessive blank lines at edges
    return text.lstrip("\n") if text.strip() else text


def merge_password_line(content: str, hash_line: str) -> str:
    """Replace existing user line or append. ``hash_line`` is ``user:$7$...``."""
    if ":" not in hash_line:
        raise ValueError("hash_line must be user:hash")
    username = hash_line.split(":", 1)[0]
    lines = content.splitlines()
    replaced = False
    new_lines: list[str] = []
    for line in lines:
        if not line.strip():
            new_lines.append(line)
            continue
        if line.split(":", 1)[0] == username:
            new_lines.append(hash_line)
            replaced = True
        else:
            new_lines.append(line)
    if not replaced:
        new_lines.append(hash_line)
    return "\n".join(new_lines) + "\n"


def remove_password_user(content: str, user_id: str) -> str:
    lines = [
        line
        for line in content.splitlines()
        if not (line.strip() and line.split(":", 1)[0] == user_id)
    ]
    return ("\n".join(lines) + "\n") if lines else ""


def parse_allowlist(content: str) -> list[str]:
    return [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def render_allowlist(ips: list[str]) -> str:
    # Stable unique order
    seen: set[str] = set()
    ordered: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    ordered.sort()
    return ("\n".join(ordered) + "\n") if ordered else ""


def add_allowlist_ips(content: str, ips: list[str]) -> str:
    current = parse_allowlist(content)
    return render_allowlist(current + list(ips))


def remove_allowlist_ips(content: str, ips: list[str]) -> str:
    deny = set(ips)
    current = [ip for ip in parse_allowlist(content) if ip not in deny]
    return render_allowlist(current)


def clear_allowlist(_content: str = "") -> str:
    return ""
