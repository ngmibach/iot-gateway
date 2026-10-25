"""Guided Windows firewall checklist (K18).

Primary path (packaged Windows .exe): Loki listens on ``0.0.0.0:3100`` as a
native process — only a Windows Firewall allow rule is needed (no WSL, no
portproxy).

Display-only: generate exact ``netsh`` commands for the user to run elevated.
Never execute or silently apply firewall rules in v1.
"""

from __future__ import annotations

from dataclasses import dataclass


LOKI_PORT = 3100
FIREWALL_RULE_NAME = "IoT Gateway Loki 3100"


@dataclass(frozen=True)
class ChecklistItem:
    """One copyable step shown in the Setup Wizard."""

    id: str
    title: str
    command: str
    notes: str = ""


def _firewall_add(listen_port: int = LOKI_PORT) -> str:
    return (
        f'netsh advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
        f"dir=in action=allow protocol=TCP localport={listen_port}"
    )


def _firewall_delete() -> str:
    return f'netsh advfirewall firewall delete rule name="{FIREWALL_RULE_NAME}"'


def _firewall_show() -> str:
    return f'netsh advfirewall firewall show rule name="{FIREWALL_RULE_NAME}"'


def generate_windows_native_checklist(
    *,
    monitoring_ip: str | None = None,
    listen_port: int = LOKI_PORT,
    include_firewall_delete: bool = False,
) -> list[ChecklistItem]:
    """Firewall-only checklist for native Windows Loki (no WSL / portproxy)."""
    verify_note_parts = [
        "Run in an elevated PowerShell or CMD. Loki already listens on this PC.",
        "Do not add portproxy — that is only for legacy WSL2 setups.",
    ]
    if monitoring_ip:
        from .readiness import gateway_loki_ready_curl

        verify_note_parts.append(
            "After confirm, probe from the gateway (SSH): "
            + gateway_loki_ready_curl(monitoring_ip, port=listen_port)
        )

    items: list[ChecklistItem] = []
    if include_firewall_delete:
        items.append(
            ChecklistItem(
                id="firewall_delete",
                title="Remove existing firewall rule (idempotent re-run)",
                command=_firewall_delete(),
                notes="Safe if the rule is missing; avoids duplicate-rule errors on add.",
            )
        )

    items.extend(
        [
            ChecklistItem(
                id="firewall_allow",
                title="Allow inbound TCP 3100 (Windows Firewall)",
                command=_firewall_add(listen_port),
                notes="Inbound allow so the gateway can push logs to MONITORING_IP:3100.",
            ),
            ChecklistItem(
                id="firewall_show",
                title="Verify firewall rule",
                command=_firewall_show(),
                notes="Confirm the rule exists and is Enabled.",
            ),
            ChecklistItem(
                id="user_confirm",
                title="Confirm in Setup Wizard",
                command="",
                notes=" ".join(verify_note_parts),
            ),
        ]
    )
    return items


def format_checklist_for_display(
    items: list[ChecklistItem],
    *,
    title: str | None = None,
) -> str:
    """Human-readable block for copy/paste UI / logs."""
    header = title or "=== Windows — Loki :3100 firewall checklist (K18) ==="
    lines: list[str] = [
        header,
        "Display only — run these yourself in an elevated shell; the app will not.",
        "",
    ]
    for i, item in enumerate(items, 1):
        lines.append(f"{i}. {item.title} [{item.id}]")
        if item.command:
            lines.append(f"   {item.command}")
        if item.notes:
            for note_line in item.notes.splitlines():
                lines.append(f"   # {note_line}")
        lines.append("")
    return "\n".join(lines)
