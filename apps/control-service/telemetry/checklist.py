"""Guided Windows/WSL2 NAT portproxy + firewall checklist (K18).

Display-only: generate exact ``netsh`` commands for the user to run elevated.
Never execute or silently apply firewall/portproxy rules in v1.
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
    shell: str  # "powershell" | "cmd" | "either"
    notes: str = ""


def generate_wsl2_nat_checklist(
    *,
    wsl2_ip: str,
    monitoring_ip: str | None = None,
    listen_address: str = "0.0.0.0",
    listen_port: int = LOKI_PORT,
    connect_port: int = LOKI_PORT,
) -> list[ChecklistItem]:
    """Build the K18 guided checklist for Loki :3100 only.

    ``monitoring_ip`` is the Windows LAN IP Promtail should use; included in
    notes so the wizard can show verify steps. Commands are never executed here.
    """
    wsl2_ip = wsl2_ip.strip()
    if not wsl2_ip:
        raise ValueError("wsl2_ip is required")

    portproxy = (
        f"netsh interface portproxy add v4tov4 "
        f"listenaddress={listen_address} listenport={listen_port} "
        f"connectaddress={wsl2_ip} connectport={connect_port}"
    )
    # CMD-style caret continuation (matches DESIGN doc); also provide one-liner above.
    portproxy_multiline = (
        f"netsh interface portproxy add v4tov4 "
        f"listenaddress={listen_address} listenport={listen_port} ^\n"
        f"  connectaddress={wsl2_ip} connectport={connect_port}"
    )
    firewall = (
        f'netsh advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" '
        f"dir=in action=allow protocol=TCP localport={listen_port}"
    )
    show_proxy = "netsh interface portproxy show v4tov4"
    verify_note_parts = [
        "Run in an elevated PowerShell or CMD. Do not apply these for :9137/:8501.",
        f"WSL2 connect address: {wsl2_ip}.",
    ]
    if monitoring_ip:
        verify_note_parts.append(
            f"After confirm, probe from the gateway: "
            f"curl -fsS --max-time 5 http://{monitoring_ip}:{listen_port}/ready"
        )

    return [
        ChecklistItem(
            id="portproxy_add",
            title="Add portproxy (LAN :3100 → WSL2 Loki)",
            command=portproxy,
            shell="either",
            notes=(
                "Maps Windows listen → WSL2 Loki only. "
                f"Multiline CMD form:\n{portproxy_multiline}"
            ),
        ),
        ChecklistItem(
            id="firewall_allow",
            title="Allow inbound TCP 3100 (Windows Firewall)",
            command=firewall,
            shell="either",
            notes="Inbound allow for Promtail push from the gateway subnet.",
        ),
        ChecklistItem(
            id="portproxy_show",
            title="Verify portproxy table",
            command=show_proxy,
            shell="either",
            notes="Confirm listenport 3100 → connectaddress matches current WSL2 IP.",
        ),
        ChecklistItem(
            id="user_confirm",
            title="Confirm in Setup Wizard",
            command="",
            shell="either",
            notes=" ".join(verify_note_parts),
        ),
    ]


def format_checklist_for_display(items: list[ChecklistItem]) -> str:
    """Human-readable block for copy/paste UI / logs."""
    lines: list[str] = [
        "=== Windows WSL2 NAT — Loki :3100 guided checklist (K18) ===",
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


def refresh_checklist_on_wsl_ip_change(
    previous_wsl2_ip: str,
    new_wsl2_ip: str,
    *,
    monitoring_ip: str | None = None,
) -> list[ChecklistItem]:
    """Re-display checklist when WSL IP changes (still no auto-apply)."""
    items = generate_wsl2_nat_checklist(
        wsl2_ip=new_wsl2_ip, monitoring_ip=monitoring_ip
    )
    delete_old = (
        f"netsh interface portproxy delete v4tov4 "
        f"listenaddress=0.0.0.0 listenport={LOKI_PORT}"
    )
    preamble = ChecklistItem(
        id="portproxy_delete_stale",
        title=f"Remove stale portproxy (was {previous_wsl2_ip})",
        command=delete_old,
        shell="either",
        notes=(
            f"WSL2 IP changed {previous_wsl2_ip} → {new_wsl2_ip}. "
            "Delete the old mapping before adding the new one."
        ),
    )
    return [preamble, *items]
