"""Hide console windows for Windows subprocesses (PowerShell NIC listing, …)."""

from __future__ import annotations

import os
import subprocess
from typing import Any

# Not always exported on every Python build; pin the Win32 values we need.
_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def hidden_kwargs() -> dict[str, Any]:
    """Extra kwargs for subprocess.run / Popen so no console flashes on Windows."""
    if os.name != "nt":
        return {}
    return {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", _CREATE_NO_WINDOW)
    }


def daemon_popen_kwargs() -> dict[str, Any]:
    """Kwargs for long-lived children (Loki/Prometheus/Grafana).

    Break away from the parent job and start a new process group so the
    binaries keep running after a one-shot ``ensure``/``start`` Python
    process exits (headless E2E, Install monitoring job thread teardown).
    """
    if os.name != "nt":
        return {"start_new_session": True}
    no_window = getattr(subprocess, "CREATE_NO_WINDOW", _CREATE_NO_WINDOW)
    new_group = getattr(
        subprocess, "CREATE_NEW_PROCESS_GROUP", _CREATE_NEW_PROCESS_GROUP
    )
    breakaway = getattr(
        subprocess, "CREATE_BREAKAWAY_FROM_JOB", _CREATE_BREAKAWAY_FROM_JOB
    )
    return {"creationflags": no_window | new_group | breakaway}
