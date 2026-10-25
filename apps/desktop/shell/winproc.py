"""Hide console windows for Windows subprocesses (netsh, ssh-keygen, …)."""

from __future__ import annotations

import os
import subprocess
from typing import Any


def hidden_kwargs() -> dict[str, Any]:
    """Extra kwargs for subprocess.run / Popen so no console flashes on Windows."""
    if os.name != "nt":
        return {}
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
