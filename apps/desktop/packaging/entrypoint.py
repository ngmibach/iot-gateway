"""PyInstaller entrypoint for IoT Gateway Monitor.

Builds a double-clickable Windows .exe / Linux binary that starts the local
control API + Setup Wizard and opens an app window. No developer CLI required.
"""

from __future__ import annotations

import os
import sys


def _prepare_path() -> None:
    """Ensure control-service packages are importable in frozen and source runs."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        root = sys._MEIPASS  # type: ignore[attr-defined]
        cs = os.path.join(root, "control-service")
        for path in (root, cs):
            if path not in sys.path:
                sys.path.insert(0, path)
        os.environ.setdefault("IOTGW_REPO_ROOT", root)
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        desktop = os.path.dirname(here)
        apps = os.path.dirname(desktop)
        repo = os.path.dirname(apps)
        cs = os.path.join(apps, "control-service")
        for path in (desktop, cs, repo):
            if path not in sys.path:
                sys.path.insert(0, path)
        os.environ.setdefault("IOTGW_REPO_ROOT", repo)


def main() -> int:
    _prepare_path()
    from shell.__main__ import main as shell_main

    return shell_main()


if __name__ == "__main__":
    raise SystemExit(main())
