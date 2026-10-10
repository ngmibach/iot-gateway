"""Native desktop window for the Setup Wizard (no CLI required).

Launch order:
1. Start control-service (:9137) + wizard HTTP (:9138) in-process threads/children.
2. Open a frameless-ish app window pointed at the wizard URL.

Window backends (first that works):
- Embedded Chromium via Playwright (``--app=``) — works without system WebKit.
- System Chrome/Chromium/Edge with ``--app=``.
- ``pywebview`` (Qt/GTK) when available.
- Last resort: default OS browser tab.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from .launcher import ProcessManager, wait_http
from .paths import CONTROL_HOST, CONTROL_PORT, WIZARD_PORT, data_dir, ensure_data_dir
from .wizard_server import serve

logger = logging.getLogger(__name__)

WIZARD_URL = f"http://{CONTROL_HOST}:{WIZARD_PORT}/wizard.html"


def _local_lib_dir() -> Path:
    """Optional user-extracted Chrome runtime libs (no sudo): apps/desktop/.local-libs."""
    return Path(__file__).resolve().parents[1] / ".local-libs" / "usr" / "lib" / "x86_64-linux-gnu"


def _with_local_libs(env: dict[str, str]) -> dict[str, str]:
    lib = _local_lib_dir()
    if lib.is_dir():
        prev = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib}:{prev}" if prev else str(lib)
    return env


def _playwright_chrome() -> Optional[Path]:
    cache = Path.home() / ".cache" / "ms-playwright"
    if not cache.is_dir():
        return None
    for chrome in sorted(cache.glob("chromium-*/chrome-linux*/chrome"), reverse=True):
        if chrome.is_file() and os.access(chrome, os.X_OK):
            return chrome
    for chrome in sorted(cache.glob("chromium-*/chrome-win*/chrome.exe"), reverse=True):
        if chrome.is_file():
            return chrome
    for chrome in sorted(cache.glob("chromium-*/chrome-mac*/Chromium"), reverse=True):
        if chrome.is_file():
            return chrome
    return None


def _system_chrome() -> Optional[str]:
    names = (
        "google-chrome-stable",
        "google-chrome",
        "chromium-browser",
        "chromium",
        "msedge",
        "microsoft-edge",
        "brave-browser",
    )
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    # Windows common paths
    if os.name == "nt":
        for candidate in (
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
            / "Google/Chrome/Application/chrome.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
            / "Google/Chrome/Application/chrome.exe",
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Google/Chrome/Application/chrome.exe",
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
            / "Microsoft/Edge/Application/msedge.exe",
        ):
            if candidate.is_file():
                return str(candidate)
    return None


def _open_app_window(url: str) -> subprocess.Popen | None:
    """Open URL in an app-mode browser window (no address bar)."""
    profile = ensure_data_dir() / "chromium-profile"
    profile.mkdir(parents=True, exist_ok=True)
    args_common = [
        f"--app={url}",
        f"--user-data-dir={profile}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=TranslateUI",
        "--window-size=1100,800",
    ]

    env = _with_local_libs(os.environ.copy())
    chrome = _playwright_chrome()
    if chrome is not None:
        logger.info("Opening app window with Playwright Chromium: %s", chrome)
        return subprocess.Popen(
            [str(chrome), *args_common],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )

    system = _system_chrome()
    if system:
        logger.info("Opening app window with system browser: %s", system)
        return subprocess.Popen(
            [system, *args_common],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )

    # pywebview fallback
    try:
        import webview  # type: ignore

        def _run() -> None:
            webview.create_window(
                "IoT Gateway Monitor",
                url,
                width=1100,
                height=800,
            )
            webview.start()

        threading.Thread(target=_run, daemon=True).start()
        logger.info("Opened pywebview window")
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("pywebview unavailable: %s", exc)

    # Last resort — OS default browser (still no CLI for the user)
    import webbrowser

    webbrowser.open(url)
    logger.warning("Fell back to default browser tab for %s", url)
    return None


def run_gui(
    *,
    host: str = CONTROL_HOST,
    port: int = WIZARD_PORT,
    start_control: bool = True,
    with_streamlit: bool = False,
) -> int:
    """Start backend services and open the desktop app window. Blocks until exit."""
    ensure_data_dir()
    mgr = ProcessManager()
    httpd = None
    browser: subprocess.Popen | None = None

    try:
        if start_control:
            ctrl = mgr.start_control_service()
            if not wait_http(ctrl.url, timeout=45, path="/health"):
                print(
                    "control-service failed to become healthy on "
                    f"http://{CONTROL_HOST}:{CONTROL_PORT}",
                    file=sys.stderr,
                )
                mgr.stop_all()
                return 1
            if with_streamlit:
                try:
                    st = mgr.start_streamlit(control_url=ctrl.url)
                    wait_http(st.url, timeout=60)
                except FileNotFoundError as exc:
                    logger.warning("streamlit skipped: %s", exc)

        httpd = serve(host, port, open_browser=False)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        wizard = f"http://{host}:{port}/wizard.html"
        if not wait_http(f"http://{host}:{port}", timeout=20, path="/api/wizard/env"):
            print("wizard server failed to start", file=sys.stderr)
            return 1

        browser = _open_app_window(wizard)
        print(f"IoT Gateway Monitor running — {wizard}")
        print(f"App data: {data_dir()}")
        print("Close the app window or press Ctrl+C to quit.")

        # Stay alive while the window process runs (or forever for webview/browser).
        try:
            if browser is not None:
                browser.wait()
            else:
                while True:
                    time.sleep(1.0)
        except KeyboardInterrupt:
            print("\nShutting down…")
        return 0
    finally:
        if browser is not None and browser.poll() is None:
            browser.terminate()
            try:
                browser.wait(timeout=5)
            except subprocess.TimeoutExpired:
                browser.kill()
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        mgr.stop_all()
