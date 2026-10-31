"""Hide console windows for Windows subprocesses (PowerShell NIC listing, …)."""

from __future__ import annotations

import os
import subprocess
import time
from typing import Any, Sequence

# Not always exported on every Python build; pin the Win32 values we need.
_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000

# Cached after first successful/failed breakaway attempt in this process.
_breakaway_allowed: bool | None = None
# When breakaway is denied, prefer WMI Create so children outlive the parent job.
_use_wmi_detach: bool | None = None


def hidden_kwargs() -> dict[str, Any]:
    """Extra kwargs for subprocess.run / Popen so no console flashes on Windows."""
    if os.name != "nt":
        return {}
    return {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", _CREATE_NO_WINDOW)
    }


def daemon_popen_kwargs(*, breakaway: bool | None = None) -> dict[str, Any]:
    """Kwargs for long-lived children (Loki/Prometheus/Grafana).

    Prefer ``CREATE_BREAKAWAY_FROM_JOB`` so binaries survive after a one-shot
    ensure/start Python exits. Some parent jobs (IDE/agent shells) disallow
    breakaway and CreateProcess then returns Access Denied — callers should
    use :func:`popen_daemon`, which falls back to WMI detach spawn.
    """
    if os.name != "nt":
        return {"start_new_session": True}
    no_window = getattr(subprocess, "CREATE_NO_WINDOW", _CREATE_NO_WINDOW)
    new_group = getattr(
        subprocess, "CREATE_NEW_PROCESS_GROUP", _CREATE_NEW_PROCESS_GROUP
    )
    flags = no_window | new_group
    use_breakaway = _breakaway_allowed if breakaway is None else breakaway
    if use_breakaway is not False:
        breakaway_flag = getattr(
            subprocess, "CREATE_BREAKAWAY_FROM_JOB", _CREATE_BREAKAWAY_FROM_JOB
        )
        flags |= breakaway_flag
    return {"creationflags": flags}


def _quote_win_arg(arg: str) -> str:
    if not arg:
        return '""'
    if any(ch in arg for ch in ' \t"&<>|^()'):
        return '"' + arg.replace('"', '\\"') + '"'
    return arg


def _cmdline(args: Sequence[str]) -> str:
    return " ".join(_quote_win_arg(str(a)) for a in args)


class _WmiProc:
    """Minimal process handle for a WMI-spawned daemon (pid only)."""

    def __init__(self, pid: int) -> None:
        self.pid = int(pid)
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        # tasklist is available on all supported Windows hosts.
        try:
            out = subprocess.check_output(
                [
                    "tasklist",
                    "/FI",
                    f"PID eq {self.pid}",
                    "/FO",
                    "CSV",
                    "/NH",
                ],
                text=True,
                stderr=subprocess.DEVNULL,
                **hidden_kwargs(),
            )
        except (OSError, subprocess.CalledProcessError):
            return None
        alive = str(self.pid) in out and "INFO:" not in out
        if alive:
            return None
        self.returncode = 0
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.time() + timeout
        while True:
            code = self.poll()
            if code is not None:
                return code
            if deadline is not None and time.time() >= deadline:
                raise subprocess.TimeoutExpired(cmd=f"pid={self.pid}", timeout=timeout)
            time.sleep(0.2)

    def terminate(self) -> None:
        subprocess.run(
            ["taskkill", "/PID", str(self.pid)],
            check=False,
            capture_output=True,
            **hidden_kwargs(),
        )

    def kill(self) -> None:
        subprocess.run(
            ["taskkill", "/F", "/PID", str(self.pid)],
            check=False,
            capture_output=True,
            **hidden_kwargs(),
        )


def _wmi_create(cmdline: str) -> int:
    """Create a process via WMI so it is not joined to the caller's job object."""
    # Escape for PowerShell single-quoted string.
    ps_cmd = cmdline.replace("'", "''")
    script = (
        f"$r = ([wmiclass]'Win32_Process').Create('{ps_cmd}'); "
        "if ($null -eq $r -or $r.ReturnValue -ne 0) { "
        "throw (\"wmi_create_failed return=\" + $(if ($r) { $r.ReturnValue } else { 'null' })) }; "
        "Write-Output $r.ProcessId"
    )
    out = subprocess.check_output(
        [
            "powershell",
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-Command",
            script,
        ],
        text=True,
        stderr=subprocess.STDOUT,
        **hidden_kwargs(),
    ).strip()
    # Last line is the PID (ignore any chatter).
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not lines:
        raise OSError(f"WMI Create returned no PID for: {cmdline}")
    return int(lines[-1])


def _stdout_log_path(stdout: Any) -> str | None:
    """Best-effort path for an open file used as Popen stdout."""
    name = getattr(stdout, "name", None)
    if isinstance(name, str) and name and name not in ("<stdout>", "<stderr>"):
        return name
    return None


def popen_daemon(
    args: Sequence[str] | str,
    **kwargs: Any,
) -> subprocess.Popen[Any] | _WmiProc:
    """``Popen`` for telemetry daemons with breakaway, then WMI detach on denial."""
    global _breakaway_allowed, _use_wmi_detach
    if os.name != "nt":
        return subprocess.Popen(args, **kwargs, **daemon_popen_kwargs())

    if not isinstance(args, (list, tuple)):
        raise TypeError("popen_daemon expects argv list on Windows")

    if _use_wmi_detach is True:
        return _spawn_wmi_daemon(args, kwargs)

    try_breakaway = _breakaway_allowed is not False
    merged = dict(kwargs)
    merged.update(daemon_popen_kwargs(breakaway=try_breakaway))
    try:
        proc = subprocess.Popen(args, **merged)
    except PermissionError:
        if not try_breakaway:
            # Already without breakaway — escape the job via WMI.
            _use_wmi_detach = True
            _breakaway_allowed = False
            return _spawn_wmi_daemon(args, kwargs)
        # Parent job forbids CREATE_BREAKAWAY_FROM_JOB — try WMI detach first
        # so children survive when the starter process/job exits.
        _breakaway_allowed = False
        _use_wmi_detach = True
        return _spawn_wmi_daemon(args, kwargs)
    else:
        if try_breakaway and _breakaway_allowed is None:
            _breakaway_allowed = True
    return proc


def _spawn_wmi_daemon(args: Sequence[str], kwargs: dict[str, Any]) -> _WmiProc:
    argv = [str(a) for a in args]
    log_path = _stdout_log_path(kwargs.get("stdout"))
    cwd = kwargs.get("cwd")
    # Close caller-owned log handle; WMI path appends via cmd redirection.
    for stream_key in ("stdout", "stderr", "stdin"):
        stream = kwargs.get(stream_key)
        if hasattr(stream, "close"):
            try:
                stream.close()
            except OSError:
                pass
    cmdline = _cmdline(argv)
    if cwd:
        # Run under cmd so we can cd + redirect.
        if log_path:
            inner = f"cd /d {_quote_win_arg(str(cwd))} && {cmdline} >> {_quote_win_arg(log_path)} 2>&1"
        else:
            inner = f"cd /d {_quote_win_arg(str(cwd))} && {cmdline}"
        cmdline = f"cmd.exe /c {inner}"
    elif log_path:
        cmdline = f"cmd.exe /c {cmdline} >> {_quote_win_arg(log_path)} 2>&1"
    pid = _wmi_create(cmdline)
    return _WmiProc(pid)
