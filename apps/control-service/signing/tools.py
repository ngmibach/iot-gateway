"""Detect platform signing CLI tools (osslsigncode / signtool / gpg)."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Optional


class SigningToolMissing(RuntimeError):
    """Raised when a required signing CLI is not on PATH."""


@dataclass(frozen=True)
class SigningTools:
    osslsigncode: Optional[str]
    signtool: Optional[str]
    gpg: Optional[str]

    @property
    def windows_ready(self) -> bool:
        return bool(self.osslsigncode or self.signtool)

    @property
    def linux_ready(self) -> bool:
        return bool(self.gpg)

    def missing_for(self, platform: str) -> list[str]:
        """Human-readable list of missing tools for a target platform."""
        plat = platform.lower().strip()
        missing: list[str] = []
        if plat == "windows":
            if not self.osslsigncode and not self.signtool:
                missing.append(
                    "osslsigncode or signtool (install osslsigncode, or "
                    "Windows SDK signtool on PATH)"
                )
        elif plat in ("linux", "ubuntu"):
            if not self.gpg:
                missing.append("gpg or gpg2 (install gnupg)")
        else:
            missing.append(f"unknown platform {platform!r}")
        return missing

    def as_dict(self) -> dict[str, object]:
        return {
            "osslsigncode": self.osslsigncode,
            "signtool": self.signtool,
            "gpg": self.gpg,
            "windows_ready": self.windows_ready,
            "linux_ready": self.linux_ready,
        }


def detect_signing_tools() -> SigningTools:
    return SigningTools(
        osslsigncode=shutil.which("osslsigncode"),
        signtool=shutil.which("signtool"),
        gpg=shutil.which("gpg") or shutil.which("gpg2"),
    )
