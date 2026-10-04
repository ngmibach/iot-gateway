"""Product binary code-signing helpers (K16).

CI may build unsigned artifacts; an admin signs them here for distribution.
Never log passphrases or private-key material.
"""

from .linux import sign_gpg_detach
from .service import (
    SignRequest,
    SignResult,
    SigningIdentity,
    list_signable_artifacts,
    sign_artifacts,
    write_sha256sums,
)
from .tools import SigningToolMissing, SigningTools, detect_signing_tools
from .windows import sign_authenticode

__all__ = [
    "SignRequest",
    "SignResult",
    "SigningIdentity",
    "SigningToolMissing",
    "SigningTools",
    "detect_signing_tools",
    "list_signable_artifacts",
    "sign_artifacts",
    "sign_authenticode",
    "sign_gpg_detach",
    "write_sha256sums",
]
