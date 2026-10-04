"""Admin code-signing API (K16) — Authenticode / GPG via signing module."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from registry.registry import Registry
from signing.service import SignRequest, SigningIdentity, list_signable_artifacts, sign_artifacts
from signing.tools import detect_signing_tools

from .deps import get_registry, require_token
from .schemas import (
    ListArtifactsRequest,
    SignArtifactsRequest,
    SignArtifactsResponse,
    SigningToolsOut,
)

router = APIRouter(dependencies=[Depends(require_token)])


@router.get("/admin/signing/tools", response_model=SigningToolsOut)
def get_signing_tools() -> SigningToolsOut:
    t = detect_signing_tools()
    return SigningToolsOut(**t.as_dict())  # type: ignore[arg-type]


@router.post("/admin/signing/list-artifacts")
def list_artifacts(body: ListArtifactsRequest) -> dict[str, Any]:
    try:
        items = list_signable_artifacts(body.folder)  # type: ignore[arg-type]
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    return {"artifacts": items}


@router.post("/admin/signing/sign", response_model=SignArtifactsResponse)
def sign(
    body: SignArtifactsRequest,
    registry: Registry = Depends(get_registry),
) -> SignArtifactsResponse:
    identity = SigningIdentity(
        platform=body.platform if body.platform in ("windows", "linux", "auto") else "auto",  # type: ignore[arg-type]
        pfx_path=body.pfx_path,
        pfx_passphrase=body.pfx_passphrase,
        thumbprint=body.thumbprint,
        gpg_key_id=body.gpg_key_id,
        gpg_passphrase=body.gpg_passphrase,
    )
    result = sign_artifacts(
        SignRequest(
            artifacts=list(body.artifacts),
            identity=identity,
            export_dir=body.export_dir,
            actor=body.actor,
        )
    )
    # audit_log: who/when/what/thumbprint — never passphrases or key material
    audit_row = registry.audit(
        "code_sign" if result.ok else "code_sign_failed",
        actor=body.actor,
        detail=result.audit_detail,
    )
    return SignArtifactsResponse(
        ok=result.ok,
        signed_paths=result.signed_paths,
        source_paths=result.source_paths,
        checksums_path=result.checksums_path,
        export_dir=result.export_dir,
        tool_used=result.tool_used,
        identity_fingerprint=result.identity_fingerprint,
        error=result.error,
        audit_id=audit_row.get("id"),
    )
