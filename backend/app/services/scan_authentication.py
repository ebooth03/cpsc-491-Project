"""Authenticate API callers before accepting scan submissions."""

import hashlib
import hmac
import json
import os
import re

from fastapi import HTTPException, Request


def require_scan_requester(request: Request) -> str | None:
    raw = os.environ.get("SCANNER_AUTH_PRINCIPALS")
    if raw is None:
        return None

    try:
        principals = json.loads(raw)
        if not isinstance(principals, dict) or not principals:
            raise ValueError
        for digest, principal in principals.items():
            if (
                re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or not isinstance(principal, dict)
                or not isinstance(principal.get("id"), str)
                or not principal["id"].strip()
                or type(principal.get("can_scan")) is not bool
            ):
                raise ValueError
    except ValueError:
        raise HTTPException(
            status_code=503, detail="Scan authentication is unavailable."
        ) from None

    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() == "bearer" and token and not any(c.isspace() for c in token):
        presented_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        for digest, principal in principals.items():
            if hmac.compare_digest(presented_digest, digest):
                if not principal["can_scan"]:
                    raise HTTPException(status_code=403, detail="Scan permission required.")
                return principal["id"]

    raise HTTPException(
        status_code=401,
        detail="Valid scan credentials are required.",
        headers={"WWW-Authenticate": "Bearer"},
    )
