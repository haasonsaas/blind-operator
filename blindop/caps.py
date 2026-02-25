from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional, Sequence

from .errors import ToolInputError
from .policy import Label, parse_label
from .util import new_id


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    s = data.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode((s + pad).encode("ascii"))
    except Exception as e:
        raise ToolInputError("invalid base64") from e


def mint_token(
    key: bytes,
    *,
    tools: Sequence[str],
    resources: Sequence[Dict[str, Any]],
    max_label: Label,
    ttl_seconds: int = 3600,
    subject: str = "operator",
) -> str:
    now = int(time.time())
    exp = now + max(int(ttl_seconds), 0)
    claims: Dict[str, Any] = {
        "ver": 1,
        "cap_id": new_id(),
        "sub": str(subject),
        "iat": now,
        "exp": exp,
        "tools": sorted(set(str(t) for t in tools)),
        "resources": list(resources),
        "max_label": max_label.value,
        "aud": "blindop",
    }
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = _b64url_encode(payload)
    sig = hmac.new(key, payload, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"v1.{payload_b64}.{sig_b64}"


def verify_token(key: bytes, token: str, *, now: Optional[int] = None) -> Dict[str, Any]:
    tok = token.strip()
    parts = tok.split(".")
    if len(parts) != 3 or parts[0] != "v1":
        raise ToolInputError("invalid token format")

    payload_b64 = parts[1]
    sig_b64 = parts[2]
    payload = _b64url_decode(payload_b64)
    sig = _b64url_decode(sig_b64)

    expected = hmac.new(key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise ToolInputError("invalid token signature")

    try:
        claims = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise ToolInputError("invalid token payload") from e

    if not isinstance(claims, dict) or claims.get("ver") != 1:
        raise ToolInputError("invalid token claims")

    if claims.get("aud") != "blindop":
        raise ToolInputError("invalid token audience")

    if now is None:
        now = int(time.time())

    exp = claims.get("exp")
    if not isinstance(exp, int):
        raise ToolInputError("invalid token exp")
    if now > exp:
        raise ToolInputError("token expired")

    tools = claims.get("tools")
    if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
        raise ToolInputError("invalid token tools")

    resources = claims.get("resources")
    if not isinstance(resources, list) or not all(isinstance(r, dict) for r in resources):
        raise ToolInputError("invalid token resources")

    max_label_raw = claims.get("max_label")
    if not isinstance(max_label_raw, str):
        raise ToolInputError("invalid token max_label")
    try:
        _ = parse_label(max_label_raw)
    except Exception as e:
        raise ToolInputError("invalid token max_label") from e

    cap_id = claims.get("cap_id")
    if not isinstance(cap_id, str) or not cap_id:
        raise ToolInputError("invalid token cap_id")

    return claims
