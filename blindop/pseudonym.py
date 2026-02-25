from __future__ import annotations

import hashlib
import hmac


def hmac_sha256_hex(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def pseudonymize(key: bytes, *, namespace: str, value: str, prefix: str = "hmac256") -> str:
    digest = hmac_sha256_hex(key, f"{namespace}\0{value}")
    return f"{prefix}:{digest}"
