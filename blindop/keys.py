from __future__ import annotations

import os
import secrets
from pathlib import Path


def load_or_create_hmac_key(key_path: Path, *, env_var: str = "BLINDOP_HMAC_KEY") -> bytes:
    env = os.getenv(env_var)
    if env:
        v = env.strip()
        if all(c in "0123456789abcdefABCDEF" for c in v) and len(v) % 2 == 0:
            return bytes.fromhex(v)
        return v.encode("utf-8", errors="strict")

    if key_path.exists():
        return key_path.read_bytes()

    key = secrets.token_bytes(32)
    key_path.write_bytes(key)
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    return key
