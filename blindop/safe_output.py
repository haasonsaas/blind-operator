from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Union

JsonValue = Union[None, bool, int, float, str, List["JsonValue"], Dict[str, "JsonValue"]]


@dataclass(frozen=True)
class SafeOutputBudget:
    max_depth: int = 10
    max_list_len: int = 200
    max_dict_keys: int = 200
    max_str_len: int = 256
    max_key_len: int = 64


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize(value: Any, budget: SafeOutputBudget = SafeOutputBudget(), _depth: int = 0) -> JsonValue:
    if _depth > budget.max_depth:
        return {"$redacted": "depth_exceeded"}

    if value is None or isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            return {"$redacted": "non_finite_float"}
        return value

    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        return {"$redacted": "bytes", "sha256": _sha256_hex(b), "len": len(b)}

    if isinstance(value, str):
        if len(value) <= budget.max_str_len:
            return value
        b = value.encode("utf-8", errors="replace")
        return {"$redacted": "string", "sha256": _sha256_hex(b), "len": len(value)}

    if isinstance(value, dict):
        items = list(value.items())
        out: Dict[str, JsonValue] = {}

        if len(items) > budget.max_dict_keys:
            items = items[: budget.max_dict_keys]
            out["$truncated_keys"] = len(value)

        for k, v in items:
            if not isinstance(k, str):
                k = str(k)
            if len(k) > budget.max_key_len:
                out[f"$redacted_key:{_sha256_hex(k.encode('utf-8', errors='replace'))}"] = sanitize(
                    v, budget, _depth=_depth + 1
                )
                continue
            out[k] = sanitize(v, budget, _depth=_depth + 1)
        return out

    if isinstance(value, (list, tuple, set)):
        seq = list(value)
        out_list: List[JsonValue] = []
        if len(seq) > budget.max_list_len:
            seq = seq[: budget.max_list_len]
            out_list.append({"$truncated_list": len(value)})
        out_list.extend(sanitize(v, budget, _depth=_depth + 1) for v in seq)
        return out_list

    raise TypeError(f"unsafe output type: {type(value).__name__}")
