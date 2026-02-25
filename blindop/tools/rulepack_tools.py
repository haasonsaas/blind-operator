from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import db
from ..errors import ToolInputError
from ..util import new_id, utc_now_iso
from ..vault import BlobStore


_FLAG_MAP = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
}

_RE_RULE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def register(
    conn: sqlite3.Connection,
    *,
    rules_path: Path,
    name: Optional[str] = None,
    max_rules: int = 500,
    max_regex_len: int = 512,
) -> Dict[str, Any]:
    raw = json.loads(rules_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ToolInputError("rulepack must be a JSON object")
    rules = raw.get("rules")
    if not isinstance(rules, list):
        raise ToolInputError("rulepack 'rules' must be a list")
    if len(rules) > max_rules:
        raise ToolInputError(f"rulepack too large (max_rules={max_rules})")

    sanitized: List[Dict[str, Any]] = []
    for r in rules:
        if not isinstance(r, dict):
            raise ToolInputError("rulepack rules must be objects")
        rid = r.get("id")
        regex = r.get("regex")
        if not isinstance(rid, str) or not _RE_RULE_ID.match(rid):
            raise ToolInputError("invalid rule id")
        if not isinstance(regex, str) or len(regex) == 0 or len(regex) > max_regex_len:
            raise ToolInputError("invalid rule regex")

        flags_in = r.get("flags", []) or []
        if not isinstance(flags_in, list) or not all(isinstance(f, (str, int)) for f in flags_in):
            raise ToolInputError("invalid rule flags")

        flags: List[str] = []
        for f in flags_in:
            fs = str(f)
            if fs not in _FLAG_MAP:
                raise ToolInputError("unsupported rule flag")
            flags.append(fs)

        # Validate regex compiles.
        re.compile(regex, flags=_flags_to_re(flags))

        rule_obj: Dict[str, Any] = {"id": rid, "regex": regex}
        if flags:
            rule_obj["flags"] = sorted(set(flags))
        sanitized.append(rule_obj)

    rules_doc = {"rules": sanitized}
    rules_json = json.dumps(rules_doc, separators=(",", ":"), sort_keys=True)
    sha256 = hashlib.sha256(rules_json.encode("utf-8")).hexdigest()
    rulepack_id = new_id()
    rec = db.rulepack_insert(conn, rulepack_id=rulepack_id, name=name, sha256=sha256, rules_json=rules_json)
    rec["rule_count"] = len(sanitized)
    return rec


def list_(conn: sqlite3.Connection, *, limit: int = 200) -> List[Dict[str, Any]]:
    return db.rulepack_list(conn, limit=limit)


def _flags_to_re(flags: List[str]) -> int:
    out = 0
    for f in flags:
        out |= _FLAG_MAP.get(f, 0)
    return out


def scan(
    conn: sqlite3.Connection,
    *,
    blob_store: BlobStore,
    handle: str,
    rulepack_id: str,
    max_scan_bytes: int = 5 * 1024 * 1024,
) -> Dict[str, Any]:
    art = db.artifact_get(conn, handle)
    blob_path = blob_store.get_path(art["blob_sha256"])
    content = blob_path.read_bytes()[:max_scan_bytes].decode("utf-8", errors="ignore")

    rp = db.rulepack_get(conn, rulepack_id)
    raw = rp.get("rules")
    rules = raw.get("rules", []) if isinstance(raw, dict) else []
    matched: List[str] = []
    for rule in rules:
        rid = rule.get("id")
        regex = rule.get("regex")
        if not rid or not regex:
            continue
        flags_list = [str(f) for f in (rule.get("flags", []) or [])]
        flags = _flags_to_re(flags_list)
        try:
            pat = re.compile(regex, flags=flags)
        except re.error:
            continue
        if pat.search(content):
            matched.append(str(rid))

    matched = sorted(set(matched))
    db.event_insert(
        conn,
        event_id=new_id(),
        case_id=art["case_id"],
        handle=handle,
        ts=utc_now_iso(),
        kind="rulepack_scanned",
        details={
            "rulepack_id": rulepack_id,
            "matched_rule_ids": matched,
            "matched_count": len(matched),
        },
    )
    return {
        "handle": handle,
        "rulepack_id": rulepack_id,
        "matched_rule_ids": matched,
        "matched_count": len(matched),
        "scanned_bytes": min(blob_path.stat().st_size, max_scan_bytes),
    }
