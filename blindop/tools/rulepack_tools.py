from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from .. import db
from ..util import new_id, utc_now_iso
from ..vault import BlobStore


_FLAG_MAP = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
}


def scan(
    conn: sqlite3.Connection,
    *,
    blob_store: BlobStore,
    handle: str,
    rules_path: Path,
    max_scan_bytes: int = 5 * 1024 * 1024,
) -> Dict[str, Any]:
    art = db.artifact_get(conn, handle)
    blob_path = blob_store.get_path(art["blob_sha256"])
    content = blob_path.read_bytes()[:max_scan_bytes].decode("utf-8", errors="ignore")

    raw = json.loads(rules_path.read_text(encoding="utf-8"))
    rules = raw.get("rules", [])
    matched: List[str] = []
    for rule in rules:
        rid = rule.get("id")
        regex = rule.get("regex")
        if not rid or not regex:
            continue
        flags = 0
        for f in rule.get("flags", []) or []:
            flags |= _FLAG_MAP.get(str(f), 0)
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
        details={"matched_rule_ids": matched, "matched_count": len(matched)},
    )
    return {
        "handle": handle,
        "matched_rule_ids": matched,
        "matched_count": len(matched),
        "scanned_bytes": min(blob_path.stat().st_size, max_scan_bytes),
    }
