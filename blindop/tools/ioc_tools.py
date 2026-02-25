from __future__ import annotations

import hashlib
import hmac
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .. import db
from ..util import new_id, utc_now_iso
from ..vault import BlobStore


_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
_RE_URL = re.compile(r"\bhttps?://[^\s\"'<>]+\b")
_RE_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _hmac_sha256_hex(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode("utf-8", errors="strict"), hashlib.sha256).hexdigest()


def extract(
    conn: sqlite3.Connection,
    *,
    blob_store: BlobStore,
    hmac_key: bytes,
    handle: str,
    include_hashes: bool = False,
    top: int = 20,
    max_scan_bytes: int = 5 * 1024 * 1024,
) -> Dict[str, Any]:
    art = db.artifact_get(conn, handle)
    blob_path = blob_store.get_path(art["blob_sha256"])
    text = blob_path.read_bytes()[:max_scan_bytes].decode("utf-8", errors="ignore")

    ipv4 = _RE_IPV4.findall(text)
    emails = [e.lower() for e in _RE_EMAIL.findall(text)]
    urls = [u.lower() for u in _RE_URL.findall(text)]
    domains = [d.lower() for d in _RE_DOMAIN.findall(text) if d not in ipv4]
    md5s = [h.lower() for h in _RE_MD5.findall(text)]
    sha1s = [h.lower() for h in _RE_SHA1.findall(text)]
    sha256s = [h.lower() for h in _RE_SHA256.findall(text)]

    counts = {
        "ipv4": len(ipv4),
        "email": len(emails),
        "url": len(urls),
        "domain": len(domains),
        "md5": len(md5s),
        "sha1": len(sha1s),
        "sha256": len(sha256s),
    }

    out: Dict[str, Any] = {
        "handle": handle,
        "counts": counts,
        "scanned_bytes": min(blob_path.stat().st_size, max_scan_bytes),
    }

    if include_hashes:
        out["hmac_sha256_top"] = {
            "ipv4": _top_hmac(ipv4, hmac_key, top),
            "email": _top_hmac(emails, hmac_key, top),
            "url": _top_hmac(urls, hmac_key, top),
            "domain": _top_hmac(domains, hmac_key, top),
            "md5": _top_hmac(md5s, hmac_key, top),
            "sha1": _top_hmac(sha1s, hmac_key, top),
            "sha256": _top_hmac(sha256s, hmac_key, top),
        }

    db.event_insert(
        conn,
        event_id=new_id(),
        case_id=art["case_id"],
        handle=handle,
        ts=utc_now_iso(),
        kind="iocs_extracted",
        details={"counts": counts},
    )
    return out


def _top_hmac(values: List[str], key: bytes, top: int) -> List[Dict[str, Any]]:
    freq: Dict[str, int] = {}
    for v in values:
        hv = _hmac_sha256_hex(key, v)
        freq[hv] = freq.get(hv, 0) + 1
    items = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[: max(0, top)]
    return [{"hmac_sha256": h, "count": c} for h, c in items]
