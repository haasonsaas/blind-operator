from __future__ import annotations

import math
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import db
from ..policy import Label
from ..util import new_id, utc_now_iso
from ..vault import BlobStore


def ingest(
    conn: sqlite3.Connection,
    *,
    blob_store: BlobStore,
    case_id: str,
    src_path: Path,
    label: Label,
) -> Dict[str, Any]:
    put = blob_store.put_file(src_path)
    db.blob_upsert(conn, put.sha256, put.size_bytes)
    handle = new_id()
    art = db.artifact_insert(
        conn,
        handle=handle,
        case_id=case_id,
        blob_sha256=put.sha256,
        orig_filename=src_path.name,
        size_bytes=put.size_bytes,
        label=label,
    )
    db.event_insert(
        conn,
        event_id=new_id(),
        case_id=case_id,
        handle=handle,
        ts=utc_now_iso(),
        kind="artifact_ingested",
        details={"blob_sha256": put.sha256, "size_bytes": put.size_bytes, "stored": put.stored},
    )
    return art


def show(conn: sqlite3.Connection, *, handle: str) -> Dict[str, Any]:
    return db.artifact_get(conn, handle)


def list_(conn: sqlite3.Connection, *, case_id: str) -> List[Dict[str, Any]]:
    return db.artifact_list(conn, case_id)


def move(conn: sqlite3.Connection, *, handle: str, case_id: str) -> Dict[str, Any]:
    moved = db.artifact_move(conn, handle, case_id)
    db.event_insert(
        conn,
        event_id=new_id(),
        case_id=case_id,
        handle=handle,
        ts=utc_now_iso(),
        kind="artifact_moved",
        details={"from_case_id": moved["from_case_id"], "to_case_id": moved["to_case_id"]},
    )
    return moved


def dedupe(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    include_unique: bool = False,
) -> Dict[str, Any]:
    groups = db.dedupe_by_sha256(conn, case_id)
    out_groups = []
    total = 0
    for sha, handles in groups.items():
        total += len(handles)
        if not include_unique and len(handles) < 2:
            continue
        out_groups.append({"blob_sha256": sha, "count": len(handles), "handles": handles})
    out_groups.sort(key=lambda g: (-g["count"], g["blob_sha256"]))
    return {
        "case_id": case_id,
        "total_artifacts": total,
        "groups": out_groups,
        "group_count": len(out_groups),
    }


def _entropy_of_file(path: Path, *, max_bytes: int = 2 * 1024 * 1024) -> float:
    data = path.read_bytes()[:max_bytes]
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _looks_text(path: Path, *, sample_bytes: int = 8192) -> bool:
    data = path.read_bytes()[:sample_bytes]
    if not data:
        return True
    printable = 0
    for b in data:
        if b in (9, 10, 13):
            printable += 1
        elif 32 <= b <= 126:
            printable += 1
    return (printable / len(data)) >= 0.9


def diff(
    conn: sqlite3.Connection,
    *,
    blob_store: BlobStore,
    handle_a: str,
    handle_b: str,
) -> Dict[str, Any]:
    a = db.artifact_get(conn, handle_a)
    b = db.artifact_get(conn, handle_b)
    same = a["blob_sha256"] == b["blob_sha256"]
    pa = blob_store.get_path(a["blob_sha256"])
    pb = blob_store.get_path(b["blob_sha256"])
    ent_a = _entropy_of_file(pa)
    ent_b = _entropy_of_file(pb)
    text_a = _looks_text(pa)
    text_b = _looks_text(pb)

    size_a = int(a["size_bytes"])
    size_b = int(b["size_bytes"])
    return {
        "handle_a": handle_a,
        "handle_b": handle_b,
        "same_blob": same,
        "blob_sha256_a": a["blob_sha256"],
        "blob_sha256_b": b["blob_sha256"],
        "size_bytes_a": size_a,
        "size_bytes_b": size_b,
        "size_delta": size_b - size_a,
        "entropy_a": round(ent_a, 4),
        "entropy_b": round(ent_b, 4),
        "looks_text_a": text_a,
        "looks_text_b": text_b,
    }
