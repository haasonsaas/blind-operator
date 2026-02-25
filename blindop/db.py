from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .errors import NotFoundError
from .policy import Label, join
from .util import utc_now_iso


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cases (
          case_id TEXT PRIMARY KEY,
          name TEXT,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blobs (
          sha256 TEXT PRIMARY KEY,
          size_bytes INTEGER NOT NULL,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artifacts (
          handle TEXT PRIMARY KEY,
          case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
          blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
          orig_filename TEXT,
          size_bytes INTEGER NOT NULL,
          ingested_at TEXT NOT NULL,
          label TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tags (
          tag TEXT PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS artifact_tags (
          handle TEXT NOT NULL REFERENCES artifacts(handle) ON DELETE CASCADE,
          tag TEXT NOT NULL REFERENCES tags(tag) ON DELETE CASCADE,
          PRIMARY KEY (handle, tag)
        );

        CREATE TABLE IF NOT EXISTS events (
          event_id TEXT PRIMARY KEY,
          case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
          handle TEXT REFERENCES artifacts(handle) ON DELETE SET NULL,
          ts TEXT NOT NULL,
          kind TEXT NOT NULL,
          details_json TEXT
        );

        CREATE TABLE IF NOT EXISTS rulepacks (
          rulepack_id TEXT PRIMARY KEY,
          name TEXT,
          sha256 TEXT NOT NULL,
          created_at TEXT NOT NULL,
          rules_json TEXT NOT NULL
        );
        """
    )
    conn.commit()


def case_create(conn: sqlite3.Connection, case_id: str, name: Optional[str]) -> Dict[str, Any]:
    created_at = utc_now_iso()
    conn.execute(
        "INSERT INTO cases(case_id, name, created_at) VALUES(?, ?, ?)",
        (case_id, name, created_at),
    )
    conn.commit()
    return {"case_id": case_id, "name": name, "created_at": created_at}


def case_list(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    rows = conn.execute("SELECT case_id, name, created_at FROM cases ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def _ensure_case(conn: sqlite3.Connection, case_id: str) -> None:
    row = conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"case not found: {case_id}")


def blob_upsert(conn: sqlite3.Connection, sha256: str, size_bytes: int) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO blobs(sha256, size_bytes, created_at) VALUES(?, ?, ?)",
        (sha256, size_bytes, utc_now_iso()),
    )
    conn.commit()


def artifact_insert(
    conn: sqlite3.Connection,
    *,
    handle: str,
    case_id: str,
    blob_sha256: str,
    orig_filename: Optional[str],
    size_bytes: int,
    label: Label,
) -> Dict[str, Any]:
    _ensure_case(conn, case_id)
    ingested_at = utc_now_iso()
    conn.execute(
        """
        INSERT INTO artifacts(handle, case_id, blob_sha256, orig_filename, size_bytes, ingested_at, label)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (handle, case_id, blob_sha256, orig_filename, size_bytes, ingested_at, label.value),
    )
    conn.commit()
    return {
        "handle": handle,
        "case_id": case_id,
        "blob_sha256": blob_sha256,
        "orig_filename": orig_filename,
        "size_bytes": size_bytes,
        "ingested_at": ingested_at,
        "label": label.value,
    }


def artifact_get(conn: sqlite3.Connection, handle: str) -> Dict[str, Any]:
    row = conn.execute(
        "SELECT handle, case_id, blob_sha256, orig_filename, size_bytes, ingested_at, label FROM artifacts WHERE handle = ?",
        (handle,),
    ).fetchone()
    if row is None:
        raise NotFoundError(f"artifact not found: {handle}")
    art = dict(row)
    art["tags"] = artifact_tags(conn, handle)
    return art


def artifact_list(conn: sqlite3.Connection, case_id: str) -> List[Dict[str, Any]]:
    _ensure_case(conn, case_id)
    rows = conn.execute(
        """
        SELECT handle, case_id, blob_sha256, orig_filename, size_bytes, ingested_at, label
        FROM artifacts
        WHERE case_id = ?
        ORDER BY ingested_at DESC
        """,
        (case_id,),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["tags"] = artifact_tags(conn, d["handle"])
        out.append(d)
    return out


def artifact_move(conn: sqlite3.Connection, handle: str, new_case_id: str) -> Dict[str, Any]:
    _ensure_case(conn, new_case_id)
    row = conn.execute("SELECT case_id FROM artifacts WHERE handle = ?", (handle,)).fetchone()
    if row is None:
        raise NotFoundError(f"artifact not found: {handle}")
    old_case_id = row["case_id"]
    conn.execute("UPDATE artifacts SET case_id = ? WHERE handle = ?", (new_case_id, handle))
    conn.commit()
    return {"handle": handle, "from_case_id": old_case_id, "to_case_id": new_case_id}


def artifact_tags(conn: sqlite3.Connection, handle: str) -> List[str]:
    rows = conn.execute(
        "SELECT tag FROM artifact_tags WHERE handle = ? ORDER BY tag ASC",
        (handle,),
    ).fetchall()
    return [r["tag"] for r in rows]


def tag_add(conn: sqlite3.Connection, handle: str, tag: str) -> Dict[str, Any]:
    conn.execute("INSERT OR IGNORE INTO tags(tag) VALUES(?)", (tag,))
    updated = conn.execute(
        "INSERT OR IGNORE INTO artifact_tags(handle, tag) VALUES(?, ?)",
        (handle, tag),
    ).rowcount
    conn.commit()
    return {"handle": handle, "tag": tag, "added": bool(updated)}


def tag_remove(conn: sqlite3.Connection, handle: str, tag: str) -> Dict[str, Any]:
    deleted = conn.execute(
        "DELETE FROM artifact_tags WHERE handle = ? AND tag = ?",
        (handle, tag),
    ).rowcount
    conn.commit()
    return {"handle": handle, "tag": tag, "removed": bool(deleted)}


def dedupe_by_sha256(conn: sqlite3.Connection, case_id: str) -> Dict[str, List[str]]:
    _ensure_case(conn, case_id)
    rows = conn.execute(
        "SELECT blob_sha256, handle FROM artifacts WHERE case_id = ? ORDER BY blob_sha256, handle",
        (case_id,),
    ).fetchall()
    groups: Dict[str, List[str]] = {}
    for r in rows:
        groups.setdefault(r["blob_sha256"], []).append(r["handle"])
    return groups


def event_insert(
    conn: sqlite3.Connection,
    *,
    event_id: str,
    case_id: str,
    ts: str,
    kind: str,
    handle: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    _ensure_case(conn, case_id)
    details_json = json.dumps(details, separators=(",", ":"), sort_keys=True) if details else None
    conn.execute(
        "INSERT INTO events(event_id, case_id, handle, ts, kind, details_json) VALUES(?, ?, ?, ?, ?, ?)",
        (event_id, case_id, handle, ts, kind, details_json),
    )
    conn.commit()
    return {
        "event_id": event_id,
        "case_id": case_id,
        "handle": handle,
        "ts": ts,
        "kind": kind,
        "details": details or {},
    }


def event_list(conn: sqlite3.Connection, case_id: str, *, limit: int = 200) -> List[Dict[str, Any]]:
    _ensure_case(conn, case_id)
    rows = conn.execute(
        """
        SELECT event_id, case_id, handle, ts, kind, details_json
        FROM events
        WHERE case_id = ?
        ORDER BY ts ASC
        LIMIT ?
        """,
        (case_id, limit),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d.pop("details_json") or "{}")
        out.append(d)
    return out


def artifact_label(conn: sqlite3.Connection, handle: str) -> Label:
    row = conn.execute("SELECT label FROM artifacts WHERE handle = ?", (handle,)).fetchone()
    if row is None:
        raise NotFoundError(f"artifact not found: {handle}")
    return Label(row["label"])


def case_label(conn: sqlite3.Connection, case_id: str) -> Label:
    _ensure_case(conn, case_id)
    rows = conn.execute("SELECT label FROM artifacts WHERE case_id = ?", (case_id,)).fetchall()
    if not rows:
        return Label.public
    return join(Label(r["label"]) for r in rows)


def artifact_case_id(conn: sqlite3.Connection, handle: str) -> str:
    row = conn.execute("SELECT case_id FROM artifacts WHERE handle = ?", (handle,)).fetchone()
    if row is None:
        raise NotFoundError(f"artifact not found: {handle}")
    return str(row["case_id"])


def event_count(conn: sqlite3.Connection, case_id: str, *, kind: str) -> int:
    _ensure_case(conn, case_id)
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM events WHERE case_id = ? AND kind = ?",
        (case_id, kind),
    ).fetchone()
    return int(row["n"]) if row is not None else 0


def rulepack_insert(
    conn: sqlite3.Connection,
    *,
    rulepack_id: str,
    name: Optional[str],
    sha256: str,
    rules_json: str,
) -> Dict[str, Any]:
    created_at = utc_now_iso()
    conn.execute(
        "INSERT INTO rulepacks(rulepack_id, name, sha256, created_at, rules_json) VALUES(?, ?, ?, ?, ?)",
        (rulepack_id, name, sha256, created_at, rules_json),
    )
    conn.commit()
    return {
        "rulepack_id": rulepack_id,
        "name": name,
        "sha256": sha256,
        "created_at": created_at,
    }


def rulepack_get(conn: sqlite3.Connection, rulepack_id: str) -> Dict[str, Any]:
    row = conn.execute(
        "SELECT rulepack_id, name, sha256, created_at, rules_json FROM rulepacks WHERE rulepack_id = ?",
        (rulepack_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError(f"rulepack not found: {rulepack_id}")
    d = dict(row)
    d["rules"] = json.loads(d.pop("rules_json"))
    return d


def rulepack_list(conn: sqlite3.Connection, *, limit: int = 200) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT rulepack_id, name, sha256, created_at, rules_json FROM rulepacks ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        rules = json.loads(d.pop("rules_json"))
        d["rule_count"] = len(rules.get("rules", []) if isinstance(rules, dict) else [])
        out.append(d)
    return out
