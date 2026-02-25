from __future__ import annotations

import sqlite3
from typing import Any, Dict

from .. import db
from ..util import new_id, utc_now_iso


def add(conn: sqlite3.Connection, *, handle: str, tag: str) -> Dict[str, Any]:
    # Ensure handle exists (foreign key errors are less clear)
    art = db.artifact_get(conn, handle)
    res = db.tag_add(conn, handle, tag)
    db.event_insert(
        conn,
        event_id=new_id(),
        case_id=art["case_id"],
        handle=handle,
        ts=utc_now_iso(),
        kind="tag_added",
        details={"tag": tag},
    )
    return res


def remove(conn: sqlite3.Connection, *, handle: str, tag: str) -> Dict[str, Any]:
    art = db.artifact_get(conn, handle)
    res = db.tag_remove(conn, handle, tag)
    db.event_insert(
        conn,
        event_id=new_id(),
        case_id=art["case_id"],
        handle=handle,
        ts=utc_now_iso(),
        kind="tag_removed",
        details={"tag": tag},
    )
    return res
