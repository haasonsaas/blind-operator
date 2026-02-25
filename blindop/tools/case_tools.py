from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from .. import db
from ..util import new_id, utc_now_iso


def create(conn: sqlite3.Connection, *, name: Optional[str]) -> Dict[str, Any]:
    case_id = new_id()
    case = db.case_create(conn, case_id, name)
    db.event_insert(
        conn,
        event_id=new_id(),
        case_id=case_id,
        ts=utc_now_iso(),
        kind="case_created",
        details={"name": name} if name else {},
    )
    return case


def list_(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    return db.case_list(conn)
