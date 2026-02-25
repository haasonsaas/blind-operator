from __future__ import annotations

import sqlite3
from typing import Any, Dict, List

from .. import db


def build(conn: sqlite3.Connection, *, case_id: str, limit: int = 200) -> Dict[str, Any]:
    events = db.event_list(conn, case_id, limit=limit)
    return {"case_id": case_id, "events": events, "event_count": len(events)}
