from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DEFAULT_STATE_DIRNAME = ".blindop"


@dataclass(frozen=True)
class StatePaths:
    root: Path
    db_path: Path
    blobs_dir: Path
    audit_log: Path
    key_path: Path


def resolve_state_dir(state_dir: Optional[str]) -> Path:
    if state_dir:
        return Path(state_dir).expanduser().resolve()
    return (Path.cwd() / DEFAULT_STATE_DIRNAME).resolve()


def ensure_state_paths(root: Path) -> StatePaths:
    root.mkdir(parents=True, exist_ok=True)
    blobs_dir = root / "blobs"
    blobs_dir.mkdir(parents=True, exist_ok=True)
    return StatePaths(
        root=root,
        db_path=root / "vault.sqlite3",
        blobs_dir=blobs_dir,
        audit_log=root / "audit.log",
        key_path=root / "hmac.key",
    )
