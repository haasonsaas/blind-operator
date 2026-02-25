from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from .errors import NotFoundError
from .util import new_id


@dataclass(frozen=True)
class PutResult:
    sha256: str
    size_bytes: int
    stored: bool


class BlobStore:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def blob_path(self, sha256: str) -> Path:
        return self.root_dir / sha256

    def has(self, sha256: str) -> bool:
        return self.blob_path(sha256).exists()

    def get_path(self, sha256: str) -> Path:
        p = self.blob_path(sha256)
        if not p.exists():
            raise NotFoundError(f"blob not found: {sha256}")
        return p

    def put_file(self, src_path: Path, *, chunk_size: int = 1024 * 1024) -> PutResult:
        tmp_path = self.root_dir / f".tmp-{new_id()}"
        h = hashlib.sha256()
        size = 0

        with src_path.open("rb") as src, tmp_path.open("wb") as dst:
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
                dst.write(chunk)
                size += len(chunk)

        sha = h.hexdigest()
        final_path = self.blob_path(sha)
        if final_path.exists():
            tmp_path.unlink(missing_ok=True)
            return PutResult(sha256=sha, size_bytes=size, stored=False)

        os.replace(tmp_path, final_path)
        try:
            final_path.chmod(0o600)
        except OSError:
            pass
        return PutResult(sha256=sha, size_bytes=size, stored=True)
