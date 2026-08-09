"""Repository selection. SQLite overlay by default; PostgreSQL when DATABASE_URL is set."""
from __future__ import annotations

import threading

from ..config import get_settings
from .base import Repository

_repo: Repository | None = None
_lock = threading.Lock()


def get_repository() -> Repository:
    global _repo
    if _repo is not None:
        return _repo
    with _lock:
        if _repo is None:
            settings = get_settings()
            if settings.database_url:
                from .postgres_repo import PostgresRepository
                _repo = PostgresRepository(settings.database_url)
            else:
                from .sqlite_repo import SQLiteRepository
                _repo = SQLiteRepository(settings.overlay_db_path)
    return _repo


def reset_repository() -> None:
    """Test hook only."""
    global _repo
    with _lock:
        _repo = None
