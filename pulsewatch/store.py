from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_SITES = 25


class Store:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sites (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    paused INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1)),
                    last_check_at TEXT
                );
                CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                    checked_at TEXT NOT NULL,
                    success INTEGER NOT NULL CHECK (success IN (0, 1)),
                    status_code INTEGER,
                    response_time_ms REAL,
                    error TEXT,
                    final_url TEXT NOT NULL,
                    redirect_count INTEGER NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS checks_site_time
                    ON checks(site_id, checked_at DESC);
                """
            )

    def create_site(self, url: str) -> dict:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
            if count >= MAX_SITES:
                raise ValueError(f"This local MVP supports up to {MAX_SITES} websites.")
            site = {
                "id": str(uuid.uuid4()),
                "url": url,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            connection.execute(
                "INSERT INTO sites (id, url, created_at) VALUES (?, ?, ?)",
                (site["id"], site["url"], site["created_at"]),
            )
        return site

    def list_sites(self) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT s.*,
                       c.checked_at AS check_at,
                       c.success AS check_success,
                       c.status_code AS check_status,
                       c.response_time_ms AS check_response_time_ms,
                       c.error AS check_error,
                       c.final_url AS check_final_url,
                       c.redirect_count AS check_redirect_count,
                       c.details_json AS check_details_json
                FROM sites s
                LEFT JOIN checks c ON c.id = (
                    SELECT id FROM checks
                    WHERE site_id = s.id
                    ORDER BY checked_at DESC, id DESC LIMIT 1
                )
                ORDER BY s.created_at DESC
                """
            ).fetchall()
        sites = []
        for row in rows:
            site = {
                "id": row["id"],
                "url": row["url"],
                "created_at": row["created_at"],
                "paused": bool(row["paused"]),
                "last_check": None,
            }
            if row["check_at"] is not None:
                site["last_check"] = {
                    "checked_at": row["check_at"],
                    "success": bool(row["check_success"]),
                    "status_code": row["check_status"],
                    "response_time_ms": row["check_response_time_ms"],
                    "error": row["check_error"],
                    "final_url": row["check_final_url"],
                    "redirect_count": row["check_redirect_count"],
                    **json.loads(row["check_details_json"]),
                }
            sites.append(site)
        return sites

    def get_site(self, site_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sites WHERE id = ?", (site_id,)
            ).fetchone()
        return dict(row) if row else None

    def due_sites(self, interval_seconds: int) -> list[dict]:
        due_before = (
            datetime.now(timezone.utc) - timedelta(seconds=interval_seconds)
        ).isoformat()
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, url FROM sites
                WHERE paused = 0
                  AND (last_check_at IS NULL OR last_check_at <= ?)
                ORDER BY COALESCE(last_check_at, created_at), created_at
                """,
                (due_before,),
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_check(self, site_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT checked_at, success FROM checks
                WHERE site_id = ? ORDER BY checked_at DESC, id DESC LIMIT 1
                """,
                (site_id,),
            ).fetchone()
        return dict(row) if row else None

    def record_check(self, site_id: str, result: dict, serialized_details: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO checks (
                    site_id, checked_at, success, status_code, response_time_ms,
                    error, final_url, redirect_count, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    site_id,
                    result["checked_at"],
                    int(result["success"]),
                    result["status_code"],
                    result["response_time_ms"],
                    result["error"],
                    result["final_url"],
                    result["redirect_count"],
                    serialized_details,
                ),
            )
            connection.execute(
                "UPDATE sites SET last_check_at = ? WHERE id = ?",
                (result["checked_at"], site_id),
            )

    def list_checks(self, site_id: str, limit: int = 100) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT checked_at, success, status_code, response_time_ms, error,
                       final_url, redirect_count, details_json
                FROM checks WHERE site_id = ?
                ORDER BY checked_at DESC, id DESC LIMIT ?
                """,
                (site_id, limit),
            ).fetchall()
        return [
            {
                "checked_at": row["checked_at"],
                "success": bool(row["success"]),
                "status_code": row["status_code"],
                "response_time_ms": row["response_time_ms"],
                "error": row["error"],
                "final_url": row["final_url"],
                "redirect_count": row["redirect_count"],
                **json.loads(row["details_json"]),
            }
            for row in rows
        ]

    def set_paused(self, site_id: str, paused: bool) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE sites SET paused = ? WHERE id = ?",
                (int(paused), site_id),
            )
        return cursor.rowcount > 0

    def delete_site(self, site_id: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM sites WHERE id = ?", (site_id,))
        return cursor.rowcount > 0
