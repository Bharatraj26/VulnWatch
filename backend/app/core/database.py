"""
VulnWatch — SQLite Database Management
=======================================
Direct SQLite integration using Python standard library (sqlite3).
Zero external dependencies, local file or in-memory database.
"""

from __future__ import annotations

import sqlite3

from flask import Flask, current_app, g


def get_db() -> sqlite3.Connection:
    """
    Get or create an SQLite connection for the current application context.
    Configures Row factory to return dict-like rows, enables foreign keys,
    WAL journal mode for concurrency, and busy timeout.
    """
    if "db" not in g:
        db_path = current_app.config.get("DATABASE_PATH", "vulnwatch.db")
        g.db = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
            timeout=10.0,
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
        if db_path != ":memory:":
            try:
                g.db.execute("PRAGMA journal_mode = WAL;")
            except sqlite3.OperationalError:
                pass
        g.db.execute("PRAGMA busy_timeout = 5000;")
    return g.db


def close_db(error: BaseException | None = None) -> None:
    """Close the active database connection if open."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app: Flask) -> None:
    """
    Initialise the SQLite tables.
    Runs idempotently on application startup and migrates legacy schemas if needed.
    """
    with app.app_context():
        db = get_db()
        # Verify schema columns
        cursor = db.execute("PRAGMA table_info(scans);")
        columns = [row["name"] for row in cursor.fetchall()]
        if columns and "started_at" not in columns:
            db.execute("DROP TABLE IF EXISTS reports;")
            db.execute("DROP TABLE IF EXISTS findings;")
            db.execute("DROP TABLE IF EXISTS scans;")

        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration REAL,
                findings_count INTEGER DEFAULT 0,
                severity TEXT DEFAULT 'info',
                target_ip TEXT,
                http_status INTEGER,
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                type TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT,
                recommendation TEXT NOT NULL,
                location TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                security_score INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                summary TEXT NOT NULL,
                status TEXT DEFAULT 'ready',
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
            """
        )
        db.commit()
