"""
Vexor Local Database — SQLite persistence
Scan sessions, findings, OSINT results survive app restarts
"""
import aiosqlite
import json
import datetime
from pathlib import Path
from vexor.config import HOME_DIR

DB_PATH = HOME_DIR / "vexor.db"


async def init_db() -> None:
    """Create tables if they don't exist"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT NOT NULL,
                scan_type   TEXT DEFAULT 'full',
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                total       INTEGER DEFAULT 0,
                critical    INTEGER DEFAULT 0,
                high        INTEGER DEFAULT 0,
                medium      INTEGER DEFAULT 0,
                low         INTEGER DEFAULT 0,
                info        INTEGER DEFAULT 0
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  INTEGER NOT NULL,
                severity    TEXT NOT NULL,
                module      TEXT NOT NULL,
                vuln        TEXT NOT NULL,
                endpoint    TEXT,
                param       TEXT,
                payload     TEXT,
                evidence    TEXT,
                description TEXT,
                remediation TEXT,
                cve         TEXT,
                created_at  TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS osint_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT NOT NULL,
                severity    TEXT NOT NULL,
                module      TEXT NOT NULL,
                vuln        TEXT NOT NULL,
                endpoint    TEXT,
                evidence    TEXT,
                created_at  TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT,
                title       TEXT NOT NULL,
                content     TEXT,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
        """)
        await db.commit()


async def create_session(target: str, scan_type: str = "full") -> int:
    """Create a new scan session, return session ID"""
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.datetime.now().isoformat()
        cursor = await db.execute(
            "INSERT INTO scan_sessions (target, scan_type, started_at) VALUES (?, ?, ?)",
            (target, scan_type, now)
        )
        await db.commit()
        return cursor.lastrowid


async def finish_session(session_id: int, counts: dict) -> None:
    """Mark session as finished with finding counts"""
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.datetime.now().isoformat()
        await db.execute("""
            UPDATE scan_sessions
            SET finished_at=?, total=?, critical=?, high=?, medium=?, low=?, info=?
            WHERE id=?
        """, (
            now,
            counts.get("total", 0),
            counts.get("CRITICAL", 0),
            counts.get("HIGH", 0),
            counts.get("MEDIUM", 0),
            counts.get("LOW", 0),
            counts.get("INFO", 0),
            session_id,
        ))
        await db.commit()


async def save_finding(session_id: int, finding) -> None:
    """Save a single finding to the database"""
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.datetime.now().isoformat()
        await db.execute("""
            INSERT INTO findings
            (session_id, severity, module, vuln, endpoint, param, payload,
             evidence, description, remediation, cve, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            getattr(finding, "severity", "INFO"),
            getattr(finding, "module", ""),
            getattr(finding, "vuln", ""),
            getattr(finding, "endpoint", ""),
            getattr(finding, "param", ""),
            getattr(finding, "payload", ""),
            getattr(finding, "evidence", ""),
            getattr(finding, "description", ""),
            getattr(finding, "remediation", ""),
            getattr(finding, "cve", ""),
            now,
        ))
        await db.commit()


async def save_finding_dict(session_id: int, f: dict) -> None:
    """Save a finding from dict (for OSINT module)"""
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.datetime.now().isoformat()
        await db.execute("""
            INSERT INTO findings
            (session_id, severity, module, vuln, endpoint, param, payload,
             evidence, description, remediation, cve, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            f.get("severity", "INFO"),
            f.get("module", ""),
            f.get("vuln", ""),
            f.get("endpoint", ""),
            f.get("param", ""),
            f.get("payload", ""),
            f.get("evidence", ""),
            f.get("description", ""),
            f.get("remediation", ""),
            f.get("cve", ""),
            now,
        ))
        await db.commit()


async def get_recent_sessions(limit: int = 20) -> list[dict]:
    """Get recent scan sessions"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT * FROM scan_sessions
            ORDER BY started_at DESC
            LIMIT ?
        """, (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def get_session_findings(session_id: int) -> list[dict]:
    """Get all findings for a session"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT * FROM findings
            WHERE session_id = ?
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH'     THEN 2
                    WHEN 'MEDIUM'   THEN 3
                    WHEN 'LOW'      THEN 4
                    ELSE 5
                END
        """, (session_id,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def get_all_findings(limit: int = 100) -> list[dict]:
    """Get recent findings across all sessions"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT f.*, s.target, s.started_at as session_date
            FROM findings f
            JOIN scan_sessions s ON f.session_id = s.id
            ORDER BY f.created_at DESC
            LIMIT ?
        """, (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def save_osint_result(target: str, result) -> None:
    """Save OSINT result"""
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.datetime.now().isoformat()
        await db.execute("""
            INSERT INTO osint_results
            (target, severity, module, vuln, endpoint, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            target,
            getattr(result, "severity", "INFO"),
            getattr(result, "module", ""),
            getattr(result, "vuln", ""),
            getattr(result, "endpoint", ""),
            getattr(result, "evidence", ""),
            now,
        ))
        await db.commit()


async def save_note(title: str, content: str, target: str = "") -> int:
    """Save a note"""
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.datetime.now().isoformat()
        cursor = await db.execute(
            "INSERT INTO notes (target, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (target, title, content, now, now)
        )
        await db.commit()
        return cursor.lastrowid


async def get_notes(target: str = "") -> list[dict]:
    """Get notes, optionally filtered by target"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if target:
            async with db.execute(
                "SELECT * FROM notes WHERE target=? ORDER BY updated_at DESC",
                (target,)
            ) as cursor:
                rows = await cursor.fetchall()
        else:
            async with db.execute(
                "SELECT * FROM notes ORDER BY updated_at DESC"
            ) as cursor:
                rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def update_note(note_id: int, title: str, content: str) -> None:
    """Update an existing note"""
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.datetime.now().isoformat()
        await db.execute(
            "UPDATE notes SET title=?, content=?, updated_at=? WHERE id=?",
            (title, content, now, note_id)
        )
        await db.commit()


async def delete_note(note_id: int) -> None:
    """Delete a note"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM notes WHERE id=?", (note_id,))
        await db.commit()


async def get_stats() -> dict:
    """Get overall statistics from database"""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM scan_sessions") as c:
            total_sessions = (await c.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM findings") as c:
            total_findings = (await c.fetchone())[0]
        async with db.execute(
            "SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'"
        ) as c:
            critical = (await c.fetchone())[0]
        async with db.execute(
            "SELECT COUNT(*) FROM findings WHERE severity='HIGH'"
        ) as c:
            high = (await c.fetchone())[0]
        return {
            "total_sessions": total_sessions,
            "total_findings": total_findings,
            "critical": critical,
            "high": high,
        }
