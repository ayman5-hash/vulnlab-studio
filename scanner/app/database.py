import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "scanner.db"


def get_connection():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = get_connection()
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            mode TEXT NOT NULL,
            difficulty TEXT NOT NULL,
            status TEXT NOT NULL,
            modules_json TEXT NOT NULL,
            security_score INTEGER NOT NULL,
            finding_count INTEGER NOT NULL,
            crawl_json TEXT,
            detector_errors_json TEXT,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            vulnerability TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            parameter TEXT,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            cwe TEXT NOT NULL,
            evidence TEXT NOT NULL,
            detection_method TEXT NOT NULL,
            exploitation_performed INTEGER NOT NULL DEFAULT 0,
            recommendation TEXT NOT NULL,
            difficulty TEXT NOT NULL,
            assessment_mode TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
                ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS whitebox_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            file TEXT NOT NULL,
            pattern TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
                ON DELETE CASCADE
        )
    """)

    con.commit()
    con.close()


def save_scan(
    *,
    target,
    mode,
    difficulty,
    status,
    modules,
    security_score,
    crawl,
    findings,
    whitebox_hits,
    detector_errors,
):
    con = get_connection()
    cur = con.cursor()

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    cur.execute(
        """
        INSERT INTO scans (
            target,
            mode,
            difficulty,
            status,
            modules_json,
            security_score,
            finding_count,
            crawl_json,
            detector_errors_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target,
            mode,
            difficulty,
            status,
            json.dumps(modules),
            security_score,
            len(findings),
            json.dumps(crawl),
            json.dumps(detector_errors),
            created_at,
        ),
    )

    scan_id = cur.lastrowid

    for finding in findings:

        if hasattr(finding, "model_dump"):
            data = finding.model_dump()
        else:
            data = finding

        cur.execute(
            """
            INSERT INTO findings (
                scan_id,
                vulnerability,
                endpoint,
                parameter,
                severity,
                confidence,
                cwe,
                evidence,
                detection_method,
                exploitation_performed,
                recommendation,
                difficulty,
                assessment_mode
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                data["vulnerability"],
                data["endpoint"],
                data.get("parameter"),
                data["severity"],
                data["confidence"],
                data["cwe"],
                data["evidence"],
                data["detection_method"],
                int(
                    data.get(
                        "exploitation_performed",
                        False,
                    )
                ),
                data["recommendation"],
                data["difficulty"],
                data["assessment_mode"],
            ),
        )

    for hit in whitebox_hits:

        cur.execute(
            """
            INSERT INTO whitebox_hits (
                scan_id,
                category,
                file,
                pattern
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                scan_id,
                hit["category"],
                hit["file"],
                hit["pattern"],
            ),
        )

    con.commit()
    con.close()

    return scan_id


def list_scans(limit=50):
    con = get_connection()

    rows = con.execute(
        """
        SELECT
            id,
            target,
            mode,
            difficulty,
            status,
            security_score,
            finding_count,
            created_at
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    con.close()

    return [
        dict(row)
        for row in rows
    ]


def get_scan(scan_id: int):
    con = get_connection()

    scan_row = con.execute(
        """
        SELECT *
        FROM scans
        WHERE id = ?
        """,
        (scan_id,),
    ).fetchone()

    if not scan_row:
        con.close()
        return None

    finding_rows = con.execute(
        """
        SELECT *
        FROM findings
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (scan_id,),
    ).fetchall()

    whitebox_rows = con.execute(
        """
        SELECT *
        FROM whitebox_hits
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (scan_id,),
    ).fetchall()

    con.close()

    scan = dict(scan_row)

    scan["modules"] = json.loads(
        scan.pop("modules_json")
    )

    scan["crawl"] = json.loads(
        scan.pop("crawl_json")
        or "{}"
    )

    scan["detector_errors"] = json.loads(
        scan.pop("detector_errors_json")
        or "[]"
    )

    scan["findings"] = [
        {
            **dict(row),
            "exploitation_performed": bool(
                row["exploitation_performed"]
            ),
        }
        for row in finding_rows
    ]

    scan["whitebox_hits"] = [
        dict(row)
        for row in whitebox_rows
    ]

    return scan
