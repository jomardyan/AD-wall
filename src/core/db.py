"""
src/core/db.py — SQLite persistence layer for AD-Wall Dashboard.
"""

import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_DB_PATH: str = ""

# ---------------------------------------------------------------------------
# Connection pool — reuse connections per-thread instead of opening a new one
# for every single database call.  WAL mode makes concurrent reads safe.
# ---------------------------------------------------------------------------
_pool: threading.local = threading.local()


def configure(db_path: str) -> None:
    global _DB_PATH
    _DB_PATH = db_path
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _connect() -> sqlite3.Connection:
    if not _DB_PATH:
        raise RuntimeError("db.py: call configure(db_path) before using the database")
    conn = getattr(_pool, "conn", None)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
            return conn
        except sqlite3.ProgrammingError:
            # Connection was closed — fall through and create a new one.
            pass
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-8000")  # 8 MB page cache
    _pool.conn = conn
    return conn


def init_db() -> None:
    conn = _connect()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            domain_controller TEXT,
            mode TEXT NOT NULL DEFAULT 'Assessment',
            modules TEXT,
            format TEXT,
            total_findings INTEGER NOT NULL DEFAULT 0,
            critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0,
            medium_count INTEGER NOT NULL DEFAULT 0,
            low_count INTEGER NOT NULL DEFAULT 0,
            info_count INTEGER NOT NULL DEFAULT 0,
            score REAL NOT NULL DEFAULT 0,
            grade TEXT NOT NULL DEFAULT 'N/A',
            output_path TEXT,
            parameters TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            rule_id TEXT,
            severity TEXT,
            category TEXT,
            title TEXT,
            description TEXT,
            remediation TEXT,
            mitre_attack TEXT,
            affected_count INTEGER NOT NULL DEFAULT 0,
            affected_objects TEXT,
            detected_at TEXT,
            verification_command TEXT,
            cis_control TEXT,
            nist_control TEXT,
            FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL DEFAULT 'INFO',
            message TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            format TEXT,
            file_path TEXT NOT NULL,
            generated_at TEXT,
            file_size INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
        );

        -- Performance indexes
        CREATE INDEX IF NOT EXISTS idx_findings_run_id   ON findings(run_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(run_id, severity);
        CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(run_id, category);
        CREATE INDEX IF NOT EXISTS idx_logs_run_id       ON logs(run_id, id);
        CREATE INDEX IF NOT EXISTS idx_reports_run_id    ON reports(run_id);
        CREATE INDEX IF NOT EXISTS idx_runs_status       ON runs(status, started_at DESC);
        """)


# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_run(run_id: str, params: dict) -> None:
    conn = _connect()
    with conn:
        conn.execute(
            """INSERT OR IGNORE INTO runs
               (id, started_at, status, domain_controller, mode, modules, format, output_path, parameters)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                run_id,
                _now_iso(),
                "running",
                params.get("domainController") or params.get("domain_controller"),
                params.get("mode", "Assessment"),
                json.dumps(params.get("modules") or []),
                json.dumps(params.get("format") or []),
                params.get("outputPath") or params.get("output_path"),
                json.dumps(params),
            ),
        )


def get_run(run_id: str) -> Optional[dict]:
    conn = _connect()
    row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    return dict(row) if row else None


def list_runs(limit: int = 100) -> list[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def complete_run(run_id: str, summary: dict) -> None:
    conn = _connect()
    with conn:
        conn.execute(
            """UPDATE runs SET
               status='completed', completed_at=?,
               total_findings=?, critical_count=?, high_count=?,
               medium_count=?, low_count=?, info_count=?,
               score=?, grade=?
               WHERE id=?""",
            (
                _now_iso(),
                summary.get("total_findings", 0),
                summary.get("critical_count", 0),
                summary.get("high_count", 0),
                summary.get("medium_count", 0),
                summary.get("low_count", 0),
                summary.get("info_count", 0),
                summary.get("score", 0),
                summary.get("grade", "N/A"),
                run_id,
            ),
        )


def fail_run(run_id: str, error: str) -> None:
    conn = _connect()
    with conn:
        conn.execute(
            "UPDATE runs SET status='failed', completed_at=? WHERE id=?",
            (_now_iso(), run_id),
        )
    add_log(run_id, f"FAILED: {error}", level="ERROR")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def save_findings(run_id: str, findings_list: list) -> None:
    conn = _connect()
    rows = []
    for f in findings_list:
        ao = f.get("AffectedObjects") or f.get("affected_objects")
        rows.append((
            run_id,
            f.get("RuleId") or f.get("rule_id"),
            f.get("Severity") or f.get("severity"),
            f.get("Category") or f.get("category"),
            f.get("Title") or f.get("title"),
            f.get("Description") or f.get("description"),
            f.get("Remediation") or f.get("remediation"),
            f.get("MitreAttack") or f.get("mitre_attack"),
            f.get("AffectedCount") or f.get("affected_count") or 0,
            json.dumps(ao) if ao is not None else None,
            f.get("DetectedAt") or f.get("detected_at"),
            f.get("VerificationCommand") or f.get("verification_command"),
            f.get("CISControl") or f.get("cis_control"),
            f.get("NISTControl") or f.get("nist_control"),
        ))
    with conn:
        conn.executemany(
            """INSERT INTO findings
               (run_id, rule_id, severity, category, title, description,
                remediation, mitre_attack, affected_count, affected_objects,
                detected_at, verification_command, cis_control, nist_control)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )


def get_findings(run_id: str, severity: str = None, category: str = None,
                 search: str = None) -> list[dict]:
    conn = _connect()
    sql = "SELECT * FROM findings WHERE run_id=?"
    params: list = [run_id]
    if severity:
        sql += " AND LOWER(severity)=LOWER(?)"
        params.append(severity)
    if category:
        sql += " AND LOWER(category)=LOWER(?)"
        params.append(category)
    if search:
        sql += " AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)"
        params += [f"%{search.lower()}%", f"%{search.lower()}%"]
    rows = conn.execute(sql, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("affected_objects"):
            try:
                d["affected_objects"] = json.loads(d["affected_objects"])
            except Exception:
                pass
        result.append(d)
    return result


def get_findings_api(run_id: str, severity: str = None, category: str = None,
                     search: str = None) -> list[dict]:
    """Return findings formatted as the existing /api/findings shape."""
    rows = get_findings(run_id, severity=severity, category=category, search=search)
    SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    rows.sort(key=lambda r: SEV_ORDER.get(r.get("severity", ""), 5))
    out = []
    for r in rows:
        ao = r.get("affected_objects")
        out.append({
            "RuleId":             r.get("rule_id"),
            "Severity":           r.get("severity"),
            "Category":           r.get("category"),
            "Title":              r.get("title"),
            "Description":        r.get("description"),
            "Remediation":        r.get("remediation"),
            "MitreAttack":        r.get("mitre_attack"),
            "AffectedCount":      r.get("affected_count", 0),
            "AffectedObjects":    ao if isinstance(ao, list) else [],
            "DetectedAt":         r.get("detected_at"),
            "VerificationCommand": r.get("verification_command"),
            "CISControl":         r.get("cis_control"),
            "NISTControl":        r.get("nist_control"),
        })
    return out


def get_severity_counts(run_id: str) -> dict:
    """Return {severity: count} using SQL aggregation instead of Python loops."""
    conn = _connect()
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM findings WHERE run_id=? GROUP BY severity",
        (run_id,),
    ).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}


def get_category_counts(run_id: str) -> dict:
    """Return {category: count} using SQL aggregation instead of Python loops."""
    conn = _connect()
    rows = conn.execute(
        "SELECT category, COUNT(*) as cnt FROM findings WHERE run_id=? GROUP BY category",
        (run_id,),
    ).fetchall()
    return {r["category"]: r["cnt"] for r in rows}


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

def add_log(run_id: str, message: str, level: str = "INFO") -> None:
    conn = _connect()
    with conn:
        conn.execute(
            "INSERT INTO logs (run_id, timestamp, level, message) VALUES (?,?,?,?)",
            (run_id, _now_iso(), level.upper(), message),
        )


def get_logs(run_id: str, since_id: int = 0) -> list[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM logs WHERE run_id=? AND id>? ORDER BY id ASC",
        (run_id, since_id),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def register_report(run_id: str, filename: str, fmt: str, file_path: str) -> None:
    size = 0
    try:
        size = os.path.getsize(file_path)
    except OSError:
        pass
    conn = _connect()
    with conn:
        conn.execute(
            """INSERT OR IGNORE INTO reports
               (run_id, filename, format, file_path, generated_at, file_size)
               VALUES (?,?,?,?,?,?)""",
            (run_id, filename, fmt, file_path, _now_iso(), size),
        )


def list_reports(run_id: str = None) -> list[dict]:
    conn = _connect()
    if run_id:
        rows = conn.execute(
            "SELECT * FROM reports WHERE run_id=? ORDER BY generated_at DESC", (run_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM reports ORDER BY generated_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Import existing JSON assessment
# ---------------------------------------------------------------------------

_FMT_EXTS = {
    ".html": "HTML", ".csv": "CSV", ".json": "JSON",
    ".md": "Markdown", ".cef": "CEF",
}


def import_json_assessment(json_path: str) -> str:
    """
    Import an ADWall_Assessment_*.json file into SQLite.
    Returns the run_id (re-uses existing if already imported).
    """
    base = os.path.basename(json_path)
    stem = re.sub(r"\.json$", "", base, flags=re.IGNORECASE)
    stem = re.sub(r"^ADWall_Assessment_", "", stem)
    run_id = "import-" + stem

    # Skip if already imported
    existing = get_run(run_id)
    if existing:
        return run_id

    with open(json_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    findings = data.get("Findings") or []
    grade_obj = data.get("PostureGrade") or {}
    grade = grade_obj.get("Grade", "N/A")
    score = float(grade_obj.get("Score", 0))

    sev_map = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = f.get("Severity", "")
        if sev in sev_map:
            sev_map[sev] += 1

    generated_at = data.get("GeneratedAt") or _now_iso()
    dc = data.get("DomainController") or data.get("Target")
    mode = data.get("Mode", "Assessment")

    conn = _connect()
    with conn:
        conn.execute(
            """INSERT OR IGNORE INTO runs
               (id, started_at, completed_at, status, domain_controller, mode,
                total_findings, critical_count, high_count, medium_count, low_count,
                info_count, score, grade, output_path, parameters)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run_id, generated_at, generated_at, "completed",
                dc, mode,
                len(findings),
                sev_map["Critical"], sev_map["High"], sev_map["Medium"],
                sev_map["Low"], sev_map["Informational"],
                score, grade,
                os.path.dirname(json_path),
                json.dumps({}),
            ),
        )

    if findings:
        save_findings(run_id, findings)

    # Register sibling report files
    base_stem = re.sub(r"\.json$", "", json_path, flags=re.IGNORECASE)
    for ext, fmt in _FMT_EXTS.items():
        candidate = base_stem + ext
        if os.path.isfile(candidate):
            register_report(run_id, os.path.basename(candidate), fmt, candidate)

    return run_id
