"""
Local case history index.

Automates the manual "have we seen this sender/domain/hash before?" check an
analyst would otherwise do by digging through a spreadsheet or asking a
teammate. Stores only IOCs and verdicts (hashes, domains, URLs, scores) —
never the raw email content or attachments — so it stays lightweight and
doesn't turn into a second copy of sensitive mail data.
"""

import os
import json
import sqlite3
import logging
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from app.core.settings_manager import get_data_dir

logger = logging.getLogger("uvicorn")

DB_PATH = os.path.join(get_data_dir(), "case_history.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    subject TEXT,
    sender TEXT,
    sender_domain TEXT,
    verdict TEXT,
    total_score INTEGER,
    threat_type TEXT,
    threat_category TEXT,
    suspicious_domains TEXT,   -- JSON list
    extracted_urls TEXT,       -- JSON list
    ip_addresses TEXT,         -- JSON list
    file_hashes TEXT           -- JSON list of {filename, sha256}
);
CREATE INDEX IF NOT EXISTS idx_cases_sender_domain ON cases(sender_domain);
CREATE INDEX IF NOT EXISTS idx_cases_verdict ON cases(verdict);
"""


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def _extract_sender_domain(sender: str) -> str:
    if not sender or "@" not in sender:
        return ""
    at = sender.rfind("@")
    end = sender.find(">", at)
    if end == -1:
        end = len(sender)
    return sender[at + 1:end].strip().lower()


def record_case(analysis_result: Dict[str, Any]) -> Optional[int]:
    """
    Appends a row summarizing a completed analysis. Takes the same dict
    produced by AnalysisResult.model_dump() (what analyze_email_eel returns).
    Never stores email body/attachment content, only IOCs + verdict.
    """
    try:
        init_db()
        sender = analysis_result.get("sender", "")
        file_hashes = [
            {"filename": att.get("filename"), "sha256": att.get("sha256")}
            for att in analysis_result.get("attachments", [])
            if att.get("sha256")
        ]

        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subject": analysis_result.get("subject", ""),
            "sender": sender,
            "sender_domain": _extract_sender_domain(sender),
            "verdict": analysis_result.get("verdict", "Unknown"),
            "total_score": analysis_result.get("total_score", 0),
            "threat_type": analysis_result.get("threat_type", ""),
            "threat_category": analysis_result.get("threat_category", ""),
            "suspicious_domains": json.dumps(analysis_result.get("suspicious_domains", [])),
            "extracted_urls": json.dumps(analysis_result.get("extracted_urls", [])),
            "ip_addresses": json.dumps(list(analysis_result.get("ip_intel", {}).keys())),
            "file_hashes": json.dumps(file_hashes),
        }

        with _connect() as conn:
            cur = conn.execute(
                """INSERT INTO cases
                   (timestamp, subject, sender, sender_domain, verdict, total_score,
                    threat_type, threat_category, suspicious_domains, extracted_urls,
                    ip_addresses, file_hashes)
                   VALUES (:timestamp, :subject, :sender, :sender_domain, :verdict,
                           :total_score, :threat_type, :threat_category,
                           :suspicious_domains, :extracted_urls, :ip_addresses, :file_hashes)""",
                row,
            )
            return cur.lastrowid
    except Exception as e:
        logger.error(f"Failed to record case history: {e}")
        return None


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    for key in ("suspicious_domains", "extracted_urls", "ip_addresses", "file_hashes"):
        try:
            d[key] = json.loads(d[key]) if d.get(key) else []
        except (TypeError, json.JSONDecodeError):
            d[key] = []
    return d


def search_case_history(query: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Free-text search across sender, sender_domain, subject, and the JSON
    IOC blobs (domains/URLs/hashes) — covers "have we seen this before?"
    for a domain, sender, or file hash without needing a separate query type.
    """
    if not query or not query.strip():
        return get_recent_cases(limit)

    init_db()
    like = f"%{query.strip().lower()}%"
    with _connect() as conn:
        rows = conn.execute(
            """SELECT * FROM cases
               WHERE lower(sender) LIKE ?
                  OR lower(sender_domain) LIKE ?
                  OR lower(subject) LIKE ?
                  OR lower(suspicious_domains) LIKE ?
                  OR lower(extracted_urls) LIKE ?
                  OR lower(file_hashes) LIKE ?
               ORDER BY id DESC
               LIMIT ?""",
            (like, like, like, like, like, like, limit),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_recent_cases(limit: int = 20) -> List[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM cases ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def check_prior_sightings(sender_domain: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Quick lookup used to flag 'this domain has shown up before' during analysis."""
    if not sender_domain:
        return []
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """SELECT id, timestamp, subject, verdict, total_score
               FROM cases WHERE sender_domain = ? ORDER BY id DESC LIMIT ?""",
            (sender_domain.lower(), limit),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]
