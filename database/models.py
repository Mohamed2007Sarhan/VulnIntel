"""
VulnIntel — Database Models & Schema
Defines the SQLite schema and initialization logic.
"""

import sqlite3
import os

SCHEMA_SQL = """
-- ─── CVE Tracking ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,
    description TEXT,
    cvss_score REAL DEFAULT 0.0,
    cvss_vector TEXT DEFAULT '',
    severity TEXT DEFAULT 'NONE',
    affected_products TEXT DEFAULT '[]',
    affected_versions TEXT DEFAULT '[]',
    published_date TEXT DEFAULT '',
    last_modified TEXT DEFAULT '',
    source TEXT DEFAULT '',
    exploit_maturity TEXT DEFAULT 'none',
    has_public_exploit INTEGER DEFAULT 0,
    patch_available INTEGER DEFAULT 0,
    patch_url TEXT DEFAULT '',
    raw_data TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- ─── Exploit Tracking ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS exploits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    exploit_title TEXT DEFAULT '',
    exploit_source TEXT DEFAULT '',
    exploit_url TEXT DEFAULT '',
    exploit_type TEXT DEFAULT '',
    platform TEXT DEFAULT '',
    description TEXT DEFAULT '',
    safe_for_lab INTEGER DEFAULT 0,
    lab_workflow TEXT DEFAULT '{}',
    raw_content TEXT DEFAULT '',
    discovered_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

-- ─── Lab Validation Results ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lab_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    exploit_id INTEGER,
    lab_target TEXT DEFAULT '',
    lab_environment TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    output_log TEXT DEFAULT '',
    validated_at TEXT DEFAULT (datetime('now')),
    notes TEXT DEFAULT '',
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
    FOREIGN KEY (exploit_id) REFERENCES exploits(id) ON DELETE SET NULL
);

-- ─── References ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    ref_type TEXT DEFAULT '',
    ref_url TEXT DEFAULT '',
    ref_source TEXT DEFAULT '',
    title TEXT DEFAULT '',
    added_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

-- ─── Detection Rules ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    detection_type TEXT DEFAULT '',
    rule_name TEXT DEFAULT '',
    rule_content TEXT DEFAULT '',
    confidence TEXT DEFAULT 'medium',
    generated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

-- ─── Lab Targets Registry ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lab_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_address TEXT DEFAULT '',
    target_type TEXT DEFAULT '',
    os_info TEXT DEFAULT '',
    description TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1,
    added_at TEXT DEFAULT (datetime('now'))
);

-- ─── Indexes ─────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date);
CREATE INDEX IF NOT EXISTS idx_cves_exploit_maturity ON cves(exploit_maturity);
CREATE INDEX IF NOT EXISTS idx_exploits_cve_id ON exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_lab_results_cve_id ON lab_results(cve_id);
CREATE INDEX IF NOT EXISTS idx_refs_cve_id ON refs(cve_id);
CREATE INDEX IF NOT EXISTS idx_detections_cve_id ON detections(cve_id);
"""


def init_database(db_path: str) -> sqlite3.Connection:
    """Initialize the database and create tables if they don't exist."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    return conn
