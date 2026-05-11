"""
VulnIntel — Database Manager
CRUD operations for all tables.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Optional, Dict, Any


class DatabaseManager:
    """Manages all database CRUD operations."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    # ─── CVE Operations ──────────────────────────────────────────────────────

    def upsert_cve(self, cve_data: Dict[str, Any]) -> int:
        """Insert or update a CVE record. Returns the row id."""
        cursor = self.conn.execute(
            """INSERT INTO cves (cve_id, description, cvss_score, cvss_vector, severity,
                                 affected_products, affected_versions, published_date,
                                 last_modified, source, exploit_maturity, has_public_exploit,
                                 patch_available, patch_url, raw_data, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(cve_id) DO UPDATE SET
                   description = excluded.description,
                   cvss_score = excluded.cvss_score,
                   cvss_vector = excluded.cvss_vector,
                   severity = excluded.severity,
                   affected_products = excluded.affected_products,
                   affected_versions = excluded.affected_versions,
                   last_modified = excluded.last_modified,
                   source = excluded.source,
                   exploit_maturity = excluded.exploit_maturity,
                   has_public_exploit = excluded.has_public_exploit,
                   patch_available = excluded.patch_available,
                   patch_url = excluded.patch_url,
                   raw_data = excluded.raw_data,
                   updated_at = datetime('now')
            """,
            (
                cve_data.get("cve_id", ""),
                cve_data.get("description", ""),
                cve_data.get("cvss_score", 0.0),
                cve_data.get("cvss_vector", ""),
                cve_data.get("severity", "NONE"),
                json.dumps(cve_data.get("affected_products", [])),
                json.dumps(cve_data.get("affected_versions", [])),
                cve_data.get("published_date", ""),
                cve_data.get("last_modified", ""),
                cve_data.get("source", ""),
                cve_data.get("exploit_maturity", "none"),
                1 if cve_data.get("has_public_exploit") else 0,
                1 if cve_data.get("patch_available") else 0,
                cve_data.get("patch_url", ""),
                json.dumps(cve_data.get("raw_data", {})),
            )
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a single CVE by its ID."""
        row = self.conn.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        return dict(row) if row else None

    def search_cves(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search CVEs by ID or description text."""
        rows = self.conn.execute(
            """SELECT * FROM cves
               WHERE cve_id LIKE ? OR description LIKE ?
               ORDER BY cvss_score DESC, published_date DESC
               LIMIT ?""",
            (f"%{query}%", f"%{query}%", limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_cves(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get most recently added/updated CVEs."""
        rows = self.conn.execute(
            "SELECT * FROM cves ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_cves_by_severity(self, severity: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Filter CVEs by severity level."""
        rows = self.conn.execute(
            "SELECT * FROM cves WHERE severity = ? ORDER BY cvss_score DESC LIMIT ?",
            (severity.upper(), limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_cves_with_exploits(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get CVEs that have known public exploits."""
        rows = self.conn.execute(
            "SELECT * FROM cves WHERE has_public_exploit = 1 ORDER BY cvss_score DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_cves(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Get all CVEs."""
        rows = self.conn.execute(
            "SELECT * FROM cves ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── Exploit Operations ──────────────────────────────────────────────────

    def add_exploit(self, exploit_data: Dict[str, Any]) -> int:
        """Add an exploit record."""
        # Check for duplicate
        existing = self.conn.execute(
            "SELECT id FROM exploits WHERE cve_id = ? AND exploit_url = ?",
            (exploit_data.get("cve_id", ""), exploit_data.get("exploit_url", ""))
        ).fetchone()
        if existing:
            return existing["id"]

        cursor = self.conn.execute(
            """INSERT INTO exploits (cve_id, exploit_title, exploit_source, exploit_url,
                                     exploit_type, platform, description, safe_for_lab,
                                     lab_workflow, raw_content)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                exploit_data.get("cve_id", ""),
                exploit_data.get("exploit_title", ""),
                exploit_data.get("exploit_source", ""),
                exploit_data.get("exploit_url", ""),
                exploit_data.get("exploit_type", ""),
                exploit_data.get("platform", ""),
                exploit_data.get("description", ""),
                1 if exploit_data.get("safe_for_lab") else 0,
                json.dumps(exploit_data.get("lab_workflow", {})),
                exploit_data.get("raw_content", ""),
            )
        )
        self.conn.commit()

        # Update CVE exploit status
        self.conn.execute(
            "UPDATE cves SET has_public_exploit = 1, exploit_maturity = 'poc', updated_at = datetime('now') WHERE cve_id = ?",
            (exploit_data.get("cve_id", ""),)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_exploits_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get all exploits associated with a CVE."""
        rows = self.conn.execute(
            "SELECT * FROM exploits WHERE cve_id = ? ORDER BY discovered_at DESC", (cve_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_exploits(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all exploits."""
        rows = self.conn.execute(
            "SELECT * FROM exploits ORDER BY discovered_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_exploit_lab_safe(self, exploit_id: int, safe: bool):
        """Mark an exploit as safe/unsafe for lab testing."""
        self.conn.execute(
            "UPDATE exploits SET safe_for_lab = ? WHERE id = ?",
            (1 if safe else 0, exploit_id)
        )
        self.conn.commit()

    # ─── Lab Results Operations ──────────────────────────────────────────────

    def add_lab_result(self, result_data: Dict[str, Any]) -> int:
        """Record a lab validation result."""
        cursor = self.conn.execute(
            """INSERT INTO lab_results (cve_id, exploit_id, lab_target, lab_environment,
                                        status, output_log, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                result_data.get("cve_id", ""),
                result_data.get("exploit_id"),
                result_data.get("lab_target", ""),
                result_data.get("lab_environment", ""),
                result_data.get("status", "pending"),
                result_data.get("output_log", ""),
                result_data.get("notes", ""),
            )
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_lab_results(self, cve_id: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get lab results, optionally filtered by CVE."""
        if cve_id:
            rows = self.conn.execute(
                "SELECT * FROM lab_results WHERE cve_id = ? ORDER BY validated_at DESC LIMIT ?",
                (cve_id, limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM lab_results ORDER BY validated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ─── Reference Operations ────────────────────────────────────────────────

    def add_reference(self, ref_data: Dict[str, Any]) -> int:
        """Add a reference link for a CVE."""
        # Avoid duplicates
        existing = self.conn.execute(
            "SELECT id FROM refs WHERE cve_id = ? AND ref_url = ?",
            (ref_data.get("cve_id", ""), ref_data.get("ref_url", ""))
        ).fetchone()
        if existing:
            return existing["id"]

        cursor = self.conn.execute(
            """INSERT INTO refs (cve_id, ref_type, ref_url, ref_source, title)
               VALUES (?, ?, ?, ?, ?)""",
            (
                ref_data.get("cve_id", ""),
                ref_data.get("ref_type", ""),
                ref_data.get("ref_url", ""),
                ref_data.get("ref_source", ""),
                ref_data.get("title", ""),
            )
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_references(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get all references for a CVE."""
        rows = self.conn.execute(
            "SELECT * FROM refs WHERE cve_id = ? ORDER BY added_at DESC", (cve_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── Detection Operations ────────────────────────────────────────────────

    def add_detection(self, detection_data: Dict[str, Any]) -> int:
        """Add a detection rule."""
        cursor = self.conn.execute(
            """INSERT INTO detections (cve_id, detection_type, rule_name, rule_content, confidence)
               VALUES (?, ?, ?, ?, ?)""",
            (
                detection_data.get("cve_id", ""),
                detection_data.get("detection_type", ""),
                detection_data.get("rule_name", ""),
                detection_data.get("rule_content", ""),
                detection_data.get("confidence", "medium"),
            )
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_detections_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get all detection rules for a CVE."""
        rows = self.conn.execute(
            "SELECT * FROM detections WHERE cve_id = ? ORDER BY generated_at DESC", (cve_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all detection rules."""
        rows = self.conn.execute(
            "SELECT * FROM detections ORDER BY generated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── Lab Targets Operations ──────────────────────────────────────────────

    def add_lab_target(self, target_data: Dict[str, Any]) -> int:
        """Register a lab target."""
        cursor = self.conn.execute(
            """INSERT INTO lab_targets (name, ip_address, target_type, os_info, description)
               VALUES (?, ?, ?, ?, ?)""",
            (
                target_data.get("name", ""),
                target_data.get("ip_address", ""),
                target_data.get("target_type", ""),
                target_data.get("os_info", ""),
                target_data.get("description", ""),
            )
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_lab_targets(self) -> List[Dict[str, Any]]:
        """Get all registered lab targets."""
        rows = self.conn.execute(
            "SELECT * FROM lab_targets WHERE is_active = 1 ORDER BY name"
        ).fetchall()
        return [dict(r) for r in rows]

    def remove_lab_target(self, target_id: int):
        """Soft-delete a lab target."""
        self.conn.execute(
            "UPDATE lab_targets SET is_active = 0 WHERE id = ?", (target_id,)
        )
        self.conn.commit()

    # ─── Dashboard Statistics ────────────────────────────────────────────────

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get aggregated statistics for the dashboard."""
        stats = {}
        stats["total_cves"] = self.conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        stats["critical_cves"] = self.conn.execute(
            "SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL'"
        ).fetchone()[0]
        stats["high_cves"] = self.conn.execute(
            "SELECT COUNT(*) FROM cves WHERE severity = 'HIGH'"
        ).fetchone()[0]
        stats["medium_cves"] = self.conn.execute(
            "SELECT COUNT(*) FROM cves WHERE severity = 'MEDIUM'"
        ).fetchone()[0]
        stats["low_cves"] = self.conn.execute(
            "SELECT COUNT(*) FROM cves WHERE severity = 'LOW'"
        ).fetchone()[0]
        stats["with_exploits"] = self.conn.execute(
            "SELECT COUNT(*) FROM cves WHERE has_public_exploit = 1"
        ).fetchone()[0]
        stats["total_exploits"] = self.conn.execute("SELECT COUNT(*) FROM exploits").fetchone()[0]
        stats["total_detections"] = self.conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        stats["lab_tests"] = self.conn.execute("SELECT COUNT(*) FROM lab_results").fetchone()[0]
        stats["lab_success"] = self.conn.execute(
            "SELECT COUNT(*) FROM lab_results WHERE status = 'success'"
        ).fetchone()[0]
        stats["total_references"] = self.conn.execute("SELECT COUNT(*) FROM refs").fetchone()[0]
        stats["lab_targets"] = self.conn.execute(
            "SELECT COUNT(*) FROM lab_targets WHERE is_active = 1"
        ).fetchone()[0]
        return stats
