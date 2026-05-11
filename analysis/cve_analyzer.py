"""
VulnIntel — CVE Analyzer
Cross-references CVE data across sources and provides enriched analysis.
"""

import logging
from typing import Dict, Any, List, Optional
from database.db_manager import DatabaseManager
from analysis.exploit_classifier import classify_exploit_maturity, calculate_risk_priority

logger = logging.getLogger(__name__)


class CVEAnalyzer:
    """Enriches and cross-references CVE data across multiple sources."""

    def __init__(self, db: DatabaseManager):
        self.db = db

    def enrich_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a CVE with cross-source data and computed fields."""
        cve_id = cve_data.get("cve_id", "")
        if not cve_id:
            return cve_data

        # Get existing exploits from DB
        exploits = self.db.get_exploits_for_cve(cve_id)

        # Classify exploit maturity
        cve_data["exploit_maturity"] = classify_exploit_maturity(cve_data, exploits)
        cve_data["has_public_exploit"] = len(exploits) > 0 or cve_data.get("has_public_exploit", False)
        cve_data["exploit_count"] = len(exploits)

        # Calculate risk priority
        cve_data["risk_priority"] = calculate_risk_priority(cve_data)

        # Get detection count
        detections = self.db.get_detections_for_cve(cve_id)
        cve_data["detection_count"] = len(detections)

        # Get lab results
        lab_results = self.db.get_lab_results(cve_id)
        cve_data["lab_test_count"] = len(lab_results)

        return cve_data

    def get_full_analysis(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a comprehensive analysis for a CVE."""
        cve = self.db.get_cve(cve_id)
        if not cve:
            return None

        exploits = self.db.get_exploits_for_cve(cve_id)
        references = self.db.get_references(cve_id)
        detections = self.db.get_detections_for_cve(cve_id)
        lab_results = self.db.get_lab_results(cve_id)

        return {
            "cve": self.enrich_cve(cve),
            "exploits": exploits,
            "references": references,
            "detections": detections,
            "lab_results": lab_results,
            "risk_priority": calculate_risk_priority(cve),
        }

    def store_source_results(self, results: List[Dict[str, Any]]):
        """Store fetched source results into the database."""
        for result in results:
            cve_id = result.get("cve_id", "")
            if not cve_id or cve_id == "UNKNOWN":
                continue
            # Upsert CVE
            self.db.upsert_cve(result)
            # Store references
            for ref in result.get("references", []):
                ref["cve_id"] = cve_id
                self.db.add_reference(ref)

    def store_exploit_results(self, exploits: List[Dict[str, Any]]):
        """Store discovered exploits into the database."""
        for exploit in exploits:
            cve_id = exploit.get("cve_id", "")
            if not cve_id or cve_id == "UNKNOWN":
                continue
            self.db.add_exploit(exploit)
