"""
VulnIntel — Base Source Abstract Class
Interface that all vulnerability sources must implement.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime


class VulnSource(ABC):
    """Abstract base class for vulnerability intelligence sources."""

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Human-readable name of the source."""
        pass

    @abstractmethod
    def fetch_recent(self, days_back: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Fetch recently published/modified CVEs.

        Args:
            days_back: Number of days to look back
            limit: Maximum number of results

        Returns:
            List of normalized CVE dictionaries
        """
        pass

    @abstractmethod
    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search for CVEs matching a query.

        Args:
            query: Search term (CVE ID, keyword, product name)
            limit: Maximum number of results

        Returns:
            List of normalized CVE dictionaries
        """
        pass

    @abstractmethod
    def get_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-3094)

        Returns:
            Normalized CVE dictionary or None
        """
        pass

    def normalize_cve(self, raw_data: Dict) -> Dict[str, Any]:
        """
        Normalize raw source data into standard CVE format.
        Subclasses should override this for source-specific normalization.
        """
        return {
            "cve_id": "",
            "description": "",
            "cvss_score": 0.0,
            "cvss_vector": "",
            "severity": "NONE",
            "affected_products": [],
            "affected_versions": [],
            "published_date": "",
            "last_modified": "",
            "source": self.source_name,
            "exploit_maturity": "none",
            "has_public_exploit": False,
            "patch_available": False,
            "patch_url": "",
            "raw_data": raw_data,
            "references": [],
        }
