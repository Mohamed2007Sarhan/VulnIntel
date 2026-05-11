"""
VulnIntel — GitHub Security Advisories Source
Fetches vulnerability data from GitHub's Security Advisory database.
"""

import requests
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from sources.base_source import VulnSource
from config import GITHUB_ADVISORIES_API, GITHUB_PAT

logger = logging.getLogger(__name__)


class GitHubAdvisoriesSource(VulnSource):
    """GitHub Security Advisories REST API integration."""

    def __init__(self, pat: str = ""):
        self.pat = pat or GITHUB_PAT
        self.base_url = GITHUB_ADVISORIES_API

    @property
    def source_name(self) -> str:
        return "github"

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.pat:
            headers["Authorization"] = f"Bearer {self.pat}"
        return headers

    def _make_request(self, params: Dict[str, Any] = None) -> Optional[List[Dict]]:
        """Make a request to GitHub Advisories API."""
        try:
            response = requests.get(
                self.base_url,
                headers=self._get_headers(),
                params=params or {},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"GitHub Advisories API request failed: {e}")
            return None

    def fetch_recent(self, days_back: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recently published GitHub security advisories."""
        since_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")

        params = {
            "type": "reviewed",
            "per_page": min(limit, 100),
            "sort": "published",
            "direction": "desc",
        }

        data = self._make_request(params)
        if not data:
            return []

        results = []
        for advisory in data[:limit]:
            # Filter by date
            published = advisory.get("published_at", "")
            if published and published < since_date:
                continue
            normalized = self._normalize_advisory(advisory)
            if normalized:
                results.append(normalized)

        logger.info(f"GitHub: Fetched {len(results)} advisories from last {days_back} days")
        return results

    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search GitHub advisories."""
        params = {
            "type": "reviewed",
            "per_page": min(limit, 100),
        }

        # If it looks like a CVE ID, use the cve_id filter
        if query.upper().startswith("CVE-"):
            params["cve_id"] = query.upper()
        else:
            # GitHub advisories API doesn't have a keyword search param
            # We fetch recent and filter locally
            params["per_page"] = 100

        data = self._make_request(params)
        if not data:
            return []

        results = []
        for advisory in data:
            normalized = self._normalize_advisory(advisory)
            if normalized:
                # If keyword search, filter by description/title match
                if not query.upper().startswith("CVE-"):
                    search_lower = query.lower()
                    title = (normalized.get("description", "") or "").lower()
                    cve_id = (normalized.get("cve_id", "") or "").lower()
                    if search_lower not in title and search_lower not in cve_id:
                        continue
                results.append(normalized)
                if len(results) >= limit:
                    break

        return results

    def get_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific CVE from GitHub advisories."""
        results = self.search(cve_id, limit=1)
        return results[0] if results else None

    def _normalize_advisory(self, advisory: Dict) -> Optional[Dict[str, Any]]:
        """Normalize GitHub advisory to standard CVE format."""
        if not advisory:
            return None

        # Extract CVE ID from identifiers
        cve_id = ""
        ghsa_id = advisory.get("ghsa_id", "")
        for identifier in advisory.get("identifiers", []):
            if identifier.get("type") == "CVE":
                cve_id = identifier.get("value", "")
                break
        # Also check cve_id field directly
        if not cve_id:
            cve_id = advisory.get("cve_id", "")
        if not cve_id:
            cve_id = ghsa_id  # Use GHSA ID as fallback

        if not cve_id:
            return None

        # Severity mapping
        severity_str = (advisory.get("severity", "") or "").upper()
        severity_map = {
            "CRITICAL": ("CRITICAL", 9.5),
            "HIGH": ("HIGH", 7.5),
            "MODERATE": ("MEDIUM", 5.5),
            "MEDIUM": ("MEDIUM", 5.5),
            "LOW": ("LOW", 2.5),
        }
        severity, default_score = severity_map.get(severity_str, ("NONE", 0.0))

        # CVSS
        cvss = advisory.get("cvss", {}) or {}
        cvss_score = cvss.get("score", default_score) or default_score
        cvss_vector = cvss.get("vector_string", "")

        # Affected products
        affected_products = []
        affected_versions = []
        for vuln in advisory.get("vulnerabilities", []):
            pkg = vuln.get("package", {}) or {}
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            if name:
                product_str = f"{ecosystem}/{name}" if ecosystem else name
                if product_str not in affected_products:
                    affected_products.append(product_str)

            vuln_range = vuln.get("vulnerable_version_range", "")
            patched = vuln.get("first_patched_version", "")
            if vuln_range:
                affected_versions.append({
                    "product": product_str if name else "",
                    "range": vuln_range,
                    "patched": patched,
                })

        # References
        references = []
        for ref in advisory.get("references", []):
            references.append({
                "ref_url": ref,
                "ref_type": "advisory",
                "ref_source": "github",
                "title": ref.split("/")[-1] if ref else "",
            })

        # Description
        description = advisory.get("summary", "") or advisory.get("description", "")

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "affected_products": affected_products,
            "affected_versions": affected_versions,
            "published_date": advisory.get("published_at", ""),
            "last_modified": advisory.get("updated_at", ""),
            "source": "github",
            "exploit_maturity": "none",
            "has_public_exploit": False,
            "patch_available": any(v.get("patched") for v in affected_versions),
            "patch_url": "",
            "raw_data": advisory,
            "references": references,
            "ghsa_id": ghsa_id,
        }
