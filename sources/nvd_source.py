"""
VulnIntel — NVD Source Integration
Fetches vulnerability data from the NIST National Vulnerability Database API 2.0.
"""

import requests
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from sources.base_source import VulnSource
from config import NVD_API_BASE, NVD_API_KEY, NVD_RATE_LIMIT_NO_KEY, NVD_RATE_LIMIT_WITH_KEY, NVD_RATE_WINDOW

logger = logging.getLogger(__name__)


class NVDSource(VulnSource):
    """NVD API 2.0 integration for CVE data."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or NVD_API_KEY
        self.base_url = NVD_API_BASE
        self._last_request_time = 0
        self._request_count = 0

    @property
    def source_name(self) -> str:
        return "nvd"

    def _rate_limit(self):
        """Enforce NVD rate limiting."""
        now = time.time()
        limit = NVD_RATE_LIMIT_WITH_KEY if self.api_key else NVD_RATE_LIMIT_NO_KEY

        if now - self._last_request_time < NVD_RATE_WINDOW:
            self._request_count += 1
            if self._request_count >= limit:
                sleep_time = NVD_RATE_WINDOW - (now - self._last_request_time) + 1
                logger.info(f"NVD rate limit reached, sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)
                self._request_count = 0
                self._last_request_time = time.time()
        else:
            self._request_count = 0
            self._last_request_time = now

    def _make_request(self, params: Dict[str, Any]) -> Optional[Dict]:
        """Make a rate-limited request to NVD API."""
        self._rate_limit()

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = requests.get(self.base_url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return None

    def fetch_recent(self, days_back: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recently published CVEs from NVD."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days_back)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(limit, 100),
        }

        data = self._make_request(params)
        if not data:
            return []

        results = []
        for vuln in data.get("vulnerabilities", [])[:limit]:
            cve = vuln.get("cve", {})
            normalized = self._normalize_nvd_cve(cve)
            if normalized:
                results.append(normalized)

        logger.info(f"NVD: Fetched {len(results)} CVEs from last {days_back} days")
        return results

    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search NVD by keyword or CVE ID."""
        params = {"resultsPerPage": min(limit, 100)}

        if query.upper().startswith("CVE-"):
            params["cveId"] = query.upper()
        else:
            params["keywordSearch"] = query

        data = self._make_request(params)
        if not data:
            return []

        results = []
        for vuln in data.get("vulnerabilities", [])[:limit]:
            cve = vuln.get("cve", {})
            normalized = self._normalize_nvd_cve(cve)
            if normalized:
                results.append(normalized)

        return results

    def get_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed info for a specific CVE."""
        params = {"cveId": cve_id.upper()}
        data = self._make_request(params)
        if not data:
            return None

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        return self._normalize_nvd_cve(vulns[0].get("cve", {}))

    def _normalize_nvd_cve(self, cve: Dict) -> Optional[Dict[str, Any]]:
        """Normalize NVD CVE data to standard format."""
        if not cve:
            return None

        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Extract description (English preferred)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description:
            descs = cve.get("descriptions", [])
            description = descs[0].get("value", "") if descs else ""

        # Extract CVSS v3.1 metrics
        cvss_score = 0.0
        cvss_vector = ""
        severity = "NONE"
        metrics = cve.get("metrics", {})

        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = metric_list[0].get("baseSeverity",
                           cvss_data.get("baseSeverity", "NONE")).upper()
                break

        # Derive severity from score if not set
        if severity == "NONE" and cvss_score > 0:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        # Extract affected products from CPE configurations
        affected_products = []
        affected_versions = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if criteria:
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3] if len(parts) > 3 else ""
                            product = parts[4] if len(parts) > 4 else ""
                            version = parts[5] if len(parts) > 5 else "*"
                            product_str = f"{vendor}/{product}"
                            if product_str not in affected_products:
                                affected_products.append(product_str)
                            if version != "*":
                                ver_info = {
                                    "product": product_str,
                                    "version": version,
                                    "vulnerable": cpe_match.get("vulnerable", True),
                                }
                                start_inc = cpe_match.get("versionStartIncluding", "")
                                end_exc = cpe_match.get("versionEndExcluding", "")
                                end_inc = cpe_match.get("versionEndIncluding", "")
                                if start_inc:
                                    ver_info["from"] = start_inc
                                if end_exc:
                                    ver_info["before"] = end_exc
                                if end_inc:
                                    ver_info["through"] = end_inc
                                affected_versions.append(ver_info)

        # Extract references
        references = []
        has_exploit_ref = False
        patch_url = ""
        for ref in cve.get("references", []):
            ref_url = ref.get("url", "")
            ref_tags = ref.get("tags", [])
            ref_type = "advisory"
            if "Exploit" in ref_tags:
                ref_type = "exploit"
                has_exploit_ref = True
            elif "Patch" in ref_tags:
                ref_type = "patch"
                if not patch_url:
                    patch_url = ref_url
            elif "Vendor Advisory" in ref_tags:
                ref_type = "vendor_advisory"

            references.append({
                "ref_url": ref_url,
                "ref_type": ref_type,
                "ref_source": ref.get("source", "nvd"),
                "title": ref_url.split("/")[-1] if ref_url else "",
            })

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "affected_products": affected_products,
            "affected_versions": affected_versions,
            "published_date": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "source": "nvd",
            "exploit_maturity": "poc" if has_exploit_ref else "none",
            "has_public_exploit": has_exploit_ref,
            "patch_available": bool(patch_url),
            "patch_url": patch_url,
            "raw_data": cve,
            "references": references,
        }
