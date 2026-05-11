"""
VulnIntel — Sploitus Source Integration
Searches Sploitus for exploit and vulnerability data via web scraping.
"""

import requests
import time
import re
import logging
from typing import List, Optional, Dict, Any
from bs4 import BeautifulSoup

from sources.base_source import VulnSource
from config import SPLOITUS_SEARCH_URL, SPLOITUS_REQUEST_DELAY

logger = logging.getLogger(__name__)


class SploitusSource(VulnSource):
    """Sploitus web scraper integration."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self._last_request = 0

    @property
    def source_name(self) -> str:
        return "sploitus"

    def _throttle(self):
        elapsed = time.time() - self._last_request
        if elapsed < SPLOITUS_REQUEST_DELAY:
            time.sleep(SPLOITUS_REQUEST_DELAY - elapsed)
        self._last_request = time.time()

    def fetch_recent(self, days_back: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        return self.search("cve", limit=limit)

    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        self._throttle()
        try:
            # Sploitus JSON API (POST)
            search_url = "https://sploitus.com/search"
            payload = {
                "type": "exploits",
                "sort": "default",
                "query": query,
                "title": False,
                "offset": 0,
            }
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            }
            response = self.session.post(search_url, json=payload, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                exploits_data = data.get("exploits", [])
                results = []
                for item in exploits_data[:limit]:
                    exploit = self._parse_json_item(item, query)
                    if exploit:
                        results.append(exploit)
                logger.info(f"Sploitus: Found {len(results)} results for '{query}'")
                return results
            return []
        except Exception as e:
            logger.error(f"Sploitus search failed: {e}")
            return []

    def _parse_json_item(self, item: Dict, query: str) -> Optional[Dict[str, Any]]:
        """Parse a Sploitus JSON API result item."""
        try:
            title = item.get("title", "") or ""
            href = item.get("href", "") or ""
            source = item.get("source", "") or ""
            
            if not href.startswith("http"):
                href = f"https://sploitus.com/?query={query}#exploits"

            text = f"{title} {href} {source}"
            cve_ids = re.findall(r'CVE-\d{4}-\d+', text)
            cve_id = cve_ids[0] if cve_ids else (query if query.upper().startswith("CVE-") else "UNKNOWN")
            if not title and not href:
                return None
            return {
                "cve_id": cve_id,
                "exploit_title": title,
                "exploit_source": "sploitus",
                "exploit_url": href,
                "exploit_type": "unknown",
                "platform": "multi",
                "description": title,
                "safe_for_lab": False,
                "lab_workflow": {},
                "raw_content": str(item),
            }
        except Exception:
            return None

    def get_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        results = self.search(cve_id, limit=1)
        return results[0] if results else None

    def _parse_card(self, card, query: str) -> Optional[Dict[str, Any]]:
        try:
            # Extract title
            title_elem = card.find(["h4", "h3", "h5", "a", "strong"])
            title = title_elem.get_text(strip=True) if title_elem else ""
            if not title:
                title = card.get_text(strip=True)[:100]
            # Extract URL
            link = card.find("a", href=True)
            url = link["href"] if link else ""
            if url and not url.startswith("http"):
                url = f"https://sploitus.com{url}"
            # Extract CVE IDs from text
            text = card.get_text()
            cve_ids = re.findall(r'CVE-\d{4}-\d+', text)
            cve_id = cve_ids[0] if cve_ids else query if query.upper().startswith("CVE-") else "UNKNOWN"

            if not title and not url:
                return None
            return {
                "cve_id": cve_id,
                "exploit_title": title,
                "exploit_source": "sploitus",
                "exploit_url": url,
                "exploit_type": "unknown",
                "platform": "multi",
                "description": title,
                "safe_for_lab": False,
                "lab_workflow": {},
                "raw_content": str(card),
            }
        except Exception:
            return None
