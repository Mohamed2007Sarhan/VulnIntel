"""
VulnIntel — IOC Generator
Extracts and structures Indicators of Compromise from CVE/exploit data.
"""

import re
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List


def generate_ioc_summary(cve: Dict[str, Any], references: List[Dict] = None,
                          exploits: List[Dict] = None) -> Dict[str, Any]:
    """Generate a structured IOC summary from CVE data."""
    cve_id = cve.get("cve_id", "")
    all_text = _gather_text(cve, references, exploits)

    iocs = {
        "cve_id": cve_id,
        "generated_at": datetime.now().isoformat(),
        "ipv4_addresses": _extract_ipv4(all_text),
        "domains": _extract_domains(all_text),
        "urls": _extract_urls(all_text),
        "file_hashes": _extract_hashes(all_text),
        "email_addresses": _extract_emails(all_text),
        "cve_references": [cve_id] if cve_id else [],
    }

    # STIX 2.1 compatible indicators
    iocs["stix_indicators"] = _build_stix_indicators(iocs)
    iocs["total_iocs"] = sum(len(v) for k, v in iocs.items()
                              if isinstance(v, list) and k != "stix_indicators")

    return iocs


def format_ioc_text(ioc_summary: Dict[str, Any]) -> str:
    """Format IOC summary as readable text."""
    lines = [
        f"# IOC Summary — {ioc_summary.get('cve_id', 'Unknown')}",
        f"Generated: {ioc_summary.get('generated_at', '')}",
        f"Total IOCs: {ioc_summary.get('total_iocs', 0)}",
        "",
    ]

    sections = [
        ("IPv4 Addresses", "ipv4_addresses"),
        ("Domains", "domains"),
        ("URLs", "urls"),
        ("File Hashes", "file_hashes"),
        ("Email Addresses", "email_addresses"),
        ("CVE References", "cve_references"),
    ]

    for title, key in sections:
        items = ioc_summary.get(key, [])
        if items:
            lines.append(f"## {title}")
            for item in items:
                lines.append(f"  - {item}")
            lines.append("")

    return "\n".join(lines)


def _gather_text(cve: Dict, references: List[Dict] = None,
                  exploits: List[Dict] = None) -> str:
    """Gather all text from CVE, references, and exploits for IOC extraction."""
    parts = [
        cve.get("description", ""),
        cve.get("patch_url", ""),
        json.dumps(cve.get("affected_products", [])),
    ]
    for ref in (references or []):
        parts.append(ref.get("ref_url", ""))
        parts.append(ref.get("title", ""))
    for exp in (exploits or []):
        parts.append(exp.get("exploit_url", ""))
        parts.append(exp.get("description", ""))
        parts.append(exp.get("raw_content", ""))
    return " ".join(str(p) for p in parts if p)


def _extract_ipv4(text: str) -> List[str]:
    pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ips = list(set(re.findall(pattern, text)))
    # Exclude common non-IOC IPs
    exclude = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8"}
    return [ip for ip in ips if ip not in exclude]


def _extract_domains(text: str) -> List[str]:
    pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = list(set(re.findall(pattern, text)))
    exclude = {"nvd.nist.gov", "github.com", "exploit-db.com", "sploitus.com",
                "cve.org", "api.github.com", "www.w3.org"}
    return [d for d in domains if d.lower() not in exclude][:20]


def _extract_urls(text: str) -> List[str]:
    pattern = r'https?://[^\s<>"\')\]]+' 
    urls = list(set(re.findall(pattern, text)))
    return urls[:20]


def _extract_hashes(text: str) -> List[str]:
    hashes = []
    # MD5
    hashes.extend(re.findall(r'\b[a-fA-F0-9]{32}\b', text))
    # SHA1
    hashes.extend(re.findall(r'\b[a-fA-F0-9]{40}\b', text))
    # SHA256
    hashes.extend(re.findall(r'\b[a-fA-F0-9]{64}\b', text))
    return list(set(hashes))[:20]


def _extract_emails(text: str) -> List[str]:
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text)))[:10]


def _build_stix_indicators(iocs: Dict) -> List[Dict]:
    """Build STIX 2.1 compatible indicator objects."""
    indicators = []
    for ip in iocs.get("ipv4_addresses", []):
        indicators.append({
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": datetime.now().isoformat() + "Z",
        })
    for domain in iocs.get("domains", []):
        indicators.append({
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": datetime.now().isoformat() + "Z",
        })
    return indicators
