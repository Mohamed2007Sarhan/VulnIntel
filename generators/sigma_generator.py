"""
VulnIntel — Sigma Rule Generator
Generates Sigma detection rules from CVE and exploit data.
"""

import uuid
import re
from datetime import datetime
from typing import Dict, Any, Optional


def generate_sigma_rule(cve: Dict[str, Any], exploit: Dict[str, Any] = None) -> str:
    """Generate a Sigma detection rule for a CVE."""
    cve_id = cve.get("cve_id", "UNKNOWN")
    description = (cve.get("description", "") or "")[:200]
    severity = (cve.get("severity", "MEDIUM") or "MEDIUM").lower()
    cvss = cve.get("cvss_score", 0.0) or 0.0

    # Map severity to Sigma level
    level_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    level = level_map.get(severity, "medium")

    # Determine logsource and detection based on vulnerability type
    logsource, detection = _infer_detection(cve, exploit)

    # Build MITRE ATT&CK tags
    tags = _infer_attack_tags(cve, exploit)
    tags_yaml = "\n".join(f"    - {t}" for t in tags)

    rule = f"""title: Detection for {cve_id}
id: {str(uuid.uuid4())}
status: experimental
description: |
    Detects potential exploitation attempts related to {cve_id}.
    {description}
    CVSS Score: {cvss}
author: VulnIntel Automated Generator
date: {datetime.now().strftime('%Y/%m/%d')}
references:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
{logsource}
{detection}
falsepositives:
    - Legitimate administrative activity
    - Security scanning tools
level: {level}
tags:
{tags_yaml}
"""
    return rule.strip()


def _infer_detection(cve: Dict, exploit: Dict = None) -> tuple:
    """Infer logsource and detection fields from CVE data."""
    desc = (cve.get("description", "") or "").lower()
    products = cve.get("affected_products", [])
    if isinstance(products, str):
        products = [products]
    products_str = " ".join(str(p) for p in products).lower()

    # Web application vulnerabilities
    if any(w in desc for w in ["sql injection", "sqli", "xss", "cross-site", "rce", "remote code",
                                 "path traversal", "directory traversal", "file inclusion",
                                 "server-side request", "ssrf", "command injection"]):
        logsource = """logsource:
    category: webserver
    product: apache"""

        # Build detection patterns
        patterns = []
        if "sql injection" in desc or "sqli" in desc:
            patterns.extend(["UNION SELECT", "OR 1=1", "' OR '", "SLEEP(", "BENCHMARK("])
        if "xss" in desc or "cross-site" in desc:
            patterns.extend(["<script>", "javascript:", "onerror=", "onload="])
        if "path traversal" in desc or "directory traversal" in desc:
            patterns.extend(["../", "..\\\\", "%2e%2e", "etc/passwd"])
        if "command injection" in desc:
            patterns.extend([";ls", "|cat", "$(", "`id`", ";whoami"])
        if "ssrf" in desc or "server-side request" in desc:
            patterns.extend(["127.0.0.1", "localhost", "metadata.google", "169.254.169.254"])
        if not patterns:
            patterns = ["exploit", "attack"]

        pattern_yaml = "\n".join(f"            - '{p}'" for p in patterns[:5])
        detection = f"""detection:
    selection:
        cs-uri-query|contains:
{pattern_yaml}
    condition: selection"""

    # Authentication / privilege escalation
    elif any(w in desc for w in ["privilege escalation", "authentication bypass", "unauthorized access"]):
        logsource = """logsource:
    category: process_creation
    product: windows"""
        detection = """detection:
    selection:
        EventID:
            - 4672
            - 4688
        NewProcessName|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
    filter:
        User|contains: 'SYSTEM'
    condition: selection and not filter"""

    # Network-based
    elif any(w in desc for w in ["buffer overflow", "heap overflow", "stack overflow", "memory corruption"]):
        logsource = """logsource:
    category: firewall"""
        detection = """detection:
    selection:
        action: allowed
        dst_port:
            - 445
            - 139
            - 3389
    condition: selection"""

    # Default generic detection
    else:
        logsource = """logsource:
    category: process_creation
    product: windows"""
        detection = """detection:
    selection:
        EventID: 1
    filter_legitimate:
        ParentImage|endswith:
            - '\\\\explorer.exe'
            - '\\\\svchost.exe'
    condition: selection and not filter_legitimate"""

    return logsource, detection


def _infer_attack_tags(cve: Dict, exploit: Dict = None) -> list:
    """Infer MITRE ATT&CK tags from CVE description."""
    desc = (cve.get("description", "") or "").lower()
    tags = [f"cve.{cve.get('cve_id', '').replace('CVE-', '').replace('-', '.')}"]

    mapping = {
        "remote code execution": "attack.execution",
        "rce": "attack.execution",
        "command injection": "attack.execution",
        "sql injection": "attack.initial_access",
        "xss": "attack.initial_access",
        "authentication bypass": "attack.initial_access",
        "privilege escalation": "attack.privilege_escalation",
        "path traversal": "attack.discovery",
        "information disclosure": "attack.collection",
        "denial of service": "attack.impact",
        "buffer overflow": "attack.execution",
        "deserialization": "attack.execution",
    }

    for keyword, tag in mapping.items():
        if keyword in desc and tag not in tags:
            tags.append(tag)

    if len(tags) == 1:
        tags.append("attack.initial_access")

    return tags
