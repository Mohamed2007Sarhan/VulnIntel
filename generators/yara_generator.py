"""
VulnIntel — YARA Signature Generator
Generates YARA rules for detecting exploit artifacts and payloads.
"""

import re
import hashlib
from datetime import datetime
from typing import Dict, Any


def generate_yara_rule(cve: Dict[str, Any], exploit: Dict[str, Any] = None) -> str:
    """Generate a YARA detection rule for a CVE/exploit."""
    cve_id = cve.get("cve_id", "UNKNOWN")
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', cve_id)
    description = (cve.get("description", "") or "")[:200].replace('"', '\\"')
    severity = cve.get("severity", "MEDIUM")
    cvss = cve.get("cvss_score", 0.0) or 0.0

    # Build string patterns based on CVE characteristics
    strings_section = _build_strings(cve, exploit)
    condition = _build_condition(cve, exploit)

    rule = f"""rule {safe_name}_Exploit {{
    meta:
        description = "{description}"
        cve = "{cve_id}"
        severity = "{severity}"
        cvss_score = "{cvss}"
        author = "VulnIntel Automated Generator"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        reference = "https://nvd.nist.gov/vuln/detail/{cve_id}"

{strings_section}

    condition:
{condition}
}}"""
    return rule


def _build_strings(cve: Dict, exploit: Dict = None) -> str:
    """Build YARA strings section from CVE and exploit data."""
    desc = (cve.get("description", "") or "").lower()
    strings = []
    idx = 0

    # CVE-specific patterns
    cve_id = cve.get("cve_id", "")
    if cve_id:
        strings.append(f'        $cve_ref = "{cve_id}" ascii wide nocase')
        idx += 1

    # Exploit title as a marker
    if exploit:
        title = (exploit.get("exploit_title", "") or "")[:80]
        if title:
            safe_title = title.replace('"', '\\"').replace("\\", "\\\\")
            strings.append(f'        $exploit_title = "{safe_title}" ascii nocase')
            idx += 1

    # Vulnerability-type-specific patterns
    if "sql injection" in desc:
        strings.extend([
            '        $sqli_1 = "UNION SELECT" ascii nocase',
            '        $sqli_2 = "OR 1=1" ascii nocase',
            '        $sqli_3 = "WAITFOR DELAY" ascii nocase',
        ])
    elif "cross-site scripting" in desc or "xss" in desc:
        strings.extend([
            '        $xss_1 = "<script>" ascii nocase',
            '        $xss_2 = "javascript:" ascii nocase',
            '        $xss_3 = "onerror=" ascii nocase',
        ])
    elif "remote code execution" in desc or "rce" in desc:
        strings.extend([
            '        $rce_1 = "/bin/sh" ascii',
            '        $rce_2 = "cmd.exe" ascii nocase',
            '        $rce_3 = "powershell" ascii nocase',
        ])
    elif "path traversal" in desc or "directory traversal" in desc:
        strings.extend([
            '        $trav_1 = "../../../" ascii',
            '        $trav_2 = "..\\\\..\\\\..\\\\' + '" ascii',
            '        $trav_3 = "etc/passwd" ascii',
        ])
    elif "buffer overflow" in desc or "memory corruption" in desc:
        strings.extend([
            '        $bof_1 = { 41 41 41 41 41 41 41 41 }',
            '        $bof_2 = "\\x90\\x90\\x90\\x90" ascii',
        ])
    elif "deserialization" in desc:
        strings.extend([
            '        $deser_1 = "rO0ABX" ascii',
            '        $deser_2 = "ObjectInputStream" ascii',
            '        $deser_3 = "Runtime.getRuntime" ascii',
        ])
    else:
        # Generic exploit indicators
        strings.extend([
            '        $gen_1 = "exploit" ascii nocase',
            '        $gen_2 = "payload" ascii nocase',
            '        $gen_3 = "shellcode" ascii nocase',
        ])

    if not strings:
        strings.append(f'        $marker = "{cve_id}" ascii')

    return "    strings:\n" + "\n".join(strings)


def _build_condition(cve: Dict, exploit: Dict = None) -> str:
    """Build YARA condition."""
    return "        any of them"
