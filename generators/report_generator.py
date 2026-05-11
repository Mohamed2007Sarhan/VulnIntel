"""
VulnIntel — Markdown Report Generator
Generates comprehensive vulnerability reports.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from generators.sigma_generator import generate_sigma_rule
from generators.yara_generator import generate_yara_rule
from generators.ioc_generator import generate_ioc_summary, format_ioc_text


def generate_full_report(cve: Dict[str, Any], exploits: List[Dict] = None,
                          references: List[Dict] = None, detections: List[Dict] = None,
                          lab_results: List[Dict] = None) -> str:
    """Generate a comprehensive Markdown vulnerability report."""
    cve_id = cve.get("cve_id", "Unknown")
    severity = cve.get("severity", "NONE")
    cvss = cve.get("cvss_score", 0.0) or 0.0
    description = cve.get("description", "No description available.")

    sections = []

    # Header
    sections.append(f"# Vulnerability Report: {cve_id}\n")
    sections.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    sections.append(f"**Platform:** VulnIntel v1.0.0\n")

    # Executive Summary
    sections.append("## Executive Summary\n")
    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    sections.append(f"| Field | Value |")
    sections.append(f"|-------|-------|")
    sections.append(f"| **CVE ID** | {cve_id} |")
    sections.append(f"| **Severity** | {severity_emoji} {severity} |")
    sections.append(f"| **CVSS Score** | {cvss} / 10.0 |")
    sections.append(f"| **CVSS Vector** | `{cve.get('cvss_vector', 'N/A')}` |")
    sections.append(f"| **Exploit Status** | {'✅ Public Exploit Available' if cve.get('has_public_exploit') else '❌ No Known Exploit'} |")
    sections.append(f"| **Exploit Maturity** | {cve.get('exploit_maturity', 'none').title()} |")
    sections.append(f"| **Patch Available** | {'✅ Yes' if cve.get('patch_available') else '❌ No'} |")
    sections.append(f"| **Published** | {cve.get('published_date', 'N/A')} |")
    sections.append(f"| **Source** | {cve.get('source', 'N/A')} |\n")

    # Description
    sections.append("## Vulnerability Description\n")
    sections.append(f"{description}\n")

    # Affected Products
    products = cve.get("affected_products", [])
    if isinstance(products, str):
        try:
            products = json.loads(products)
        except Exception:
            products = [products]
    if products:
        sections.append("## Affected Products\n")
        for p in products:
            sections.append(f"- {p}")
        sections.append("")

    # Exploits
    exploits = exploits or []
    if exploits:
        sections.append(f"## Known Exploits ({len(exploits)})\n")
        for i, exp in enumerate(exploits, 1):
            sections.append(f"### Exploit #{i}: {exp.get('exploit_title', 'Untitled')}\n")
            sections.append(f"- **Source:** {exp.get('exploit_source', 'N/A')}")
            sections.append(f"- **Type:** {exp.get('exploit_type', 'N/A')}")
            sections.append(f"- **Platform:** {exp.get('platform', 'N/A')}")
            sections.append(f"- **URL:** {exp.get('exploit_url', 'N/A')}")
            safe = "✅ Safe" if exp.get("safe_for_lab") else "⚠️ Review Required"
            sections.append(f"- **Lab Safety:** {safe}\n")
    else:
        sections.append("## Exploits\n")
        sections.append("No public exploits currently known for this vulnerability.\n")

    # Detection Rules
    if detections:
        sections.append(f"## Detection Rules ({len(detections)})\n")
        for det in detections:
            sections.append(f"### {det.get('detection_type', '').upper()}: {det.get('rule_name', '')}\n")
            sections.append(f"**Confidence:** {det.get('confidence', 'medium')}\n")
            sections.append(f"```yaml\n{det.get('rule_content', '')}\n```\n")

    # Lab Results
    if lab_results:
        sections.append(f"## Lab Validation Results ({len(lab_results)})\n")
        sections.append("| Target | Environment | Status | Date |")
        sections.append("|--------|-------------|--------|------|")
        for lr in lab_results:
            status_icon = {"success": "✅", "failure": "❌", "partial": "⚠️"}.get(lr.get("status", ""), "❓")
            sections.append(f"| {lr.get('lab_target', 'N/A')} | {lr.get('lab_environment', 'N/A')} | {status_icon} {lr.get('status', 'N/A')} | {lr.get('validated_at', 'N/A')} |")
        sections.append("")

    # References
    references = references or []
    if references:
        sections.append(f"## References ({len(references)})\n")
        for ref in references:
            sections.append(f"- [{ref.get('title', ref.get('ref_url', ''))}]({ref.get('ref_url', '')}) ({ref.get('ref_type', '')})")
        sections.append("")

    # Remediation
    sections.append("## Remediation Recommendations\n")
    sections.append(_generate_remediation(cve))

    # Footer
    sections.append("\n---")
    sections.append("*This report was auto-generated by VulnIntel for defensive security research only.*")

    return "\n".join(sections)


def _generate_remediation(cve: Dict) -> str:
    """Generate remediation recommendations based on CVE data."""
    lines = []
    if cve.get("patch_available"):
        lines.append(f"1. **Apply the official patch immediately.**")
        if cve.get("patch_url"):
            lines.append(f"   - Patch URL: {cve['patch_url']}")
    else:
        lines.append("1. **No official patch is currently available.** Monitor vendor channels for updates.")

    desc = (cve.get("description", "") or "").lower()
    if "sql injection" in desc:
        lines.append("2. Implement parameterized queries / prepared statements.")
        lines.append("3. Deploy a Web Application Firewall (WAF) with SQLi rules.")
    elif "xss" in desc or "cross-site" in desc:
        lines.append("2. Sanitize and encode all user inputs before rendering.")
        lines.append("3. Implement Content Security Policy (CSP) headers.")
    elif "remote code execution" in desc:
        lines.append("2. Restrict network access to affected services.")
        lines.append("3. Implement application-level sandboxing.")
    elif "privilege escalation" in desc:
        lines.append("2. Apply principle of least privilege to all accounts.")
        lines.append("3. Audit user permissions and access controls.")
    else:
        lines.append("2. Review vendor documentation for specific mitigation steps.")
        lines.append("3. Implement defense-in-depth controls around affected components.")

    lines.append(f"4. Monitor for exploitation attempts using the detection rules above.")
    lines.append(f"5. Conduct a risk assessment for affected environments.")

    return "\n".join(lines)
