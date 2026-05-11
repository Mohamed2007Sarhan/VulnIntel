"""
VulnIntel — Remediation Engine
Generates remediation recommendations and configuration hardening steps.
"""

from typing import Dict, Any, List


def generate_remediation(cve: Dict[str, Any]) -> Dict[str, Any]:
    """Generate structured remediation data for a CVE."""
    desc = (cve.get("description", "") or "").lower()
    severity = cve.get("severity", "NONE")

    result = {
        "cve_id": cve.get("cve_id", ""),
        "priority": _get_priority(severity),
        "steps": [],
        "workarounds": [],
        "hardening": [],
    }

    # Patch step
    if cve.get("patch_available"):
        result["steps"].append({
            "order": 1,
            "action": "Apply official vendor patch",
            "details": f"Patch URL: {cve.get('patch_url', 'Check vendor advisory')}",
            "urgency": "immediate" if severity in ("CRITICAL", "HIGH") else "standard",
        })

    # Vulnerability-type-specific remediation
    vuln_remediations = {
        "sql injection": {
            "steps": ["Implement parameterized queries", "Input validation on all user-supplied data"],
            "workarounds": ["Deploy WAF with SQL injection rules", "Restrict database user privileges"],
            "hardening": ["Enable database query logging", "Use stored procedures"],
        },
        "cross-site scripting": {
            "steps": ["Encode all output", "Validate and sanitize input"],
            "workarounds": ["Implement CSP headers", "Enable HttpOnly and Secure cookie flags"],
            "hardening": ["Deploy browser-based XSS filtering", "Use auto-escaping templates"],
        },
        "remote code execution": {
            "steps": ["Restrict network access to service", "Disable unnecessary features"],
            "workarounds": ["Implement application sandboxing", "Network segmentation"],
            "hardening": ["Enable ASLR/DEP", "Apply AppLocker/SELinux policies"],
        },
        "privilege escalation": {
            "steps": ["Apply least privilege principle", "Audit all service accounts"],
            "workarounds": ["Remove unnecessary SUID/admin rights", "Enable UAC/sudo logging"],
            "hardening": ["Implement role-based access control", "Monitor privilege changes"],
        },
        "denial of service": {
            "steps": ["Apply rate limiting", "Configure connection timeouts"],
            "workarounds": ["Deploy DDoS protection", "Scale infrastructure"],
            "hardening": ["Implement resource quotas", "Configure health monitoring"],
        },
    }

    for vuln_type, remediation in vuln_remediations.items():
        if vuln_type in desc:
            for step in remediation["steps"]:
                result["steps"].append({"order": len(result["steps"]) + 1, "action": step})
            result["workarounds"].extend(remediation["workarounds"])
            result["hardening"].extend(remediation["hardening"])
            break

    # Generic steps if nothing matched
    if len(result["steps"]) <= 1:
        result["steps"].append({"order": 2, "action": "Monitor vendor advisory for updates"})
        result["steps"].append({"order": 3, "action": "Implement network segmentation around affected systems"})
        result["workarounds"].append("Restrict access to affected component")
        result["hardening"].append("Enable comprehensive logging on affected systems")

    return result


def _get_priority(severity: str) -> str:
    return {"CRITICAL": "P1 — Immediate", "HIGH": "P2 — Urgent",
            "MEDIUM": "P3 — Standard", "LOW": "P4 — Scheduled"}.get(severity, "P4 — Scheduled")
