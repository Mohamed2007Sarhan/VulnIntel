"""
VulnIntel — Sandbox Workflow Generator
Generates safe, step-by-step lab testing workflows for exploits.
"""

from typing import Dict, Any, List


def generate_workflow(cve: Dict[str, Any], exploit: Dict[str, Any],
                       target: Dict[str, Any] = None) -> Dict[str, Any]:
    """Generate a sandboxed testing workflow for a CVE/exploit pair."""
    cve_id = cve.get("cve_id", "Unknown")
    exploit_title = exploit.get("exploit_title", "Unknown Exploit")
    exploit_type = exploit.get("exploit_type", "unknown")
    target_name = target.get("name", "Lab Target") if target else "Lab Target"
    target_ip = target.get("ip_address", "N/A") if target else "N/A"

    workflow = {
        "cve_id": cve_id,
        "exploit_title": exploit_title,
        "target": target_name,
        "phases": []
    }

    # Phase 1: Pre-conditions
    workflow["phases"].append({
        "phase": "Pre-Conditions",
        "steps": [
            f"1. Verify target '{target_name}' ({target_ip}) is isolated on lab network",
            "2. Take a VM/container snapshot before testing",
            "3. Verify no production traffic reaches the target",
            "4. Confirm authorization for testing",
            "5. Start network capture (tcpdump/Wireshark) for forensic review",
        ]
    })

    # Phase 2: Validation steps (non-destructive)
    validation_steps = _get_validation_steps(cve, exploit)
    workflow["phases"].append({
        "phase": "Validation",
        "steps": validation_steps
    })

    # Phase 3: Post-conditions
    workflow["phases"].append({
        "phase": "Post-Validation",
        "steps": [
            "1. Stop network capture",
            "2. Verify target service stability (service still running, responding)",
            "3. Check for unexpected file changes on target",
            "4. Review captured traffic for exploit artifacts",
            "5. Document results in VulnIntel lab results",
        ]
    })

    # Phase 4: Rollback
    workflow["phases"].append({
        "phase": "Rollback",
        "steps": [
            "1. Restore VM/container from pre-test snapshot",
            "2. Verify clean state after restoration",
            "3. Clear any temporary test files from host machine",
        ]
    })

    return workflow


def format_workflow_text(workflow: Dict[str, Any]) -> str:
    """Format workflow as readable text."""
    lines = [
        f"# Lab Workflow: {workflow.get('cve_id', '')}",
        f"**Exploit:** {workflow.get('exploit_title', '')}",
        f"**Target:** {workflow.get('target', '')}\n",
    ]
    for phase in workflow.get("phases", []):
        lines.append(f"## {phase['phase']}\n")
        for step in phase.get("steps", []):
            lines.append(f"  {step}")
        lines.append("")
    return "\n".join(lines)


def _get_validation_steps(cve: Dict, exploit: Dict) -> List[str]:
    """Generate validation steps based on exploit type."""
    desc = (cve.get("description", "") or "").lower()
    exploit_type = (exploit.get("exploit_type", "") or "").lower()

    steps = [f"1. Review exploit code/documentation thoroughly before execution"]

    if "sql injection" in desc:
        steps.extend([
            "2. Craft a non-destructive SQL injection test (e.g., boolean-based, time-based)",
            "3. Use a benign payload: ' OR '1'='1' -- (read-only verification)",
            "4. Verify response indicates injection success without data modification",
            "5. Document the injection point and parameter",
        ])
    elif "xss" in desc or "cross-site" in desc:
        steps.extend([
            "2. Inject a benign XSS payload: <script>alert('VulnIntel-Test')</script>",
            "3. Verify the script executes in the browser context",
            "4. Check if the payload persists (stored XSS) or requires victim interaction (reflected)",
            "5. Document the vulnerable parameter and response",
        ])
    elif "remote code execution" in desc or exploit_type == "remote":
        steps.extend([
            "2. Use a safe verification command (e.g., 'id', 'whoami', 'hostname')",
            "3. DO NOT use destructive commands or shell spawns",
            "4. Verify command output confirms code execution",
            "5. Document the execution vector and required conditions",
        ])
    elif "path traversal" in desc or "directory traversal" in desc:
        steps.extend([
            "2. Test with a known safe file read (e.g., /etc/hostname or C:\\Windows\\win.ini)",
            "3. Verify file content is returned in response",
            "4. Test path depth required for traversal",
            "5. Document the vulnerable endpoint",
        ])
    elif exploit_type == "dos":
        steps.extend([
            "2. ⚠️ WARNING: DoS testing will disrupt the target service",
            "3. Ensure target can be restarted easily",
            "4. Send minimal traffic to trigger the condition (single request if possible)",
            "5. Observe service state — check if it crashes or hangs",
            "6. Do NOT sustain the attack",
        ])
    else:
        steps.extend([
            "2. Read exploit documentation and identify the vulnerability trigger",
            "3. Execute the exploit with minimal, non-destructive parameters",
            "4. Observe target response and behavior",
            "5. Document success/failure indicators",
        ])

    steps.append(f"{len(steps)+1}. ⛔ STOP immediately if instability is detected")
    return steps
