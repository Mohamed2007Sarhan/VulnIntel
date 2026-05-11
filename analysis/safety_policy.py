"""
VulnIntel — Safety Policy Enforcement
Hard safety module that blocks unauthorized or dangerous operations.
"""

import re
import logging
from typing import Tuple

from config import SAFETY_POLICY, PRIVATE_NETWORK_RANGES

logger = logging.getLogger(__name__)

# Patterns indicating destructive or malicious payloads
DANGEROUS_PATTERNS = [
    r"rm\s+-rf", r"format\s+[cC]:", r"del\s+/[sS]", r"DROP\s+TABLE",
    r"DELETE\s+FROM", r"mkfs\.", r"dd\s+if=", r"shutdown",
    r"passwd", r"useradd", r"net\s+user", r"reg\s+add",
    r"schtasks", r"crontab", r"nc\s+-[elp]", r"ncat\s+-[elp]",
    r"reverse.shell", r"msfvenom", r"meterpreter",
    r"mimikatz", r"LaZagne", r"procdump",
    r"exfiltrate", r"data.leak", r"curl.*\|.*sh",
    r"wget.*\|.*bash", r"powershell.*-enc",
]

PERSISTENCE_PATTERNS = [
    r"registry.*run", r"startup.*folder", r"crontab\s+-e",
    r"systemctl\s+enable", r"sc\s+create", r"schtasks\s+/create",
    r"autorun", r"backdoor", r"rootkit", r"implant",
]


def is_private_ip(address: str) -> bool:
    """Check if an IP/hostname is on a private network."""
    address = address.strip().lower()
    for prefix in PRIVATE_NETWORK_RANGES:
        if address.startswith(prefix.lower()):
            return True
    return False


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate that a target is in an authorized lab environment.
    Returns (is_valid, reason).
    """
    if not SAFETY_POLICY["enforce_lab_whitelist"]:
        return True, "Lab whitelist enforcement disabled"

    target = target.strip()
    if not target:
        return False, "Empty target address"

    # Block public targets
    if SAFETY_POLICY["block_public_targets"]:
        if not is_private_ip(target):
            msg = f"BLOCKED: Target '{target}' is not on a private network. Only RFC 1918 addresses are allowed."
            logger.warning(msg)
            return False, msg

    return True, "Target validated — private network"


def validate_payload(content: str) -> Tuple[bool, str]:
    """
    Check if exploit content contains dangerous/destructive patterns.
    Returns (is_safe, reason).
    """
    if not content:
        return True, "Empty content"

    content_lower = content.lower()

    # Check for destructive patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            msg = f"BLOCKED: Payload contains dangerous pattern matching '{pattern}'"
            logger.warning(msg)
            return False, msg

    # Check for persistence mechanisms
    if SAFETY_POLICY["block_persistence"]:
        for pattern in PERSISTENCE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                msg = f"BLOCKED: Payload contains persistence mechanism matching '{pattern}'"
                logger.warning(msg)
                return False, msg

    return True, "Payload passed safety checks"


def validate_action(action: str) -> Tuple[bool, str]:
    """
    Validate a requested action against the safety policy.
    Returns (is_allowed, reason).
    """
    action_lower = action.lower()

    blocked_actions = {
        "credential_theft": SAFETY_POLICY["block_credential_theft"],
        "data_exfiltration": SAFETY_POLICY["block_data_exfiltration"],
        "weaponized_generation": SAFETY_POLICY["block_weaponized_generation"],
        "persistence": SAFETY_POLICY["block_persistence"],
    }

    for action_type, is_blocked in blocked_actions.items():
        if is_blocked and action_type.replace("_", " ") in action_lower:
            msg = f"BLOCKED: Action '{action}' violates safety policy ({action_type})"
            logger.warning(msg)
            return False, msg

    # Check for real-world exploitation keywords
    real_world_keywords = [
        "internet target", "public server", "production",
        "unauthorized", "without permission", "scan internet",
        "shodan target", "random host", "mass scan",
    ]
    for keyword in real_world_keywords:
        if keyword in action_lower:
            msg = f"REFUSED: Action involves real-world targeting ('{keyword}')"
            logger.warning(msg)
            return False, msg

    return True, "Action permitted within safety policy"


def get_safety_status() -> dict:
    """Get current safety policy status for GUI display."""
    return {
        "all_enforced": all(SAFETY_POLICY.values()),
        "policies": SAFETY_POLICY.copy(),
        "status": "ENFORCED" if all(SAFETY_POLICY.values()) else "PARTIAL",
    }
