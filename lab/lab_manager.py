"""
VulnIntel — Lab Manager
Registry of authorized lab targets and health validation.
"""

import logging
from typing import Dict, Any, List, Tuple

from database.db_manager import DatabaseManager
from analysis.safety_policy import validate_target, is_private_ip

logger = logging.getLogger(__name__)


class LabManager:
    """Manages lab target registry and validation workflows."""

    def __init__(self, db: DatabaseManager):
        self.db = db

    def register_target(self, name: str, ip: str, target_type: str = "",
                         os_info: str = "", description: str = "") -> Tuple[bool, str]:
        """Register a new lab target after validation."""
        # Validate target is on private network
        valid, reason = validate_target(ip)
        if not valid:
            return False, reason

        target_id = self.db.add_lab_target({
            "name": name,
            "ip_address": ip,
            "target_type": target_type,
            "os_info": os_info,
            "description": description,
        })
        return True, f"Target '{name}' registered (ID: {target_id})"

    def get_targets(self) -> List[Dict[str, Any]]:
        """Get all active lab targets."""
        return self.db.get_lab_targets()

    def remove_target(self, target_id: int):
        """Remove a lab target."""
        self.db.remove_lab_target(target_id)

    def is_authorized_target(self, ip: str) -> bool:
        """Check if an IP is in the authorized lab targets."""
        targets = self.db.get_lab_targets()
        for t in targets:
            if t.get("ip_address", "").strip() == ip.strip():
                return True
        return False

    def record_result(self, cve_id: str, exploit_id: int, target: str,
                       environment: str, status: str, log: str = "", notes: str = "") -> int:
        """Record a lab validation result."""
        return self.db.add_lab_result({
            "cve_id": cve_id,
            "exploit_id": exploit_id,
            "lab_target": target,
            "lab_environment": environment,
            "status": status,
            "output_log": log,
            "notes": notes,
        })

    def get_results(self, cve_id: str = None) -> List[Dict[str, Any]]:
        """Get lab validation results."""
        return self.db.get_lab_results(cve_id)
