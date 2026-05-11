"""
VulnIntel — Severity Badge Component
Colored badge widget for displaying CVE severity levels.
"""

import customtkinter as ctk
from config import COLORS, SEVERITY_MAP


class SeverityBadge(ctk.CTkFrame):
    """A colored badge displaying CVE severity level."""

    def __init__(self, parent, severity: str = "NONE", size: str = "normal", **kwargs):
        self.severity = severity.upper()
        info = SEVERITY_MAP.get(self.severity, SEVERITY_MAP["NONE"])
        color = info["color"]

        super().__init__(parent, fg_color=color, corner_radius=6,
                         height=24 if size == "small" else 28, **kwargs)

        self.label = ctk.CTkLabel(
            self, text=f"{info['icon']} {self.severity}",
            font=ctk.CTkFont(family="Consolas", size=11 if size == "small" else 12, weight="bold"),
            text_color="#ffffff" if self.severity != "LOW" else "#000000",
        )
        self.label.pack(padx=8, pady=2)

    def update_severity(self, severity: str):
        self.severity = severity.upper()
        info = SEVERITY_MAP.get(self.severity, SEVERITY_MAP["NONE"])
        self.configure(fg_color=info["color"])
        self.label.configure(
            text=f"{info['icon']} {self.severity}",
            text_color="#ffffff" if self.severity != "LOW" else "#000000"
        )
