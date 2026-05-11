"""
VulnIntel — CVE Card Component
Card widget for displaying CVE summary information.
"""

import customtkinter as ctk
from config import COLORS, SEVERITY_MAP, EXPLOIT_MATURITY


class CVECard(ctk.CTkFrame):
    """A card widget displaying CVE summary info with severity coloring."""

    def __init__(self, parent, cve_data: dict, on_click=None, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_card"], corner_radius=10,
                         border_width=1, border_color=COLORS["border"],
                         cursor="hand2", **kwargs)
        self.cve_data = cve_data
        self.on_click = on_click

        self.bind("<Button-1>", self._handle_click)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

        self._build()

    def _build(self):
        cve_id = self.cve_data.get("cve_id", "N/A")
        severity = (self.cve_data.get("severity", "NONE") or "NONE").upper()
        cvss = self.cve_data.get("cvss_score", 0.0) or 0.0
        desc = (self.cve_data.get("description", "") or "")[:120]
        has_exploit = self.cve_data.get("has_public_exploit", False)
        maturity = self.cve_data.get("exploit_maturity", "none")
        sev_info = SEVERITY_MAP.get(severity, SEVERITY_MAP["NONE"])

        # Top row: CVE ID + Severity
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=12, pady=(10, 4))

        ctk.CTkLabel(
            top, text=cve_id,
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS["accent_primary"],
        ).pack(side="left")

        # Severity pill
        sev_frame = ctk.CTkFrame(top, fg_color=sev_info["color"], corner_radius=6, height=22)
        sev_frame.pack(side="right")
        ctk.CTkLabel(
            sev_frame, text=f"{sev_info['icon']} {severity}  {cvss}",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#ffffff" if severity != "LOW" else "#000000",
        ).pack(padx=6, pady=1)

        # Description
        ctk.CTkLabel(
            self, text=desc + ("..." if len(desc) >= 120 else ""),
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
            wraplength=400, anchor="w", justify="left",
        ).pack(fill="x", padx=12, pady=(0, 6))

        # Bottom row: Exploit status + Source
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=12, pady=(0, 10))

        if has_exploit:
            mat_info = EXPLOIT_MATURITY.get(maturity, EXPLOIT_MATURITY["none"])
            ctk.CTkLabel(
                bottom, text=f"⚡ {mat_info['label']}",
                font=ctk.CTkFont(size=11), text_color=mat_info["color"],
            ).pack(side="left")
        else:
            ctk.CTkLabel(
                bottom, text="No exploit known",
                font=ctk.CTkFont(size=11), text_color=COLORS["text_muted"],
            ).pack(side="left")

        source = self.cve_data.get("source", "")
        if source:
            ctk.CTkLabel(
                bottom, text=source.upper(),
                font=ctk.CTkFont(size=10), text_color=COLORS["text_muted"],
            ).pack(side="right")

    def _handle_click(self, event=None):
        if self.on_click:
            self.on_click(self.cve_data)

    def _on_enter(self, event=None):
        self.configure(fg_color=COLORS["bg_card_hover"], border_color=COLORS["border_active"])

    def _on_leave(self, event=None):
        self.configure(fg_color=COLORS["bg_card"], border_color=COLORS["border"])
