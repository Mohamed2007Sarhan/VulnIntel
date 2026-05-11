"""
VulnIntel — Reports Frame
Panel for generating and exporting vulnerability reports.
"""

import os
import customtkinter as ctk
from config import COLORS, EXPORTS_DIR
from generators.report_generator import generate_full_report


class ReportsFrame(ctk.CTkFrame):
    """Report generation and export panel."""

    def __init__(self, parent, db_manager, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.db = db_manager
        self._build()

    def _build(self):
        ctk.CTkLabel(
            self, text="📄 Reports",
            font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_primary"],
        ).pack(anchor="w", padx=20, pady=(20, 10))

        # Controls
        ctrl = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=10,
                             border_width=1, border_color=COLORS["border"])
        ctrl.pack(fill="x", padx=20, pady=(0, 10))

        inner = ctk.CTkFrame(ctrl, fg_color="transparent")
        inner.pack(padx=15, pady=10)

        ctk.CTkLabel(inner, text="CVE ID:", font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"]).pack(side="left")
        self.cve_entry = ctk.CTkEntry(inner, width=180, font=ctk.CTkFont(family="Consolas", size=12),
                                       placeholder_text="CVE-2024-XXXXX",
                                       fg_color=COLORS["bg_secondary"], border_color=COLORS["border"])
        self.cve_entry.pack(side="left", padx=8)

        ctk.CTkButton(inner, text="Generate Report", fg_color=COLORS["accent_primary"],
                       hover_color=COLORS["accent_secondary"], text_color="#000",
                       font=ctk.CTkFont(size=12, weight="bold"),
                       command=self._generate).pack(side="left", padx=5)

        ctk.CTkButton(inner, text="Export to File", fg_color="#6366f1",
                       hover_color="#818cf8",
                       font=ctk.CTkFont(size=12, weight="bold"),
                       command=self._export).pack(side="left", padx=5)

        self.status = ctk.CTkLabel(inner, text="", font=ctk.CTkFont(size=12),
                                    text_color=COLORS["text_muted"])
        self.status.pack(side="left", padx=10)

        # Report viewer
        self.viewer = ctk.CTkTextbox(self, fg_color=COLORS["bg_secondary"], corner_radius=10,
                                      font=ctk.CTkFont(family="Consolas", size=12),
                                      text_color=COLORS["text_primary"],
                                      border_width=1, border_color=COLORS["border"])
        self.viewer.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    def _generate(self):
        cve_id = self.cve_entry.get().strip().upper()
        if not cve_id:
            self.status.configure(text="❌ Enter a CVE ID", text_color=COLORS["error"])
            return

        cve = self.db.get_cve(cve_id)
        if not cve:
            cve = {"cve_id": cve_id, "description": "CVE not found in local database",
                    "severity": "NONE", "cvss_score": 0.0}

        exploits = self.db.get_exploits_for_cve(cve_id)
        refs = self.db.get_references(cve_id)
        detections = self.db.get_detections_for_cve(cve_id)
        lab_results = self.db.get_lab_results(cve_id)

        report = generate_full_report(cve, exploits, refs, detections, lab_results)
        self.viewer.delete("1.0", "end")
        self.viewer.insert("1.0", report)
        self.status.configure(text="✅ Report generated", text_color=COLORS["success"])
        self._current_report = report
        self._current_cve_id = cve_id

    def _export(self):
        if not hasattr(self, "_current_report") or not self._current_report:
            self.status.configure(text="❌ Generate a report first", text_color=COLORS["error"])
            return

        os.makedirs(EXPORTS_DIR, exist_ok=True)
        filename = f"report_{self._current_cve_id}.md"
        filepath = os.path.join(EXPORTS_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self._current_report)
        self.status.configure(text=f"✅ Exported: {filename}", text_color=COLORS["success"])
