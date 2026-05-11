"""
VulnIntel — Target Analysis Frame
AI-powered target/application analysis panel.
Describe your target and the AI recommends the best security approach.
"""

import threading
import customtkinter as ctk
from config import COLORS


class TargetAnalysisFrame(ctk.CTkFrame):
    """Target analysis panel with AI-powered recommendations."""

    def __init__(self, parent, db_manager, ai_analyzer=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.db = db_manager
        self.ai = ai_analyzer
        self._build()

    def _build(self):
        # Title
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))

        ctk.CTkLabel(
            header, text="🎯 Target Analysis",
            font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_primary"],
        ).pack(side="left")

        ai_badge = ctk.CTkLabel(
            header, text="🤖 AI-Powered",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLORS["accent_primary"],
            fg_color=COLORS["bg_card"], corner_radius=6, padx=8, pady=2,
        )
        ai_badge.pack(side="right")

        # ─── Input Form ──────────────────────────────────────────────────
        form = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12,
                             border_width=1, border_color=COLORS["border"])
        form.pack(fill="x", padx=20, pady=(0, 10))

        # Row 1: Name + Type
        row1 = ctk.CTkFrame(form, fg_color="transparent")
        row1.pack(fill="x", padx=15, pady=(12, 4))

        ctk.CTkLabel(row1, text="Target Name:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=110, anchor="w").pack(side="left")
        self.name_entry = ctk.CTkEntry(row1, width=250, font=ctk.CTkFont(size=12),
                                        placeholder_text="e.g. Apache HTTP Server, WordPress, vsftpd...",
                                        fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
                                        corner_radius=8)
        self.name_entry.pack(side="left", padx=5)

        ctk.CTkLabel(row1, text="Type:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=50, anchor="w").pack(side="left", padx=(15, 0))
        self.type_combo = ctk.CTkComboBox(
            row1, values=["Web Application", "Web Server", "Database", "Operating System",
                           "Network Service", "CMS", "API", "IoT Device", "Container",
                           "Mail Server", "FTP Server", "DNS Server", "Other"],
            width=160, font=ctk.CTkFont(size=12),
            fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
            dropdown_fg_color=COLORS["bg_card"], dropdown_hover_color=COLORS["bg_card_hover"],
        )
        self.type_combo.set("Web Application")
        self.type_combo.pack(side="left", padx=5)

        # Row 2: OS + Version
        row2 = ctk.CTkFrame(form, fg_color="transparent")
        row2.pack(fill="x", padx=15, pady=4)

        ctk.CTkLabel(row2, text="OS:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=110, anchor="w").pack(side="left")
        self.os_combo = ctk.CTkComboBox(
            row2, values=["Linux (Ubuntu)", "Linux (Debian)", "Linux (CentOS)", "Linux (Other)",
                           "Windows Server", "Windows Desktop", "macOS", "FreeBSD", "Unknown"],
            width=250, font=ctk.CTkFont(size=12),
            fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
            dropdown_fg_color=COLORS["bg_card"], dropdown_hover_color=COLORS["bg_card_hover"],
        )
        self.os_combo.set("Linux (Ubuntu)")
        self.os_combo.pack(side="left", padx=5)

        ctk.CTkLabel(row2, text="Version:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=50, anchor="w").pack(side="left", padx=(15, 0))
        self.version_entry = ctk.CTkEntry(row2, width=160, font=ctk.CTkFont(size=12),
                                           placeholder_text="e.g. 2.4.49, 5.7, 8.0...",
                                           fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
                                           corner_radius=8)
        self.version_entry.pack(side="left", padx=5)

        # Row 3: Services
        row3 = ctk.CTkFrame(form, fg_color="transparent")
        row3.pack(fill="x", padx=15, pady=4)

        ctk.CTkLabel(row3, text="Services/Ports:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=110, anchor="w").pack(side="left")
        self.services_entry = ctk.CTkEntry(row3, font=ctk.CTkFont(size=12),
                                            placeholder_text="e.g. HTTP:80, SSH:22, MySQL:3306, FTP:21...",
                                            fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
                                            corner_radius=8)
        self.services_entry.pack(side="left", fill="x", expand=True, padx=5)

        # Row 4: Description
        row4 = ctk.CTkFrame(form, fg_color="transparent")
        row4.pack(fill="x", padx=15, pady=4)

        ctk.CTkLabel(row4, text="Description:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=110, anchor="nw").pack(side="left", anchor="n")

        self.desc_text = ctk.CTkTextbox(row4, height=80, font=ctk.CTkFont(size=12),
                                         fg_color=COLORS["bg_secondary"],
                                         border_color=COLORS["border"], border_width=1,
                                         text_color=COLORS["text_primary"], corner_radius=8)
        self.desc_text.pack(side="left", fill="x", expand=True, padx=5)
        self.desc_text.insert("1.0", "")

        # Buttons
        btn_row = ctk.CTkFrame(form, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(4, 12))

        ctk.CTkButton(btn_row, text="🤖 Analyze with AI", height=38,
                       font=ctk.CTkFont(size=14, weight="bold"),
                       fg_color=COLORS["accent_primary"], hover_color=COLORS["accent_secondary"],
                       text_color="#000", corner_radius=10,
                       command=self._analyze).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row, text="🔍 Search CVEs for Target", height=38,
                       font=ctk.CTkFont(size=13, weight="bold"),
                       fg_color=COLORS["info"], hover_color="#38bdf8",
                       text_color="#fff", corner_radius=10,
                       command=self._search_cves).pack(side="left", padx=3)

        self.analysis_status = ctk.CTkLabel(btn_row, text="", font=ctk.CTkFont(size=12),
                                             text_color=COLORS["text_muted"])
        self.analysis_status.pack(side="left", padx=15)

        # ─── Results Area ────────────────────────────────────────────────
        self.results = ctk.CTkTextbox(
            self, fg_color=COLORS["bg_secondary"], corner_radius=12,
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=COLORS["text_primary"],
            border_width=1, border_color=COLORS["border"],
        )
        self.results.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.results.insert("1.0", "Enter target details above and click 'Analyze with AI' to get\n"
                                    "AI-powered vulnerability analysis and security recommendations.\n\n"
                                    "The AI will:\n"
                                    "  • Identify potential vulnerability categories\n"
                                    "  • Recommend specific CVEs to investigate\n"
                                    "  • Suggest safe lab testing strategies\n"
                                    "  • Provide detection recommendations\n\n"
                                    "⚠️  Analysis is for authorized lab environments ONLY.")

    def _get_target_info(self) -> dict:
        return {
            "name": self.name_entry.get().strip(),
            "type": self.type_combo.get(),
            "os": self.os_combo.get(),
            "version": self.version_entry.get().strip(),
            "services": self.services_entry.get().strip(),
            "description": self.desc_text.get("1.0", "end").strip(),
        }

    def _analyze(self):
        info = self._get_target_info()
        if not info["name"]:
            self.analysis_status.configure(text="❌ Enter a target name", text_color=COLORS["error"])
            return

        if not self.ai:
            self.analysis_status.configure(text="❌ AI module not available", text_color=COLORS["error"])
            return

        self.analysis_status.configure(text="🔄 AI analyzing...", text_color=COLORS["info"])
        self.results.delete("1.0", "end")
        self.results.insert("1.0", "⏳ Waiting for AI analysis...\nThis may take 30-60 seconds.\n")

        def _do_analysis():
            try:
                result = self.ai.analyze_target(info)
                self.after(0, lambda: self._show_result(result))
                self.after(0, lambda: self.analysis_status.configure(
                    text="✅ Analysis complete", text_color=COLORS["success"]))
            except Exception as e:
                self.after(0, lambda: self._show_result(f"[Error] {e}"))
                self.after(0, lambda: self.analysis_status.configure(
                    text="❌ Analysis failed", text_color=COLORS["error"]))

        threading.Thread(target=_do_analysis, daemon=True).start()

    def _search_cves(self):
        """Search local DB for CVEs matching the target."""
        info = self._get_target_info()
        query = info["name"]
        if info["version"]:
            query += " " + info["version"]

        results = self.db.search_cves(query, limit=20)
        if not results and info["name"]:
            # Try just the name
            results = self.db.search_cves(info["name"], limit=20)

        self.results.delete("1.0", "end")
        if results:
            self.results.insert("1.0", f"Found {len(results)} CVEs matching '{query}':\n\n")
            for cve in results:
                sev = cve.get("severity", "NONE")
                cvss = cve.get("cvss_score", 0.0)
                desc = (cve.get("description", "") or "")[:120]
                exploit = "⚡" if cve.get("has_public_exploit") else "  "
                self.results.insert("end",
                    f"  {exploit} [{sev:8s}] {cve.get('cve_id', '')}  CVSS:{cvss}  {desc}...\n")
        else:
            self.results.insert("1.0",
                f"No CVEs found for '{query}'.\n"
                "Try syncing sources first, or use AI analysis for recommendations.")

    def _show_result(self, text: str):
        self.results.delete("1.0", "end")
        self.results.insert("1.0", text)

    def refresh(self):
        pass
