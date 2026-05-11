"""
VulnIntel — Dashboard Frame
Main overview panel with KPIs, live monitoring status, and recent CVEs.
"""

import customtkinter as ctk
from datetime import datetime
from config import COLORS
from gui.components.cve_card import CVECard
from gui.components.status_indicator import StatusIndicator


class DashboardFrame(ctk.CTkFrame):
    """Dashboard panel with KPI cards, monitoring status, and recent activity."""

    def __init__(self, parent, db_manager, on_cve_click=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.db = db_manager
        self.on_cve_click = on_cve_click
        self._build()

    def _build(self):
        # ─── Header ──────────────────────────────────────────────────────
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(fill="x", padx=24, pady=(20, 5))

        ctk.CTkLabel(
            title_frame, text="📊  Dashboard",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=COLORS["text_primary"],
        ).pack(side="left")

        # Right side: safety + time
        right_info = ctk.CTkFrame(title_frame, fg_color="transparent")
        right_info.pack(side="right")

        self.safety_indicator = StatusIndicator(right_info, label="Safety: ENFORCED", status="active")
        self.safety_indicator.pack(side="left", padx=(0, 15))

        self.time_label = ctk.CTkLabel(
            right_info, text="",
            font=ctk.CTkFont(size=11), text_color=COLORS["text_muted"],
        )
        self.time_label.pack(side="left")
        self._update_time()

        # ─── Monitoring Banner ───────────────────────────────────────────
        self.monitor_banner = ctk.CTkFrame(self, fg_color=COLORS["bg_tertiary"],
                                            corner_radius=10, border_width=1,
                                            border_color=COLORS["accent_primary"])
        self.monitor_banner.pack(fill="x", padx=24, pady=(8, 5))

        banner_inner = ctk.CTkFrame(self.monitor_banner, fg_color="transparent")
        banner_inner.pack(padx=15, pady=8)

        self.monitor_pulse = ctk.CTkLabel(banner_inner, text="●",
                                           font=ctk.CTkFont(size=14),
                                           text_color=COLORS["success"])
        self.monitor_pulse.pack(side="left")

        ctk.CTkLabel(banner_inner, text="  Continuous Monitoring Active",
                      font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["accent_primary"]).pack(side="left")

        self.monitor_detail = ctk.CTkLabel(
            banner_inner, text="  —  Watching NVD • GitHub • ExploitDB • Sploitus",
            font=ctk.CTkFont(size=11), text_color=COLORS["text_secondary"],
        )
        self.monitor_detail.pack(side="left", padx=10)

        # ─── KPI Cards Row ───────────────────────────────────────────────
        self.kpi_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.kpi_frame.pack(fill="x", padx=24, pady=8)

        # ─── Two Column Layout ───────────────────────────────────────────
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="both", expand=True, padx=24, pady=(5, 20))

        # Left: Recent CVEs
        left_col = ctk.CTkFrame(bottom, fg_color="transparent")
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 8))

        ctk.CTkLabel(
            left_col, text="🔔  Recent Vulnerabilities",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text_primary"],
        ).pack(anchor="w", pady=(0, 6))

        self.cve_scroll = ctk.CTkScrollableFrame(
            left_col, fg_color=COLORS["bg_secondary"], corner_radius=10,
            border_width=1, border_color=COLORS["border"],
        )
        self.cve_scroll.pack(fill="both", expand=True)

        ctk.CTkLabel(
            left_col, text="📝  Live Pipeline Logs",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text_primary"],
        ).pack(anchor="w", pady=(10, 6))

        self.log_box = ctk.CTkTextbox(
            left_col, fg_color=COLORS["bg_secondary"], corner_radius=10,
            border_width=1, border_color=COLORS["border"],
            font=ctk.CTkFont(family="Consolas", size=11), text_color=COLORS["text_secondary"],
            height=120
        )
        self.log_box.pack(fill="x")
        self.log_box.insert("end", "Pipeline initialized. Waiting for events...\n")

        # Right: Quick Stats + Severity Distribution
        right_col = ctk.CTkFrame(bottom, fg_color="transparent", width=280)
        right_col.pack(side="right", fill="y", padx=(8, 0))
        right_col.pack_propagate(False)

        ctk.CTkLabel(
            right_col, text="📈  Severity Distribution",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text_primary"],
        ).pack(anchor="w", pady=(0, 6))

        self.severity_frame = ctk.CTkFrame(
            right_col, fg_color=COLORS["bg_secondary"], corner_radius=10,
            border_width=1, border_color=COLORS["border"],
        )
        self.severity_frame.pack(fill="x", pady=(0, 10))

        # Source status
        ctk.CTkLabel(
            right_col, text="📡  Source Status",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text_primary"],
        ).pack(anchor="w", pady=(10, 6))

        self.source_frame = ctk.CTkFrame(
            right_col, fg_color=COLORS["bg_secondary"], corner_radius=10,
            border_width=1, border_color=COLORS["border"],
        )
        self.source_frame.pack(fill="x")

        self.refresh()

    def append_log(self, text: str):
        """Append a message to the live log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.after(0, lambda: self._do_append_log(f"[{timestamp}] {text}\n"))

    def _do_append_log(self, text: str):
        self.log_box.insert("end", text)
        self.log_box.see("end")

    def _update_time(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.configure(text=now)
        self.after(1000, self._update_time)

    def refresh(self):
        """Refresh dashboard data."""
        stats = self.db.get_dashboard_stats()

        # ─── Rebuild KPIs ────────────────────────────────────────────────
        for w in self.kpi_frame.winfo_children():
            w.destroy()

        kpis = [
            ("Total CVEs",    stats.get("total_cves", 0),     COLORS["accent_primary"], "🛡️"),
            ("Critical",      stats.get("critical_cves", 0),  COLORS["severity_critical"], "🔴"),
            ("High",          stats.get("high_cves", 0),      COLORS["severity_high"], "🟠"),
            ("Medium",        stats.get("medium_cves", 0),    COLORS["severity_medium"], "🟡"),
            ("Exploits",      stats.get("total_exploits", 0), COLORS["warning"], "⚡"),
            ("Detections",    stats.get("total_detections", 0), COLORS["info"], "📡"),
            ("Lab Tests",     stats.get("lab_tests", 0),      COLORS["success"], "🧪"),
        ]

        for label, value, color, icon in kpis:
            card = ctk.CTkFrame(self.kpi_frame, fg_color=COLORS["bg_card"],
                                corner_radius=12, border_width=1, border_color=COLORS["border"])
            card.pack(side="left", fill="both", expand=True, padx=3)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(padx=12, pady=10)

            top_row = ctk.CTkFrame(inner, fg_color="transparent")
            top_row.pack(fill="x")
            ctk.CTkLabel(top_row, text=icon, font=ctk.CTkFont(size=18)).pack(side="left")
            ctk.CTkLabel(top_row, text=label, font=ctk.CTkFont(size=11),
                          text_color=COLORS["text_muted"]).pack(side="left", padx=5)

            ctk.CTkLabel(inner, text=str(value),
                          font=ctk.CTkFont(size=26, weight="bold"),
                          text_color=color).pack(anchor="w")

        # ─── Severity Distribution Bars ──────────────────────────────────
        for w in self.severity_frame.winfo_children():
            w.destroy()

        total = max(stats.get("total_cves", 0), 1)
        sev_data = [
            ("CRITICAL", stats.get("critical_cves", 0), COLORS["severity_critical"]),
            ("HIGH",     stats.get("high_cves", 0),     COLORS["severity_high"]),
            ("MEDIUM",   stats.get("medium_cves", 0),   COLORS["severity_medium"]),
            ("LOW",      stats.get("low_cves", 0),      COLORS["severity_low"]),
        ]

        for sev_name, count, color in sev_data:
            row = ctk.CTkFrame(self.severity_frame, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=4)

            ctk.CTkLabel(row, text=sev_name, font=ctk.CTkFont(size=11, weight="bold"),
                          text_color=color, width=70, anchor="w").pack(side="left")

            bar_bg = ctk.CTkFrame(row, fg_color=COLORS["bg_card"], height=14, corner_radius=7)
            bar_bg.pack(side="left", fill="x", expand=True, padx=5)
            bar_bg.pack_propagate(False)

            pct = (count / total) if total > 0 else 0
            if pct > 0:
                bar_fill = ctk.CTkFrame(bar_bg, fg_color=color, corner_radius=7)
                bar_fill.place(relx=0, rely=0, relwidth=max(pct, 0.02), relheight=1)

            ctk.CTkLabel(row, text=str(count), font=ctk.CTkFont(size=11, weight="bold"),
                          text_color=COLORS["text_secondary"], width=35, anchor="e").pack(side="right")

        # ─── Source Status ───────────────────────────────────────────────
        for w in self.source_frame.winfo_children():
            w.destroy()

        sources = [
            ("NVD",        "●", COLORS["success"]),
            ("GitHub",     "●", COLORS["success"]),
            ("Exploit-DB", "●", COLORS["success"]),
            ("Sploitus",   "●", COLORS["success"]),
        ]
        for src_name, dot, color in sources:
            row = ctk.CTkFrame(self.source_frame, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=3)
            ctk.CTkLabel(row, text=dot, font=ctk.CTkFont(size=10),
                          text_color=color).pack(side="left")
            ctk.CTkLabel(row, text=f"  {src_name}", font=ctk.CTkFont(size=11),
                          text_color=COLORS["text_secondary"]).pack(side="left")
            ctk.CTkLabel(row, text="Connected", font=ctk.CTkFont(size=10),
                          text_color=COLORS["text_muted"]).pack(side="right")

        # ─── Recent CVEs ─────────────────────────────────────────────────
        for w in self.cve_scroll.winfo_children():
            w.destroy()

        recent = self.db.get_recent_cves(limit=25)
        if not recent:
            empty_frame = ctk.CTkFrame(self.cve_scroll, fg_color="transparent")
            empty_frame.pack(fill="both", expand=True, pady=40)
            ctk.CTkLabel(
                empty_frame, text="⏳",
                font=ctk.CTkFont(size=40),
            ).pack()
            ctk.CTkLabel(
                empty_frame, text="Monitoring started...\nWaiting for first sync to complete.",
                font=ctk.CTkFont(size=14), text_color=COLORS["text_muted"],
                justify="center",
            ).pack(pady=10)
        else:
            for cve in recent:
                card = CVECard(self.cve_scroll, cve, on_click=self.on_cve_click)
                card.pack(fill="x", padx=5, pady=3)
