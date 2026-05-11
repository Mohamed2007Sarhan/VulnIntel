"""
VulnIntel — CVE Browser Frame
Searchable, filterable CVE listing with detail view.
"""

import json
import customtkinter as ctk
from config import COLORS, SEVERITY_MAP
from gui.components.search_bar import SearchBar


class CVEBrowserFrame(ctk.CTkFrame):
    """CVE search and browsing panel."""

    def __init__(self, parent, db_manager, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.db = db_manager
        self.selected_cve = None
        self._build()

    def _build(self):
        # Title
        ctk.CTkLabel(
            self, text="🔍 CVE Browser",
            font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_primary"],
        ).pack(anchor="w", padx=20, pady=(20, 10))

        # Search bar
        self.search = SearchBar(self, command=self._on_search)
        self.search.pack(fill="x", padx=20, pady=(0, 10))

        # Filter row
        filter_frame = ctk.CTkFrame(self, fg_color="transparent")
        filter_frame.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(filter_frame, text="Filter:", font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"]).pack(side="left", padx=(0, 8))

        self.severity_filter = ctk.CTkComboBox(
            filter_frame, values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            width=120, font=ctk.CTkFont(size=12), command=self._on_filter,
            fg_color=COLORS["bg_card"], border_color=COLORS["border"],
        )
        self.severity_filter.set("All")
        self.severity_filter.pack(side="left", padx=4)

        self.exploit_filter = ctk.CTkComboBox(
            filter_frame, values=["All", "With Exploit", "No Exploit"],
            width=140, font=ctk.CTkFont(size=12), command=self._on_filter,
            fg_color=COLORS["bg_card"], border_color=COLORS["border"],
        )
        self.exploit_filter.set("All")
        self.exploit_filter.pack(side="left", padx=4)

        # Content area: List + Detail
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # CVE List (left)
        self.list_frame = ctk.CTkScrollableFrame(
            content, fg_color=COLORS["bg_secondary"], corner_radius=10,
            width=420, border_width=1, border_color=COLORS["border"],
        )
        self.list_frame.pack(side="left", fill="both", expand=False, padx=(0, 10))

        # Detail panel (right)
        self.detail_frame = ctk.CTkScrollableFrame(
            content, fg_color=COLORS["bg_secondary"], corner_radius=10,
            border_width=1, border_color=COLORS["border"],
        )
        self.detail_frame.pack(side="left", fill="both", expand=True)

        self._show_placeholder_detail()
        self.refresh()

    def refresh(self):
        """Reload CVE list from database."""
        self._load_cves(self.db.get_all_cves(limit=200))

    def _on_search(self, query: str):
        results = self.db.search_cves(query)
        self._load_cves(results)

    def _on_filter(self, *args):
        severity = self.severity_filter.get()
        exploit = self.exploit_filter.get()

        if severity != "All":
            cves = self.db.get_cves_by_severity(severity)
        else:
            cves = self.db.get_all_cves(limit=200)

        if exploit == "With Exploit":
            cves = [c for c in cves if c.get("has_public_exploit")]
        elif exploit == "No Exploit":
            cves = [c for c in cves if not c.get("has_public_exploit")]

        self._load_cves(cves)

    def _load_cves(self, cves):
        for w in self.list_frame.winfo_children():
            w.destroy()

        if not cves:
            ctk.CTkLabel(
                self.list_frame, text="No CVEs found.", font=ctk.CTkFont(size=14),
                text_color=COLORS["text_muted"],
            ).pack(pady=40)
            return

        for cve in cves:
            row = ctk.CTkFrame(self.list_frame, fg_color=COLORS["bg_card"],
                                corner_radius=8, cursor="hand2",
                                border_width=1, border_color=COLORS["border"])
            row.pack(fill="x", pady=2, padx=2)
            row.bind("<Button-1>", lambda e, c=cve: self._select_cve(c))

            sev = (cve.get("severity", "NONE") or "NONE").upper()
            sev_info = SEVERITY_MAP.get(sev, SEVERITY_MAP["NONE"])

            top_r = ctk.CTkFrame(row, fg_color="transparent")
            top_r.pack(fill="x", padx=8, pady=4)
            top_r.bind("<Button-1>", lambda e, c=cve: self._select_cve(c))

            id_lbl = ctk.CTkLabel(top_r, text=cve.get("cve_id", ""),
                                   font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                                   text_color=COLORS["accent_primary"])
            id_lbl.pack(side="left")
            id_lbl.bind("<Button-1>", lambda e, c=cve: self._select_cve(c))

            score_lbl = ctk.CTkLabel(top_r, text=f"{sev_info['icon']} {cve.get('cvss_score', 0.0)}",
                                      font=ctk.CTkFont(size=11), text_color=sev_info["color"])
            score_lbl.pack(side="right")
            score_lbl.bind("<Button-1>", lambda e, c=cve: self._select_cve(c))

            desc = (cve.get("description", "") or "")[:80]
            desc_lbl = ctk.CTkLabel(row, text=desc + "..." if len(desc) >= 80 else desc,
                                     font=ctk.CTkFont(size=11), text_color=COLORS["text_muted"],
                                     anchor="w", justify="left", wraplength=380)
            desc_lbl.pack(fill="x", padx=8, pady=(0, 4))
            desc_lbl.bind("<Button-1>", lambda e, c=cve: self._select_cve(c))

    def _select_cve(self, cve):
        self.selected_cve = cve
        self._show_detail(cve)

    def _show_placeholder_detail(self):
        for w in self.detail_frame.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self.detail_frame, text="Select a CVE to view details",
            font=ctk.CTkFont(size=16), text_color=COLORS["text_muted"],
        ).pack(pady=100)

    def _show_detail(self, cve):
        for w in self.detail_frame.winfo_children():
            w.destroy()

        cve_id = cve.get("cve_id", "N/A")
        sev = (cve.get("severity", "NONE") or "NONE").upper()
        sev_info = SEVERITY_MAP.get(sev, SEVERITY_MAP["NONE"])

        # Header
        ctk.CTkLabel(
            self.detail_frame, text=cve_id,
            font=ctk.CTkFont(family="Consolas", size=22, weight="bold"),
            text_color=COLORS["accent_primary"],
        ).pack(anchor="w", padx=15, pady=(15, 5))

        # Severity + CVSS
        info_frame = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        info_frame.pack(fill="x", padx=15, pady=5)

        sev_pill = ctk.CTkFrame(info_frame, fg_color=sev_info["color"], corner_radius=6)
        sev_pill.pack(side="left")
        ctk.CTkLabel(sev_pill, text=f"{sev_info['icon']} {sev}",
                      font=ctk.CTkFont(size=12, weight="bold"),
                      text_color="#fff").pack(padx=8, pady=2)

        ctk.CTkLabel(info_frame, text=f"CVSS: {cve.get('cvss_score', 0.0)}",
                      font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=sev_info["color"]).pack(side="left", padx=10)

        if cve.get("has_public_exploit"):
            ctk.CTkLabel(info_frame, text="⚡ Exploit Available",
                          font=ctk.CTkFont(size=12), text_color=COLORS["warning"]).pack(side="left", padx=10)

        # Description
        ctk.CTkLabel(
            self.detail_frame, text="Description",
            font=ctk.CTkFont(size=14, weight="bold"), text_color=COLORS["text_primary"],
        ).pack(anchor="w", padx=15, pady=(15, 3))

        ctk.CTkLabel(
            self.detail_frame, text=cve.get("description", "N/A"),
            font=ctk.CTkFont(size=12), text_color=COLORS["text_secondary"],
            wraplength=500, anchor="w", justify="left",
        ).pack(anchor="w", padx=15, pady=(0, 10))

        # Affected Products
        products = cve.get("affected_products", "[]")
        if isinstance(products, str):
            try:
                products = json.loads(products)
            except Exception:
                products = []
        if products:
            ctk.CTkLabel(self.detail_frame, text="Affected Products",
                          font=ctk.CTkFont(size=14, weight="bold"),
                          text_color=COLORS["text_primary"]).pack(anchor="w", padx=15, pady=(10, 3))
            for p in products[:10]:
                ctk.CTkLabel(self.detail_frame, text=f"  • {p}",
                              font=ctk.CTkFont(size=12), text_color=COLORS["text_secondary"]
                              ).pack(anchor="w", padx=15)

        # Metadata
        ctk.CTkLabel(self.detail_frame, text="Metadata",
                      font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=COLORS["text_primary"]).pack(anchor="w", padx=15, pady=(15, 3))
        meta_items = [
            ("Published", cve.get("published_date", "N/A")),
            ("Last Modified", cve.get("last_modified", "N/A")),
            ("Source", cve.get("source", "N/A")),
            ("CVSS Vector", cve.get("cvss_vector", "N/A")),
            ("Exploit Maturity", cve.get("exploit_maturity", "none").title()),
            ("Patch Available", "Yes" if cve.get("patch_available") else "No"),
        ]
        for label, val in meta_items:
            row = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
            row.pack(fill="x", padx=15)
            ctk.CTkLabel(row, text=f"{label}:", font=ctk.CTkFont(size=12, weight="bold"),
                          text_color=COLORS["text_secondary"], width=130, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(val), font=ctk.CTkFont(size=12),
                          text_color=COLORS["text_primary"]).pack(side="left")
