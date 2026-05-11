"""
VulnIntel — Detection Rules Frame
Panel for generating and viewing Sigma/YARA/IOC rules.
"""

import customtkinter as ctk
from config import COLORS
from generators.sigma_generator import generate_sigma_rule
from generators.yara_generator import generate_yara_rule
from generators.ioc_generator import generate_ioc_summary, format_ioc_text


class DetectionFrame(ctk.CTkFrame):
    """Detection rule generation and browsing panel."""

    def __init__(self, parent, db_manager, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.db = db_manager
        self._build()

    def _build(self):
        ctk.CTkLabel(
            self, text="📡 Detection Rules",
            font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_primary"],
        ).pack(anchor="w", padx=20, pady=(20, 10))

        # Generate controls
        gen_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=10,
                                  border_width=1, border_color=COLORS["border"])
        gen_frame.pack(fill="x", padx=20, pady=(0, 10))

        inner = ctk.CTkFrame(gen_frame, fg_color="transparent")
        inner.pack(padx=15, pady=10)

        ctk.CTkLabel(inner, text="CVE ID:", font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"]).pack(side="left", padx=(0, 5))
        self.cve_entry = ctk.CTkEntry(inner, width=180, font=ctk.CTkFont(family="Consolas", size=12),
                                       placeholder_text="CVE-2024-XXXXX",
                                       fg_color=COLORS["bg_secondary"], border_color=COLORS["border"])
        self.cve_entry.pack(side="left", padx=5)

        ctk.CTkButton(inner, text="Sigma", width=80, fg_color="#6366f1",
                       hover_color="#818cf8", command=self._gen_sigma,
                       font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=3)
        ctk.CTkButton(inner, text="YARA", width=80, fg_color="#ec4899",
                       hover_color="#f472b6", command=self._gen_yara,
                       font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=3)
        ctk.CTkButton(inner, text="IOC", width=80, fg_color="#f59e0b",
                       hover_color="#fbbf24", text_color="#000",
                       command=self._gen_ioc,
                       font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=3)
        ctk.CTkButton(inner, text="All", width=60, fg_color=COLORS["accent_primary"],
                       hover_color=COLORS["accent_secondary"], text_color="#000",
                       command=self._gen_all,
                       font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=3)

        # Content: rule list + viewer
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Rule list
        self.rule_list = ctk.CTkScrollableFrame(content, fg_color=COLORS["bg_secondary"],
                                                  corner_radius=10, width=300,
                                                  border_width=1, border_color=COLORS["border"])
        self.rule_list.pack(side="left", fill="both", expand=False, padx=(0, 10))

        # Rule viewer
        self.viewer = ctk.CTkTextbox(content, fg_color=COLORS["bg_secondary"],
                                      corner_radius=10, font=ctk.CTkFont(family="Consolas", size=12),
                                      text_color=COLORS["text_primary"],
                                      border_width=1, border_color=COLORS["border"])
        self.viewer.pack(side="left", fill="both", expand=True)

        self.refresh()

    def refresh(self):
        detections = self.db.get_all_detections(limit=100)
        self._load_rules(detections)

    def _load_rules(self, detections):
        for w in self.rule_list.winfo_children():
            w.destroy()

        if not detections:
            ctk.CTkLabel(self.rule_list, text="No detection rules yet.\nEnter a CVE ID and click Generate.",
                          font=ctk.CTkFont(size=12), text_color=COLORS["text_muted"]).pack(pady=40)
            return

        type_colors = {"sigma": "#6366f1", "yara": "#ec4899", "ioc": "#f59e0b"}
        for det in detections:
            row = ctk.CTkFrame(self.rule_list, fg_color=COLORS["bg_card"], corner_radius=6,
                                cursor="hand2", border_width=1, border_color=COLORS["border"])
            row.pack(fill="x", pady=2, padx=2)
            row.bind("<Button-1>", lambda e, d=det: self._show_rule(d))

            top = ctk.CTkFrame(row, fg_color="transparent")
            top.pack(fill="x", padx=6, pady=3)
            top.bind("<Button-1>", lambda e, d=det: self._show_rule(d))

            det_type = det.get("detection_type", "")
            color = type_colors.get(det_type, COLORS["text_muted"])
            lbl = ctk.CTkLabel(top, text=det_type.upper(), font=ctk.CTkFont(size=10, weight="bold"),
                                text_color=color)
            lbl.pack(side="left")
            lbl.bind("<Button-1>", lambda e, d=det: self._show_rule(d))

            name = ctk.CTkLabel(top, text=det.get("rule_name", ""), font=ctk.CTkFont(size=11),
                                 text_color=COLORS["text_secondary"])
            name.pack(side="left", padx=5)
            name.bind("<Button-1>", lambda e, d=det: self._show_rule(d))

    def _show_rule(self, detection):
        self.viewer.delete("1.0", "end")
        self.viewer.insert("1.0", detection.get("rule_content", ""))

    def _get_cve_data(self):
        cve_id = self.cve_entry.get().strip().upper()
        if not cve_id:
            return None, None
        cve = self.db.get_cve(cve_id)
        if not cve:
            cve = {"cve_id": cve_id, "description": "CVE not in local database", "severity": "MEDIUM", "cvss_score": 5.0}
        return cve_id, cve

    def _gen_sigma(self):
        cve_id, cve = self._get_cve_data()
        if not cve:
            return
        rule = generate_sigma_rule(cve)
        self.db.add_detection({"cve_id": cve_id, "detection_type": "sigma",
                                "rule_name": f"Sigma_{cve_id}", "rule_content": rule, "confidence": "medium"})
        self.viewer.delete("1.0", "end")
        self.viewer.insert("1.0", rule)
        self.refresh()

    def _gen_yara(self):
        cve_id, cve = self._get_cve_data()
        if not cve:
            return
        rule = generate_yara_rule(cve)
        self.db.add_detection({"cve_id": cve_id, "detection_type": "yara",
                                "rule_name": f"YARA_{cve_id}", "rule_content": rule, "confidence": "medium"})
        self.viewer.delete("1.0", "end")
        self.viewer.insert("1.0", rule)
        self.refresh()

    def _gen_ioc(self):
        cve_id, cve = self._get_cve_data()
        if not cve:
            return
        refs = self.db.get_references(cve_id)
        exploits = self.db.get_exploits_for_cve(cve_id)
        ioc = generate_ioc_summary(cve, refs, exploits)
        text = format_ioc_text(ioc)
        self.db.add_detection({"cve_id": cve_id, "detection_type": "ioc",
                                "rule_name": f"IOC_{cve_id}", "rule_content": text, "confidence": "medium"})
        self.viewer.delete("1.0", "end")
        self.viewer.insert("1.0", text)
        self.refresh()

    def _gen_all(self):
        self._gen_sigma()
        self._gen_yara()
        self._gen_ioc()
