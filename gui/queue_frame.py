"""
VulnIntel — Queue Frame
Task queue for batch processing CVEs in order — fetch, analyze, generate detections.
"""

import threading
import time
import customtkinter as ctk
from config import COLORS


class QueueFrame(ctk.CTkFrame):
    """Queue management panel for batch CVE processing."""

    def __init__(self, parent, db_manager, analyzer, sources, ai_analyzer=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.db = db_manager
        self.analyzer = analyzer
        self.sources = sources
        self.ai = ai_analyzer
        self.queue_items = []
        self.is_processing = False
        self._build()

    def _build(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))

        ctk.CTkLabel(
            header, text="📋 Processing Queue",
            font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_primary"],
        ).pack(side="left")

        # Queue status badge
        self.queue_badge = ctk.CTkLabel(
            header, text="IDLE", font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLORS["text_muted"],
            fg_color=COLORS["bg_card"], corner_radius=6, padx=10, pady=2,
        )
        self.queue_badge.pack(side="right", padx=5)

        self.queue_count_label = ctk.CTkLabel(
            header, text="0 items", font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
        )
        self.queue_count_label.pack(side="right", padx=10)

        # ─── Add to Queue Section ────────────────────────────────────────
        add_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12,
                                  border_width=1, border_color=COLORS["border"])
        add_frame.pack(fill="x", padx=20, pady=(0, 10))

        add_inner = ctk.CTkFrame(add_frame, fg_color="transparent")
        add_inner.pack(padx=15, pady=12)

        ctk.CTkLabel(add_inner, text="Add CVE:", font=ctk.CTkFont(size=13, weight="bold"),
                      text_color=COLORS["text_primary"]).pack(side="left", padx=(0, 8))

        self.cve_entry = ctk.CTkEntry(
            add_inner, width=200, font=ctk.CTkFont(family="Consolas", size=13),
            placeholder_text="CVE-2024-XXXXX",
            fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
            border_width=1, corner_radius=8,
        )
        self.cve_entry.pack(side="left", padx=5)
        self.cve_entry.bind("<Return>", lambda e: self._add_to_queue())

        # Processing options
        ctk.CTkLabel(add_inner, text="Actions:", font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"]).pack(side="left", padx=(15, 5))

        self.opt_fetch = ctk.CTkCheckBox(add_inner, text="Fetch", font=ctk.CTkFont(size=11),
                                          text_color=COLORS["text_primary"],
                                          fg_color=COLORS["accent_primary"],
                                          hover_color=COLORS["accent_secondary"])
        self.opt_fetch.pack(side="left", padx=3)
        self.opt_fetch.select()

        self.opt_exploit = ctk.CTkCheckBox(add_inner, text="Exploits", font=ctk.CTkFont(size=11),
                                            text_color=COLORS["text_primary"],
                                            fg_color="#f59e0b", hover_color="#fbbf24")
        self.opt_exploit.pack(side="left", padx=3)
        self.opt_exploit.select()

        self.opt_sigma = ctk.CTkCheckBox(add_inner, text="Sigma", font=ctk.CTkFont(size=11),
                                          text_color=COLORS["text_primary"],
                                          fg_color="#6366f1", hover_color="#818cf8")
        self.opt_sigma.pack(side="left", padx=3)
        self.opt_sigma.select()

        self.opt_yara = ctk.CTkCheckBox(add_inner, text="YARA", font=ctk.CTkFont(size=11),
                                         text_color=COLORS["text_primary"],
                                         fg_color="#ec4899", hover_color="#f472b6")
        self.opt_yara.pack(side="left", padx=3)
        self.opt_yara.select()

        self.opt_report = ctk.CTkCheckBox(add_inner, text="Report", font=ctk.CTkFont(size=11),
                                           text_color=COLORS["text_primary"],
                                           fg_color=COLORS["info"], hover_color="#38bdf8")
        self.opt_report.pack(side="left", padx=3)

        ctk.CTkButton(add_inner, text="➕ Add", width=70, height=30,
                       fg_color=COLORS["accent_primary"], hover_color=COLORS["accent_secondary"],
                       text_color="#000", font=ctk.CTkFont(size=12, weight="bold"),
                       corner_radius=8, command=self._add_to_queue).pack(side="left", padx=(10, 0))

        # Bulk add
        row2 = ctk.CTkFrame(add_frame, fg_color="transparent")
        row2.pack(fill="x", padx=15, pady=(0, 12))

        ctk.CTkButton(row2, text="Add All DB CVEs", width=130, height=28,
                       fg_color=COLORS["bg_tertiary"], hover_color=COLORS["bg_card_hover"],
                       text_color=COLORS["text_primary"], font=ctk.CTkFont(size=11),
                       corner_radius=6, command=self._add_all_from_db).pack(side="left", padx=3)

        ctk.CTkButton(row2, text="Add Critical Only", width=130, height=28,
                       fg_color=COLORS["severity_critical"], hover_color="#dc2626",
                       text_color="#fff", font=ctk.CTkFont(size=11),
                       corner_radius=6, command=self._add_critical).pack(side="left", padx=3)

        ctk.CTkButton(row2, text="Clear Queue", width=100, height=28,
                       fg_color=COLORS["bg_tertiary"], hover_color=COLORS["error"],
                       text_color=COLORS["text_secondary"], font=ctk.CTkFont(size=11),
                       corner_radius=6, command=self._clear_queue).pack(side="right", padx=3)

        # ─── Control Buttons ─────────────────────────────────────────────
        ctrl = ctk.CTkFrame(self, fg_color="transparent")
        ctrl.pack(fill="x", padx=20, pady=(0, 10))

        self.start_btn = ctk.CTkButton(
            ctrl, text="▶  Start Processing", height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["success"], hover_color="#16a34a",
            text_color="#fff", corner_radius=10,
            command=self._start_processing,
        )
        self.start_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = ctk.CTkButton(
            ctrl, text="⏹  Stop", height=40, width=100,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["error"], hover_color="#dc2626",
            text_color="#fff", corner_radius=10,
            state="disabled", command=self._stop_processing,
        )
        self.stop_btn.pack(side="left", padx=3)

        # Progress bar
        self.progress = ctk.CTkProgressBar(
            ctrl, fg_color=COLORS["bg_card"], progress_color=COLORS["accent_primary"],
            height=12, corner_radius=6,
        )
        self.progress.pack(side="left", fill="x", expand=True, padx=(15, 0))
        self.progress.set(0)

        # ─── Queue List + Log ────────────────────────────────────────────
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Queue items list
        left = ctk.CTkFrame(content, fg_color="transparent")
        left.pack(side="left", fill="both", expand=False, padx=(0, 10))

        ctk.CTkLabel(left, text="Queue Items", font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=COLORS["text_primary"]).pack(anchor="w", pady=(0, 5))

        self.queue_list = ctk.CTkScrollableFrame(
            left, fg_color=COLORS["bg_secondary"], corner_radius=10,
            width=420, border_width=1, border_color=COLORS["border"],
        )
        self.queue_list.pack(fill="both", expand=True)

        # Processing log
        right = ctk.CTkFrame(content, fg_color="transparent")
        right.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(right, text="Processing Log", font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=COLORS["text_primary"]).pack(anchor="w", pady=(0, 5))

        self.log_view = ctk.CTkTextbox(
            right, fg_color=COLORS["bg_secondary"], corner_radius=10,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_secondary"],
            border_width=1, border_color=COLORS["border"],
        )
        self.log_view.pack(fill="both", expand=True)

        self._update_queue_display()

    def _add_to_queue(self):
        cve_id = self.cve_entry.get().strip().upper()
        if not cve_id:
            return
        # Avoid duplicates
        if any(item["cve_id"] == cve_id for item in self.queue_items):
            return

        actions = []
        if self.opt_fetch.get():
            actions.append("fetch")
        if self.opt_exploit.get():
            actions.append("exploits")
        if self.opt_sigma.get():
            actions.append("sigma")
        if self.opt_yara.get():
            actions.append("yara")
        if self.opt_report.get():
            actions.append("report")

        self.queue_items.append({
            "cve_id": cve_id,
            "actions": actions,
            "status": "pending",
            "progress": "",
        })
        self.cve_entry.delete(0, "end")
        self._update_queue_display()

    def _add_all_from_db(self):
        cves = self.db.get_all_cves(limit=50)
        for cve in cves:
            cve_id = cve.get("cve_id", "")
            if cve_id and not any(item["cve_id"] == cve_id for item in self.queue_items):
                self.queue_items.append({
                    "cve_id": cve_id,
                    "actions": ["exploits", "sigma", "yara"],
                    "status": "pending",
                    "progress": "",
                })
        self._update_queue_display()

    def _add_critical(self):
        cves = self.db.get_cves_by_severity("CRITICAL", limit=50)
        cves += self.db.get_cves_by_severity("HIGH", limit=50)
        for cve in cves:
            cve_id = cve.get("cve_id", "")
            if cve_id and not any(item["cve_id"] == cve_id for item in self.queue_items):
                self.queue_items.append({
                    "cve_id": cve_id,
                    "actions": ["fetch", "exploits", "sigma", "yara", "report"],
                    "status": "pending",
                    "progress": "",
                })
        self._update_queue_display()

    def _clear_queue(self):
        self.queue_items = [item for item in self.queue_items if item["status"] == "processing"]
        self._update_queue_display()

    def _update_queue_display(self):
        for w in self.queue_list.winfo_children():
            w.destroy()

        pending = sum(1 for i in self.queue_items if i["status"] == "pending")
        done = sum(1 for i in self.queue_items if i["status"] == "done")
        total = len(self.queue_items)

        self.queue_count_label.configure(text=f"{total} items ({pending} pending, {done} done)")

        if not self.queue_items:
            ctk.CTkLabel(self.queue_list, text="Queue is empty.\nAdd CVE IDs to begin batch processing.",
                          font=ctk.CTkFont(size=13), text_color=COLORS["text_muted"]).pack(pady=40)
            return

        for i, item in enumerate(self.queue_items):
            status = item["status"]
            status_icons = {"pending": "⏳", "processing": "🔄", "done": "✅", "error": "❌"}
            status_colors = {"pending": COLORS["text_muted"], "processing": COLORS["info"],
                              "done": COLORS["success"], "error": COLORS["error"]}

            row = ctk.CTkFrame(self.queue_list, fg_color=COLORS["bg_card"], corner_radius=8,
                                border_width=1,
                                border_color=COLORS["border_active"] if status == "processing" else COLORS["border"])
            row.pack(fill="x", pady=2, padx=2)

            inner = ctk.CTkFrame(row, fg_color="transparent")
            inner.pack(fill="x", padx=10, pady=5)

            # Order number
            ctk.CTkLabel(inner, text=f"#{i+1}", font=ctk.CTkFont(size=11, weight="bold"),
                          text_color=COLORS["text_muted"], width=30).pack(side="left")

            # Status icon
            ctk.CTkLabel(inner, text=status_icons.get(status, "❓"),
                          font=ctk.CTkFont(size=14)).pack(side="left", padx=3)

            # CVE ID
            ctk.CTkLabel(inner, text=item["cve_id"],
                          font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                          text_color=COLORS["accent_primary"]).pack(side="left", padx=5)

            # Actions tags
            for action in item.get("actions", [])[:4]:
                tag_colors = {"fetch": COLORS["info"], "exploits": "#f59e0b",
                               "sigma": "#6366f1", "yara": "#ec4899", "report": COLORS["accent_primary"]}
                tag = ctk.CTkLabel(inner, text=action, font=ctk.CTkFont(size=9),
                                    text_color="#fff", fg_color=tag_colors.get(action, COLORS["text_muted"]),
                                    corner_radius=4, padx=4, pady=1)
                tag.pack(side="left", padx=1)

            # Status text
            progress_text = item.get("progress", status)
            ctk.CTkLabel(inner, text=progress_text, font=ctk.CTkFont(size=10),
                          text_color=status_colors.get(status, COLORS["text_muted"])).pack(side="right")

    def _log(self, text: str):
        self.after(0, lambda: self._do_log(text))

    def _do_log(self, text: str):
        self.log_view.insert("end", f"{text}\n")
        self.log_view.see("end")

    def _start_processing(self):
        if self.is_processing:
            return
        pending = [i for i in self.queue_items if i["status"] == "pending"]
        if not pending:
            return

        self.is_processing = True
        self.start_btn.configure(state="disabled", text="⏳ Processing...")
        self.stop_btn.configure(state="normal")
        self.queue_badge.configure(text="PROCESSING", text_color=COLORS["info"],
                                    fg_color=COLORS["bg_tertiary"])

        thread = threading.Thread(target=self._process_queue, daemon=True)
        thread.start()

    def _stop_processing(self):
        self.is_processing = False
        self.after(0, lambda: self.start_btn.configure(state="normal", text="▶  Start Processing"))
        self.after(0, lambda: self.stop_btn.configure(state="disabled"))
        self.after(0, lambda: self.queue_badge.configure(text="STOPPED", text_color=COLORS["warning"]))

    def _process_queue(self):
        from generators.sigma_generator import generate_sigma_rule
        from generators.yara_generator import generate_yara_rule
        from generators.ioc_generator import generate_ioc_summary, format_ioc_text
        from generators.report_generator import generate_full_report
        import os
        from config import EXPORTS_DIR

        pending = [i for i in self.queue_items if i["status"] == "pending"]
        total = len(pending)

        for idx, item in enumerate(pending):
            if not self.is_processing:
                break

            cve_id = item["cve_id"]
            item["status"] = "processing"
            item["progress"] = "Starting..."
            self.after(0, self._update_queue_display)
            self.after(0, lambda: self.progress.set((idx) / total))
            self._log(f"━━━ Processing [{idx+1}/{total}] {cve_id} ━━━")

            try:
                # Step 1: Fetch from sources
                if "fetch" in item["actions"]:
                    item["progress"] = "Fetching..."
                    self.after(0, self._update_queue_display)
                    self._log(f"  ⟶ Fetching {cve_id} from NVD...")
                    try:
                        results = self.sources["nvd"].search(cve_id, limit=1)
                        if results:
                            self.analyzer.store_source_results(results)
                            self._log(f"  ✓ NVD data stored")
                    except Exception as e:
                        self._log(f"  ✗ NVD fetch error: {str(e)[:60]}")

                # Step 2: Search exploits
                if "exploits" in item["actions"]:
                    item["progress"] = "Searching exploits..."
                    self.after(0, self._update_queue_display)
                    for src_name in ("exploitdb", "sploitus"):
                        try:
                            src = self.sources.get(src_name)
                            if src:
                                self._log(f"  ⟶ Searching {src_name} for exploits...")
                                exploits = src.search(cve_id, limit=5)
                                
                                # Fallback if cve_id is multiple words and fails
                                if not exploits and len(cve_id.split("-")) > 3:
                                    pass # For CVE IDs we don't truncate
                                elif not exploits and len(cve_id.split()) > 1:
                                    short_cve = " ".join(cve_id.split()[:2])
                                    self._log(f"  ⚠️ No results for full name. Retrying with '{short_cve}'...")
                                    exploits = src.search(short_cve, limit=5)
                                    
                                for exp in exploits:
                                    if exp.get("exploit_url"):
                                        exp["cve_id"] = cve_id
                                        self.db.add_exploit(exp)
                                self._log(f"  ✓ Found {len(exploits)} from {src_name}")
                        except Exception as e:
                            self._log(f"  ✗ {src_name} error: {str(e)[:60]}")

                # Get CVE data for rule generation
                cve = self.db.get_cve(cve_id) or {"cve_id": cve_id, "description": "", "severity": "MEDIUM", "cvss_score": 5.0}

                # Step 3: Sigma rule
                if "sigma" in item["actions"]:
                    item["progress"] = "Generating Sigma..."
                    self.after(0, self._update_queue_display)
                    try:
                        rule = generate_sigma_rule(cve)
                        self.db.add_detection({"cve_id": cve_id, "detection_type": "sigma",
                                                "rule_name": f"Sigma_{cve_id}", "rule_content": rule})
                        self._log(f"  ✓ Sigma rule generated")
                    except Exception as e:
                        self._log(f"  ✗ Sigma error: {str(e)[:60]}")

                # Step 4: YARA rule
                if "yara" in item["actions"]:
                    item["progress"] = "Generating YARA..."
                    self.after(0, self._update_queue_display)
                    try:
                        rule = generate_yara_rule(cve)
                        self.db.add_detection({"cve_id": cve_id, "detection_type": "yara",
                                                "rule_name": f"YARA_{cve_id}", "rule_content": rule})
                        self._log(f"  ✓ YARA rule generated")
                    except Exception as e:
                        self._log(f"  ✗ YARA error: {str(e)[:60]}")

                # Step 5: Report
                if "report" in item["actions"]:
                    item["progress"] = "Generating report..."
                    self.after(0, self._update_queue_display)
                    try:
                        exploits = self.db.get_exploits_for_cve(cve_id)
                        refs = self.db.get_references(cve_id)
                        dets = self.db.get_detections_for_cve(cve_id)
                        report = generate_full_report(cve, exploits, refs, dets)
                        os.makedirs(EXPORTS_DIR, exist_ok=True)
                        with open(os.path.join(EXPORTS_DIR, f"report_{cve_id}.md"), "w", encoding="utf-8") as f:
                            f.write(report)
                        self._log(f"  ✓ Report exported")
                    except Exception as e:
                        self._log(f"  ✗ Report error: {str(e)[:60]}")

                item["status"] = "done"
                item["progress"] = "Complete"
                self._log(f"  ✅ {cve_id} — All tasks complete")

            except Exception as e:
                item["status"] = "error"
                item["progress"] = str(e)[:40]
                self._log(f"  ❌ {cve_id} — Error: {e}")

            self.after(0, self._update_queue_display)
            time.sleep(0.5)

        self.after(0, lambda: self.progress.set(1.0))
        self.is_processing = False
        self.after(0, lambda: self.start_btn.configure(state="normal", text="▶  Start Processing"))
        self.after(0, lambda: self.stop_btn.configure(state="disabled"))
        self.after(0, lambda: self.queue_badge.configure(text="COMPLETE", text_color=COLORS["success"]))
        self._log(f"\n{'━'*50}\n✅ Queue processing complete!\n{'━'*50}")

    def refresh(self):
        self._update_queue_display()
