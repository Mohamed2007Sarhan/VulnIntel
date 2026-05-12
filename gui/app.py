"""
VulnIntel — Main GUI Application v2.0
Full autonomous monitoring pipeline + Public Search + Queue.
Monitoring never stops until manually stopped.
"""

import threading
import time
import logging
import customtkinter as ctk

from config import (COLORS, APPEARANCE_MODE, COLOR_THEME,
                    APP_NAME, APP_VERSION, WINDOW_SIZE, MIN_WINDOW_SIZE, DB_PATH,
                    DEFAULT_SYNC_INTERVAL)
from database.models import init_database
from database.db_manager import DatabaseManager
from lab.lab_manager import LabManager
from analysis.cve_analyzer import CVEAnalyzer
from analysis.ai_analyzer import AIAnalyzer
from sources.nvd_source import NVDSource
from sources.github_advisories import GitHubAdvisoriesSource
from sources.exploitdb_source import ExploitDBSource
from sources.sploitus_source import SploitusSource

from gui.dashboard_frame import DashboardFrame
from gui.cve_browser_frame import CVEBrowserFrame
from gui.exploit_frame import ExploitFrame
from gui.detection_frame import DetectionFrame
from gui.lab_frame import LabFrame
from gui.reports_frame import ReportsFrame
from gui.settings_frame import SettingsFrame
from gui.queue_frame import QueueFrame
from gui.target_analysis_frame import TargetAnalysisFrame
from gui.public_search_frame import PublicSearchFrame

logger = logging.getLogger(__name__)


class VulnIntelApp(ctk.CTk):
    """Main application window with autonomous monitoring pipeline."""

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode(APPEARANCE_MODE)
        ctk.set_default_color_theme(COLOR_THEME)

        self.title(f"{APP_NAME} v{APP_VERSION} — Defensive Vulnerability Intelligence")
        self.geometry(WINDOW_SIZE)
        self.minsize(*MIN_WINDOW_SIZE)
        self.configure(fg_color=COLORS["bg_primary"])

        # DB Rotation Mechanism
        import os
        from datetime import datetime
        if os.path.exists(DB_PATH):
            db_size_mb = os.path.getsize(DB_PATH) / (1024 * 1024)
            if db_size_mb > 50.0:  # Rotate if DB > 50 MB
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                archive_path = DB_PATH.replace(".db", f"_{timestamp}.db")
                os.rename(DB_PATH, archive_path)
                logger.info(f"Database size ({db_size_mb:.1f} MB) exceeded limit. Rotated to {archive_path}")

        # Core systems
        self.conn = init_database(DB_PATH)
        self.db = DatabaseManager(self.conn)
        self.lab_mgr = LabManager(self.db)
        self.analyzer = CVEAnalyzer(self.db)
        self.ai_analyzer = AIAnalyzer()

        # Sources
        self.sources = {
            "nvd": NVDSource(),
            "github": GitHubAdvisoriesSource(),
            "exploitdb": ExploitDBSource(),
            "sploitus": SploitusSource(),
        }

        # Monitoring state — always on
        self._monitoring = True
        self._monitor_thread = None
        self._sync_cycle = 0
        self._is_syncing = False

        self.current_frame_name = None
        self._build_ui()
        self._show_frame("dashboard")

        # Auto-start the full pipeline
        self.after(1000, self._start_pipeline)

    def _build_ui(self):
        """Build the main UI layout."""
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True)

        # ─── Sidebar ─────────────────────────────────────────────────────
        self.sidebar = ctk.CTkFrame(
            self.main_container, fg_color=COLORS["bg_secondary"],
            width=240, corner_radius=0,
            border_width=1, border_color=COLORS["border"],
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Logo header
        logo_bg = ctk.CTkFrame(self.sidebar, fg_color=COLORS["bg_tertiary"],
                                corner_radius=0, height=75)
        logo_bg.pack(fill="x")
        logo_bg.pack_propagate(False)

        logo_inner = ctk.CTkFrame(logo_bg, fg_color="transparent")
        logo_inner.pack(expand=True)

        ctk.CTkLabel(logo_inner, text="🛡️", font=ctk.CTkFont(size=30)).pack(side="left", padx=(15, 5))
        title_col = ctk.CTkFrame(logo_inner, fg_color="transparent")
        title_col.pack(side="left")
        ctk.CTkLabel(title_col, text="VulnIntel",
                      font=ctk.CTkFont(family="Segoe UI", size=21, weight="bold"),
                      text_color=COLORS["accent_primary"]).pack(anchor="w")
        ctk.CTkLabel(title_col, text="Defensive Intelligence v2.0",
                      font=ctk.CTkFont(size=9), text_color=COLORS["text_muted"]).pack(anchor="w")

        # Accent line
        ctk.CTkFrame(self.sidebar, fg_color=COLORS["accent_primary"], height=2).pack(fill="x")

        # ─── Live Monitor Status ─────────────────────────────────────────
        self.monitor_frame = ctk.CTkFrame(self.sidebar, fg_color=COLORS["bg_card"],
                                           corner_radius=8, border_width=1,
                                           border_color=COLORS["success"])
        self.monitor_frame.pack(fill="x", padx=12, pady=(10, 4))

        m_inner = ctk.CTkFrame(self.monitor_frame, fg_color="transparent")
        m_inner.pack(padx=10, pady=6)

        self.monitor_dot = ctk.CTkLabel(m_inner, text="●", font=ctk.CTkFont(size=14),
                                         text_color=COLORS["success"], width=15)
        self.monitor_dot.pack(side="left")
        self.monitor_label = ctk.CTkLabel(m_inner, text="Pipeline: STARTING",
                                           font=ctk.CTkFont(size=11, weight="bold"),
                                           text_color=COLORS["success"])
        self.monitor_label.pack(side="left", padx=5)

        self.monitor_detail = ctk.CTkLabel(self.sidebar, text="Initializing...",
                                            font=ctk.CTkFont(size=9),
                                            text_color=COLORS["text_muted"])
        self.monitor_detail.pack(padx=15, anchor="w")

        # ─── Navigation ──────────────────────────────────────────────────
        ctk.CTkLabel(self.sidebar, text="NAVIGATION",
                      font=ctk.CTkFont(size=9, weight="bold"),
                      text_color=COLORS["text_muted"]).pack(anchor="w", padx=18, pady=(10, 4))

        self.nav_buttons = {}
        nav_items = [
            ("dashboard",       "📊  Dashboard"),
            ("cve_browser",     "🔍  CVE Browser"),
            ("exploits",        "⚡  Exploits"),
            ("public_search",   "🌐  Public Search"),
            ("target_analysis", "🎯  Target Analysis"),
            ("queue",           "📋  Queue"),
            ("detections",      "📡  Detections"),
            ("lab",             "🧪  Lab"),
            ("reports",         "📄  Reports"),
            ("settings",        "⚙️  Settings"),
        ]

        for name, label in nav_items:
            btn = ctk.CTkButton(
                self.sidebar, text=label, anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=13),
                fg_color="transparent",
                hover_color=COLORS["bg_tertiary"],
                text_color=COLORS["text_secondary"],
                height=34, corner_radius=8,
                command=lambda n=name: self._show_frame(n),
            )
            btn.pack(fill="x", padx=8, pady=1)
            self.nav_buttons[name] = btn

        # Bottom spacer
        ctk.CTkFrame(self.sidebar, fg_color="transparent").pack(fill="both", expand=True)

        # Manual sync
        self.sync_btn = ctk.CTkButton(
            self.sidebar, text="🔄  Force Sync Now",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS["accent_primary"],
            hover_color=COLORS["accent_secondary"],
            text_color="#000000", height=32, corner_radius=8,
            command=self._manual_sync,
        )
        self.sync_btn.pack(fill="x", padx=12, pady=(5, 3))

        # Stop/Start monitor toggle
        self.toggle_btn = ctk.CTkButton(
            self.sidebar, text="⏹  Stop Monitor",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=COLORS["error"], hover_color="#dc2626",
            text_color="#fff", height=28, corner_radius=8,
            command=self._toggle_monitor,
        )
        self.toggle_btn.pack(fill="x", padx=12, pady=(0, 3))

        # Status
        self.status_label = ctk.CTkLabel(
            self.sidebar, text="Starting...",
            font=ctk.CTkFont(size=10), text_color=COLORS["text_muted"],
        )
        self.status_label.pack(padx=12, pady=(0, 4))

        # Safety
        safety_frame = ctk.CTkFrame(self.sidebar, fg_color=COLORS["bg_tertiary"],
                                     corner_radius=8, border_width=1, border_color=COLORS["border"])
        safety_frame.pack(fill="x", padx=12, pady=(0, 10))
        ctk.CTkLabel(safety_frame, text="🔒 Safety: ENFORCED",
                      font=ctk.CTkFont(size=10, weight="bold"),
                      text_color=COLORS["success"]).pack(pady=4)

        # ─── Content Area ────────────────────────────────────────────────
        self.content_area = ctk.CTkFrame(
            self.main_container, fg_color=COLORS["bg_primary"], corner_radius=0,
        )
        self.content_area.pack(side="left", fill="both", expand=True)

        # Create all frames
        self.frames = {}
        self.frames["dashboard"] = DashboardFrame(
            self.content_area, self.db, on_cve_click=self._on_cve_click)
        self.frames["cve_browser"] = CVEBrowserFrame(self.content_area, self.db)
        self.frames["exploits"] = ExploitFrame(self.content_area, self.db)
        self.frames["public_search"] = PublicSearchFrame(
            self.content_area, self.db, ai_analyzer=self.ai_analyzer)
        self.frames["target_analysis"] = TargetAnalysisFrame(
            self.content_area, self.db, ai_analyzer=self.ai_analyzer)
        self.frames["queue"] = QueueFrame(
            self.content_area, self.db, self.analyzer, self.sources,
            ai_analyzer=self.ai_analyzer)
        self.frames["detections"] = DetectionFrame(self.content_area, self.db)
        self.frames["lab"] = LabFrame(self.content_area, self.db, self.lab_mgr)
        self.frames["reports"] = ReportsFrame(self.content_area, self.db)
        self.frames["settings"] = SettingsFrame(self.content_area, app_ref=self)

    def _show_frame(self, name: str):
        for nav_name, btn in self.nav_buttons.items():
            if nav_name == name:
                btn.configure(fg_color=COLORS["bg_tertiary"], text_color=COLORS["accent_primary"])
            else:
                btn.configure(fg_color="transparent", text_color=COLORS["text_secondary"])

        if self.current_frame_name and self.current_frame_name in self.frames:
            self.frames[self.current_frame_name].pack_forget()

        self.current_frame_name = name
        frame = self.frames.get(name)
        if frame:
            frame.pack(fill="both", expand=True)
            if hasattr(frame, "refresh"):
                frame.refresh()

    def _on_cve_click(self, cve_data):
        self._show_frame("cve_browser")
        browser = self.frames.get("cve_browser")
        if browser:
            browser._select_cve(cve_data)

    # ═══════════════════════════════════════════════════════════════════
    #  AUTONOMOUS PIPELINE — runs forever until manually stopped
    # ═══════════════════════════════════════════════════════════════════

    def _start_pipeline(self):
        """Start the autonomous monitoring pipeline."""
        logger.info("Starting autonomous vulnerability pipeline...")
        self._monitoring = True
        self._update_monitor("active", "Pipeline: ACTIVE", "Starting first sync cycle...")
        self._monitor_thread = threading.Thread(target=self._pipeline_loop, daemon=True)
        self._monitor_thread.start()

    def _pipeline_loop(self):
        """Main autonomous pipeline loop — never stops unless toggled off."""
        from generators.sigma_generator import generate_sigma_rule
        from generators.yara_generator import generate_yara_rule

        while self._monitoring:
            self._sync_cycle += 1
            cycle = self._sync_cycle
            self._set_detail(f"Cycle #{cycle} starting...")
            logger.info(f"Pipeline cycle #{cycle} starting")

            # ── Phase 1: Sync all sources ────────────────────────────────
            self._update_monitor("syncing", "Pipeline: SYNCING", f"Cycle #{cycle} — Fetching CVEs...")
            total_cves = 0
            total_exploits = 0
            errors = []

            for src_name, source in self.sources.items():
                if not self._monitoring:
                    return
                try:
                    self._set_detail(f"Cycle #{cycle} — Syncing {src_name}...")
                    self._set_status(f"Syncing {src_name}...")
                    results = source.fetch_recent(days_back=7, limit=40)
                    if results:
                        self.analyzer.store_source_results(results)
                        total_cves += len(results)

                    # Store exploits from exploit sources
                    if src_name in ("exploitdb", "sploitus") and results:
                        for r in results:
                            if r.get("exploit_url"):
                                self.db.add_exploit(r)
                                total_exploits += 1
                except Exception as e:
                    errors.append(src_name)
                    logger.error(f"Pipeline sync error ({src_name}): {e}")

            if self._monitoring:
                # ── Phase 2: Auto-generate detections for ALL new CVEs ───────────
                self._update_monitor("syncing", "Pipeline: DETECTIONS", f"Cycle #{cycle} — Generating rules...")
                try:
                    from generators.sigma_generator import generate_sigma_rule
                    from generators.yara_generator import generate_yara_rule
                    from generators.ioc_generator import generate_ioc_summary, format_ioc_text
                    import os
                    from config import DATA_DIR
                    det_dir = os.path.join(DATA_DIR, "detections")
                    os.makedirs(det_dir, exist_ok=True)
                    
                    all_cves = self.db.get_all_cves(limit=10000)
                    for cve in all_cves:
                        if not self._monitoring:
                            break
                        cve_id = cve.get("cve_id", "")
                        if not cve_id:
                            continue

                        existing = self.db.get_detections_for_cve(cve_id)
                        existing_types = [d.get("detection_type", "") for d in existing]

                        # Skip if we already have all 3
                        if "sigma" in existing_types and "yara" in existing_types and "ioc" in existing_types:
                            continue

                        rules_generated = 0

                        if "sigma" not in existing_types:
                            try:
                                sigma = generate_sigma_rule(cve)
                                sigma_path = os.path.join(det_dir, f"{cve_id}_sigma.yml")
                                with open(sigma_path, "w", encoding="utf-8") as f:
                                    f.write(sigma)
                                self.db.add_detection({"cve_id": cve_id, "detection_type": "sigma",
                                                        "rule_name": f"Sigma_{cve_id}", "rule_content": f"Saved to: {sigma_path}\n\n{sigma}"})
                                rules_generated += 1
                            except Exception as e:
                                logger.error(f"Sigma error for {cve_id}: {e}")

                        if "yara" not in existing_types:
                            try:
                                yara = generate_yara_rule(cve)
                                yara_path = os.path.join(det_dir, f"{cve_id}_yara.yar")
                                with open(yara_path, "w", encoding="utf-8") as f:
                                    f.write(yara)
                                self.db.add_detection({"cve_id": cve_id, "detection_type": "yara",
                                                        "rule_name": f"YARA_{cve_id}", "rule_content": f"Saved to: {yara_path}\n\n{yara}"})
                                rules_generated += 1
                            except Exception as e:
                                logger.error(f"Yara error for {cve_id}: {e}")

                        if "ioc" not in existing_types:
                            try:
                                refs = self.db.get_references(cve_id)
                                exploits = self.db.get_exploits_for_cve(cve_id)
                                ioc = generate_ioc_summary(cve, refs, exploits)
                                text = format_ioc_text(ioc)
                                ioc_path = os.path.join(det_dir, f"{cve_id}_ioc.txt")
                                with open(ioc_path, "w", encoding="utf-8") as f:
                                    f.write(text)
                                self.db.add_detection({"cve_id": cve_id, "detection_type": "ioc",
                                                        "rule_name": f"IOC_{cve_id}", "rule_content": f"Saved to: {ioc_path}\n\n{text}"})
                                rules_generated += 1
                            except Exception as e:
                                logger.error(f"IOC error for {cve_id}: {e}")
                                
                        if rules_generated > 0:
                            self._log_to_ui(f"🛡️ Generated {rules_generated} detection rules (Sigma/Yara/IOC) for {cve_id}")
                except Exception as e:
                    logger.error(f"Pipeline detection gen error: {e}")

                # ── Phase 3: AI Exploit Generation (Heavy) ───────────
                self._update_monitor("syncing", "Pipeline: EXPLOITS", f"Cycle #{cycle} — Searching exploits...")
                try:
                    import re as _re
                    all_cves = self.db.get_all_cves(limit=10000)
                    no_exploit_cves = [c for c in all_cves if not c.get("has_public_exploit")]

                    # Process all items that need exploits/AI analysis
                    for cve in no_exploit_cves:
                        if not self._monitoring:
                            return
                        cve_id = cve.get("cve_id", "")
                        if not cve_id:
                            continue

                        # Extract product keywords from description for smarter search
                        desc = (cve.get("description", "") or "")
                        search_queries = [cve_id]  # Always search by CVE ID

                        # Extract product name from affected_products
                        products = cve.get("affected_products", "")
                        if isinstance(products, str):
                            try:
                                import json
                                products = json.loads(products) if products.startswith("[") else []
                            except Exception:
                                products = []
                        if products:
                            # Use first product as keyword (e.g. "apache:http_server" -> "apache http server")
                            product_kw = str(products[0]).replace(":", " ").replace("_", " ").split("*")[0].strip()
                            if product_kw and len(product_kw) > 2:
                                search_queries.append(product_kw)

                        # Also extract known software names from description
                        known_sw = _re.findall(
                            r'\b(Apache|Nginx|WordPress|Drupal|Joomla|PHP|Python|Node\.js|Java|'
                            r'MySQL|PostgreSQL|Redis|MongoDB|Docker|Kubernetes|Jenkins|GitLab|'
                            r'Grafana|Kibana|Elasticsearch|Tomcat|Spring|Django|Flask|Laravel|'
                            r'OpenSSH|vsftpd|ProFTPD|Samba|SMB|Exchange|IIS|Oracle|SAP|'
                            r'Chrome|Firefox|Edge|Safari|Linux|Windows|macOS|Android|iOS|'
                            r'VMware|Citrix|Fortinet|Palo Alto|SonicWall|Cisco|Juniper)\b',
                            desc, _re.IGNORECASE
                        )
                        if known_sw:
                            # Add the first matched product + "exploit"
                            sw_kw = known_sw[0]
                            search_queries.append(f"{sw_kw} exploit")

                        self._set_detail(f"Cycle #{cycle} — Exploits: {cve_id} ({len(search_queries)} queries)")
                        self._log_to_ui(f"🔍 Searching Exploit-DB and Sploitus for {cve_id}...")

                        cve_exploits_found = 0
                        from concurrent.futures import ThreadPoolExecutor, as_completed

                        def search_src(src, q):
                            try:
                                return src.search(q, limit=5)
                            except Exception:
                                return []

                        with ThreadPoolExecutor(max_workers=4) as executor:
                            futures = []
                            for query in search_queries:
                                for src_name in ("exploitdb", "sploitus"):
                                    src = self.sources.get(src_name)
                                    if src:
                                        futures.append(executor.submit(search_src, src, query))
                                        
                            for future in as_completed(futures):
                                if not self._monitoring:
                                    break
                                exploits = future.result()
                                for exp in exploits:
                                    if exp.get("exploit_url"):
                                        exp["cve_id"] = cve_id
                                        
                                        # Save public exploit reference to file
                                        import os
                                        from config import DATA_DIR
                                        pub_dir = os.path.join(DATA_DIR, "public_exploits")
                                        os.makedirs(pub_dir, exist_ok=True)
                                        
                                        safe_title = "".join(c for c in str(exp.get("exploit_title", "exploit")) if c.isalnum() or c in (' ', '-', '_')).strip().replace(" ", "_")[:50]
                                        if not safe_title: safe_title = "exploit"
                                        file_path = os.path.join(pub_dir, f"{cve_id}_{exp.get('exploit_source', 'public')}_{safe_title}.txt")
                                        
                                        content = f"CVE: {cve_id}\nSource: {exp.get('exploit_source')}\nURL: {exp.get('exploit_url')}\nTitle: {exp.get('exploit_title')}\n"
                                        with open(file_path, "w", encoding="utf-8") as f:
                                            f.write(content)
                                            
                                        exp["description"] = f"{exp.get('description', '')}\n📁 Saved reference to: {file_path}"
                                        self.db.add_exploit(exp)
                                        cve_exploits_found += 1
                                        total_exploits += 1
                                        
                        if cve_exploits_found > 0:
                            self._log_to_ui(f"✅ Found {cve_exploits_found} public exploits for {cve_id} from sources!")

                        # If no exploits were found anywhere, ask AI to generate a theoretical one
                        if cve_exploits_found == 0 and self.ai_analyzer:
                            self._set_detail(f"Cycle #{cycle} — AI analyzing missing exploit for {cve_id}")
                            self._log_to_ui(f"🤖 No public exploits found for {cve_id}. Asking AI to generate a lab PoC...")
                            try:
                                ai_analysis = self.ai_analyzer.analyze_failed_exploit_search(cve, search_queries)
                                if ai_analysis and not ai_analysis.startswith("[AI Error]"):
                                    # Parse AI JSON response
                                    import os
                                    import json
                                    from config import DATA_DIR
                                    ai_dir_base = os.path.join(DATA_DIR, "ai_exploits")
                                    os.makedirs(ai_dir_base, exist_ok=True)
                                    
                                    # Create a specific folder for this CVE
                                    cve_folder = os.path.join(ai_dir_base, cve_id)
                                    os.makedirs(cve_folder, exist_ok=True)
                                    
                                    try:
                                        # Ultra-robust JSON extraction
                                        import json
                                        parsed_data = None
                                        
                                        # Attempt 1: Extract from markdown block
                                        if "```json" in ai_analysis:
                                            block = ai_analysis.split("```json")[1].split("```")[0].strip()
                                            try:
                                                parsed_data = json.loads(block)
                                            except Exception:
                                                pass
                                                
                                        # Attempt 2: Use raw_decode to parse the first JSON object and ignore surrounding text
                                        if parsed_data is None:
                                            start_idx = ai_analysis.find('{')
                                            if start_idx != -1:
                                                try:
                                                    parsed_data, _ = json.JSONDecoder().raw_decode(ai_analysis[start_idx:])
                                                except Exception:
                                                    pass
                                                    
                                        if parsed_data is None:
                                            raise json.JSONDecodeError("Could not extract valid JSON from AI response", ai_analysis, 0)
                                            
                                        # Save Markdown Analysis
                                        analysis_path = os.path.join(cve_folder, "analysis.md")
                                        with open(analysis_path, "w", encoding="utf-8") as f:
                                            f.write(parsed_data.get("analysis_markdown", "No analysis provided."))
                                            
                                        # Save PoC Script
                                        script_name = parsed_data.get("poc_script_filename", "exploit.txt")
                                        script_content = parsed_data.get("poc_script_content", "")
                                        if script_content:
                                            script_path = os.path.join(cve_folder, script_name)
                                            with open(script_path, "w", encoding="utf-8") as f:
                                                f.write(script_content)
                                                
                                        # Save Docker Compose if exists
                                        docker_content = parsed_data.get("docker_compose_content", "")
                                        if docker_content:
                                            docker_path = os.path.join(cve_folder, "docker-compose.yml")
                                            with open(docker_path, "w", encoding="utf-8") as f:
                                                f.write(docker_content)

                                        self.db.add_exploit({
                                            "cve_id": cve_id,
                                            "exploit_title": f"AI Generated Theoretical Approach for {cve_id}",
                                            "exploit_source": "ai_generated",
                                            "exploit_url": f"file:///{cve_folder.replace(chr(92), '/')}",
                                            "exploit_type": "theoretical",
                                            "platform": "multi",
                                            "description": f"AI-generated theoretical exploit. Saved to folder: {cve_folder}",
                                            "safe_for_lab": True,
                                            "raw_content": parsed_data.get("analysis_markdown", "Generated analysis.")
                                        })
                                        total_exploits += 1
                                        self._log_to_ui(f"✅ AI successfully generated an exploit approach for {cve_id}")
                                        self._log_to_ui(f"   📁 Saved to folder: {cve_folder}")
                                        
                                    except json.JSONDecodeError as e:
                                        logger.error(f"Failed to parse AI JSON for {cve_id}: {e}")
                                        # Fallback: Save the raw text if parsing fails
                                        fallback_path = os.path.join(cve_folder, "raw_output.txt")
                                        with open(fallback_path, "w", encoding="utf-8") as f:
                                            f.write(ai_analysis)
                                        self._log_to_ui(f"⚠️ AI JSON parsing failed for {cve_id}. Saved raw output to: {fallback_path}")
                                else:
                                    self._log_to_ui(f"⚠️ AI failed to generate exploit approach for {cve_id}")
                            except Exception as e:
                                logger.error(f"Failed to generate AI exploit for {cve_id}: {e}")
                                
                            # Adding a small delay to prevent rapid-firing AI requests and hitting rate limits
                            import time
                            time.sleep(10)
                            
                            # Adding a small delay to prevent rapid-firing AI requests and hitting rate limits
                            import time
                            time.sleep(10)
                            
                except Exception as e:
                    logger.error(f"Pipeline exploit search error: {e}")

            # Phase 3 (Detections) has been merged into Phase 1 to generate rules immediately per CVE.

            # ── Cycle complete — refresh UI ──────────────────────────────
            err_text = f" ({len(errors)} errors)" if errors else ""
            self._update_monitor("active", "Pipeline: ACTIVE",
                                  f"Cycle #{cycle} done — {total_cves} CVEs, {total_exploits} exploits{err_text}")
            self._set_status(f"✅ Cycle #{cycle}: {total_cves} CVEs, {total_exploits} exploits{err_text}")

            # Refresh current visible frame
            self.after(0, self._refresh_current_frame)

            logger.info(f"Pipeline cycle #{cycle} complete: {total_cves} CVEs, {total_exploits} exploits{err_text}")

            # ── Wait for next cycle ──────────────────────────────────────
            self._set_detail(f"Next sync in {DEFAULT_SYNC_INTERVAL // 60} min...")
            for i in range(DEFAULT_SYNC_INTERVAL):
                if not self._monitoring:
                    return
                time.sleep(1)
                # Update countdown every 30 seconds
                remaining = DEFAULT_SYNC_INTERVAL - i
                if remaining % 30 == 0:
                    self._set_detail(f"Next sync in {remaining // 60}m {remaining % 60}s...")

    def _toggle_monitor(self):
        """Toggle the monitoring pipeline on/off."""
        if self._monitoring:
            self._monitoring = False
            self.toggle_btn.configure(text="▶  Start Monitor", fg_color=COLORS["success"],
                                       hover_color="#16a34a")
            self._update_monitor("stopped", "Pipeline: STOPPED", "Manually stopped")
            self._set_status("⏹ Monitor stopped")
        else:
            self._monitoring = True
            self.toggle_btn.configure(text="⏹  Stop Monitor", fg_color=COLORS["error"],
                                       hover_color="#dc2626")
            self._start_pipeline()

    def _manual_sync(self):
        """Force an immediate sync cycle."""
        if self._is_syncing:
            return
        self._is_syncing = True
        self.sync_btn.configure(state="disabled", text="⏳ Syncing...")

        def _do():
            total = 0
            for name, source in self.sources.items():
                try:
                    self._set_status(f"Force syncing {name}...")
                    results = source.fetch_recent(days_back=7, limit=30)
                    if results:
                        self.analyzer.store_source_results(results)
                        total += len(results)
                    if name in ("exploitdb", "sploitus"):
                        for r in results:
                            if r.get("exploit_url"):
                                self.db.add_exploit(r)
                except Exception as e:
                    logger.error(f"Force sync error ({name}): {e}")

            self._is_syncing = False
            self.after(0, lambda: self.sync_btn.configure(state="normal", text="🔄  Force Sync Now"))
            self._set_status(f"✅ Force synced {total} items")
            self.after(0, self._refresh_current_frame)

        threading.Thread(target=_do, daemon=True).start()

    # ─── UI Helpers ──────────────────────────────────────────────────────

    def _update_monitor(self, status: str, label: str, detail: str = ""):
        colors = {"active": COLORS["success"], "syncing": COLORS["info"],
                   "stopped": COLORS["error"], "idle": COLORS["text_muted"]}
        border_color = colors.get(status, COLORS["text_muted"])
        self.after(0, lambda: self.monitor_dot.configure(text_color=border_color))
        self.after(0, lambda: self.monitor_label.configure(text=label, text_color=border_color))
        self.after(0, lambda: self.monitor_frame.configure(border_color=border_color))
        if detail:
            self._set_detail(detail)

    def _set_detail(self, text: str):
        self.after(0, lambda: self.monitor_detail.configure(text=text))

    def _set_status(self, text: str):
        color = COLORS["success"] if "✅" in text else (COLORS["warning"] if "⏹" in text else COLORS["text_muted"])
        self.after(0, lambda: self.status_label.configure(text=text, text_color=color))

    def _log_to_ui(self, text: str):
        """Send log messages to the dashboard log view."""
        logger.info(f"UI Log: {text}")
        if "dashboard" in self.frames:
            dash = self.frames["dashboard"]
            if hasattr(dash, "append_log"):
                dash.append_log(text)

    def _refresh_current_frame(self):
        if self.current_frame_name in self.frames:
            frame = self.frames[self.current_frame_name]
            if hasattr(frame, "refresh"):
                frame.refresh()

    def destroy(self):
        self._monitoring = False
        try:
            self.conn.close()
        except Exception:
            pass
        super().destroy()
