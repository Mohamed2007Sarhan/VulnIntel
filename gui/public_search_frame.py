"""
VulnIntel — Public Search Frame
AI-powered internet-wide vulnerability and exploit search.
Describe your lab target and the AI searches the entire internet for matching CVEs and exploits.
"""

import threading
import re
import requests
import logging
import customtkinter as ctk
from config import COLORS
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class PublicSearchFrame(ctk.CTkFrame):
    """Public internet search panel — AI finds vulns/exploits from the web."""

    def __init__(self, parent, db_manager, ai_analyzer=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.db = db_manager
        self.ai = ai_analyzer
        self._searching = False
        self._build()

    def _build(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))

        ctk.CTkLabel(
            header, text="🌐 Public Search",
            font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_primary"],
        ).pack(side="left")

        ctk.CTkLabel(
            header, text="🤖 AI + Internet Search",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLORS["accent_primary"],
            fg_color=COLORS["bg_card"], corner_radius=6, padx=8, pady=2,
        ).pack(side="right")

        # Description
        ctk.CTkLabel(
            self, text="Describe your lab target in detail — the AI will search the internet for matching vulnerabilities and exploits, then recommend the best approach.",
            font=ctk.CTkFont(size=12), text_color=COLORS["text_secondary"],
            wraplength=900, anchor="w", justify="left",
        ).pack(anchor="w", padx=24, pady=(0, 8))

        # ─── Input Form ──────────────────────────────────────────────────
        form = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=12,
                             border_width=1, border_color=COLORS["border"])
        form.pack(fill="x", padx=20, pady=(0, 10))

        # Row 1
        r1 = ctk.CTkFrame(form, fg_color="transparent")
        r1.pack(fill="x", padx=15, pady=(12, 4))

        ctk.CTkLabel(r1, text="Software/Target:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=120, anchor="w").pack(side="left")
        self.target_entry = ctk.CTkEntry(r1, width=300, font=ctk.CTkFont(size=12),
                                          placeholder_text="e.g. Apache 2.4.49, WordPress 5.8, vsftpd 2.3.4...",
                                          fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
                                          corner_radius=8)
        self.target_entry.pack(side="left", padx=5)

        ctk.CTkLabel(r1, text="OS:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=30).pack(side="left", padx=(15, 0))
        self.os_entry = ctk.CTkEntry(r1, width=180, font=ctk.CTkFont(size=12),
                                      placeholder_text="e.g. Ubuntu 20.04, Windows Server 2019",
                                      fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
                                      corner_radius=8)
        self.os_entry.pack(side="left", padx=5)

        # Row 2: Services
        r2 = ctk.CTkFrame(form, fg_color="transparent")
        r2.pack(fill="x", padx=15, pady=4)

        ctk.CTkLabel(r2, text="Services/Ports:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=120, anchor="w").pack(side="left")
        self.services_entry = ctk.CTkEntry(r2, font=ctk.CTkFont(size=12),
                                            placeholder_text="e.g. HTTP:80, SSH:22, FTP:21, MySQL:3306, SMB:445...",
                                            fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
                                            corner_radius=8)
        self.services_entry.pack(side="left", fill="x", expand=True, padx=5)

        # Row 3: Description
        r3 = ctk.CTkFrame(form, fg_color="transparent")
        r3.pack(fill="x", padx=15, pady=4)

        ctk.CTkLabel(r3, text="Description:", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=COLORS["text_secondary"], width=120, anchor="nw").pack(side="left", anchor="n")
        self.desc_text = ctk.CTkTextbox(r3, height=70, font=ctk.CTkFont(size=12),
                                         fg_color=COLORS["bg_secondary"],
                                         border_color=COLORS["border"], border_width=1,
                                         text_color=COLORS["text_primary"], corner_radius=8)
        self.desc_text.pack(side="left", fill="x", expand=True, padx=5)

        # Buttons
        btn_row = ctk.CTkFrame(form, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(6, 12))

        self.search_btn = ctk.CTkButton(
            btn_row, text="🌐 Search Internet + AI Analysis", height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent_primary"], hover_color=COLORS["accent_secondary"],
            text_color="#000", corner_radius=10,
            command=self._start_search,
        )
        self.search_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = ctk.CTkButton(
            btn_row, text="⏹ Stop", height=40, width=80,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=COLORS["error"], hover_color="#dc2626",
            text_color="#fff", corner_radius=10,
            state="disabled", command=self._stop_search,
        )
        self.stop_btn.pack(side="left", padx=3)

        self.status_label = ctk.CTkLabel(btn_row, text="", font=ctk.CTkFont(size=12),
                                          text_color=COLORS["text_muted"])
        self.status_label.pack(side="left", padx=15)

        # ─── Results Area ────────────────────────────────────────────────
        self.results = ctk.CTkTextbox(
            self, fg_color=COLORS["bg_secondary"], corner_radius=12,
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=COLORS["text_primary"],
            border_width=1, border_color=COLORS["border"],
        )
        self.results.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.results.insert("1.0",
            "🌐 PUBLIC SEARCH — Internet-Wide Vulnerability Discovery\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "This tool searches the ENTIRE INTERNET for vulnerabilities\n"
            "and exploits matching your lab target description.\n\n"
            "It will:\n"
            "  1. Search NVD for matching CVEs\n"
            "  2. Search Exploit-DB for public exploits\n"
            "  3. Search Sploitus for additional exploits\n"
            "  4. Search GitHub for PoC repositories\n"
            "  5. Use AI to analyze all findings and recommend the best approach\n\n"
            "⚠️  FOR AUTHORIZED LAB ENVIRONMENTS ONLY\n"
        )

    def _start_search(self):
        target = self.target_entry.get().strip()
        if not target:
            self.status_label.configure(text="❌ Enter a target name", text_color=COLORS["error"])
            return

        self._searching = True
        self.search_btn.configure(state="disabled", text="⏳ Searching...")
        self.stop_btn.configure(state="normal")
        self.status_label.configure(text="🔄 Searching internet...", text_color=COLORS["info"])

        self.results.delete("1.0", "end")
        self._log("🌐 PUBLIC SEARCH INITIATED")
        self._log("━" * 55)

        info = {
            "target": target,
            "os": self.os_entry.get().strip(),
            "services": self.services_entry.get().strip(),
            "description": self.desc_text.get("1.0", "end").strip(),
        }

        thread = threading.Thread(target=self._do_search, args=(info,), daemon=True)
        thread.start()

    def _stop_search(self):
        self._searching = False
        self.after(0, lambda: self.search_btn.configure(state="normal", text="🌐 Search Internet + AI Analysis"))
        self.after(0, lambda: self.stop_btn.configure(state="disabled"))
        self.after(0, lambda: self.status_label.configure(text="⏹ Stopped", text_color=COLORS["warning"]))

    def _do_search(self, info: dict):
        target = info["target"]
        all_cves = []
        all_exploits = []

        # ─── Step 1: Search NVD ──────────────────────────────────────────
        if self._searching:
            self._log(f"\n📡 Step 1/5: Searching NVD for '{target}'...")
            self._set_status("Searching NVD...")
            try:
                from sources.nvd_source import NVDSource
                nvd = NVDSource()
                results = nvd.search(target, limit=20)
                if results:
                    for r in results:
                        all_cves.append(r)
                        from analysis.cve_analyzer import CVEAnalyzer
                        from database.db_manager import DatabaseManager
                        self.db.upsert_cve(r)
                        for ref in r.get("references", []):
                            ref["cve_id"] = r["cve_id"]
                            self.db.add_reference(ref)
                    self._log(f"  ✅ Found {len(results)} CVEs from NVD")
                    for r in results[:5]:
                        sev = r.get("severity", "NONE")
                        cvss = r.get("cvss_score", 0.0)
                        self._log(f"    [{sev:8s}] {r['cve_id']}  CVSS:{cvss}  {(r.get('description','') or '')[:80]}...")
                else:
                    self._log("  ⚠️ No NVD results")
            except Exception as e:
                self._log(f"  ❌ NVD error: {str(e)[:80]}")

        # ─── Step 2: Search Exploit-DB ───────────────────────────────────
        if self._searching:
            self._log(f"\n⚡ Step 2/5: Searching Exploit-DB for '{target}'...")
            self._set_status("Searching Exploit-DB...")
            try:
                from sources.exploitdb_source import ExploitDBSource
                edb = ExploitDBSource()
                results = edb.search(target, limit=15)
                if not results and len(target.split()) > 1:
                    short_target = " ".join(target.split()[:2])
                    self._log(f"  ⚠️ No results for full name. Retrying with '{short_target}'...")
                    results = edb.search(short_target, limit=15)

                if results:
                    for r in results:
                        all_exploits.append(r)
                        if r.get("exploit_url"):
                            r["cve_id"] = r.get("cve_id", "UNKNOWN")
                            self.db.add_exploit(r)
                    self._log(f"  ✅ Found {len(results)} exploits from Exploit-DB")
                    for r in results[:5]:
                        self._log(f"    ⚡ {r.get('exploit_title', '')[:80]}")
                else:
                    self._log("  ⚠️ No Exploit-DB results")
            except Exception as e:
                self._log(f"  ❌ Exploit-DB error: {str(e)[:80]}")

        # ─── Step 3: Search Sploitus ─────────────────────────────────────
        if self._searching:
            self._log(f"\n🔍 Step 3/5: Searching Sploitus for '{target}'...")
            self._set_status("Searching Sploitus...")
            try:
                from sources.sploitus_source import SploitusSource
                spl = SploitusSource()
                results = spl.search(target, limit=15)
                if not results and len(target.split()) > 1:
                    short_target = " ".join(target.split()[:2])
                    self._log(f"  ⚠️ No results for full name. Retrying with '{short_target}'...")
                    results = spl.search(short_target, limit=15)

                if results:
                    for r in results:
                        all_exploits.append(r)
                        if r.get("exploit_url"):
                            r["cve_id"] = r.get("cve_id", "UNKNOWN")
                            self.db.add_exploit(r)
                    self._log(f"  ✅ Found {len(results)} exploits from Sploitus")
                    for r in results[:5]:
                        self._log(f"    ⚡ {r.get('exploit_title', '')[:80]}")
                else:
                    self._log("  ⚠️ No Sploitus results")
            except Exception as e:
                self._log(f"  ❌ Sploitus error: {str(e)[:80]}")

        # ─── Step 4: Search GitHub for PoC ───────────────────────────────
        if self._searching:
            self._log(f"\n🐙 Step 4/5: Searching GitHub for PoC repos...")
            self._set_status("Searching GitHub...")
            try:
                github_results = self._search_github_poc(target)
                if github_results:
                    self._log(f"  ✅ Found {len(github_results)} GitHub PoC repos")
                    for gr in github_results[:5]:
                        self._log(f"    📦 {gr['name']} ⭐{gr['stars']} — {gr['url']}")
                else:
                    self._log("  ⚠️ No GitHub PoC results")
            except Exception as e:
                self._log(f"  ❌ GitHub error: {str(e)[:80]}")

        # ─── Step 5: AI Analysis ─────────────────────────────────────────
        if self._searching and self.ai:
            self._log(f"\n🤖 Step 5/5: AI analyzing all findings...")
            self._set_status("AI analyzing...")
            try:
                # Build context for AI
                cve_summary = "\n".join(
                    f"- {c.get('cve_id','?')} | CVSS:{c.get('cvss_score',0)} | {c.get('severity','?')} | {(c.get('description','') or '')[:120]}"
                    for c in all_cves[:15]
                )
                exploit_summary = "\n".join(
                    f"- {e.get('exploit_title','?')[:100]} | Source:{e.get('exploit_source','?')} | URL:{e.get('exploit_url','?')}"
                    for e in all_exploits[:15]
                )

                ai_prompt = f"""I'm doing authorized security research on a lab target. Here's what I found:

TARGET: {target}
OS: {info.get('os', 'Unknown')}
SERVICES: {info.get('services', 'Unknown')}
DESCRIPTION: {info.get('description', 'None')}

FOUND CVEs ({len(all_cves)} total):
{cve_summary if cve_summary else 'None found'}

FOUND EXPLOITS ({len(all_exploits)} total):
{exploit_summary if exploit_summary else 'None found'}

Based on ALL findings, provide:
1. THE BEST vulnerability to exploit in a lab (pick one specific CVE + exploit)
2. Why this is the best choice (success rate, ease of use, reliability)
3. Step-by-step safe lab testing procedure
4. What detection rules should be created
5. Alternative approaches if the primary fails

Be specific — recommend exact CVE IDs and exploit URLs."""

                result = self.ai._call_llm(
                    "You are a defensive security research assistant. Analyze vulnerability scan results and recommend the best approach for authorized lab testing. Always pick the BEST specific CVE and exploit. Be very specific and actionable. Output bash setup scripts and a python exploit script wrapped in markdown.",
                    ai_prompt,
                    max_tokens=3000,
                )
                self._log(f"\n{'━' * 55}")
                self._log("🤖 AI RECOMMENDATION")
                self._log("━" * 55)
                self._log(result)

                # Save AI result to physical file
                import os
                from config import DATA_DIR
                ai_dir = os.path.join(DATA_DIR, "ai_exploits")
                os.makedirs(ai_dir, exist_ok=True)
                file_path = os.path.join(ai_dir, f"public_search_{target.replace(' ', '_')}_poc.txt")
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(result)
                self._log(f"\n📁 AI Exploit Script Saved to: {file_path}")
            except Exception as e:
                self._log(f"  ❌ AI error: {str(e)[:80]}")
        elif self._searching:
            self._log("\n⚠️ AI module not configured — showing raw results only")

        # ─── Summary ─────────────────────────────────────────────────────
        self._log(f"\n{'━' * 55}")
        self._log(f"📊 SEARCH COMPLETE")
        self._log(f"  Total CVEs found: {len(all_cves)}")
        self._log(f"  Total Exploits found: {len(all_exploits)}")
        self._log(f"  All data saved to local database")
        self._log(f"{'━' * 55}")

        self._searching = False
        self.after(0, lambda: self.search_btn.configure(state="normal", text="🌐 Search Internet + AI Analysis"))
        self.after(0, lambda: self.stop_btn.configure(state="disabled"))
        self.after(0, lambda: self.status_label.configure(text="✅ Search complete", text_color=COLORS["success"]))

    def _search_github_poc(self, query: str) -> list:
        """Search GitHub for PoC repositories."""
        try:
            url = "https://api.github.com/search/repositories"
            params = {
                "q": f"{query} exploit OR poc OR vulnerability",
                "sort": "stars",
                "order": "desc",
                "per_page": 10,
            }
            headers = {"Accept": "application/vnd.github.v3+json"}
            resp = requests.get(url, params=params, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get("items", [])[:10]:
                    results.append({
                        "name": item.get("full_name", ""),
                        "url": item.get("html_url", ""),
                        "description": item.get("description", ""),
                        "stars": item.get("stargazers_count", 0),
                        "language": item.get("language", ""),
                    })
                return results
            return []
        except Exception as e:
            logger.error(f"GitHub PoC search failed: {e}")
            return []

    def _log(self, text: str):
        self.after(0, lambda t=text: self._do_log(t))

    def _do_log(self, text: str):
        self.results.insert("end", f"{text}\n")
        self.results.see("end")

    def _set_status(self, text: str):
        self.after(0, lambda: self.status_label.configure(text=text, text_color=COLORS["info"]))

    def refresh(self):
        pass
