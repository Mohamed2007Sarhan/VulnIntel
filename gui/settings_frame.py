"""
VulnIntel — Settings Frame
Configuration panel for API keys, sync settings, and safety policy.
"""

import customtkinter as ctk
from config import COLORS, SAFETY_POLICY


class SettingsFrame(ctk.CTkFrame):
    """Settings and configuration panel."""

    def __init__(self, parent, app_ref=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.app_ref = app_ref
        self._build()

    def _build(self):
        ctk.CTkLabel(
            self, text="⚙️ Settings",
            font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_primary"],
        ).pack(anchor="w", padx=20, pady=(20, 15))

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # API Keys Section
        self._section(scroll, "🔑 API Keys")
        api_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=10,
                                  border_width=1, border_color=COLORS["border"])
        api_frame.pack(fill="x", pady=(0, 15))

        # NVD API Key
        r1 = ctk.CTkFrame(api_frame, fg_color="transparent")
        r1.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(r1, text="NVD API Key:", font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"], width=120, anchor="w").pack(side="left")
        self.nvd_key = ctk.CTkEntry(r1, width=350, show="•",
                                     fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
                                     placeholder_text="Optional — increases rate limit to 50 req/30s")
        self.nvd_key.pack(side="left", padx=5)

        # GitHub PAT
        r2 = ctk.CTkFrame(api_frame, fg_color="transparent")
        r2.pack(fill="x", padx=15, pady=(0, 8))
        ctk.CTkLabel(r2, text="GitHub PAT:", font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"], width=120, anchor="w").pack(side="left")
        self.gh_pat = ctk.CTkEntry(r2, width=350, show="•",
                                    fg_color=COLORS["bg_secondary"], border_color=COLORS["border"],
                                    placeholder_text="Required for GitHub Security Advisories")
        self.gh_pat.pack(side="left", padx=5)

        ctk.CTkButton(api_frame, text="Save API Keys", fg_color=COLORS["accent_primary"],
                       hover_color=COLORS["accent_secondary"], text_color="#000",
                       font=ctk.CTkFont(size=12, weight="bold"),
                       command=self._save_keys).pack(padx=15, pady=(0, 10))

        # Safety Policy Section
        self._section(scroll, "🛡️ Safety Policy")
        safety_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=10,
                                     border_width=1, border_color=COLORS["border"])
        safety_frame.pack(fill="x", pady=(0, 15))

        self.safety_vars = {}
        policy_labels = {
            "enforce_lab_whitelist": "Enforce Lab Target Whitelist",
            "block_public_targets": "Block Public/Internet Targets",
            "block_weaponized_generation": "Block Weaponized Exploit Generation",
            "block_persistence": "Block Persistence Mechanisms",
            "block_credential_theft": "Block Credential Theft",
            "block_data_exfiltration": "Block Data Exfiltration",
            "require_snapshot_before_test": "Require VM Snapshot Before Testing",
            "log_all_decisions": "Log All Safety Decisions",
        }

        for key, label in policy_labels.items():
            row = ctk.CTkFrame(safety_frame, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=3)

            var = ctk.BooleanVar(value=SAFETY_POLICY.get(key, True))
            self.safety_vars[key] = var

            sw = ctk.CTkSwitch(row, text=label, variable=var,
                                font=ctk.CTkFont(size=12),
                                text_color=COLORS["text_primary"],
                                progress_color=COLORS["accent_primary"],
                                state="disabled")  # Safety policies are locked ON
            sw.pack(side="left")

            ctk.CTkLabel(row, text="🔒 Locked", font=ctk.CTkFont(size=10),
                          text_color=COLORS["text_muted"]).pack(side="right")

        ctk.CTkLabel(safety_frame,
                      text="⚠️ Safety policies cannot be disabled. This is by design.",
                      font=ctk.CTkFont(size=11), text_color=COLORS["warning"]).pack(padx=15, pady=8)

        # About Section
        self._section(scroll, "ℹ️ About")
        about = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=10,
                              border_width=1, border_color=COLORS["border"])
        about.pack(fill="x")

        about_text = (
            "VulnIntel v1.0.0 — Defensive Vulnerability Intelligence Platform\n\n"
            "Purpose: Continuous vulnerability monitoring, exploit intelligence,\n"
            "detection rule generation, and safe lab validation.\n\n"
            "Sources: NVD • GitHub Advisories • Exploit-DB • Sploitus\n"
            "Outputs: Sigma Rules • YARA Signatures • IOC Summaries • Reports\n\n"
            "⚠️ For authorized security research environments ONLY."
        )
        ctk.CTkLabel(about, text=about_text, font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"], justify="left",
                      anchor="w").pack(padx=15, pady=10, anchor="w")

    def _section(self, parent, title):
        ctk.CTkLabel(parent, text=title, font=ctk.CTkFont(size=16, weight="bold"),
                      text_color=COLORS["text_primary"]).pack(anchor="w", pady=(10, 5))

    def _save_keys(self):
        import config
        nvd = self.nvd_key.get().strip()
        gh = self.gh_pat.get().strip()
        if nvd:
            config.NVD_API_KEY = nvd
        if gh:
            config.GITHUB_PAT = gh
