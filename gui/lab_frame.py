"""
VulnIntel — Lab Validation Frame
Panel for managing lab targets and viewing validation results.
"""

import customtkinter as ctk
from config import COLORS
from analysis.safety_policy import is_private_ip
from lab.sandbox_workflow import generate_workflow, format_workflow_text


class LabFrame(ctk.CTkFrame):
    """Lab target management and validation panel."""

    def __init__(self, parent, db_manager, lab_manager, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.db = db_manager
        self.lab = lab_manager
        self._build()

    def _build(self):
        ctk.CTkLabel(
            self, text="🧪 Lab Validation",
            font=ctk.CTkFont(size=24, weight="bold"), text_color=COLORS["text_primary"],
        ).pack(anchor="w", padx=20, pady=(20, 10))

        # Top: Add target form
        form = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=10,
                             border_width=1, border_color=COLORS["border"])
        form.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(form, text="Register Lab Target", font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=COLORS["text_primary"]).pack(anchor="w", padx=15, pady=(10, 5))

        row1 = ctk.CTkFrame(form, fg_color="transparent")
        row1.pack(fill="x", padx=15, pady=3)

        ctk.CTkLabel(row1, text="Name:", font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"], width=70).pack(side="left")
        self.name_entry = ctk.CTkEntry(row1, width=200, fg_color=COLORS["bg_secondary"],
                                        border_color=COLORS["border"], placeholder_text="Metasploitable")
        self.name_entry.pack(side="left", padx=5)

        ctk.CTkLabel(row1, text="IP:", font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"], width=30).pack(side="left", padx=(15, 0))
        self.ip_entry = ctk.CTkEntry(row1, width=150, fg_color=COLORS["bg_secondary"],
                                      border_color=COLORS["border"], placeholder_text="192.168.1.100")
        self.ip_entry.pack(side="left", padx=5)

        ctk.CTkLabel(row1, text="Type:", font=ctk.CTkFont(size=12),
                      text_color=COLORS["text_secondary"], width=40).pack(side="left", padx=(15, 0))
        self.type_combo = ctk.CTkComboBox(row1, values=["Docker", "VirtualBox", "VMware", "HackTheBox", "CTF", "Other"],
                                           width=120, fg_color=COLORS["bg_secondary"], border_color=COLORS["border"])
        self.type_combo.set("Docker")
        self.type_combo.pack(side="left", padx=5)

        row2 = ctk.CTkFrame(form, fg_color="transparent")
        row2.pack(fill="x", padx=15, pady=(3, 10))

        ctk.CTkButton(row2, text="➕ Register Target", fg_color=COLORS["accent_primary"],
                       hover_color=COLORS["accent_secondary"], text_color="#000",
                       font=ctk.CTkFont(size=12, weight="bold"),
                       command=self._add_target).pack(side="left")

        self.form_status = ctk.CTkLabel(row2, text="", font=ctk.CTkFont(size=12),
                                         text_color=COLORS["text_muted"])
        self.form_status.pack(side="left", padx=15)

        # Content: Targets list + Results
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Targets list
        left = ctk.CTkFrame(content, fg_color="transparent")
        left.pack(side="left", fill="both", expand=False, padx=(0, 10))

        ctk.CTkLabel(left, text="Registered Targets", font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=COLORS["text_primary"]).pack(anchor="w", pady=(0, 5))
        self.targets_list = ctk.CTkScrollableFrame(left, fg_color=COLORS["bg_secondary"],
                                                     corner_radius=10, width=350,
                                                     border_width=1, border_color=COLORS["border"])
        self.targets_list.pack(fill="both", expand=True)

        # Results / workflow viewer
        right = ctk.CTkFrame(content, fg_color="transparent")
        right.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(right, text="Lab Results & Workflows", font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=COLORS["text_primary"]).pack(anchor="w", pady=(0, 5))
        self.result_viewer = ctk.CTkTextbox(right, fg_color=COLORS["bg_secondary"],
                                             corner_radius=10, font=ctk.CTkFont(family="Consolas", size=12),
                                             text_color=COLORS["text_primary"],
                                             border_width=1, border_color=COLORS["border"])
        self.result_viewer.pack(fill="both", expand=True)

        self.refresh()

    def refresh(self):
        # Reload targets
        for w in self.targets_list.winfo_children():
            w.destroy()

        targets = self.lab.get_targets()
        if not targets:
            ctk.CTkLabel(self.targets_list, text="No lab targets registered.",
                          font=ctk.CTkFont(size=12), text_color=COLORS["text_muted"]).pack(pady=30)
        else:
            for t in targets:
                row = ctk.CTkFrame(self.targets_list, fg_color=COLORS["bg_card"], corner_radius=8,
                                    border_width=1, border_color=COLORS["border"])
                row.pack(fill="x", pady=2, padx=2)
                inner = ctk.CTkFrame(row, fg_color="transparent")
                inner.pack(fill="x", padx=8, pady=5)
                ctk.CTkLabel(inner, text=f"🖥️ {t['name']}",
                              font=ctk.CTkFont(size=12, weight="bold"),
                              text_color=COLORS["accent_primary"]).pack(side="left")
                ctk.CTkLabel(inner, text=t.get("ip_address", ""),
                              font=ctk.CTkFont(family="Consolas", size=11),
                              text_color=COLORS["text_secondary"]).pack(side="left", padx=10)
                ctk.CTkLabel(inner, text=t.get("target_type", ""),
                              font=ctk.CTkFont(size=10), text_color=COLORS["text_muted"]).pack(side="right")

        # Show recent results
        results = self.lab.get_results()
        if results:
            self.result_viewer.delete("1.0", "end")
            lines = ["=== Recent Lab Results ===\n"]
            for r in results[:20]:
                status_icon = {"success": "✅", "failure": "❌", "partial": "⚠️"}.get(r.get("status", ""), "❓")
                lines.append(f"{status_icon} {r.get('cve_id', '')} | {r.get('lab_target', '')} | "
                              f"{r.get('status', '')} | {r.get('validated_at', '')}")
                if r.get("notes"):
                    lines.append(f"   Notes: {r['notes']}")
                lines.append("")
            self.result_viewer.insert("1.0", "\n".join(lines))

    def _add_target(self):
        name = self.name_entry.get().strip()
        ip = self.ip_entry.get().strip()
        target_type = self.type_combo.get()

        if not name or not ip:
            self.form_status.configure(text="❌ Name and IP are required", text_color=COLORS["error"])
            return

        success, msg = self.lab.register_target(name, ip, target_type)
        if success:
            self.form_status.configure(text=f"✅ {msg}", text_color=COLORS["success"])
            self.name_entry.delete(0, "end")
            self.ip_entry.delete(0, "end")
            self.refresh()
        else:
            self.form_status.configure(text=f"❌ {msg}", text_color=COLORS["error"])
