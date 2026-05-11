"""
VulnIntel — Status Indicator Component
Real-time status indicator widget.
"""

import customtkinter as ctk
from config import COLORS


class StatusIndicator(ctk.CTkFrame):
    """A small colored dot with label for status display."""

    def __init__(self, parent, label: str = "", status: str = "idle", **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)

        status_colors = {
            "active": COLORS["success"],
            "syncing": COLORS["info"],
            "error": COLORS["error"],
            "idle": COLORS["text_muted"],
            "warning": COLORS["warning"],
        }

        self.dot = ctk.CTkLabel(
            self, text="●", font=ctk.CTkFont(size=14),
            text_color=status_colors.get(status, COLORS["text_muted"]),
            width=20,
        )
        self.dot.pack(side="left", padx=(0, 4))

        self.status_label = ctk.CTkLabel(
            self, text=label,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=COLORS["text_secondary"],
        )
        self.status_label.pack(side="left")

        self._colors = status_colors

    def set_status(self, status: str, label: str = None):
        color = self._colors.get(status, COLORS["text_muted"])
        self.dot.configure(text_color=color)
        if label:
            self.status_label.configure(text=label)
