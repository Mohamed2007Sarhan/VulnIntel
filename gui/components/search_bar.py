"""
VulnIntel — Search Bar Component
Global search bar with filtering capabilities.
"""

import customtkinter as ctk
from config import COLORS


class SearchBar(ctk.CTkFrame):
    """Styled search bar with placeholder text and callback."""

    def __init__(self, parent, placeholder: str = "Search CVEs, exploits, products...",
                 command=None, **kwargs):
        super().__init__(parent, fg_color=COLORS["bg_card"], corner_radius=10,
                         border_width=1, border_color=COLORS["border"], **kwargs)

        self.command = command

        self.search_icon = ctk.CTkLabel(
            self, text="🔍", font=ctk.CTkFont(size=16), width=30,
            text_color=COLORS["text_muted"],
        )
        self.search_icon.pack(side="left", padx=(10, 0))

        self.entry = ctk.CTkEntry(
            self, placeholder_text=placeholder,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color="transparent", border_width=0,
            text_color=COLORS["text_primary"],
            placeholder_text_color=COLORS["text_muted"],
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=5, pady=6)
        self.entry.bind("<Return>", self._on_search)

        self.search_btn = ctk.CTkButton(
            self, text="Search", width=70, height=28,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS["accent_primary"],
            hover_color=COLORS["accent_secondary"],
            text_color="#000000",
            corner_radius=6,
            command=self._on_search,
        )
        self.search_btn.pack(side="right", padx=8, pady=6)

    def _on_search(self, event=None):
        query = self.entry.get().strip()
        if self.command and query:
            self.command(query)

    def get_query(self) -> str:
        return self.entry.get().strip()

    def clear(self):
        self.entry.delete(0, "end")
