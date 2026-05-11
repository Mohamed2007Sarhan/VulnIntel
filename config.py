"""
VulnIntel — Configuration & Constants
Central configuration for the entire platform.
"""

import os

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
EXPORTS_DIR = os.path.join(BASE_DIR, "exports")
DB_PATH = os.path.join(DATA_DIR, "vulnintel.db")

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(EXPORTS_DIR, exist_ok=True)

# ─── API Endpoints ──────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORIES_API = "https://api.github.com/advisories"
SPLOITUS_SEARCH_URL = "https://sploitus.com/"

# ─── Rate Limits ─────────────────────────────────────────────────────────────
NVD_RATE_LIMIT_NO_KEY = 5       # requests per 30 seconds
NVD_RATE_LIMIT_WITH_KEY = 50    # requests per 30 seconds
NVD_RATE_WINDOW = 30            # seconds
GITHUB_RATE_LIMIT = 60          # requests per hour (unauthenticated)
GITHUB_RATE_LIMIT_AUTH = 5000   # requests per hour (authenticated)
SPLOITUS_REQUEST_DELAY = 2.0    # seconds between requests

# ─── API Keys (loaded from env or settings) ──────────────────────────────────
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
GITHUB_PAT = os.environ.get("GITHUB_PAT", "")

# ─── GUI Theme ───────────────────────────────────────────────────────────────
APPEARANCE_MODE = "dark"
COLOR_THEME = "blue"

# Color palette
COLORS = {
    "bg_primary":       "#0f0f1a",
    "bg_secondary":     "#1a1a2e",
    "bg_tertiary":      "#16213e",
    "bg_card":          "#1e1e36",
    "bg_card_hover":    "#2a2a4a",
    "accent_primary":   "#00d4aa",
    "accent_secondary": "#0ea5e9",
    "accent_gradient_start": "#00d4aa",
    "accent_gradient_end":   "#0ea5e9",
    "text_primary":     "#e2e8f0",
    "text_secondary":   "#94a3b8",
    "text_muted":       "#64748b",
    "border":           "#2d2d50",
    "border_active":    "#00d4aa",
    "severity_critical":"#ef4444",
    "severity_high":    "#f97316",
    "severity_medium":  "#eab308",
    "severity_low":     "#22c55e",
    "severity_none":    "#64748b",
    "success":          "#22c55e",
    "warning":          "#eab308",
    "error":            "#ef4444",
    "info":             "#0ea5e9",
    "safe":             "#22c55e",
    "unsafe":           "#ef4444",
    "caution":          "#f97316",
}

# Severity display mapping
SEVERITY_MAP = {
    "CRITICAL": {"color": COLORS["severity_critical"], "icon": "🔴", "weight": 4},
    "HIGH":     {"color": COLORS["severity_high"],     "icon": "🟠", "weight": 3},
    "MEDIUM":   {"color": COLORS["severity_medium"],   "icon": "🟡", "weight": 2},
    "LOW":      {"color": COLORS["severity_low"],      "icon": "🟢", "weight": 1},
    "NONE":     {"color": COLORS["severity_none"],     "icon": "⚪", "weight": 0},
}

# Exploit maturity levels
EXPLOIT_MATURITY = {
    "weaponized":   {"label": "Weaponized",   "color": COLORS["error"],   "weight": 3},
    "poc":          {"label": "PoC Available", "color": COLORS["warning"], "weight": 2},
    "theoretical":  {"label": "Theoretical",  "color": COLORS["info"],    "weight": 1},
    "none":         {"label": "No Exploit",   "color": COLORS["text_muted"], "weight": 0},
}

# ─── Safety Policy ───────────────────────────────────────────────────────────
SAFETY_POLICY = {
    "enforce_lab_whitelist":       True,
    "block_public_targets":        True,
    "block_weaponized_generation": True,
    "block_persistence":           True,
    "block_credential_theft":      True,
    "block_data_exfiltration":     True,
    "require_snapshot_before_test": True,
    "log_all_decisions":           True,
}

# Private network ranges (RFC 1918 + localhost)
PRIVATE_NETWORK_RANGES = [
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "localhost",
    "0.0.0.0",
]

# ─── Sync Settings ───────────────────────────────────────────────────────────
DEFAULT_SYNC_INTERVAL = 1800  # 30 minutes in seconds
MAX_CVE_FETCH_LIMIT = 100     # max CVEs per fetch operation
DEFAULT_DAYS_LOOKBACK = 7     # default time window for new CVE lookup

# ─── Application Info ────────────────────────────────────────────────────────
APP_NAME = "VulnIntel"
APP_VERSION = "2.0.0"
APP_DESCRIPTION = "Defensive Vulnerability Intelligence Platform"
WINDOW_SIZE = "1500x900"
MIN_WINDOW_SIZE = (1200, 700)
