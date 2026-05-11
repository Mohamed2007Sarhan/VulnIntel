"""
VulnIntel — Main Entry Point
Defensive Vulnerability Intelligence Platform

Launch this file to start the application:
    python main.py
"""

import sys
import os
import logging

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
    ]
)

logger = logging.getLogger("vulnintel")


def main():
    """Launch VulnIntel application."""
    logger.info("Starting VulnIntel — Defensive Vulnerability Intelligence Platform")
    logger.info("Safety Policy: ALL ENFORCED")

    try:
        from gui.app import VulnIntelApp
        app = VulnIntelApp()
        app.mainloop()
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
