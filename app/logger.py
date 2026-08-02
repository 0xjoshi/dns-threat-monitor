# ============================================================
# logger.py — CSV Event Logger
# ============================================================

import csv
import os
from datetime import datetime
from app.config import LOG_FILE, COLOR_BOLD, COLOR_RESET


def init_logger():
    """Create logs/ directory and write CSV header if needed."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Type", "Domain/URL", "Risk", "Details"])

    print(f"{COLOR_BOLD}[LOGGER]{COLOR_RESET} Log file ready → {LOG_FILE}")


def log_event(event_type: str, target: str, risk: str, details: str = ""):
    """Append one row to the CSV log."""
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            event_type,
            target,
            risk,
            details
        ])
