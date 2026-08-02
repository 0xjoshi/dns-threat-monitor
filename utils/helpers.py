# ============================================================
# helpers.py — Shared Utility Functions
# ============================================================

import csv
import os
from collections import Counter
from app.config import LOG_FILE, COLOR_BOLD, COLOR_RED, COLOR_YELLOW, COLOR_RESET


def print_summary():
    """Print a risk summary table from the CSV log."""
    if not os.path.exists(LOG_FILE):
        print("[!] No log file found yet.")
        return

    rows = []
    with open(LOG_FILE, "r") as f:
        reader = csv.DictReader(f)
        rows   = list(reader)

    if not rows:
        print("[!] Log is empty.")
        return

    total  = len(rows)
    counts = Counter(r["Risk"] for r in rows)

    print(f"\n{COLOR_BOLD}{'='*45}")
    print(f"  THREAT SUMMARY  ({total} events logged)")
    print(f"{'='*45}{COLOR_RESET}")
    print(f"  {COLOR_RED}HIGH   : {counts.get('HIGH',   0)}{COLOR_RESET}")
    print(f"  {COLOR_YELLOW}MEDIUM : {counts.get('MEDIUM', 0)}{COLOR_RESET}")
    print(f"  LOW    : {counts.get('LOW',    0)}")
    print(f"{COLOR_BOLD}{'='*45}{COLOR_RESET}\n")

    # Top 5 HIGH-risk targets
    high_targets = [r["Domain/URL"] for r in rows if r["Risk"] == "HIGH"]
    if high_targets:
        top5 = Counter(high_targets).most_common(5)
        print(f"{COLOR_BOLD}Top HIGH-risk targets:{COLOR_RESET}")
        for rank, (target, cnt) in enumerate(top5, 1):
            print(f"  {rank}. {target} ({cnt}x)")
        print()


def clear_logs():
    """Delete the CSV log and recreate the header."""
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
        print("[INFO] Logs cleared.")
    from app.logger import init_logger
    init_logger()


def load_blacklist_from_file(filepath: str) -> list:
    """
    Reload blacklist keywords from any text file (one keyword per line).
    Returns list of lowercase stripped strings.
    """
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r") as f:
        return [line.strip().lower() for line in f if line.strip()]
