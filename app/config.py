# ============================================================
# config.py — Central Configuration
# DNS & HTTP Threat Monitoring Tool
# ============================================================

import os

# ── Paths ────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE     = os.path.join(BASE_DIR, "logs", "traffic_logs.csv")
BLACKLIST    = os.path.join(BASE_DIR, "data", "blacklist.txt")
WHITELIST = os.path.join(BASE_DIR, "data", "whitelist.txt")

# ── DNS Sniffing ─────────────────────────────────────────────
DNS_FILTER   = "udp port 53"        # BPF filter for scapy
INTERFACE    = None                  # None = auto-detect default interface

# ── Detection Thresholds ──────────────────────────────────────
DOMAIN_LEN_THRESHOLD    = 25        # chars; longer → HIGH risk
ENTROPY_THRESHOLD       = 3.8       # Shannon entropy; higher → HIGH (DGA hint)
NUMBER_SEQ_THRESHOLD    = 3         # consecutive digits → HIGH risk

# ── Risk Levels (for display / comparison) ───────────────────
RISK_LOW    = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH   = "HIGH"

# ── Console Colors ────────────────────────────────────────────
COLOR_RESET  = "\033[0m"
COLOR_GREEN  = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED    = "\033[91m"
COLOR_CYAN   = "\033[96m"
COLOR_BOLD   = "\033[1m"
