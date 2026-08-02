# ============================================================
# detector.py — Rule-Based + Entropy Threat Detector
# ============================================================

import re
import math
import os

from app.config import (
    BLACKLIST,
    WHITELIST,
    DOMAIN_LEN_THRESHOLD,
    ENTROPY_THRESHOLD,
    NUMBER_SEQ_THRESHOLD,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
)


# ------------------------------------------------------------
# Load blacklist / whitelist
# ------------------------------------------------------------
def _load_list(path):
    items = []

    if os.path.exists(path):
        with open(path, "r") as f:
            items = [
                line.strip().lower()
                for line in f
                if line.strip()
            ]

    return items


BLACKLIST_KEYWORDS = _load_list(BLACKLIST)
WHITELIST_DOMAINS = _load_list(WHITELIST)


# ------------------------------------------------------------
# Shannon Entropy
# ------------------------------------------------------------
def _entropy(s: str) -> float:
    if not s:
        return 0.0

    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


# ------------------------------------------------------------
# Main Analyzer
# ------------------------------------------------------------
def analyze_domain(domain: str) -> tuple:
    """
    Analyze a DNS domain.

    Returns:
        (risk_level, reason)
    """

    domain_clean = domain.lower().rstrip(".")

    # --------------------------------------------------------
    # Ignore reverse DNS lookups
    # --------------------------------------------------------
    if domain_clean.endswith(".in-addr.arpa"):
        return RISK_LOW, "reverse DNS lookup"

    if domain_clean.endswith(".ip6.arpa"):
        return RISK_LOW, "IPv6 reverse DNS lookup"

    if domain_clean == "localhost":
        return RISK_LOW, "localhost"

    if domain_clean.endswith(".local"):
        return RISK_LOW, "local network hostname"

    # --------------------------------------------------------
    # Trusted whitelist domains
    # --------------------------------------------------------
    for trusted in WHITELIST_DOMAINS:
        if domain_clean == trusted or domain_clean.endswith("." + trusted):
            return RISK_LOW, f"trusted domain ({trusted})"

    risk = RISK_LOW
    reasons = []

    # Analyze only first label (subdomain)
    subdomain = domain_clean.split(".")[0]

    # --------------------------------------------------------
    # Rule 1 — Blacklisted keywords
    # --------------------------------------------------------
    for word in BLACKLIST_KEYWORDS:
        if word in domain_clean:
            risk = RISK_MEDIUM
            reasons.append(f"blacklisted keyword: '{word}'")
            break

    # --------------------------------------------------------
    # Rule 2 — Long subdomain
    # --------------------------------------------------------
    if len(subdomain) > DOMAIN_LEN_THRESHOLD:
        risk = RISK_HIGH
        reasons.append(f"long subdomain ({len(subdomain)} chars)")

    # --------------------------------------------------------
    # Rule 3 — Long digit sequence
    # --------------------------------------------------------
    if re.search(rf"[0-9]{{{NUMBER_SEQ_THRESHOLD},}}", subdomain):
        risk = RISK_HIGH
        reasons.append("long digit sequence detected")

    # --------------------------------------------------------
    # Rule 4 — High entropy
    # --------------------------------------------------------
    entropy = round(_entropy(subdomain), 2)

    if entropy >= ENTROPY_THRESHOLD:
        risk = RISK_HIGH
        reasons.append(f"high entropy ({entropy}) — possible DGA")

    # --------------------------------------------------------
    # Rule 5 — Excessive hyphens
    # --------------------------------------------------------
    if domain_clean.count("-") >= 3:
        if risk == RISK_LOW:
            risk = RISK_MEDIUM

        reasons.append("excessive hyphens")

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------
    if not reasons:
        reasons.append("no suspicious indicators")

    return risk, "; ".join(reasons)