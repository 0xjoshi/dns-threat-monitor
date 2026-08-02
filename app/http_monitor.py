# ============================================================
# http_monitor.py — HTTP URL Risk Checker
# ============================================================

import requests
from app.detector import analyze_domain
from app.logger import log_event
from app.config import (
    COLOR_CYAN, COLOR_GREEN, COLOR_YELLOW, COLOR_RED,
    COLOR_BOLD, COLOR_RESET, RISK_LOW, RISK_MEDIUM, RISK_HIGH
)


# ── Color helper ──────────────────────────────────────────────
def _risk_color(risk: str) -> str:
    return {
        RISK_LOW:    COLOR_GREEN,
        RISK_MEDIUM: COLOR_YELLOW,
        RISK_HIGH:   COLOR_RED,
    }.get(risk, COLOR_RESET)


# ── Single URL check ─────────────────────────────────────────
def check_url(url: str) -> dict:
    """
    Checks a URL for threats.
    Returns a dict with keys: url, status_code, risk, reason
    """
    # Extract domain from URL
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc or url
    except Exception:
        domain = url

    risk, reason = analyze_domain(domain)

    # Extra flag: HTTP (not HTTPS) = always at least MEDIUM
    if url.startswith("http://") and risk == RISK_LOW:
        risk   = RISK_MEDIUM
        reason = "non-HTTPS connection; " + reason

    status_code = None
    try:
        resp        = requests.get(url, timeout=5, allow_redirects=True)
        status_code = resp.status_code

        # Flag unusual status codes
        if status_code in (301, 302, 303, 307, 308):
            reason += f"; redirect ({status_code})"
            if risk == RISK_LOW:
                risk = RISK_MEDIUM

    except requests.exceptions.SSLError:
        reason += "; SSL error"
        risk    = RISK_HIGH
    except requests.exceptions.ConnectionError:
        reason += "; connection refused"
        risk    = RISK_HIGH
    except requests.exceptions.Timeout:
        reason += "; request timed out"
        if risk == RISK_LOW:
            risk = RISK_MEDIUM
    except Exception as e:
        reason += f"; error: {e}"
        risk    = RISK_HIGH

    color = _risk_color(risk)
    print(
        f"{COLOR_CYAN}[HTTP]{COLOR_RESET} "
        f"{COLOR_BOLD}{url}{COLOR_RESET} | "
        f"status={status_code} | "
        f"risk={color}{risk}{COLOR_RESET} | "
        f"{reason}"
    )

    log_event("HTTP", url, risk, f"status={status_code}; {reason}")

    return {"url": url, "status_code": status_code, "risk": risk, "reason": reason}


# ── Batch URL scan ────────────────────────────────────────────
def scan_urls(url_list: list) -> list:
    """Check a list of URLs and return results."""
    print(
        f"\n{COLOR_BOLD}[HTTP MONITOR]{COLOR_RESET} "
        f"Scanning {len(url_list)} URL(s)...\n"
        f"{'-'*60}"
    )
    return [check_url(u) for u in url_list]
