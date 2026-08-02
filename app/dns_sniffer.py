# ============================================================
# dns_sniffer.py — Real-Time DNS Packet Sniffer (Scapy)
# ============================================================

from scapy.all import sniff, DNSQR, IP
from app.detector import analyze_domain
from app.logger import log_event
from app.config import (
    DNS_FILTER, INTERFACE,
    COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_CYAN,
    COLOR_BOLD, COLOR_RESET,
    RISK_LOW, RISK_MEDIUM, RISK_HIGH
)


# ── Color helper ──────────────────────────────────────────────
def _risk_color(risk: str) -> str:
    return {
        RISK_LOW:    COLOR_GREEN,
        RISK_MEDIUM: COLOR_YELLOW,
        RISK_HIGH:   COLOR_RED,
    }.get(risk, COLOR_RESET)


# ── Packet callback ───────────────────────────────────────────
def _process_packet(packet):
    """Called by scapy for every captured packet."""
    if not packet.haslayer(DNSQR):
        return

    try:
        domain = packet[DNSQR].qname.decode().strip(".")
    except Exception:
        return

    # Skip empty or purely numeric
    if not domain or domain.replace(".", "").isdigit():
        return

    # Source IP (best-effort)
    src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

    risk, reason = analyze_domain(domain)
    color        = _risk_color(risk)

    # Console output
    print(
        f"{COLOR_CYAN}[DNS]{COLOR_RESET} "
        f"{COLOR_BOLD}{domain}{COLOR_RESET} | "
        f"src={src_ip} | "
        f"risk={color}{risk}{COLOR_RESET} | "
        f"{reason}"
    )

    # CSV log
    log_event("DNS", domain, risk, f"src={src_ip}; {reason}")


# ── Public start function ─────────────────────────────────────
def start_dns_sniff():
    """Start sniffing DNS queries indefinitely (blocking)."""
    print(
        f"\n{COLOR_BOLD}[DNS SNIFFER]{COLOR_RESET} "
        f"Listening on interface={INTERFACE or 'default'} "
        f"filter='{DNS_FILTER}'\n"
        f"{'-'*60}"
    )
    sniff(
        iface=INTERFACE,
        filter=DNS_FILTER,
        prn=_process_packet,
        store=0
    )
