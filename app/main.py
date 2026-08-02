# ============================================================
# main.py — Monitoring Orchestrator
# ============================================================

import threading
from app.logger import init_logger
from app.config import COLOR_BOLD, COLOR_CYAN, COLOR_RESET


# ── Banner ────────────────────────────────────────────────────
BANNER = f"""
{COLOR_CYAN}{COLOR_BOLD}
  ██████╗ ███╗   ██╗███████╗    ███╗   ███╗ ██████╗ ███╗   ██╗
  ██╔══██╗████╗  ██║██╔════╝    ████╗ ████║██╔═══██╗████╗  ██║
  ██║  ██║██╔██╗ ██║███████╗    ██╔████╔██║██║   ██║██╔██╗ ██║
  ██║  ██║██║╚██╗██║╚════██║    ██║╚██╔╝██║██║   ██║██║╚██╗██║
  ██████╔╝██║ ╚████║███████║    ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
        DNS & HTTP Threat Monitor  |  SOC Project v1.0
{COLOR_RESET}"""


# ── Mode menu ─────────────────────────────────────────────────
def _show_menu():
    print(f"{COLOR_BOLD}Select monitoring mode:{COLOR_RESET}")
    print("  [1] DNS Sniffer only (requires root/admin)")
    print("  [2] HTTP URL Scanner only")
    print("  [3] Both (DNS + HTTP)")
    print("  [4] Exit")
    return input("\nEnter choice (1/2/3/4): ").strip()


# ── DNS thread wrapper ────────────────────────────────────────
def _run_dns():
    from app.dns_sniffer import start_dns_sniff
    try:
        start_dns_sniff()
    except PermissionError:
        print("\n[!] Permission denied — run with sudo / admin rights for DNS sniffing.")
    except Exception as e:
        print(f"\n[!] DNS sniffer error: {e}")


# ── HTTP scan runner ──────────────────────────────────────────
def _run_http():
    from app.http_monitor import scan_urls
    print("\nEnter URLs to scan (comma-separated):")
    raw   = input("  URLs: ").strip()
    urls  = [u.strip() for u in raw.split(",") if u.strip()]
    if not urls:
        print("[!] No URLs provided.")
        return
    scan_urls(urls)


# ── Public entry point ────────────────────────────────────────
def start_monitoring():
    print(BANNER)
    init_logger()

    choice = _show_menu()

    if choice == "1":
        _run_dns()

    elif choice == "2":
        _run_http()

    elif choice == "3":
        dns_thread = threading.Thread(target=_run_dns, daemon=True, name="DNS-Thread")
        dns_thread.start()
        _run_http()                  # HTTP runs in main thread
        dns_thread.join()

    elif choice == "4":
        print("Bye!")

    else:
        print("[!] Invalid choice. Exiting.")
