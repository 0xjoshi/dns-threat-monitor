# ============================================================
# run.py — Entry Point
# Run:  python run.py
# DNS sniffing requires root/admin privileges.
# ============================================================

from app.main import start_monitoring

if __name__ == "__main__":
    start_monitoring()
