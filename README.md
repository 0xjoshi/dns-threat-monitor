# 📡 DNS & HTTP Threat Monitoring Tool

> A lightweight, real-time cybersecurity tool for SOC analysts and security enthusiasts.  
> Monitors DNS queries and HTTP requests, classifies threats, and logs everything to CSV.

---

## 🧠 Overview

This tool captures live DNS traffic using **Scapy**, analyzes domains with a **multi-rule detection engine** (keyword matching + Shannon entropy + pattern rules), and flags suspicious activity as **LOW / MEDIUM / HIGH** risk. It also includes an HTTP URL scanner that checks URLs for phishing indicators, bad SSL, and suspicious redirects.

---

## 🚀 Features

| Feature | Details |
|---|---|
| 🔍 Real-time DNS capture | Uses Scapy to sniff UDP port 53 packets |
| 🧠 Multi-rule detection | Keyword blacklist + entropy (DGA) + digit sequences + hyphens |
| 🌐 HTTP URL scanner | Checks URLs for risk, SSL errors, redirects, and bad domains |
| 📊 CSV logging | Every event logged with timestamp, type, domain, risk, reason |
| 🎨 Color-coded console | GREEN / YELLOW / RED for instant visual triage |
| ⚙️ Config-driven | All thresholds and paths in one config file |
| 🧵 Threaded mode | Run DNS sniffer + HTTP scanner simultaneously |

---

## 📂 Project Structure

```
dns-threat-monitor/
│
├── app/
│   ├── __init__.py
│   ├── main.py          # Orchestrator + menu
│   ├── dns_sniffer.py   # Scapy DNS packet capture
│   ├── http_monitor.py  # HTTP URL risk checker
│   ├── detector.py      # Rule-based + entropy detection engine
│   ├── logger.py        # CSV event logger
│   └── config.py        # All settings & constants
│
├── utils/
│   ├── __init__.py
│   └── helpers.py       # Summary reports & log utilities
│
├── data/
│   └── blacklist.txt    # Suspicious keywords (editable)
│
├── logs/
│   └── traffic_logs.csv # Auto-created on first run
│
├── run.py               # Entry point
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/dns-threat-monitor.git
cd dns-threat-monitor
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the tool

**Linux / macOS** (DNS sniffing needs root):
```bash
sudo python run.py
```

**Windows** (run as Administrator):
```cmd
python run.py
```

---

## 🖥️ Usage

When you run the tool, you'll see an interactive menu:

```
Select monitoring mode:
  [1] DNS Sniffer only  (requires root/admin)
  [2] HTTP URL Scanner only
  [3] Both (DNS + HTTP)
  [4] Exit
```

### Mode 2 — HTTP Scanner example
```
Enter URLs to scan (comma-separated):
  URLs: http://secure-login-bank.xyz, https://google.com

[HTTP] http://secure-login-bank.xyz | status=200 | risk=HIGH | blacklisted keyword: 'secure'; non-HTTPS
[HTTP] https://google.com           | status=200 | risk=LOW  | no suspicious indicators
```

### Mode 1 — DNS Sniffer example (live output)
```
[DNS] xn--randomdga8271.ru  | src=192.168.1.5 | risk=HIGH   | high entropy (4.1) — possible DGA
[DNS] login-verify-bank.com  | src=192.168.1.5 | risk=HIGH   | blacklisted keyword: 'login'
[DNS] google.com             | src=192.168.1.5 | risk=LOW    | no suspicious indicators
```

---

## 🔥 Detection Engine Rules

| Rule | Condition | Risk |
|---|---|---|
| Blacklist keyword | Domain contains login, bank, verify… | MEDIUM |
| Long domain | > 25 characters | HIGH |
| Digit sequence | 3+ consecutive numbers | HIGH |
| High entropy | Shannon entropy ≥ 3.8 (DGA indicator) | HIGH |
| Excessive hyphens | 3+ hyphens in domain | MEDIUM |
| HTTP (not HTTPS) | URL starts with `http://` | MEDIUM |
| SSL error | Certificate invalid/expired | HIGH |

---

## 📊 Log Output

All events are saved to `logs/traffic_logs.csv`:

```
Timestamp,Type,Domain/URL,Risk,Details
2025-07-10 14:32:01,DNS,login-secure.xyz,HIGH,src=192.168.1.1; blacklisted keyword: 'login'
2025-07-10 14:32:05,HTTP,http://verify-bank.tk,HIGH,status=200; blacklisted keyword: 'verify'
```

---

## 🛠️ Configuration

Edit `app/config.py` to tune thresholds:

```python
DOMAIN_LEN_THRESHOLD  = 25     # chars before HIGH risk
ENTROPY_THRESHOLD     = 3.8    # Shannon entropy cutoff
NUMBER_SEQ_THRESHOLD  = 3      # consecutive digits cutoff
```

Edit `data/blacklist.txt` to add your own suspicious keywords (one per line).

---

## 📈 View Summary Report

Open a Python shell in the project root:

```python
from utils.helpers import print_summary
print_summary()
```

Output:
```
=============================================
  THREAT SUMMARY  (47 events logged)
=============================================
  HIGH   : 12
  MEDIUM : 18
  LOW    : 17
=============================================

Top HIGH-risk targets:
  1. xn--dga8271random.ru (4x)
  2. login-secure-bank.xyz (3x)
```

---

## 🔧 Tech Stack

- **Python 3.8+**
- **Scapy** — raw DNS packet capture
- **Requests** — HTTP probing
- **csv / os / threading** — stdlib only (no heavy dependencies)

---

## 🎯 Use Cases

- SOC monitoring simulation & practice
- Blue team threat detection training
- Network traffic analysis for CTF
- Cybersecurity portfolio project

---

## 🔮 Planned Upgrades

- [ ] Flask web dashboard with live feed
- [ ] VirusTotal API integration
- [ ] WHOIS lookup on suspicious domains
- [ ] Email/Slack alerting for HIGH-risk events
- [ ] Integration with IDS/IPS system

---

## 👨‍💻 Author

Cybersecurity Enthusiast — Blue Team / SOC Focus  
Built as a hands-on SOC simulation project.

---

## 📜 License

MIT License — free to use and modify.
