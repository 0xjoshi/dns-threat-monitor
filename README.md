# 📡 DNS & HTTP Threat Monitoring Tool

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/Status-Active-success)

A lightweight, real-time cybersecurity tool that monitors DNS queries and HTTP URLs, detects suspicious activity using rule-based threat analysis, and logs security events for SOC monitoring and incident analysis.

---

# 🎯 Project Objective

DNS is one of the most commonly abused protocols in cyber attacks such as phishing, malware command-and-control (C2), Domain Generation Algorithm (DGA) communication, and data exfiltration.

This project simulates how a Security Operations Center (SOC) analyst monitors network traffic, identifies suspicious domains using multiple detection techniques, classifies threats, and records events for investigation.

This tool was built for:

- SOC Analyst practice
- Blue Team learning
- Cybersecurity portfolio
- Network traffic analysis
- CTF practice

---

# 🏗 Project Architecture

```
                +------------------------+
                |   Network Traffic      |
                +-----------+------------+
                            |
                            |
                   DNS / HTTP Requests
                            |
             +--------------+--------------+
             |                             |
             | DNS Packet Sniffer (Scapy)  |
             | HTTP URL Scanner            |
             +--------------+--------------+
                            |
                    Detection Engine
                            |
      +-----------+---------+----------+-----------+
      |           |                    |           |
 Blacklist    Whitelist          Entropy      Pattern Rules
  Matching      Check            Detection
      |                               |
      +---------------+---------------+
                      |
               Risk Classification
          LOW / MEDIUM / HIGH
                      |
      +---------------+----------------+
      |                                |
 Console Output                  CSV Logging
```

---

# 🚀 Features

| Feature | Description |
|----------|-------------|
| 🔍 Real-time DNS Monitoring | Live DNS packet capture using Scapy |
| 🌐 HTTP URL Scanner | Scan URLs for phishing indicators |
| 🛡 Whitelist Support | Ignore trusted domains automatically |
| 🚫 Blacklist Detection | Detect suspicious keywords |
| 🧠 Shannon Entropy Analysis | Detect possible DGA domains |
| 🔢 Digit Pattern Detection | Identify suspicious numeric domains |
| ➖ Hyphen Detection | Detect phishing-style domains |
| 📊 CSV Logging | Save every event for later analysis |
| 🎨 Color Console | Easy-to-read LOW/MEDIUM/HIGH alerts |
| ⚙ Configurable | Modify thresholds from one config file |
| 🧵 Multi-threaded | DNS monitoring and HTTP scanning together |

---

# 📂 Project Structure

```
dns-threat-monitor/

│
├── app/
│   ├── main.py
│   ├── dns_sniffer.py
│   ├── http_monitor.py
│   ├── detector.py
│   ├── logger.py
│   └── config.py
│
├── data/
│   ├── blacklist.txt
│   └── whitelist.txt
│
├── logs/
│   └── traffic_logs.csv
│
├── utils/
│   └── helpers.py
│
├── screenshots/
│
├── run.py
├── requirements.txt
└── README.md
```

---

# ⚙ Installation

Clone repository

```bash
git clone https://github.com/YOUR_USERNAME/dns-threat-monitor.git

cd dns-threat-monitor
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# ▶ Running

### Windows

Run Command Prompt as Administrator

```bash
python run.py
```

### Linux

```bash
sudo python3 run.py
```

---

# 🖥 Menu

```
Select monitoring mode

1. DNS Sniffer only

2. HTTP URL Scanner

3. Both (DNS + HTTP)

4. Exit
```

---

# 🔍 Detection Workflow

```
DNS Request
      │
      ▼

Normalize Domain

      │
      ▼

Whitelist Check

      │
      ▼

Blacklist Check

      │
      ▼

Entropy Analysis

      │
      ▼

Pattern Matching

      │
      ▼

Risk Classification

      │
      ▼

CSV Logger + Console Output
```

---

# 🔥 Detection Rules

| Rule | Condition | Risk |
|------|-----------|------|
| Blacklisted Keyword | login, verify, secure, bank | MEDIUM |
| Long Domain | >25 characters | HIGH |
| Digit Sequence | 3 or more digits | HIGH |
| High Entropy | ≥3.8 | HIGH |
| Excessive Hyphens | 3 or more | MEDIUM |
| HTTP URL | Non HTTPS | MEDIUM |
| SSL Error | Invalid certificate | HIGH |

---

# 📊 Sample Output

DNS Monitoring

```
[DNS]

google.com

Risk : LOW

Reason : Trusted Domain
```

```
[DNS]

login-bank-security.xyz

Risk : HIGH

Reason

• Blacklisted keyword

• High entropy

• Possible phishing
```

HTTP Scanner

```
[HTTP]

http://verify-bank.xyz

Risk : HIGH

Reason

• Non HTTPS

• Blacklisted keyword

• Suspicious URL
```

---

# 📈 Threat Summary

```
=====================================

THREAT SUMMARY

=====================================

HIGH     12

MEDIUM   17

LOW      51

=====================================

Top High Risk Domains

login-bank.xyz

random8271.ru
```

---

# 📂 Logs

All events are stored in

```
logs/traffic_logs.csv
```

Example

```
Timestamp,Type,Target,Risk,Reason

2026-07-12,DNS,google.com,LOW,Trusted Domain

2026-07-12,DNS,login-bank.xyz,HIGH,Blacklisted Keyword

2026-07-12,HTTP,http://bank-login.xyz,HIGH,Non HTTPS
```

---

# ⚙ Configuration

Modify

```
app/config.py
```

```
DOMAIN_LEN_THRESHOLD = 25

ENTROPY_THRESHOLD = 3.8

NUMBER_SEQ_THRESHOLD = 3
```

Customize

```
data/blacklist.txt
```

and

```
data/whitelist.txt
```

without changing any source code.

---

# 🛠 Technologies Used

- Python
- Scapy
- Requests
- CSV
- Threading
- Regex
- Shannon Entropy
- Network Packet Analysis

---

# 🛡 Skills Demonstrated

- Network Security
- DNS Analysis
- HTTP Security
- Packet Capture
- Threat Detection
- SOC Monitoring
- Threat Hunting
- Python Programming
- Multithreading
- Log Analysis
- Cybersecurity Automation

---

# 📷 Screenshots

Add screenshots here.

```
screenshots/

menu.png

dns-monitor.png

http-scanner.png
```

---

# 🚀 Roadmap

## Version 1.0

- DNS Monitoring
- HTTP Scanner
- CSV Logging

## Version 2.0

- Interactive Console
- Better Detection Engine
- Weighted Risk Scoring
- Improved Whitelist

## Version 3.0

- Flask Dashboard
- Live Charts
- Search Logs
- Statistics

## Version 4.0

- VirusTotal Integration
- WHOIS Lookup
- AbuseIPDB
- GeoIP
- Email Alerts
- Slack Alerts
- REST API

---

# ⚠ Disclaimer

This project is intended for educational purposes, cybersecurity training, and defensive security research only.

Only use it on networks that you own or have permission to monitor.

---

# 👨‍💻 Author

**Yogesh Joshi**

SOC Analyst | Blue Team | Python | Network Security

GitHub: https://github.com/0xjoshi

---

# ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub.

---

# 📜 License

MIT License
