# 🛡️ Ethical Hacking Platform

A comprehensive cybersecurity simulation platform featuring real network traffic generation, Snort IDS integration, and professional SOC operations with alert correlation.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.3-green)
![Snort](https://img.shields.io/badge/Snort-3.0-orange)
![License](https://img.shields.io/badge/License-Educational-red)

---

## 🎯 Overview

An educational platform simulating real-world cybersecurity scenarios with separate Red Team (offensive) and Blue Team (defensive) interfaces. Features real network traffic generation, Snort IDS integration, and SOC-level alert correlation.

### Key Features

- **4 Attack Modules**: SQL Injection, Brute Force, Port Scanner, DDoS
- **Multi-Layer Defense**: IDS, Snort 3, Firewall, Alert Correlator
- **Real-Time Monitoring**: WebSocket-powered dashboards
- **SOC Operations**: Alert correlation, incident management, automated response
- **Real Traffic**: Actual HTTP requests and TCP packets, not simulated
- **Professional Reports**: Automated PDF generation with ReportLab

---

## 🏗️ Architecture

```
Windows (Flask App)  →  Kali Linux (DVWA + Snort 3)
    ↓                           ↓
Red Team Interface      Snort detects attacks
Blue Team Dashboard  ←  Alerts forwarded via HTTP
```

**Components:**
- **Red Team**: Launches real attacks against DVWA
- **Blue Team**: Monitors, detects, and responds to threats
- **Snort IDS**: Network-level intrusion detection on Kali
- **Alert Correlator**: Groups related alerts into incidents (SOC-level)
- **Firewall**: IP blocking with immediate effect

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Kali Linux (for DVWA + Snort)
- Docker (for DVWA)

### Installation

**1. Windows (Flask App)**
```bash
pip install flask flask-socketio requests beautifulsoup4 reportlab
python app.py
```
Access: `http://localhost:5000`

**2. Kali Linux (DVWA)**
```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```
Access: `http://<kali-ip>/login.php` (admin/password)

**3. Kali Linux (Snort)**
```bash
# Configure and start Snort
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast -l /var/log/snort/

# Start alert forwarder
python3 snort_forwarder.py
```

---

## 🎮 Usage

### Red Team
1. Navigate to `/red-team`
2. Select attack type (SQL Injection, Brute Force, Port Scanner, DDoS)
3. Configure target and parameters
4. Launch attack and monitor real-time progress

### Blue Team
1. Navigate to `/blue-team`
2. Monitor security dashboard (score, active threats, alerts)
3. Investigate incidents (correlated alerts from IDS + Snort)
4. Respond to threats (acknowledge, block IP, close incident)
5. Generate PDF reports

---

## 🔴 Attack Modules

### SQL Injection
Exploits DVWA SQL vulnerability with CSRF token handling. Extracts user data from MySQL database.

### Brute Force
Password cracking with wordlist. Handles CSRF tokens, detects successful authentication.

### Port Scanner
Multi-threaded TCP SYN scanning with banner grabbing and service identification.

### DDoS
HTTP flood simulation with baseline measurement and performance degradation tracking.

---

## 🔵 Defense Components

### IDS (Intrusion Detection System)
Application-level pattern matching with 5 detection rules (SQL, Brute Force, Port Scan, DDoS, Malicious Payloads).

### Snort Monitor
Integrates Snort 3 running on Kali. Parses alerts, maps SIDs to attack types, forwards to Flask via HTTP.

### Alert Correlator
SOC-level functionality. Groups related alerts into incidents based on attack type, source IP, and time window (120s). Reduces alert fatigue.

### Firewall
IP blacklisting with dynamic rule creation. Blocks attacks before and during execution.

### Report Generator
Automated PDF reports with executive summary, incidents, alerts, and recommendations.

---

## 📡 API Endpoints

### Red Team
- `GET /api/red/attacks` - List available attacks
- `POST /api/red/launch` - Launch attack
- `GET /api/red/history` - Attack history

### Blue Team
- `GET /api/blue/dashboard` - Dashboard metrics
- `GET /api/blue/incidents` - Correlated incidents
- `POST /api/blue/incidents/<id>/acknowledge` - Acknowledge incident
- `POST /api/blue/incidents/<id>/block` - Block source IP
- `POST /api/blue/firewall/block` - Manual IP blocking
- `POST /api/snort-alert` - Receive Snort alerts (from Kali)

---

## 📁 Project Structure

```
├── app.py                      # Main Flask application
├── attacks/                    # Red Team modules
│   ├── sql_injection.py
│   ├── brute_force.py
│   ├── port_scanner.py
│   └── ddos.py
├── defense/                    # Blue Team modules
│   ├── ids.py
│   ├── snort_monitor.py
│   ├── alert_correlator.py
│   ├── firewall.py
│   ├── log_analyzer.py
│   └── report_generator.py
├── templates/                  # HTML interfaces
│   ├── index.html
│   ├── red_team.html
│   └── blue_team.html
├── static/
│   ├── css/style.css
│   └── js/
│       ├── red_team.js
│       └── blue_team.js
├── snort_forwarder.py         # Kali alert forwarder
└── requirements.txt
```

---

## 🔍 Snort Integration

### Configuration
- **Main config**: `/etc/snort/snort.lua`
- **Custom rules**: `/etc/snort/rules/local.rules` (40+ rules)
- **Alert format**: `alert_fast.txt` (one-line format)

### Key Rules
```snort
# SQL Injection (SID 1000001)
alert tcp any any -> any 80 (msg:"SQL Injection - OR 1=1"; content:"OR"; content:"1=1"; sid:1000001;)

# Brute Force (SID 1000015)
alert tcp any any -> any 80 (msg:"Brute Force - DVWA"; content:"/vulnerabilities/brute"; threshold:type threshold, track by_src, count 3, seconds 30; sid:1000015;)

# Port Scan (SID 1000021)
alert tcp any any -> $HOME_NET any (msg:"Port Scan"; flags:S; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000021;)

# DDoS (SID 1000031)
alert tcp any any -> any 80 (msg:"DDoS - HTTP Flood"; content:"GET"; threshold:type threshold, track by_src, count 50, seconds 10; sid:1000031;)
```

---

## 🎓 Educational Value

**Demonstrates:**
- Offensive security techniques (web exploitation, network attacks)
- Defensive security operations (IDS, SOC workflows, incident response)
- Real-time monitoring and alerting
- Alert correlation and incident management
- Multi-layer defense architecture
- Python development (Flask, threading, WebSocket, regex)

**Skills Developed:**
- Web application security
- Network intrusion detection
- Security operations center (SOC) workflows
- Incident response procedures
- Python security tool development

---

## 🚀 Future Enhancements

- Additional attack types (XSS, CSRF, File Upload)
- Machine learning-based anomaly detection
- PCAP file analysis and visualization
- Database persistence (SQLite/PostgreSQL)
- Multi-user support with role-based access
- Integration with MITRE ATT&CK framework

---

## 📚 References

- [DVWA Documentation](https://github.com/digininja/DVWA)
- [Snort 3 Manual](https://www.snort.org/documents)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---