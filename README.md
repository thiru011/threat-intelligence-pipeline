# 🛡️ Automated Cyber Threat Intelligence Pipeline

A Python-based Cyber Threat Intelligence (CTI) system that collects, processes, enriches, and monitors Indicators of Compromise (IOCs) in real time using network traffic analysis.

---

## 📌 Project Overview

The Threat Intelligence Pipeline automates the process of collecting threat data, enriching IOCs, performing risk analysis, and detecting malicious activities from live network traffic.

This project is designed for:

- Security Operations Centers (SOC)
- Threat Hunting
- Incident Response
- Cybersecurity Research

---

## 🎯 Objectives

- Automate IOC collection
- Enrich threat intelligence
- Monitor network traffic in real time
- Detect malicious activities
- Generate security alerts
- Provide API access to threat data

---

## 🚀 Features

### Threat Intelligence
- IOC Collection
- IOC Enrichment
- Threat Scoring
- Confidence Scoring
- Risk Analysis
- IOC Deduplication

### Network Monitoring
- Real-time Packet Capture
- DNS Monitoring
- ICMP Detection
- Port Scan Detection
- Brute Force Detection
- Malicious IP Detection

### Security Features
- MITRE ATT&CK Mapping
- Threat Correlation
- Alert Generation
- API Access

---

## 🛠 Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Programming Language |
| Scapy | Packet Capture |
| FastAPI | REST API |
| JSON | Data Storage |
| Netifaces | Interface Detection |
| Linux | Deployment |

---

## 📂 Project Structure

```text
threat-intelligence-pipeline/
│
├── main.py
├── real_network_monitor.py
├── requirements.txt
├── install.sh
├── README.md
│
├── data/
│   ├── collected_iocs.json
│   ├── processed_iocs.json
│   └── .gitkeep
│
└── screenshots/
```

---

## ⚙ Installation

### Clone Repository

```bash
git clone https://github.com/thiru011/threat-intelligence-pipeline.git
cd threat-intelligence-pipeline
```

### Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or

```bash
chmod +x install.sh
./install.sh
```

---

## ▶ Running the Project

```bash
python3 main.py
```

For packet capture:

```bash
sudo python3 main.py
```

---

## 🌐 API Server

Run API:

```bash
uvicorn api:app --reload
```

Open:

```text
http://localhost:8000
http://localhost:8000/docs
```

---

## 📡 Threat Detection Workflow

```text
Threat Feeds
     ↓
IOC Collection
     ↓
IOC Processing
     ↓
Threat Enrichment
     ↓
Risk Scoring
     ↓
Storage
     ↓
Network Monitoring
     ↓
Threat Detection
     ↓
Alert Generation
```

---

## 🏗 System Architecture

```text
+------------------+
| Threat Feeds     |
| OTX / URLHaus    |
+------------------+
          |
          v
+------------------+
| IOC Collector    |
+------------------+
          |
          v
+------------------+
| IOC Processor    |
+------------------+
          |
          v
+------------------+
| Threat Enricher  |
+------------------+
          |
          v
+------------------+
| Storage Layer    |
+------------------+
          |
          v
+------------------+
| Network Monitor  |
+------------------+
          |
          v
+------------------+
| Detection Engine |
+------------------+
          |
          v
+------------------+
| Alerts & API     |
+------------------+
```

---

## 🔍 Detection Techniques

| Detection | Description |
|-----------|-------------|
| ICMP Detection | Detect suspicious ping traffic |
| DNS Monitoring | Detect malicious domains |
| Port Scan Detection | Detect scanning attempts |
| Brute Force Detection | Detect login attacks |
| Malicious IP Detection | Detect bad IPs |

---

## 📊 Sample Output

```text
🚨 MALICIOUS_OUTGOING:
192.168.1.10 -> 185.220.101.132

🚨 PORT_SCAN_ATTEMPT:
192.168.1.10 -> port 22

🚨 BRUTE_FORCE_ATTEMPT:
192.168.1.15 -> SSH
```

---

## 🧠 MITRE ATT&CK Mapping

| Detection | MITRE ID |
|-----------|-----------|
| Port Scan | T1046 |
| Brute Force | T1110 |
| DNS Tunneling | T1071 |
| Command & Control | T1105 |

---

## 🔒 Security Improvements

- IOC Deduplication
- Risk Scoring
- Confidence Scoring
- Exception Handling
- Real Packet Capture
- Threat Enrichment
- MITRE Mapping

---

## 🚀 Future Enhancements

- VirusTotal API Integration
- AlienVault OTX API
- Machine Learning Detection
- SIEM Integration
- Docker Deployment
- Email Alerts
- Database Integration
- Wazuh Integration
- Splunk Integration

---

## 📚 Learning Outcomes

This project provided practical knowledge in:

- Cyber Threat Intelligence
- Threat Hunting
- Packet Analysis
- Python Security Automation
- Network Monitoring
- API Development
- Security Analytics
- Incident Response

---

## 👨‍💻 Team Members

| Name | Role |
|------|------|
| Hariprakash P | Developer |
| Thirumoorthy K | Developer |
| Manojkumar K | Developer |



---

## 📜 License

MIT License

---

⭐ Star this repository if you find it useful.
