# 🛡️ Automated Cyber Threat Intelligence Pipeline

### Real-time Network Monitoring for SOC Operations

---

## 📌 Project Overview

An **Automated Cyber Threat Intelligence Pipeline** that collects, processes, and enriches Indicators of Compromise (IOCs) with **Real-time Network Traffic Monitoring**. Designed for Security Operations Centers (SOCs).

---

## 🚀 Features

- ✅ **Automated IOC Collection** from multiple threat feeds
- ✅ **Real-time Network Monitoring** (incoming/outgoing traffic)
- ✅ **ICMP/Ping Detection**
- ✅ **Port Scan Detection**
- ✅ **Brute Force Detection**
- ✅ **DNS Query Monitoring**
- ✅ **Interactive Menu System**

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.x |
| Network Monitoring | Scapy, netifaces |
| Data Format | JSON |
| OS | Kali Linux / Ubuntu |

---

## 📋 Quick Start

### 1. Install Dependencies
```bash
chmod +x install.sh
./install.sh
2. First Run (Setup Data)
bash
python3 main.py
Select Option 2 - Pull IOC Collection

Select Option 3 - Process & Enrich IOCs

3. Start Real Network Monitoring
bash
sudo python3 main.py
Select Option 8 → Option 1 - Start REAL Monitoring

4. Test Detection
bash
ping 8.8.8.8
curl http://google.com
nslookup drmcet.ac.in
📊 Menu Options
Option	Function
1	Quick Threat Scan
2	Pull IOC Collection
3	Process & Enrich IOCs
4	Add Custom IOC
5	View Collected Data
6	Store Enriched Data
7	Start API Server
8	🌐 LIVE NETWORK ANALYSIS
9	System Status
10	Help & Documentation
11	Exit
🔍 Network Monitoring Features
Detection Type	Description
Malicious IP	Traffic to/from known malicious IPs
Malicious Domain	DNS queries to malicious domains
ICMP/Ping	Ping requests to malicious IPs
Port Scan	Port scanning activities
Brute Force	Brute force attempts on services
