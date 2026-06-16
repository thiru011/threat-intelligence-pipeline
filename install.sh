#!/bin/bash
echo "🔧 Installing Threat Intelligence Pipeline..."
echo "======================================"
sudo apt update
sudo apt install python3 python3-pip python3-venv tcpdump -y
pip3 install requests fastapi uvicorn python-dotenv scapy netifaces
sudo setcap cap_net_raw=eip $(readlink -f $(which python3))
echo ""
echo "✅ Installation complete!"
echo "======================================"
echo "📌 Quick Start:"
echo "1. python3 main.py"
echo "2. Select Option 2 & 3 to setup data"
echo "3. sudo python3 main.py"
echo "4. Select Option 8 for monitoring"
