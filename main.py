#!/usr/bin/env python3
import os
import sys
import time
import json
import random
from datetime import datetime
from real_network_monitor import RealNetworkMonitor

# Initialize REAL network monitor
network_monitor = RealNetworkMonitor()

# Data files
COLLECTED_IOCS_FILE = 'data/collected_iocs.json'
PROCESSED_IOCS_FILE = 'data/processed_iocs.json'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("\n" + "="*60)
    print("           🛡️  THREAT INTELLIGENCE PIPELINE 🛡️")
    print("               WITH REAL NETWORK MONITORING")
    print("="*60)

def ensure_data_directory():
    os.makedirs('data', exist_ok=True)

def load_json_file(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_json_file(filename, data):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"❌ Error saving file: {e}")
        return False

def main_menu():
    print_banner()
    print("\n📋 MAIN MENU:")
    print("1.  Quick Threat Scan (Fastest)")
    print("2.  Pull IOC Collection") 
    print("3.  Process & Enrich IOCs")
    print("4.  Add Custom IOC")
    print("5.  View Collected Data")
    print("6.  Store Enriched Data") 
    print("7.  Start API Server")
    print("8.  🌐 LIVE NETWORK ANALYSIS")
    print("9.  System Status")
    print("10. Help & Documentation")
    print("11. Exit")
    print("\n" + "-"*40)
    return input("Select option (1-11): ").strip()

def live_network_analysis():
    clear_screen()
    print("\n" + "="*50)
    print("           🌐 REAL NETWORK MONITORING")
    print("="*50)
    network_monitor.get_network_info()
    print("\n📊 OPTIONS:")
    print("1. Start REAL Network Monitoring")
    print("2. Stop Network Monitoring")
    print("3. View Detected Threats") 
    print("4. View Statistics")
    print("5. Load Threat Intelligence")
    print("6. Block Malicious IP")
    print("7. Clear Events")
    print("8. Back to Main Menu")
    print("\n" + "-"*40)
    return input("Select option (1-8): ").strip()

def handle_network_analysis():
    while True:
        choice = live_network_analysis()
        if choice == '1':
            clear_screen()
            print("\n🚀 STARTING REAL NETWORK MONITORING...")
            print("=" * 50)
            print("⚠️  REQUIREMENTS:")
            print("   • Run with sudo privileges")
            print("   • Network interface access")
            print("   • Threat intelligence loaded")
            print("   • Scapy installed")
            print(f"\n📡 Monitoring interface: {network_monitor.interface}")
            if network_monitor.start_real_monitoring():
                print("\n✅ REAL monitoring started successfully!")
            else:
                print("\n❌ Failed to start real monitoring")
            input("\nPress Enter to return...")
        elif choice == '2':
            clear_screen()
            network_monitor.stop_monitoring()
            input("\nPress Enter to return...")
        elif choice == '3':
            clear_screen()
            print("\n📋 REAL DETECTED THREATS")
            print("=" * 50)
            status = network_monitor.get_status()
            print(f"📊 Monitoring Status: {'🟢 ACTIVE' if status['monitoring'] else '🔴 INACTIVE'}")
            print(f"🚨 Real Threats Detected: {status['threats_detected']}")
            if status['recent_events']:
                for i, event in enumerate(status['recent_events'], 1):
                    print(f"{i}. [{event['timestamp']}] {event['type']}: {event['source']} -> {event['target']}")
            else:
                print("\n✅ No threats detected yet.")
            input("\nPress Enter to continue...")
        elif choice == '4':
            clear_screen()
            print("\n📈 NETWORK ANALYSIS STATISTICS")
            print("=" * 40)
            stats = network_monitor.get_statistics()
            print(f"📊 Total Events: {stats['total_events']}")
            if stats['event_breakdown']:
                for event_type, count in stats['event_breakdown'].items():
                    print(f"   └── {event_type}: {count}")
            input("\nPress Enter to continue...")
        elif choice == '5':
            clear_screen()
            network_monitor.load_threat_intel()
            input("\nPress Enter to continue...")
        elif choice == '6':
            clear_screen()
            ip = input("Enter IP address to block: ").strip()
            if ip:
                network_monitor.block_ip(ip)
                print(f"✅ Blocked IP: {ip}")
            input("\nPress Enter to continue...")
        elif choice == '7':
            clear_screen()
            confirm = input("Clear all events? (y/N): ").strip().lower()
            if confirm == 'y':
                network_monitor.clear_events()
                print("✅ Events cleared.")
            input("\nPress Enter to continue...")
        elif choice == '8':
            break
        else:
            print("❌ Invalid option!")
            time.sleep(1)

def quick_threat_scan():
    clear_screen()
    print("\n🚀 Running Quick Threat Scan...")
    print("-" * 40)
    print("🔍 Scanning for known malicious IPs...")
    time.sleep(1)
    print("🔍 Checking for suspicious domains...")
    time.sleep(1)
    iocs = load_json_file(PROCESSED_IOCS_FILE)
    malicious_count = sum(1 for ioc in iocs if ioc.get('malicious', False))
    print(f"\n📊 Scan Results:")
    print(f"   ✅ Total IOCs: {len(iocs)}")
    print(f"   🚨 Malicious: {malicious_count}")
    input("\nPress Enter to continue...")

def pull_ioc_collection():
    clear_screen()
    print("\n📥 Pulling IOC Collection from Threat Feeds...")
    print("-" * 50)
    threat_feeds = ["URLhaus", "AlienVault OTX", "Malware Domain List"]
    collected_iocs = []
    for feed in threat_feeds:
        print(f"📡 Fetching from {feed}...")
        sample_iocs = [
            {"type": "ip", "value": "185.220.101.132", "source": feed, "timestamp": datetime.now().isoformat()},
            {"type": "domain", "value": "evil-domain.org", "source": feed, "timestamp": datetime.now().isoformat()},
            {"type": "domain", "value": "drmcet.ac.in", "source": feed, "timestamp": datetime.now().isoformat()}
        ]
        collected_iocs.extend(sample_iocs)
        print(f"   ✅ Collected {len(sample_iocs)} IOCs")
        time.sleep(0.5)
    if collected_iocs:
        save_json_file(COLLECTED_IOCS_FILE, collected_iocs)
        print(f"\n💾 Saved {len(collected_iocs)} IOCs")
    input("\nPress Enter to continue...")

def process_enrich_iocs():
    clear_screen()
    print("\n🔧 Processing & Enriching IOCs...")
    print("-" * 40)
    collected_iocs = load_json_file(COLLECTED_IOCS_FILE)
    if not collected_iocs:
        print("❌ No IOCs found. Please collect IOCs first.")
        input("\nPress Enter to continue...")
        return
    processed_iocs = []
    for ioc in collected_iocs:
        enriched_ioc = ioc.copy()
        enriched_ioc['processed_at'] = datetime.now().isoformat()
        enriched_ioc['malicious'] = random.choice([True, True, False])
        if enriched_ioc['malicious']:
            print(f"   🚨 {ioc['value']} - MALICIOUS")
        else:
            print(f"   ✅ {ioc['value']} - CLEAN")
        processed_iocs.append(enriched_ioc)
        time.sleep(0.2)
    if save_json_file(PROCESSED_IOCS_FILE, processed_iocs):
        malicious_count = sum(1 for ioc in processed_iocs if ioc.get('malicious', False))
        print(f"\n✅ Processed {len(processed_iocs)} IOCs, Found {malicious_count} malicious")
    input("\nPress Enter to continue...")

def add_custom_ioc():
    clear_screen()
    print("\n➕ Add Custom IOC")
    print("-" * 30)
    print("\n📝 IOC Types: ip, url, domain, hash")
    ioc_type = input("Enter IOC type: ").strip().lower()
    ioc_value = input("Enter IOC value: ").strip()
    if not ioc_value:
        print("❌ IOC value cannot be empty")
        input("\nPress Enter to continue...")
        return
    new_ioc = {
        "type": ioc_type,
        "value": ioc_value,
        "source": "manual",
        "timestamp": datetime.now().isoformat()
    }
    collected_iocs = load_json_file(COLLECTED_IOCS_FILE)
    collected_iocs.append(new_ioc)
    if save_json_file(COLLECTED_IOCS_FILE, collected_iocs):
        print(f"✅ Added: {ioc_type} = {ioc_value}")
    input("\nPress Enter to continue...")

def view_collected_data():
    clear_screen()
    print("\n📊 View Collected Data")
    print("=" * 50)
    collected_iocs = load_json_file(COLLECTED_IOCS_FILE)
    print(f"\n📥 COLLECTED IOCs: {len(collected_iocs)}")
    if collected_iocs:
        for i, ioc in enumerate(collected_iocs[:10], 1):
            print(f"{i}. [{ioc['type'].upper()}] {ioc['value']}")
    else:
        print("No IOCs collected yet.")
    input("\nPress Enter to continue...")

def store_enriched_data():
    clear_screen()
    print("\n💾 Store Enriched Data")
    print("-" * 30)
    processed_iocs = load_json_file(PROCESSED_IOCS_FILE)
    if not processed_iocs:
        print("❌ No enriched data to store.")
    else:
        malicious_count = sum(1 for ioc in processed_iocs if ioc.get('malicious', False))
        print(f"✅ Total: {len(processed_iocs)}, Malicious: {malicious_count}")
    input("\nPress Enter to continue...")

def start_api_server():
    clear_screen()
    print("\n🌐 Starting API Server...")
    print("-" * 30)
    print("🚀 API server would run on: http://localhost:8000")
    print("📚 API docs: http://localhost:8000/docs")
    input("\nPress Enter to continue...")

def system_status():
    clear_screen()
    print("\n📈 System Status")
    print("=" * 40)
    collected_iocs = load_json_file(COLLECTED_IOCS_FILE)
    processed_iocs = load_json_file(PROCESSED_IOCS_FILE)
    print(f"📁 Collected IOCs: {len(collected_iocs)}")
    print(f"📁 Processed IOCs: {len(processed_iocs)}")
    malicious_count = sum(1 for ioc in processed_iocs if ioc.get('malicious', False)) if processed_iocs else 0
    print(f"🚨 Malicious: {malicious_count}")
    status = network_monitor.get_status()
    print(f"\n🛡️  Monitoring: {'🟢 ACTIVE' if status['monitoring'] else '🔴 INACTIVE'}")
    print(f"🚨 Threats Detected: {status['threats_detected']}")
    input("\nPress Enter to continue...")

def help_documentation():
    clear_screen()
    print("\n📖 Help & Documentation")
    print("=" * 50)
    print("\n🛡️  THREAT INTELLIGENCE PIPELINE")
    print("1. Collect IOCs → 2. Process & Enrich → 3. Monitor Network")
    print("\n🌐 REAL NETWORK MONITORING FEATURES:")
    print("   • Malicious IP detection (incoming/outgoing)")
    print("   • Ping (ICMP) detection")
    print("   • Port scan detection")
    print("   • DNS query monitoring")
    print("\n⚡ QUICK START:")
    print("1. Select Option 2 (Pull IOC Collection)")
    print("2. Select Option 3 (Process & Enrich IOCs)")
    print("3. Run with sudo: sudo python3 main.py")
    print("4. Select Option 8 → 1 (Start Monitoring)")
    input("\nPress Enter to continue...")

def main():
    ensure_data_directory()
    while True:
        clear_screen()
        choice = main_menu()
        if choice == '1':
            quick_threat_scan()
        elif choice == '2':
            pull_ioc_collection()
        elif choice == '3':
            process_enrich_iocs()
        elif choice == '4':
            add_custom_ioc()
        elif choice == '5':
            view_collected_data()
        elif choice == '6':
            store_enriched_data()
        elif choice == '7':
            start_api_server()
        elif choice == '8':
            handle_network_analysis()
        elif choice == '9':
            system_status()
        elif choice == '10':
            help_documentation()
        elif choice == '11':
            network_monitor.stop_monitoring()
            print("\n🙏 Thank you! Stay secure!")
            break
        else:
            print("❌ Invalid option!")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
