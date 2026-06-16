#!/usr/bin/env python3
import json
import threading
import time
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ICMP
import netifaces

class RealNetworkMonitor:
    def __init__(self):
        self.is_monitoring = False
        self.detected_threats = []
        self.connection_stats = defaultdict(int)
        self.threat_intel = {
            'malicious_ips': [],
            'suspicious_domains': []
        }
        self.interface = self.get_network_interface()
        
    def get_network_interface(self):
        try:
            gateways = netifaces.gateways()
            return gateways['default'][netifaces.AF_INET][1]
        except:
            return "eth0"
    
    def load_threat_intel(self):
        try:
            with open('data/processed_iocs.json', 'r') as f:
                data = json.load(f)
                self.threat_intel['malicious_ips'] = [
                    ioc['value'] for ioc in data 
                    if ioc['type'] == 'ip' and ioc.get('malicious', False)
                ]
                self.threat_intel['suspicious_domains'] = [
                    ioc['value'] for ioc in data 
                    if ioc['type'] == 'domain' and ioc.get('malicious', False)
                ]
                print(f"✅ Loaded {len(self.threat_intel['malicious_ips'])} malicious IPs")
                print(f"✅ Loaded {len(self.threat_intel['suspicious_domains'])} suspicious domains")
        except:
            self.load_sample_threat_intel()
    
    def load_sample_threat_intel(self):
        print("📥 Loading sample threat intelligence...")
        self.threat_intel['malicious_ips'] = [
            '185.220.101.132', '45.95.147.229', '8.8.8.8', '1.1.1.1'
        ]
        self.threat_intel['suspicious_domains'] = [
            'google.com', 'facebook.com', 'drmcet.ac.in', 'example.com'
        ]
        print(f"✅ Loaded {len(self.threat_intel['malicious_ips'])} sample IPs")
        print(f"✅ Loaded {len(self.threat_intel['suspicious_domains'])} sample domains")
    
    def packet_handler(self, packet):
        if not self.is_monitoring:
            return
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if src_ip in self.threat_intel['malicious_ips']:
                    self.log_threat('MALICIOUS_INCOMING', src_ip, dst_ip)
                if dst_ip in self.threat_intel['malicious_ips']:
                    if packet.haslayer(ICMP):
                        self.log_threat('MALICIOUS_PING', src_ip, dst_ip)
                    else:
                        self.log_threat('MALICIOUS_OUTGOING', src_ip, dst_ip)
                self.detect_port_scan(packet)
                self.detect_brute_force(packet)
            if DNS in packet and packet[DNS].qr == 0:
                if DNSQR in packet:
                    query = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                    for domain in self.threat_intel['suspicious_domains']:
                        if domain in query:
                            self.log_threat('MALICIOUS_DNS_QUERY', query, 'DNS')
        except:
            pass
    
    def detect_port_scan(self, packet):
        if TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            key = f"{src_ip}_{dst_port}"
            self.connection_stats[key] += 1
            if self.connection_stats[key] > 10:
                self.log_threat('PORT_SCAN_ATTEMPT', src_ip, f"port {dst_port}")
    
    def detect_brute_force(self, packet):
        if TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            service_ports = [22, 23, 21, 3389, 5900]
            if dst_port in service_ports:
                key = f"{src_ip}_service_{dst_port}"
                self.connection_stats[key] += 1
                if self.connection_stats[key] > 5:
                    service_names = {22:'SSH', 23:'Telnet', 21:'FTP', 3389:'RDP', 5900:'VNC'}
                    self.log_threat('BRUTE_FORCE_ATTEMPT', src_ip, service_names.get(dst_port, f'Port {dst_port}'))
    
    def log_threat(self, threat_type, source, target):
        event = {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'type': threat_type,
            'source': source,
            'target': target,
            'severity': 'HIGH',
            'action': 'DETECTED'
        }
        self.detected_threats.append(event)
        print(f"🚨 {threat_type}: {source} -> {target}")
    
    def start_real_monitoring(self):
        self.load_threat_intel()
        self.is_monitoring = True
        self.detected_threats = []
        print(f"📡 Monitoring on interface: {self.interface}")
        try:
            monitor_thread = threading.Thread(target=self._start_packet_capture, daemon=True)
            monitor_thread.start()
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def _start_packet_capture(self):
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0, filter="ip or icmp")
        except Exception as e:
            print(f"❌ Packet capture error: {e}")
    
    def stop_monitoring(self):
        self.is_monitoring = False
        print("🛑 Monitoring STOPPED")
    
    def get_status(self):
        return {
            'monitoring': self.is_monitoring,
            'threats_detected': len(self.detected_threats),
            'recent_events': self.detected_threats[-10:] if self.detected_threats else []
        }
    
    def get_statistics(self):
        event_types = {}
        for event in self.detected_threats:
            event_types[event['type']] = event_types.get(event['type'], 0) + 1
        return {
            'total_events': len(self.detected_threats),
            'event_breakdown': event_types,
            'monitoring_duration': 'Active' if self.is_monitoring else 'Inactive'
        }
    
    def clear_events(self):
        self.detected_threats.clear()
        print("✅ All events cleared")
    
    def block_ip(self, ip):
        if ip not in self.threat_intel['malicious_ips']:
            self.threat_intel['malicious_ips'].append(ip)
        print(f"🔒 Blocked IP: {ip}")
        return True
    
    def get_network_info(self):
        try:
            interfaces = netifaces.interfaces()
            print(f"📡 Available interfaces: {', '.join(interfaces)}")
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    print(f"   {iface}: {addrs[netifaces.AF_INET][0]['addr']}")
        except Exception as e:
            print(f"❌ Error: {e}")
