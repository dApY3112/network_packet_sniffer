from flask import Flask, render_template, request
from scapy.all import sniff, ARP, TCP, UDP
import threading
import time

# Initialize Flask app
app = Flask(__name__)

# Global variables for packet stats, ip_mac mapping, and suspicious activity
packet_stats = {'total': 0, 'arp': 0, 'tcp': 0, 'udp': 0}
ip_mac_mapping = {}
suspicious_activity = []

# Packet filter parameters
packet_filter = {'ip': '', 'protocol': ''}

# Function to detect ARP spoofing
def detect_arp_spoof(packet):
    if packet.haslayer(ARP):
        arp_packet = packet[ARP]
        if arp_packet.op == 2:  # ARP reply
            ip = arp_packet.psrc
            mac = arp_packet.hwsrc
            if ip in ip_mac_mapping:
                if ip_mac_mapping[ip] != mac:
                    suspicious_activity.append(f"[{time.ctime()}] ARP Spoofing detected: {ip} is being spoofed by {mac}")
            else:
                ip_mac_mapping[ip] = mac

# Function to detect unusual port usage
def detect_unusual_ports(packet):
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        port = packet.dport  # Destination port
        if port not in range(1, 1025):  # Example range for normal ports
            suspicious_activity.append(f"[{time.ctime()}] Unusual port usage detected: Port {port} is being used")

# Callback for packet sniffing with filtering
def packet_callback(packet):
    if packet_filter['ip'] and (packet.haslayer(ARP) and packet[ARP].psrc != packet_filter['ip']) and \
       not (packet.haslayer(TCP) and packet[IP].src == packet_filter['ip']) and \
       not (packet.haslayer(UDP) and packet[IP].src == packet_filter['ip']):
        return  # Skip packet if it doesn't match the filter

    packet_stats['total'] += 1
    if packet.haslayer(ARP):
        packet_stats['arp'] += 1
        detect_arp_spoof(packet)
    elif packet.haslayer(TCP):
        packet_stats['tcp'] += 1
        detect_unusual_ports(packet)
    elif packet.haslayer(UDP):
        packet_stats['udp'] += 1
        detect_unusual_ports(packet)

# Flask route for the dashboard with filtering functionality
@app.route('/', methods=['GET', 'POST'])
def index():
    global packet_filter
    if request.method == 'POST':
        packet_filter = {
            'ip': request.form.get('ip', ''),
            'protocol': request.form.get('protocol', '')
        }

    return render_template('index.html', stats=packet_stats, suspicious=suspicious_activity, filter=packet_filter)

# Function to start the Flask server (main thread)
def start_flask_server():
    app.run(debug=True, host='0.0.0.0', port=5000)

# Function to start packet sniffing (in a separate thread)
def start_packet_sniffing():
    sniff(prn=packet_callback, store=0)

# Run Flask and packet sniffing in separate threads
if __name__ == '__main__':
    # Start packet sniffing in a separate thread
    sniffer_thread = threading.Thread(target=start_packet_sniffing)
    sniffer_thread.daemon = True  # Allow sniffer to stop when main program exits
    sniffer_thread.start()

    # Start Flask server in the main thread
    start_flask_server()
