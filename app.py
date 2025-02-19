from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from scapy.all import sniff, ARP, TCP, UDP, IP
import threading
import logging

# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app)

# Set up logging
logging.basicConfig(filename='network_monitor.log', level=logging.INFO)

class NetworkMonitor:
    def __init__(self):
        self.packet_stats = {'total': 0, 'arp': 0, 'tcp': 0, 'udp': 0}
        self.ip_mac_mapping = {}
        self.suspicious_activity = []
        self.packet_filter = {'ip': '', 'protocol': ''}

    def detect_arp_spoof(self, packet):
        if packet.op == 2:  # ARP reply
            ip = packet.psrc
            mac = packet.hwsrc
            if ip in self.ip_mac_mapping and self.ip_mac_mapping[ip] != mac:
                message = f"ARP Spoofing detected: {ip} is being spoofed by {mac}"
                self.suspicious_activity.append(message)
                emit('new_alert', {'message': message}, namespace='/alert')
                logging.info(message)
            else:
                self.ip_mac_mapping[ip] = mac

    def detect_unusual_ports(self, packet):
        port = packet.dport
        if port >= 1025:  # Example range for normal ports
            message = f"Unusual port usage detected: Port {port} is being used"
            self.suspicious_activity.append(message)
            emit('new_alert', {'message': message}, namespace='/alert')
            logging.info(message)

    def packet_callback(self, packet):
        # Apply packet filters
        if not self.apply_filters(packet):
            return

        self.packet_stats['total'] += 1
        if packet.haslayer(ARP):
            self.packet_stats['arp'] += 1
            self.detect_arp_spoof(packet[ARP])
        elif packet.haslayer(TCP):
            self.packet_stats['tcp'] += 1
            self.detect_unusual_ports(packet[TCP])
        elif packet.haslayer(UDP):
            self.packet_stats['udp'] += 1
            self.detect_unusual_ports(packet[UDP])

    def apply_filters(self, packet):
        if self.packet_filter['ip'] and packet.haslayer(IP) and packet[IP].src != self.packet_filter['ip']:
            return False
        if self.packet_filter['protocol']:
            if (self.packet_filter['protocol'].lower() == 'tcp' and not packet.haslayer(TCP)) or \
               (self.packet_filter['protocol'].lower() == 'udp' and not packet.haslayer(UDP)):
                return False
        return True

monitor = NetworkMonitor()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        monitor.packet_filter['ip'] = request.form.get('ip', '')
        monitor.packet_filter['protocol'] = request.form.get('protocol', '')
    return render_template('index.html', stats=monitor.packet_stats, suspicious=monitor.suspicious_activity, filter=monitor.packet_filter)

def start_packet_sniffing():
    sniff(prn=monitor.packet_callback, store=False)

if __name__ == '__main__':
    threading.Thread(target=start_packet_sniffing, daemon=True).start()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
