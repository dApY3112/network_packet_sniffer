# Network Packet Sniffer

This is a simple network packet sniffer application built with **Flask** and **Scapy** to capture, analyze, and display network packets in real-time. It also includes features to detect suspicious activities like **ARP Spoofing** and **unusual port usage**. The application provides a web interface where users can:

- View packet statistics (total, ARP, TCP, UDP packets).
- Apply filters to capture packets by IP address and protocol (ARP, TCP, UDP).
- Detect suspicious network activities (e.g., ARP spoofing).
- View suspicious activity logs in real-time.

## Features

- **Real-Time Packet Capture**: Sniff packets from the network in real time.
- **Packet Filtering**: Filter captured packets by IP address and protocol (ARP, TCP, UDP).
- **Suspicious Activity Detection**:
  - **ARP Spoofing Detection**: Detect and log ARP spoofing attempts.
  - **Unusual Port Usage Detection**: Detect unusual port usage outside the range of normal ports (1-1024).
- **Traffic Statistics**: Display statistics for total packets, ARP, TCP, and UDP packets.
- **Suspicious Activity Logs**: Display logs of suspicious activities like ARP spoofing and unusual port usage.

## Requirements

- Python 3.x
- Flask
- Scapy
- Threading


To install the necessary Python dependencies, use the following command:

```bash
pip install flask scapy

## Running the Application

To run the packet sniffer application, follow these steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/network_packet_sniffer.git
   cd network_packet_sniffer
    python app.py