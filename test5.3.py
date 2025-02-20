import subprocess
import os 
import re
from prometheus_client import start_http_server, Gauge
import time
from scapy.all import sniff, Raw, IP, TCP, UDP
from threading import Thread, Lock
import psutil
from collections import defaultdict
from plyer import notification
import socket
from ping3 import ping  # For latency monitoring
import socket
# Prometheus Gauges
PACKETCOUNT = Gauge('network_packet_count', 'Number of packets captured')
BANDWIDTH_USAGE = Gauge('network_bandwidth_usage', 'Total bandwidth usage in bytes per second')
TOTAL_ANOMALIES = Gauge('network_total_anomalies', 'Cumulative total anomalies detected')

BLACKLISTED_PORTS = Gauge('network_blacklisted_ports', 'Number of packets involving blacklisted ports')
BLACKLISTED_DOMAINS = Gauge('network_blacklisted_domains', 'Number of packets involving blacklisted domains')

SYSTEM_CPU_USAGE = Gauge('system_cpu_usage', 'CPU usage percentage', ['device'])
SYSTEM_MEMORY_USAGE = Gauge('system_memory_usage', 'Memory usage percentage', ['device'])
SYSTEM_DISK_USAGE = Gauge('system_disk_usage', 'Disk usage percentage', ['device'])

DDOS_ATTEMPTS = Gauge('network_ddos_attempts', 'Number of potential DDoS attempts detected')
NETWORK_LATENCY = Gauge('network_latency', 'Network latency (round-trip time in ms)', ['target'])




# Global Variables and Lock
total_anomalies = 0
lock = Lock()
ip_ports = defaultdict(set)
ip_packet_count = defaultdict(int)  # Track packets per source IP (for DDoS detection)
high_bandwidth_usage_logs = []  # List to store high bandwidth usage logs

# Blacklisted ports and domains
BLACKLISTED_PORTS_LIST = {22, 23, 3389}  # Example blacklisted ports
BLACKLISTED_DOMAINS_LIST = {"example.com", "maliciousdomain.com"}  # Example blacklisted domains

# Thresholds
THRESHOLD_BANDWIDTH = 20000  # Example: 20,000 bytes/sec
DDoS_THRESHOLD = 10000  # Example: More than 100 packets from the same source in a second is considered a DDoS

# Alert cooldown variables
last_alert_time = 0
ALERT_COOLDOWN = 100  # Cooldown period in seconds

# Function to show a system popup alert with cooldown
def show_alert(bandwidth):
    global last_alert_time
    current_time = time.time()

    # Check if the cooldown period has elapsed
    if current_time - last_alert_time >= ALERT_COOLDOWN:
        try:
            notification.notify(
                title="High Bandwidth Usage Alert!",
                message=f"Bandwidth usage has reached {bandwidth} bytes/sec.",
                app_name="Network Monitor",
                timeout=10  # Display duration in seconds
            )
            print(f"Alert triggered for high bandwidth usage: {bandwidth} bytes/sec.")
            last_alert_time = current_time  # Update the last alert time
        except Exception as e:
            print(f"Error showing alert: {e}")
 
# TShark Capture Function with Alert
def tshark_capture():
    try:
        print("Starting TShark capture...")

        tshark_process = subprocess.Popen(
            ["tshark", "-i", "Ethernet", "-T", "fields", "-e", "frame.len", "-e", "ip.dst", "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        packet_count = 0
        total_bandwidth = 0
        start_time = time.time()
        destination_ips = defaultdict(int)  # Dictionary to track destination IP addresses

        for line in tshark_process.stdout:
            match = re.match(r'(\d+)\s+(\S+)', line.strip())
            if match:
                packet_size = int(match.group(1))
                dst_ip = match.group(2)

                packet_count += 1
                total_bandwidth += packet_size
                destination_ips[dst_ip] += packet_size  # Track the bandwidth usage for each destination IP

            if time.time() - start_time >= 1:
                PACKETCOUNT.set(packet_count)
                BANDWIDTH_USAGE.set(total_bandwidth)

                # Trigger alert if bandwidth exceeds threshold
                if total_bandwidth > THRESHOLD_BANDWIDTH:
                    show_alert(total_bandwidth)
                    
                    # Log the high bandwidth usage event with destination IP, if it exceeds the threshold
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    for dst_ip, bandwidth in destination_ips.items():
                        if bandwidth > THRESHOLD_BANDWIDTH:  # Only log if the bandwidth exceeds threshold
                            high_bandwidth_usage_logs.append(f"{timestamp}: {dst_ip} - {bandwidth} bytes/sec")

                # Reset counters for the next second
                packet_count = 0
                total_bandwidth = 0
                destination_ips.clear()  # Clear destination IP dictionary
                start_time = time.time()

    except Exception as e:
        print(f"Error in TShark capture: {e}")

# Scapy Packet Analyzer
def scapy_analyze_packet(packet):
    global total_anomalies

    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # DDoS Detection: Track packets from the same source IP
            ip_packet_count[src_ip] += 1
            if ip_packet_count[src_ip] > DDoS_THRESHOLD:
                with lock:
                    total_anomalies += 1
                    DDOS_ATTEMPTS.inc()
                    print(f"DDoS attempt detected from {src_ip} (over {DDoS_THRESHOLD} packets in 1 second).")

            # Check for blacklisted ports (TCP or UDP)
            if TCP in packet or UDP in packet:
                sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
                dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
                if sport in BLACKLISTED_PORTS_LIST or dport in BLACKLISTED_PORTS_LIST:
                    with lock:
                        total_anomalies += 1
                    BLACKLISTED_PORTS.inc()
                    print(f"Blacklisted port detected: {sport if sport in BLACKLISTED_PORTS_LIST else dport}")

            # Check for blacklisted domains (based on destination IP or known domain list)
            if dst_ip in BLACKLISTED_DOMAINS_LIST:
                with lock:
                    total_anomalies += 1
                BLACKLISTED_DOMAINS.inc()
                print(f"Blacklisted domain detected: {dst_ip}")

        # Detect suspicious packet data
        if Raw in packet and b"suspicious" in packet[Raw].load:
            with lock:
                total_anomalies += 1
                TOTAL_ANOMALIES.set(total_anomalies)

    except Exception as e:
        print(f"Error analyzing packet: {e}")

# Scapy Sniffer
def scapy_sniffer():
    print("Starting Scapy packet sniffer...")
    sniff(iface="Wi-Fi", prn=scapy_analyze_packet, store=False)

# Reset Anomalies Periodically (Only at the end of the day)
def reset_anomalies():
    global total_anomalies
    while True:
        current_time = time.localtime()
        # Reset the anomalies count at midnight
        if current_time.tm_hour == 0 and current_time.tm_min == 0:
            with lock:
                total_anomalies = 0
                TOTAL_ANOMALIES.set(total_anomalies)
                print("Anomalies count reset for the new day.")
        time.sleep(60)  # Check every minute to reset at midnight

# Monitor Network Latency
def monitor_latency(target=None):
    while True:
        try:
            if target is None:
                # Automatically detect the default gateway (router IP)
                gateways = psutil.net_if_addrs()
                default_gateway = None

                for iface, addrs in gateways.items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:  # Get IPv4 address
                            default_gateway = addr.address
                            break
                    if default_gateway:
                        break  # Stop searching once found

                if default_gateway:
                    target = default_gateway
                else:
                    print("Error: Default gateway not found, using public DNS 8.8.8.8 as fallback.")
                    target = "8.8.8.8"  # Google Public DNS as fallback

            # Now ping the target
            rtt = ping(target, unit="ms")
            if rtt is not None:
                NETWORK_LATENCY.labels(target=target).set(rtt)
            else:
                print(f"Unable to ping target: {target}")

        except Exception as e:
            print(f"Error measuring latency: {e}")

        time.sleep(1)  # Update latency every second


# System Metrics Monitoring
def monitor_local_metrics():
    previous_read = 0
    previous_write = 0

    while True:
        # CPU and memory usage
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent

        # Dynamic disk I/O monitoring
        disk_io = psutil.disk_io_counters()
        read_bytes = disk_io.read_bytes
        write_bytes = disk_io.write_bytes
        read_speed = (read_bytes - previous_read) / 1024  # KB/s
        write_speed = (write_bytes - previous_write) / 1024  # KB/s

        previous_read = read_bytes
        previous_write = write_bytes

        # Static disk usage percentage
        disk_usage = psutil.disk_usage('/').percent

        # Export metrics to Prometheus
        SYSTEM_CPU_USAGE.labels(device="localhost").set(cpu_usage)
        SYSTEM_MEMORY_USAGE.labels(device="localhost").set(memory)
        SYSTEM_DISK_USAGE.labels(device="localhost").set(disk_usage)

        # Updates every 5 seconds
        time.sleep(5)
def is_blacklisted_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]  # Get domain name from IP
        return domain in BLACKLISTED_DOMAINS_LIST
    except (socket.herror, socket.gaierror):  # Catch lookup errors
        return False

if dst_ip in BLACKLISTED_DOMAINS_LIST or is_blacklisted_domain(dst_ip):
    with lock:
        total_anomalies += 1
    BLACKLISTED_DOMAINS.inc()
    print(f"Blacklisted domain detected: {dst_ip}")
    
def load_blacklist(file_path):
    try:
        with open(file_path, "r") as file:
            return set(line.strip() for line in file if line.strip())
    except FileNotFoundError:
        print(f"Warning: {file_path} not found. Using an empty blacklist.")
        return set()

# Load blacklists at startup
BLACKLISTED_PORTS_LIST = load_blacklist("blacklisted_ports.txt")
BLACKLISTED_DOMAINS_LIST = load_blacklist("blacklisted_domains.txt")

BLACKLISTED_PORTS_LIST = load_blacklist("blacklisted_ports.txt")
BLACKLISTED_DOMAINS_LIST = load_blacklist("blacklisted_domains.txt")

# Command Line Report Generation with Interval (per minute)
def generate_report(command):
    if command == "high_bandwidth":
        print("Generating high bandwidth usage report...")

        # Define the path where you want to save the report
        file_path = "D:\\PYCODES FOR CAPSTONE\\LogAllerts\\report.txt"

        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Clear the log file before writing new logs
        with open(file_path, "w") as file:  # Open the file in write mode to clear it
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            file.write(f"Report generated at: {timestamp}\n")

            # Log the high bandwidth usage for each destination IP
            for log in high_bandwidth_usage_logs:
                file.write(log + "\n")

            # Clear the logs after saving to file to avoid duplication
            high_bandwidth_usage_logs.clear()

        print(f"Report saved to {file_path}.")
    else:
        print("Invalid command.")

# Start Prometheus Server
def start_prometheus_server():
    start_http_server(8000)

if __name__ == '__main__':
    # Start Prometheus server in a separate thread
    Thread(target=start_prometheus_server, daemon=True).start()

    # Start packet capture in a separate thread
    Thread(target=tshark_capture, daemon=True).start()

    # Start Scapy sniffing in a separate thread
    Thread(target=scapy_sniffer, daemon=True).start()

    # Start latency monitoring in a separate thread
    Thread(target=monitor_latency, daemon=True).start()

    # Start system metrics monitoring in a separate thread
    Thread(target=monitor_local_metrics, daemon=True).start()

    # Start anomaly reset monitoring in a separate thread
    Thread(target=reset_anomalies, daemon=True).start()

    # Wait for command-line input to generate reports
    while True:
        command = input("Enter command (e.g., 'high_band' to view bandwidth report): ").strip()
        generate_report(command)