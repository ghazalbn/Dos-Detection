import time
from scapy.all import sniff

# Monitor network traffic and detect DoS attacks
def monitor_traffic(ip_requests, threshold_ip, duration, dos_detector, callback):
    start_time = time.time()
    end_time = start_time + duration

    while time.time() < end_time:
        # Capture incoming packets
        packets = sniff(filter="tcp", count=100)

        for packet in packets:
            source_ip = packet[1][1].src

            # Increment request count for the source IP
            ip_requests[source_ip] += 1

            # Check for DoS attack
            if dos_detector(ip_requests, source_ip, threshold_ip):
                print(f"Possible DoS attack detected from IP: {source_ip}")
                callback(source_ip)

        time.sleep(0.1)  # Adjust sleep duration based on monitoring requirements

# Detect a DoS attack based on request count from a single IP
def detect_dos_attack(ip_requests, source_ip, threshold_ip):
    return ip_requests[source_ip] > threshold_ip
