import time
import random
from collections import defaultdict
from scapy.all import IP, TCP, send
from traffic_monitor import monitor_traffic, detect_dos_attack
from dos_response import respond_to_dos_attack

# Define threshold values
THRESHOLD_REQUESTS_PER_SECOND = 10  # Maximum number of requests per second
THRESHOLD_IP_REQUESTS = 10          # Maximum number of requests from a single IP
THRESHOLD_DURATION = 10             # Duration (in seconds) to monitor traffic patterns
SRC_IP_RANGE = 10                   # Range of source IP addresses
NUMBER_OF_REQUESTS = 100            

# Track IP addresses and request counts
ip_requests = defaultdict(int)
# blocked_ips = set()

# Simulate sending requests and detect/respond to DoS attacks
def simulate_and_detect():
    target_ip = "192.168.0.1"  # target IP address
    target_port = 80  # target port

    num_requests = NUMBER_OF_REQUESTS  # Number of requests to send

    start_time = time.time()

    for _ in range(num_requests):
        
        i=random.choice(list(range(SRC_IP_RANGE)))
        # Craft TCP packet
        packet = IP(src=f'127.0.0.{i}', dst=target_ip) / TCP(dport=target_port)

        print("\n","*"*50)

        # if packet.src in blocked_ips:
        if detect_dos_attack(ip_requests, packet.src, THRESHOLD_REQUESTS_PER_SECOND):
            print(f"This source ({packet.src}) is blocked.")
            continue
        # Send the packet
        send(packet, verbose=False)
        print("Sending packet:",packet)
        # Increment request count
        ip_requests[packet.src] += 1

        # Check for DoS attack
        if detect_dos_attack(ip_requests, packet.src, THRESHOLD_REQUESTS_PER_SECOND):
            print(f"Possible DoS attack detected from IP: {packet.src}")
            respond_to_dos_attack(packet.src)
            # blocked_ips.add(packet.src)
        

        # Calculate sleep duration for desired requests per second
        elapsed_time = time.time() - start_time
        sleep_duration = max(0, 1 / THRESHOLD_REQUESTS_PER_SECOND - elapsed_time)
        time.sleep(sleep_duration)
    print("*"*50, "\nFinished sending requests.")

# Main program
if __name__ == '__main__':
    print("DoS Attack Detection and Response Program")
    print("-----------------------------------------")

    # Simulate sending requests and detect/respond to DoS attacks
    simulate_and_detect()
