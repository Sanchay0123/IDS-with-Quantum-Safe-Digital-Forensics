import time
import json
import redis
import random
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap

def generate_test_suite(filename="threat_suite.pcap"):
    """Programmatically crafts a multi-layer threat vector PCAP file."""
    print(f"[*] Compiling cryptographic threat matrix into {filename}...")
    packets = []
    
    # Vector 1: Benign Baseline
    for i in range(50):
        pkt = IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=443, dport=random.randint(49152, 65535)) / Raw(load=f"BENIGN_TRAFFIC_DATA_{i}")
        packets.append(pkt)
        
    # Vector 2: Layer 1 Rule Match (YARA / Deterministic)
    # Substitute this string with an exact match for one of your 1,699 active signatures
    for _ in range(10):
        pkt = IP(src="10.0.0.5", dst="192.168.1.1") / TCP(sport=1337, dport=80) / Raw(load="EVIL_MALWARE_SIGNATURE_STRING_HERE")
        packets.append(pkt)
        
    # Vector 3: Layer 2 Cryptographic Anomaly (High Entropy)
    # High-entropy random byte string designed to bypass rules but cross the 7.5 entropy threshold
    for _ in range(10):
        high_entropy_payload = os.urandom(256)
        pkt = IP(src="10.0.0.6", dst="192.168.1.1") / UDP(sport=53, dport=53) / Raw(load=high_entropy_payload)
        packets.append(pkt)
        
    # Vector 4: Duplicated Echo Stream (Testing your Native Payload Deduplication)
    # Identical payloads sent consecutively to verify the Redis NX cache hit rate
    static_payload = b"EXACT_SAME_EXPLOIT_PAYLOAD_STRING_ABCDE12345"
    for _ in range(15):
        pkt = IP(src="10.0.0.7", dst="192.168.1.1") / TCP(sport=8080, dport=80) / Raw(load=static_payload)
        packets.append(pkt)

    wrpcap(filename, packets)
    print(f"[+] Successfully baked {len(packets)} structural packets into test suit.")

def replay_pcap_to_redis(filename="threat_suite.pcap", pps=100):
    """Parses the generated PCAP and streams it down the master's Redis engine."""
    r = redis.Redis(host='localhost', port=6379, db=0)
    print(f"[*] Connecting to local packet_buffer queue. Injecting at {pps} PPS...")
    
    # Read raw packets via Scapy's PcapReader for high-efficiency processing
    from scapy.utils import PcapReader
    
    total_injected = 0
    delay = 1.0 / pps
    
    with PcapReader(filename) as pcap_reader:
        for pkt in pcap_reader:
            # Extract raw network bytes from the PCAP layer frame
            raw_bytes = bytes(pkt)
            hex_payload = raw_bytes.hex()
            
            # Pipe straight into the master node's processing core
            r.lpush("packet_buffer", hex_payload)
            total_injected += 1
            
            time.sleep(delay)
            
    print(f"[+] Replay sequence complete. Total injected packets: {total_injected}")

if __name__ == "__main__":
    import os
    # 1. Cook the test vectors
    generate_test_suite()
    
    # 2. Wait a moment for the user to verify master is online
    print("\n[!] Ensure sentinel_master.py is running in another shell.")
    input("[?] Press Enter to fire the traffic replay simulation matrix...")
    
    # 3. Stream traffic down the ingestion pipe
    replay_pcap_to_redis(pps=50)