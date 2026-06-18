import sys
import redis
from scapy.all import sniff, Raw

# Connect to the local native Redis service
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Define the network interface to sniff on (e.g., 'wlan0', 'eth0', 'lo')
# 'lo' (loopback) is perfect for testing local traffic exploits
INTERFACE = "lo" 
# BPF Filter: Look at all IP traffic, excluding our own Redis (6379) and Dashboard (8000/8080) traffic to avoid infinite loops
BPF_FILTER = "ip and not port 6379 and not port 8000 and not port 8080"

print(f"[*] Initializing promiscuous mode on interface: {INTERFACE}")
print(f"[*] Applying Kernel BPF Filter: {BPF_FILTER}")

def packet_callback(packet):
    """
    Callback executed for every single packet passing the BPF filter.
    Extracts the payload and drops it into the high-speed Redis buffer.
    """
    if packet.haslayer(Raw):
        # Extract raw binary payload
        payload_bytes = packet[Raw].load
        
        # Metadata context to pass down to the engine
        packet_metadata = payload_bytes.hex()
        
        # Push to the tail of the Redis ingestion list
        redis_client.lpush("packet_buffer", packet_metadata)

try:
    # Start sniffing. store=0 ensures scapy doesn't keep packets in memory
    sniff(iface=INTERFACE, filter=BPF_FILTER, prn=packet_callback, store=0)
except PermissionError:
    print("[-] Critical Error: Sniffing requires raw socket permissions. Run with 'sudo'.")
    sys.exit(1)
except KeyboardInterrupt:
    print("\n[-] Sniffer safely disarmed.")