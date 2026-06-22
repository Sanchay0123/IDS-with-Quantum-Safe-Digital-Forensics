import yara
import redis
import time
import math
from collections import Counter
from datetime import datetime, timezone
from scapy.all import IP, TCP, UDP, Raw

# In core/pipeline.py

class DualEnginePipeline:
    def __init__(self, rules_file="matrix.yar"):
        print("[*] Initializing Native C YARA Engine...")
        self.rules = yara.compile(filepath=rules_file)
        self.redis = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

    def process_packet(self, packet_bytes: bytes) -> dict | None:
        if not self.rules: return None
        
        matches = self.rules.match(data=packet_bytes)
        if matches:
            best_match = matches[0]
            # Use deterministic threat signature as the unique key
            threat_name = best_match.rule
            cache_key = f"dedup:{threat_name}"
            
            # Atomic lock: if we already saw this specific YARA rule, return None
            if not self.redis.set(cache_key, "1", ex=2, nx=True):
                return None
                
            return {
                "engine": f"YARA-C ({best_match.rule})",
                "threat_name": threat_name,
                "severity": "HIGH",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        return None

class AnomalyEngine:
    def __init__(self):
        print("[*] Initializing Stateful ML Feature Extractor...")
        self.redis = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        
    def extract_features(self, packet_bytes: bytes) -> list | None:
        """
        Translates raw packet bytes into a mathematical vector: [size, protocol, flags, delta_t]
        """
        try:
            packet = IP(packet_bytes)
            size = len(packet_bytes)
            protocol = packet.proto
            
            flags = 0
            if TCP in packet:
                flags = int(packet[TCP].flags)
            elif UDP in packet:
                flags = 0
                
            src_ip = packet.src
            current_time = time.time()
            redis_key = f"last_seen:{src_ip}"
            
            last_seen = self.redis.get(redis_key)
            if last_seen:
                delta_t = current_time - float(last_seen)
            else:
                delta_t = 0.0 
                
            self.redis.set(redis_key, current_time, ex=3600)
            
            feature_vector = [size, protocol, flags, round(delta_t, 4)]
            return feature_vector
            
        except Exception:
            return None


class EntropyEngine:
    def __init__(self, threshold=7.5):
        print(f"[*] Initializing Shannon Entropy Analyzer (Threshold: {threshold})...")
        self.threshold = threshold

    def analyze(self, packet_bytes: bytes) -> dict | None:
        """
        Calculates Shannon Entropy on the RAW PAYLOAD to flag encrypted exfiltration.
        """
        if not packet_bytes:
            return None

        try:
            packet = IP(packet_bytes)
            
            # We must strip away the low-entropy IP/TCP/UDP headers
            # and ONLY analyze the application layer payload.
            if Raw in packet:
                payload = bytes(packet[Raw])
            else:
                return None # No payload to analyze
                
            if not payload:
                return None

            counts = Counter(payload)
            length = len(payload)
            
            entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
            
            if entropy >= self.threshold:
                return {
                    "engine": "Entropy Engine",
                    "threat_name": f"High Entropy Payload ({entropy:.2f}/8.0)",
                    "severity": "HIGH",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
        except Exception:
            # Drop malformed packets
            pass
            
        return None