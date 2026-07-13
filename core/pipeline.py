import yara
import redis
import time
import math
from collections import Counter
from datetime import datetime, timezone
from scapy.all import IP, TCP, UDP, Raw

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
            
            # --- METADATA EXTRACTION ---
            severity_level = best_match.meta.get('severity', 'HIGH')
            human_readable_name = best_match.meta.get('description', 'Unknown Exploit Signature')
            
            cache_key = f"dedup:{best_match.rule}"
            
            if not self.redis.set(cache_key, "1", ex=2, nx=True):
                return None
                
            # --- UI MAPPING ---
            return {
                "engine": "YARA-C",
                "threat_name": f"YARA-C ({best_match.rule})",
                "description": human_readable_name,
                "severity": severity_level,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        return None

class AnomalyEngine:
    def __init__(self):
        print("[*] Initializing Stateful ML Feature Extractor...")
        self.redis = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        
    def extract_features(self, packet_bytes: bytes) -> list | None:
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
            
            return [size, protocol, flags, round(delta_t, 4)]
            
        except Exception:
            return None

class EntropyEngine:
    def __init__(self, threshold=7.5):
        print(f"[*] Initializing Shannon Entropy Analyzer (Threshold: {threshold})...")
        self.threshold = threshold

    def analyze(self, packet_bytes: bytes) -> dict | None:
        if not packet_bytes:
            return None

        try:
            packet = IP(packet_bytes)
            
            if Raw in packet:
                payload = bytes(packet[Raw])
            else:
                return None 
                
            if not payload:
                return None

            counts = Counter(payload)
            length = len(payload)
            
            entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
            
            if entropy >= self.threshold:
                # --- UI MAPPING ---
                return {
                    "engine": "ENTROPY-ANALYSIS",
                    "threat_name": "CRYPTOGRAPHIC ANOMALY DETECTED",
                    "description": f"High Shannon Entropy Payload ({entropy:.2f}/8.0) indicating potential encrypted exfiltration.",
                    "severity": "HIGH",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
        except Exception:
            pass
            
        return None