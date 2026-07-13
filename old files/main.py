#root
import json
import redis
import joblib
import numpy as np
import hashlib
from datetime import datetime, timezone
from core.crypto import QuantumForensicCrypto
from core.pipeline import DualEnginePipeline, AnomalyEngine, EntropyEngine
from core.logger import ForensicLogger
from scapy.all import IP, ICMP
from collections import OrderedDict
import time

def main():
    print("[*] Initializing Quantum-Safe Hybrid IDS Worker Engine...")
    
    # 1. Boot Subsystems
    crypto = QuantumForensicCrypto()
    pipeline = DualEnginePipeline()               # Layer 1: Deterministic Rules
    anomaly_engine = AnomalyEngine()              # Layer 3: Behavioral Heuristics
    entropy_engine = EntropyEngine(threshold=7.5) # Layer 2: Cryptographic Anomalies
    logger = ForensicLogger(crypto)
    
    redis_client = redis.Redis(host='localhost', port=6379, db=0, socket_keepalive=True)
    
    # 2. Load the Machine Learning Baseline
    try:
        ml_model = joblib.load("models/isolation_forest.joblib")
        print("[+] Machine Learning Inference Engine Online (Isolation Forest).")
    except FileNotFoundError:
        print("[-] ML Model not found. Heuristic inference disabled. Run train_baseline.py first.")
        ml_model = None

    
    seen_alerts = OrderedDict()
    print("[+] Engine armed. Awaiting data from packet_buffer queue...\n")

    try:
        while True:
            try:
                item = redis_client.brpop("packet_buffer", timeout=1)
                if item:
                    _, packet_hex = item
                    packet_bytes = bytes.fromhex(packet_hex.decode('utf-8'))
                    
                    # --- 🚀 NEW: OS NOISE PRE-FILTER ---
                    # Drop kernel-generated ICMP Boomerangs (Destination Unreachable)
                    # so they don't trigger false behavioral anomalies in the ML Engine.
                    try:
                        pkt = IP(packet_bytes)
                        if ICMP in pkt and pkt[ICMP].type == 3:
                            continue # Silently drop and move to the next packet
                    except Exception:
                        pass # If it's malformed, let the inspection engines deal with it
                    
                    # --- THE HYBRID ROUTING CASCADED LOGIC ---
                    alert = None
                    
                    # Pass 1: YARA handles its own deduplication internally
                    alert = pipeline.process_packet(packet_bytes)
                    
                    if not alert:
                        # Pass 2: Cryptographic Entropy
                        entropy_alert = entropy_engine.analyze(packet_bytes)
                        if entropy_alert:
                            # Manually apply suppression here for entropy alerts
                            # ... (use the same Redis NX logic as before)
                            alert = entropy_alert
                            
                        # Pass 3: Unsupervised Behavioral Inference (Isolation Forest)
                        elif ml_model:
                            vector = anomaly_engine.extract_features(packet_bytes)
                            if vector:
                                # scikit-learn expects a 2D matrix
                                prediction = ml_model.predict([vector])[0]
                                if prediction == -1:
                                    alert = {
                                        "engine": "ML-Anomaly (Isolation Forest)",
                                        "threat_name": "Behavioral Deviation / Zero-Day",
                                        "severity": "HIGH",
                                        "timestamp": datetime.now(timezone.utc).isoformat()
                                    }
                    
                    # --- NATIVE HARDENED PAYLOAD DEDUPLICATION ---
                    if alert:
                        # 1. Extract the raw payload so we ignore mutated header checksums
                        try:
                            pkt = IP(packet_bytes)
                            # If it has a payload, use it; otherwise fallback to full hash
                            fingerprint_data = bytes(pkt[Raw]) if Raw in pkt else packet_bytes
                        except Exception:
                            fingerprint_data = packet_bytes
                        
                        # 2. Hash the PAYLOAD, not the header
                        packet_hash = hashlib.sha256(fingerprint_data).hexdigest()
                        cache_key = f"dedup:{packet_hash}"
                        
                        # 3. Atomic check
                        is_new_threat = redis_client.set(cache_key, "1", ex=2, nx=True)
                        
                        if is_new_threat:
                            print(f"[!] Threat Caught! Engine: {alert['engine']} | Securing forensics...")
                            logger.generate_secure_log(alert)
                            print(f"[+] Forensic Envelope permanently stored and published.")
                            
            except redis.exceptions.TimeoutError:
                continue

    except KeyboardInterrupt:
        print("\n[-] Releasing native cryptographic memory spaces...")
        crypto.close()
        print("[-] IDS Engine worker safely shut down.")

if __name__ == "__main__":
    main()