import json
import redis
import hashlib
from core.crypto import QuantumForensicCrypto
from core.pipeline import DualEnginePipeline
from core.logger import ForensicLogger

def main():
    print("[*] Initializing Quantum-Safe Hybrid IDS Worker Engine...")
    crypto = QuantumForensicCrypto()
    pipeline = DualEnginePipeline()
    logger = ForensicLogger(crypto)
    
    redis_client = redis.Redis(host='localhost', port=6379, db=0, socket_keepalive=True)
    print("[+] Engine armed. Awaiting data from packet_buffer queue...\n")

    try:
        while True:
            try:
                item = redis_client.brpop("packet_buffer", timeout=1)
                if item:
                    _, packet_hex = item
                    packet_bytes = bytes.fromhex(packet_hex.decode('utf-8'))
                    alert = pipeline.process_packet(packet_bytes)
                    
                    if alert:
                        # --- OPTION B: STATE-BASED DEDUPLICATION CACHE ---
                        # Hash the raw packet to create a unique cryptographic fingerprint
                        packet_hash = hashlib.sha256(packet_bytes).hexdigest()
                        cache_key = f"dedup:{packet_hash}"
                        
                        # nx=True: Only write if the key doesn't exist
                        # ex=2: Expire and delete the key after 2 seconds
                        # This operation is atomic.
                        is_new_threat = redis_client.set(cache_key, "1", ex=2, nx=True)
                        
                        if is_new_threat:
                            print(f"[!] Threat Caught! Engine: {alert['engine']} | Securing forensics...")
                            logger.generate_secure_log(alert)
                            print(f"[+] Forensic Envelope permanently stored and published.")
                        else:
                            # It's an echo/duplicate within the 2-second window. Drop it silently.
                            pass
                            
            except redis.exceptions.TimeoutError:
                continue

    except KeyboardInterrupt:
        print("\n[-] Releasing native cryptographic memory spaces...")
        crypto.close()
        print("[-] IDS Engine worker safely shut down.")

if __name__ == "__main__":
    main()