import json
import sqlite3
import redis

class ForensicLogger:
    def __init__(self, crypto_engine):
        self.crypto = crypto_engine
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        self.db_path = "forensics.db"
        
        # Initialize local storage table schemas
        self._init_db()

    def _init_db(self):
        """Guarantees the persistence table is structured and available."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Added threat_name to the schema
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    engine TEXT,
                    severity TEXT,
                    threat_name TEXT,
                    kem_envelope TEXT,
                    encrypted_payload TEXT,
                    mldsa_signature TEXT
                )
            """)
            conn.commit()
    
    def generate_secure_log(self, alert_event: dict) -> dict:
        """
        Transforms raw alerts into persistent, quantum-encrypted forensic assets.
        """
        serialized_event = json.dumps(alert_event).encode('utf-8')

        # Run real PQC algorithms
        kem_ciphertext, encrypted_payload = self.crypto.encrypt_payload(serialized_event)

        # Extract threat name, defaulting to "Unknown Threat" as a failsafe
        threat_name = alert_event.get("threat_name", "Unknown Threat")

        # 1. Create the deterministic payload string
        deterministic_payload = f"{threat_name}::{kem_ciphertext.hex()}".encode('utf-8')
        
        # 2. Sign it exactly ONCE
        mldsa_signature = self.crypto.sign_log(deterministic_payload)

        # --- LOCAL CRYPTO SELF-TEST ---
        print("\n=== [LOCAL CRYPTO SELF-TEST] ===")
        test_msg_sig = False
        test_sig_msg = False
        
        try: 
            test_msg_sig = self.crypto.verify_signature(deterministic_payload, mldsa_signature)
        except Exception: pass
        
        try: 
            test_sig_msg = self.crypto.verify_signature(mldsa_signature, deterministic_payload)
        except Exception: pass

        if not test_msg_sig and not test_sig_msg:
            print("[-] FATAL: The crypto engine cannot verify its own signature locally.")
        else:
            print(f"[+] Math Validated! (Message, Signature): {test_msg_sig} | (Signature, Message): {test_sig_msg}")
        print("=================================\n")

        # 3. Assemble the final envelope
        forensic_envelope = {
            "timestamp": alert_event["timestamp"],
            "engine": alert_event["engine"],
            "severity": alert_event["severity"],
            "threat_name": threat_name,
            "kem_envelope": kem_ciphertext.hex(),
            "encrypted_payload": encrypted_payload.hex(),
            "mldsa_signature": mldsa_signature.hex()
        }

        # Destination 1: Write to local persistent DB (The Forensic Chain)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_events 
                (timestamp, engine, severity, threat_name, kem_envelope, encrypted_payload, mldsa_signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                forensic_envelope["timestamp"],
                forensic_envelope["engine"],
                forensic_envelope["severity"],
                forensic_envelope["threat_name"],
                forensic_envelope["kem_envelope"],
                forensic_envelope["encrypted_payload"],
                forensic_envelope["mldsa_signature"]
            ))
            conn.commit()

        # --- The Air-Gapped Forensic Flat File ---
        with open("quantum_vault.enc", "a") as vault:
            vault.write(f"--- EVENT: {forensic_envelope['timestamp']} ---\n")
            vault.write(f"THREAT:       {forensic_envelope['threat_name']}\n")
            vault.write(f"KEM_ENVELOPE: {forensic_envelope['kem_envelope']}\n")
            vault.write(f"CIPHERTEXT:   {forensic_envelope['encrypted_payload']}\n")
            vault.write(f"DSA_SIG:      {forensic_envelope['mldsa_signature']}\n\n")

        # Destination 2: Push to Redis for live dashboard UI consumption
        self.redis_client.publish('ids_alerts', json.dumps(forensic_envelope))

        return forensic_envelope