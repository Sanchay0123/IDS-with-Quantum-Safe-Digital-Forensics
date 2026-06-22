import os
import joblib
import numpy as np
from scapy.all import sniff
from sklearn.ensemble import IsolationForest
from core.pipeline import AnomalyEngine

# Ensure the models directory exists
os.makedirs("models", exist_ok=True)
MODEL_PATH = "models/isolation_forest.joblib"

def main():
    print("[*] Initializing Machine Learning Baseline Architect...")
    engine = AnomalyEngine()
    dataset = []

    print("\n[!] Sniffing 1,000 baseline packets on loopback (lo)...")
    print("[*] To generate traffic, open another terminal and run:")
    print("    ping 127.0.0.1")
    print("    curl http://localhost:8000/api/history  (if dashboard is running)\n")

    def process_packet(packet):
        # Scapy sniff returns a Packet object. Our engine expects raw bytes.
        raw_bytes = bytes(packet)
        vector = engine.extract_features(raw_bytes)
        
        if vector:
            dataset.append(vector)
            if len(dataset) % 100 == 0:
                print(f"[*] Collected {len(dataset)} / 1000 feature vectors...")

    # Sniff exactly 1000 packets, then stop automatically
    sniff(iface="lo", prn=process_packet, count=1000)

    print("\n[+] Baseline collection complete. Compiling Isolation Forest...")
    
    # Convert list of vectors to a numpy matrix for scikit-learn
    X_train = np.array(dataset)

    # Initialize the model. 
    # contamination=0.01 means we assume our baseline is relatively clean, 
    # and we want to flag the top 1% of outliers in future traffic.
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    
    # Train the model on our multi-dimensional feature matrix
    model.fit(X_train)

    # Serialize and save the trained model to disk
    joblib.dump(model, MODEL_PATH)
    
    print(f"[+] Model trained successfully!")
    print(f"[+] Architecture saved to: {MODEL_PATH}")
    print("[+] The Anomaly Engine is now ready for production inference.")

if __name__ == "__main__":
    main()