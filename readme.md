# SENTINEL_QS: Quantum-Safe Hybrid Intrusion Detection System

![SENTINEL_QS Dashboard](https://via.placeholder.com/1000x500.png?text=SENTINEL_QS+Dashboard+Preview) *(Note: Replace with an actual screenshot of your UI)*

SENTINEL_QS is a high-velocity, multi-layered Intrusion Detection System (IDS) architected for modern Linux environments. It combines the deterministic precision of native C-compiled YARA rules with unsupervised machine learning and Shannon entropy analysis. 

To guarantee the integrity of threat intelligence, every detected anomaly is cryptographically sealed using Post-Quantum Cryptography (ML-KEM and ML-DSA), ensuring an immutable chain of custody for forensic logs.

## 🚀 Core Architecture

The system routes raw network traffic through a zero-latency Redis queue into a three-tiered inspection pipeline:

* **Layer 1: Deterministic C-Engine (YARA)**
    * Compiles 1,500+ OSINT Emerging Threats (ET) signatures into a native C-matrix for wire-speed packet inspection.
    * Detects explicit CVEs (e.g., Log4j JNDI lookups, Path Traversals) with zero false positives.
* **Layer 2: Cryptographic Anomaly Detection**
    * Calculates Shannon Entropy on raw application payloads. 
    * Flags high-entropy byte streams (H > 7.5) indicative of encrypted data exfiltration or obfuscated C2 beacons.
* **Layer 3: Unsupervised Behavioral ML**
    * Utilizes a stateful `IsolationForest` model to extract vector features (size, protocol, TCP flags, ∆t).
    * Identifies zero-day volumetric and timing anomalies that bypass static signatures.

## 🔐 Post-Quantum Forensics (PQC)
Standard logging mechanisms are vulnerable to post-breach tampering. SENTINEL_QS secures its SQLite forensic database using:
* **ML-KEM (Kyber):** Encapsulates the payload data.
* **ML-DSA (Dilithium):** Signs the deterministic threat envelope, providing mathematical proof of log integrity against both classical and quantum cryptographic attacks.

## ⚡ Technical Stack
* **Core Systems:** Python 3, Scapy (Raw Sockets), Linux (Arch/Ubuntu native)
* **Data Pipeline:** Redis (Pub/Sub & Atomic NX Deduplication), SQLite3
* **Security & ML:** `yara-python`, `scikit-learn` (Isolation Forest), Custom PQC wrappers
* **Frontend UI:** FastAPI, WebSockets, TailwindCSS, Jinja2

## 🛠️ Quick Start

**1. Clone & Setup Environment**
```bash
git clone [https://github.com/yourusername/sentinel-qs.git](https://github.com/yourusername/sentinel-qs.git)
cd sentinel-qs
pip install -r requirements.txt