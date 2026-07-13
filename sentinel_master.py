import asyncio
import json
import sqlite3
import os
import threading
import time
import hashlib
from collections import OrderedDict
from datetime import datetime, timezone

import redis
import redis.asyncio as aioredis
import joblib
import uvicorn
from weasyprint import HTML
from jinja2 import Template
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from scapy.all import IP, ICMP, Raw

from core.crypto import QuantumForensicCrypto
from core.pipeline import DualEnginePipeline, AnomalyEngine, EntropyEngine
from core.logger import ForensicLogger

# =====================================================================
# 1. THE UNIFIED MEMORY SPACE
# =====================================================================
shared_crypto = QuantumForensicCrypto()
DB_PATH = "forensics.db"

app = FastAPI(title="Quantum IDS Master Node")
async_redis = aioredis.from_url("redis://localhost")

class VerifyRequest(BaseModel):
    threat_name: str
    kem_envelope: str
    mldsa_signature: str

# =====================================================================
# 2. FASTAPI BACKEND ROUTES
# =====================================================================
@app.get("/")
async def serve_dashboard():
    with open("dashboard/index.html", "r") as file:
        return HTMLResponse(content=file.read())

@app.get("/api/history")
async def get_historical_logs():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, engine, severity, threat_name, kem_envelope, encrypted_payload, mldsa_signature 
                FROM security_events 
                ORDER BY id DESC LIMIT 50
            """)
            logs = [dict(row) for row in cursor.fetchall()]
            return JSONResponse(content=logs)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/api/verify")
async def verify_integrity(req: VerifyRequest):
    try:
        deterministic_payload = f"{req.threat_name}::{req.kem_envelope}".encode('utf-8')
        signature_bytes = bytes.fromhex(req.mldsa_signature)
        
        is_valid = False
        
        # Try Order 1: (Message, Signature)
        try:
            if shared_crypto.verify_signature(deterministic_payload, signature_bytes):
                is_valid = True
        except Exception:
            pass
            
        # Try Order 2: (Signature, Message)
        if not is_valid:
            try:
                if shared_crypto.verify_signature(signature_bytes, deterministic_payload):
                    is_valid = True
            except Exception:
                pass
        
        if is_valid:
            return {"status": "VALID", "message": "ML-DSA Signature Verified. Chain of custody intact."}
        else:
            return {"status": "TAMPERED", "message": "CRITICAL: Signature mismatch. Forensics compromised."}
    except Exception as e:
         return {"status": "ERROR", "message": str(e)}

         
@app.get("/api/report")
async def generate_pdf_report():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, engine, severity, threat_name, mldsa_signature 
                FROM security_events 
                ORDER BY id DESC LIMIT 50
            """)
            alerts = [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: 'Courier New', monospace; background-color: #0d1117; color: #dee4d9; padding: 40px; }
            h1 { color: #7ee787; border-bottom: 1px solid #3f4a3d; padding-bottom: 10px; }
            .alert { border: 1px solid #3f4a3d; padding: 15px; margin-bottom: 20px; background-color: #161b22; }
            .critical { color: #f85149; font-weight: bold; }
            .high { color: #d29922; font-weight: bold; }
            .code { background-color: #090c10; padding: 10px; font-size: 10px; word-break: break-all; color: #b3ffb3; margin-top: 10px; }
        </style>
    </head>
    <body>
        <h1>SENTINEL_QS: Forensic Incident Report</h1>
        <p>Generated: {{ timestamp }}</p>
        <p>Total Anomalies Logged: {{ alerts|length }}</p>
        
        {% for alert in alerts %}
        <div class="alert">
            <span class="{% if alert.severity == 'CRITICAL' %}critical{% else %}high{% endif %}">
                [{{ alert.severity }}]
            </span> 
            <strong>{{ alert.engine }}</strong> - {{ alert.timestamp }}
            <p style="margin: 5px 0 0 0;">Threat: {{ alert.threat_name }}</p>
            <div class="code">SIG: {{ alert.mldsa_signature[:100] }}...</div>
        </div>
        {% endfor %}
    </body>
    </html>
    """
    
    template = Template(html_template)
    rendered_html = template.render(alerts=alerts, timestamp=datetime.now(timezone.utc).isoformat())
    output_path = "sentinel_report.pdf"
    
    HTML(string=rendered_html).write_pdf(output_path)
    return FileResponse(output_path, media_type='application/pdf', filename='Sentinel_Forensics.pdf')

@app.websocket("/ws/alerts")
async def alert_stream(websocket: WebSocket):
    await websocket.accept()
    pubsub = async_redis.pubsub()
    await pubsub.subscribe("ids_alerts")
    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True)
            if message:
                payload = message["data"].decode("utf-8")
                await websocket.send_text(payload)
            await asyncio.sleep(0.01)
    except WebSocketDisconnect:
        await pubsub.unsubscribe("ids_alerts")


# =====================================================================
# 3. BACKGROUND IDS WORKER THREAD
# =====================================================================
def ids_worker_thread():
    print("\n[*] Booting Native IDS Worker Thread...")
    pipeline = DualEnginePipeline()
    anomaly_engine = AnomalyEngine()
    entropy_engine = EntropyEngine(threshold=7.5)
    
    logger = ForensicLogger(shared_crypto)
    sync_redis = redis.Redis(host='localhost', port=6379, db=0, socket_keepalive=True)
    
    try:
        ml_model = joblib.load("models/isolation_forest.joblib")
    except FileNotFoundError:
        ml_model = None

    print("[+] IDS Engine armed. Awaiting traffic on loopback...\n")

    while True:
        try:
            item = sync_redis.brpop("packet_buffer", timeout=1)
            if item:
                _, packet_hex = item
                packet_bytes = bytes.fromhex(packet_hex.decode('utf-8'))
                
                try:
                    pkt = IP(packet_bytes)
                    if ICMP in pkt and pkt[ICMP].type == 3:
                        continue 
                except Exception:
                    pass 
                
                alert = pipeline.process_packet(packet_bytes)
                
                if not alert:
                    alert = entropy_engine.analyze(packet_bytes)
                        
                if not alert and ml_model:
                    vector = anomaly_engine.extract_features(packet_bytes)
                    if vector and ml_model.predict([vector])[0] == -1:
                        alert = {
                            "engine": "ML-Anomaly (Isolation Forest)",
                            "threat_name": "UNAUTHORIZED BEHAVIORAL DEVIATION",
                            "description": "Unsupervised ML model detected severe volumetric or timing anomalies.",
                            "severity": "HIGH",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                
                if alert:
                    # --- NATIVE HARDENED PAYLOAD DEDUPLICATION ---
                    # 1. Extract the raw payload so we ignore mutated header checksums (TX/RX Echo Fix)
                    try:
                        pkt = IP(packet_bytes)
                        fingerprint_data = bytes(pkt[Raw]) if Raw in pkt else packet_bytes
                    except Exception:
                        fingerprint_data = packet_bytes
                    
                    # 2. Hash the PAYLOAD, not the header or timestamp
                    packet_hash = hashlib.sha256(fingerprint_data).hexdigest()
                    cache_key = f"dedup:{packet_hash}"
                    
                    # 3. Atomic check
                    if sync_redis.set(cache_key, "1", ex=2, nx=True):
                        print(f"[!] Threat Caught! Engine: {alert['engine']} | Securing forensics...")
                        logger.generate_secure_log(alert)
                        
        except redis.exceptions.TimeoutError:
            continue
        except Exception as e:
            print(f"[-] Worker Error: {e}")

# =====================================================================
# 4. ORCHESTRATOR ENTRY POINT
# =====================================================================
if __name__ == "__main__":
    worker = threading.Thread(target=ids_worker_thread, daemon=True)
    worker.start()
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")