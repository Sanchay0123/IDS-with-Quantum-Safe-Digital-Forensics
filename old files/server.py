#/dashboard
import asyncio
import json
import sqlite3
import os
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
import redis.asyncio as aioredis
from weasyprint import HTML
from jinja2 import Template

# Import your quantum crypto layer for the verification endpoint
from core.crypto import QuantumForensicCrypto

app = FastAPI(title="Quantum IDS Dashboard API")
redis_client = aioredis.from_url("redis://localhost")
DB_PATH = "forensics.db"

# Initialize the crypto engine for the validation API
crypto = QuantumForensicCrypto()

# --- PYDANTIC MODELS ---
class VerifyRequest(BaseModel):
    threat_name: str
    kem_envelope: str
    mldsa_signature: str

@app.get("/")
async def serve_dashboard():
    with open("dashboard/index.html", "r") as file:
        return HTMLResponse(content=file.read())

@app.get("/api/history")
async def get_historical_logs():
    """Retrieves the last 50 cryptographic forensic entries directly from disk storage."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Added threat_name to ensure UI has the data to verify
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
    """
    Takes the cryptographic envelope from the UI and mathematically proves it hasn't been tampered with.
    """
    try:
        # Reconstruct the EXACT deterministic string signed by the logger
        deterministic_payload = f"{req.threat_name}::{req.kem_envelope}".encode('utf-8')
        
        # 🚀 THE FIX: Convert the JSON hex string back into raw cryptographic bytes
        signature_bytes = bytes.fromhex(req.mldsa_signature)
        
        # Verify using the raw bytes
        is_valid = crypto.verify_signature(deterministic_payload, signature_bytes)
        
        if is_valid:
            return {"status": "VALID", "message": "ML-DSA Signature Verified. Chain of custody intact."}
        else:
            return {"status": "TAMPERED", "message": "CRITICAL: Signature mismatch. Forensics compromised."}
    except Exception as e:
         return {"status": "ERROR", "message": str(e)}

@app.get("/api/report")
async def generate_pdf_report():
    """
    Pulls the latest alerts from SQLite, injects them into a styled Jinja2 HTML template,
    and renders a dark-mode PDF report via WeasyPrint.
    """
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
    rendered_html = template.render(alerts=alerts, timestamp=datetime.utcnow().isoformat())
    
    output_path = "sentinel_report.pdf"
    
    # Render using WeasyPrint (bypassing wkhtmltopdf and Qt entirely)
    HTML(string=rendered_html).write_pdf(output_path)
    
    return FileResponse(output_path, media_type='application/pdf', filename='Sentinel_Forensics.pdf')


@app.websocket("/ws/alerts")
async def alert_stream(websocket: WebSocket):
    await websocket.accept()
    print("[+] Dashboard client connected to live feed.")
    
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("ids_alerts")
    
    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True)
            if message:
                payload = message["data"].decode("utf-8")
                await websocket.send_text(payload)
            await asyncio.sleep(0.01)
    except WebSocketDisconnect:
        print("[-] Dashboard client disconnected.")
        await pubsub.unsubscribe("ids_alerts")