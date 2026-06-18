import asyncio
import json
import sqlite3
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
import redis.asyncio as aioredis

app = FastAPI(title="Quantum IDS Dashboard API")
redis_client = aioredis.from_url("redis://localhost")
DB_PATH = "forensics.db"

@app.get("/")
async def serve_dashboard():
    with open("dashboard/index.html", "r") as file:
        return HTMLResponse(content=file.read())

@app.get("/api/history")
async def get_historical_logs():
    """Retrieves the last 50 cryptographic forensic entries directly from disk storage."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row  # Returns results as dictionaries
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, engine, severity, kem_envelope, encrypted_payload, mldsa_signature 
                FROM security_events 
                ORDER BY id DESC LIMIT 50
            """)
            logs = [dict(row) for row in cursor.fetchall()]
            return JSONResponse(content=logs)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

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