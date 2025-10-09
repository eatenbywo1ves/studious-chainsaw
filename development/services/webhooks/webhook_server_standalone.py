"""
Standalone Webhook Server with embedded webhook system
No relative imports - everything self-contained for Docker deployment
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uvicorn
import httpx
from datetime import datetime
import json
import sqlite3
import logging
from enum import Enum
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === Embedded Webhook System Classes ===


class WebhookEvent(Enum):
    """Supported webhook event types"""

    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    ACTION = "action"
    ERROR = "error"
    STATUS_CHANGED = "status_changed"
    CUSTOM = "custom"


class DeliveryStatus(Enum):
    """Webhook delivery status"""

    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class WebhookConfig:
    """Webhook configuration"""

    id: str
    url: str
    events: List[WebhookEvent]
    secret: Optional[str] = None
    active: bool = True
    headers: Dict[str, str] = field(default_factory=dict)
    retry_count: int = 3
    timeout: int = 30
    created_at: datetime = field(default_factory=datetime.now)


class WebhookManager:
    """Manages webhook storage and operations"""

    def __init__(self, db_path: str = "webhooks.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                events TEXT NOT NULL,
                secret TEXT,
                active BOOLEAN DEFAULT 1,
                headers TEXT,
                retry_count INTEGER DEFAULT 3,
                timeout INTEGER DEFAULT 30,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deliveries (
                id TEXT PRIMARY KEY,
                webhook_id TEXT,
                event TEXT,
                payload TEXT,
                status TEXT,
                response_code INTEGER,
                response_body TEXT,
                attempts INTEGER DEFAULT 0,
                delivered_at TIMESTAMP,
                FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
            )
        """)

        conn.commit()
        conn.close()

    def register_webhook(self, config: WebhookConfig) -> str:
        """Register a new webhook"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO webhooks (id, url, events, secret, active, headers, retry_count, timeout, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                config.id,
                config.url,
                json.dumps([e.value for e in config.events]),
                config.secret,
                config.active,
                json.dumps(config.headers),
                config.retry_count,
                config.timeout,
                config.created_at.isoformat(),
            ),
        )

        conn.commit()
        conn.close()
        return config.id

    def get_webhook(self, webhook_id: str) -> Optional[WebhookConfig]:
        """Get webhook by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return WebhookConfig(
                id=row[0],
                url=row[1],
                events=[WebhookEvent(e) for e in json.loads(row[2])],
                secret=row[3],
                active=bool(row[4]),
                headers=json.loads(row[5]) if row[5] else {},
                retry_count=row[6],
                timeout=row[7],
                created_at=datetime.fromisoformat(row[8]) if row[8] else datetime.now(),
            )
        return None

    def list_webhooks(self) -> List[WebhookConfig]:
        """List all webhooks"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM webhooks")
        rows = cursor.fetchall()
        conn.close()

        webhooks = []
        for row in rows:
            webhooks.append(
                WebhookConfig(
                    id=row[0],
                    url=row[1],
                    events=[WebhookEvent(e) for e in json.loads(row[2])],
                    secret=row[3],
                    active=bool(row[4]),
                    headers=json.loads(row[5]) if row[5] else {},
                    retry_count=row[6],
                    timeout=row[7],
                    created_at=datetime.fromisoformat(row[8]) if row[8] else datetime.now(),
                )
            )
        return webhooks


# === FastAPI Application ===

app = FastAPI(
    title="Webhook Server",
    description="Production-ready webhook management system",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global webhook manager
webhook_manager = WebhookManager()

# === Pydantic Models ===


class WebhookRegistration(BaseModel):
    url: str
    events: List[str] = ["*"]
    secret: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


class WebhookResponse(BaseModel):
    id: str
    url: str
    events: List[str]
    active: bool
    created_at: str


class TriggerEventRequest(BaseModel):
    event_type: str
    payload: Dict[str, Any]


# === API Endpoints ===


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Webhook Server",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "webhooks": "/api/webhooks",
            "trigger": "/api/events/trigger",
        },
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/api/webhooks", response_model=WebhookResponse)
async def register_webhook(registration: WebhookRegistration):
    """Register a new webhook"""
    import uuid

    webhook_id = str(uuid.uuid4())

    # Convert string events to WebhookEvent enums
    events = []
    for event in registration.events:
        if event == "*":
            events = list(WebhookEvent)
            break
        try:
            events.append(WebhookEvent(event))
        except ValueError:
            events.append(WebhookEvent.CUSTOM)

    config = WebhookConfig(
        id=webhook_id,
        url=registration.url,
        events=events,
        secret=registration.secret,
        headers=registration.headers or {},
    )

    webhook_manager.register_webhook(config)

    return WebhookResponse(
        id=webhook_id,
        url=config.url,
        events=[e.value for e in config.events],
        active=config.active,
        created_at=config.created_at.isoformat(),
    )


@app.get("/api/webhooks", response_model=List[WebhookResponse])
async def list_webhooks():
    """List all registered webhooks"""
    webhooks = webhook_manager.list_webhooks()
    return [
        WebhookResponse(
            id=w.id,
            url=w.url,
            events=[e.value for e in w.events],
            active=w.active,
            created_at=w.created_at.isoformat(),
        )
        for w in webhooks
    ]


@app.get("/api/webhooks/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(webhook_id: str):
    """Get specific webhook"""
    webhook = webhook_manager.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return WebhookResponse(
        id=webhook.id,
        url=webhook.url,
        events=[e.value for e in webhook.events],
        active=webhook.active,
        created_at=webhook.created_at.isoformat(),
    )


@app.post("/api/events/trigger")
async def trigger_event(request: TriggerEventRequest, background_tasks: BackgroundTasks):
    """Trigger webhook events"""

    async def send_webhook(webhook: WebhookConfig, event_type: str, payload: dict):
        """Send webhook notification"""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    webhook.url,
                    json={
                        "event": event_type,
                        "payload": payload,
                        "timestamp": datetime.now().isoformat(),
                    },
                    headers=webhook.headers,
                    timeout=webhook.timeout,
                )
                logger.info(f"Webhook delivered to {webhook.url}: {response.status_code}")
            except Exception as e:
                logger.error(f"Failed to deliver webhook to {webhook.url}: {e}")

    # Get all active webhooks
    webhooks = webhook_manager.list_webhooks()
    triggered_count = 0

    for webhook in webhooks:
        if webhook.active:
            # Check if webhook should receive this event
            event_type = request.event_type
            should_trigger = False

            for event in webhook.events:
                if event == WebhookEvent.CUSTOM or event.value == event_type:
                    should_trigger = True
                    break

            if should_trigger:
                background_tasks.add_task(send_webhook, webhook, event_type, request.payload)
                triggered_count += 1

    return {
        "message": f"Event triggered for {triggered_count} webhooks",
        "event_type": request.event_type,
    }


@app.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    """Delete a webhook"""
    webhook = webhook_manager.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    conn = sqlite3.connect(webhook_manager.db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
    conn.commit()
    conn.close()

    return {"message": f"Webhook {webhook_id} deleted"}


# === Dashboard HTML ===


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Simple dashboard for webhook management"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Webhook Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            .webhook { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
            button { background: #007bff; color: white; border: none; padding: 5px 10px; cursor: pointer; }
            input, select { margin: 5px; padding: 5px; }
        </style>
    </head>
    <body>
        <h1>Webhook Management Dashboard</h1>

        <div>
            <h2>Register New Webhook</h2>
            <input id="url" type="text" placeholder="Webhook URL" style="width: 300px;">
            <button onclick="registerWebhook()">Register</button>
        </div>

        <div>
            <h2>Registered Webhooks</h2>
            <div id="webhooks"></div>
        </div>

        <div>
            <h2>Trigger Test Event</h2>
            <input id="eventType" type="text" placeholder="Event Type" value="test">
            <button onclick="triggerEvent()">Trigger</button>
        </div>

        <script>
            async function loadWebhooks() {
                const response = await fetch('/api/webhooks');
                const webhooks = await response.json();
                const container = document.getElementById('webhooks');
                container.innerHTML = webhooks.map(w => `
                    <div class="webhook">
                        <strong>URL:</strong> ${w.url}<br>
                        <strong>ID:</strong> ${w.id}<br>
                        <strong>Events:</strong> ${w.events.join(', ')}<br>
                        <strong>Active:</strong> ${w.active}<br>
                        <button onclick="deleteWebhook('${w.id}')">Delete</button>
                    </div>
                `).join('');
            }

            async function registerWebhook() {
                const url = document.getElementById('url').value;
                if (!url) return;

                await fetch('/api/webhooks', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, events: ['*']})
                });
                loadWebhooks();
            }

            async function deleteWebhook(id) {
                await fetch(`/api/webhooks/${id}`, {method: 'DELETE'});
                loadWebhooks();
            }

            async function triggerEvent() {
                const eventType = document.getElementById('eventType').value;
                await fetch('/api/events/trigger', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        event_type: eventType,
                        payload: {message: 'Test event', timestamp: new Date().toISOString()}
                    })
                });
                alert('Event triggered!');
            }

            loadWebhooks();
        </script>
    </body>
    </html>
    """


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
