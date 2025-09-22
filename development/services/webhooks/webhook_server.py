"""
FastAPI Webhook Server with Dashboard
Production-ready webhook server with monitoring and management UI
"""

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any
import uvicorn
import asyncio
import httpx
from datetime import datetime
import json
import hashlib
import hmac
import sqlite3
from contextlib import asynccontextmanager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import webhook system
from .webhook_system import (
    WebhookManager, 
    WebhookConfig,
    WebhookEvent,
    DeliveryStatus
)

# Global webhook manager
webhook_manager = None


# Pydantic models for API
class WebhookRegistration(BaseModel):
    """Model for webhook registration request"""
    url: HttpUrl
    events: List[str] = Field(..., min_items=1)
    secret: Optional[str] = None
    active: bool = True
    retry_count: int = Field(default=3, ge=0, le=10)
    retry_delay: int = Field(default=5, ge=1, le=60)
    timeout: int = Field(default=30, ge=5, le=300)
    headers: Dict[str, str] = {}
    metadata: Dict[str, Any] = {}


class WebhookUpdate(BaseModel):
    """Model for webhook update request"""
    events: Optional[List[str]] = None
    active: Optional[bool] = None
    retry_count: Optional[int] = Field(None, ge=0, le=10)
    retry_delay: Optional[int] = Field(None, ge=1, le=60)
    timeout: Optional[int] = Field(None, ge=5, le=300)
    headers: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None


class EventTrigger(BaseModel):
    """Model for triggering an event"""
    event: str
    data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = {}


class WebhookTest(BaseModel):
    """Model for testing a webhook"""
    url: HttpUrl
    event: str = "test.ping"
    data: Dict[str, Any] = {"test": True}
    secret: Optional[str] = None
    headers: Dict[str, str] = {}


# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage webhook manager lifecycle"""
    global webhook_manager
    webhook_manager = WebhookManager(db_path="webhooks.db")
    webhook_manager.start()
    logger.info("Webhook manager started")
    yield
    webhook_manager.stop()
    logger.info("Webhook manager stopped")


# Create FastAPI app
app = FastAPI(
    title="Webhook Management System",
    description="Complete webhook management with monitoring and testing",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API Endpoints
@app.get("/")
async def dashboard():
    """Serve webhook dashboard"""
    return HTMLResponse(content=DASHBOARD_HTML, status_code=200)


@app.post("/api/webhooks", response_model=Dict[str, str])
async def register_webhook(webhook: WebhookRegistration):
    """Register a new webhook"""
    try:
        webhook_id = webhook_manager.register_webhook(
            url=str(webhook.url),
            events=webhook.events,
            secret=webhook.secret,
            headers=webhook.headers,
            active=webhook.active,
            retry_count=webhook.retry_count,
            retry_delay=webhook.retry_delay,
            timeout=webhook.timeout,
            metadata=webhook.metadata
        )
        return {"webhook_id": webhook_id, "status": "registered"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/webhooks")
async def list_webhooks():
    """List all registered webhooks"""
    webhooks = []
    for webhook_id, webhook in webhook_manager.registry.webhooks.items():
        webhooks.append({
            "id": webhook.id,
            "url": webhook.url,
            "events": webhook.events,
            "active": webhook.active,
            "created_at": webhook.created_at,
            "updated_at": webhook.updated_at
        })
    return {"webhooks": webhooks, "total": len(webhooks)}


@app.get("/api/webhooks/{webhook_id}")
async def get_webhook(webhook_id: str):
    """Get details of a specific webhook"""
    if webhook_id not in webhook_manager.registry.webhooks:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    webhook = webhook_manager.registry.webhooks[webhook_id]
    stats = webhook_manager.get_webhook_stats(webhook_id)
    
    return {
        "webhook": {
            "id": webhook.id,
            "url": webhook.url,
            "events": webhook.events,
            "secret": webhook.secret is not None,
            "active": webhook.active,
            "retry_count": webhook.retry_count,
            "retry_delay": webhook.retry_delay,
            "timeout": webhook.timeout,
            "headers": webhook.headers,
            "metadata": webhook.metadata,
            "created_at": webhook.created_at,
            "updated_at": webhook.updated_at
        },
        "statistics": stats
    }


@app.patch("/api/webhooks/{webhook_id}")
async def update_webhook(webhook_id: str, updates: WebhookUpdate):
    """Update a webhook configuration"""
    if webhook_id not in webhook_manager.registry.webhooks:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    update_dict = updates.dict(exclude_unset=True)
    webhook_manager.registry.update_webhook(webhook_id, update_dict)
    
    return {"status": "updated", "webhook_id": webhook_id}


@app.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    """Delete a webhook"""
    if webhook_id not in webhook_manager.registry.webhooks:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    webhook_manager.registry.unregister(webhook_id)
    return {"status": "deleted", "webhook_id": webhook_id}


@app.post("/api/events/trigger")
async def trigger_event(event: EventTrigger, background_tasks: BackgroundTasks):
    """Trigger a webhook event"""
    background_tasks.add_task(
        webhook_manager.trigger_event,
        event.event,
        event.data,
        event.metadata
    )
    
    # Get count of webhooks that will receive this event
    webhooks = webhook_manager.registry.get_webhooks_for_event(event.event)
    
    return {
        "status": "triggered",
        "event": event.event,
        "webhook_count": len(webhooks)
    }


@app.post("/api/webhooks/test")
async def test_webhook(test: WebhookTest):
    """Test a webhook endpoint without registering it"""
    try:
        async with httpx.AsyncClient() as client:
            headers = test.headers.copy()
            headers['Content-Type'] = 'application/json'
            headers['X-Webhook-Event'] = test.event
            headers['X-Webhook-Test'] = 'true'
            
            # Add signature if secret provided
            if test.secret:
                payload_json = json.dumps(test.data, sort_keys=True)
                signature = hmac.new(
                    test.secret.encode(),
                    payload_json.encode(),
                    hashlib.sha256
                ).hexdigest()
                headers['X-Webhook-Signature'] = f"sha256={signature}"
            
            response = await client.post(
                str(test.url),
                json=test.data,
                headers=headers,
                timeout=30
            )
            
            return {
                "status": "success",
                "response_code": response.status_code,
                "response_body": response.text[:500]  # Limit response size
            }
            
    except httpx.TimeoutException:
        return {"status": "timeout", "error": "Request timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/api/events")
async def list_events():
    """List all available webhook events"""
    events = [
        {
            "name": event.value,
            "description": event.name.replace("_", " ").title()
        }
        for event in WebhookEvent
    ]
    return {"events": events, "total": len(events)}


@app.get("/api/deliveries")
async def get_recent_deliveries(limit: int = 50):
    """Get recent webhook deliveries"""
    conn = sqlite3.connect("webhooks.db")
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            da.id,
            da.webhook_id,
            w.url,
            da.attempt_number,
            da.status,
            da.response_code,
            da.error_message,
            da.timestamp,
            da.duration_ms
        FROM delivery_attempts da
        JOIN webhooks w ON da.webhook_id = w.id
        ORDER BY da.timestamp DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    deliveries = []
    for row in rows:
        deliveries.append({
            "id": row[0],
            "webhook_id": row[1],
            "url": row[2],
            "attempt_number": row[3],
            "status": row[4],
            "response_code": row[5],
            "error_message": row[6],
            "timestamp": row[7],
            "duration_ms": row[8]
        })
    
    return {"deliveries": deliveries, "total": len(deliveries)}


@app.get("/api/stats")
async def get_system_stats():
    """Get overall system statistics"""
    conn = sqlite3.connect("webhooks.db")
    cursor = conn.cursor()
    
    # Get webhook counts
    cursor.execute("SELECT COUNT(*) FROM webhooks WHERE active = 1")
    active_webhooks = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM webhooks")
    total_webhooks = cursor.fetchone()[0]
    
    # Get delivery stats
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) as successful,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
            AVG(duration_ms) as avg_duration
        FROM delivery_attempts
        WHERE datetime(timestamp) >= datetime('now', '-24 hours')
    """)
    
    row = cursor.fetchone()
    conn.close()
    
    return {
        "webhooks": {
            "active": active_webhooks,
            "total": total_webhooks
        },
        "deliveries_24h": {
            "total": row[0] or 0,
            "successful": row[1] or 0,
            "failed": row[2] or 0,
            "avg_duration_ms": row[3] or 0
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "webhook-server"}


# Dashboard HTML
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webhook Management Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        h2 {
            color: #333;
            margin-bottom: 20px;
        }
        .webhook-form {
            display: grid;
            gap: 15px;
            margin-bottom: 30px;
        }
        input, select, button {
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }
        button {
            background: #667eea;
            color: white;
            border: none;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #764ba2;
        }
        .webhook-list {
            display: grid;
            gap: 15px;
        }
        .webhook-item {
            padding: 20px;
            border: 1px solid #eee;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .webhook-url {
            font-weight: 500;
            color: #333;
            margin-bottom: 5px;
        }
        .webhook-events {
            color: #666;
            font-size: 14px;
        }
        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }
        .badge-active {
            background: #10b981;
            color: white;
        }
        .badge-inactive {
            background: #ef4444;
            color: white;
        }
        .delivery-list {
            max-height: 400px;
            overflow-y: auto;
        }
        .delivery-item {
            padding: 15px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .status-delivered {
            color: #10b981;
        }
        .status-failed {
            color: #ef4444;
        }
        .status-retrying {
            color: #f59e0b;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔗 Webhook Management Dashboard</h1>
            <p style="color: #666; margin-top: 10px;">Real-time webhook monitoring and management</p>
        </div>

        <div class="stats" id="stats">
            <div class="stat-card">
                <div class="stat-value" id="active-webhooks">-</div>
                <div class="stat-label">Active Webhooks</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="total-deliveries">-</div>
                <div class="stat-label">Deliveries (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="success-rate">-</div>
                <div class="stat-label">Success Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="avg-duration">-</div>
                <div class="stat-label">Avg Response Time</div>
            </div>
        </div>

        <div class="section">
            <h2>Register New Webhook</h2>
            <div class="webhook-form">
                <input type="url" id="webhook-url" placeholder="Webhook URL (https://example.com/webhook)" />
                <input type="text" id="webhook-events" placeholder="Events (comma-separated, e.g., data.created,data.updated)" />
                <input type="text" id="webhook-secret" placeholder="Secret (optional)" />
                <button onclick="registerWebhook()">Register Webhook</button>
            </div>
        </div>

        <div class="section">
            <h2>Registered Webhooks</h2>
            <div class="webhook-list" id="webhook-list">
                <!-- Webhooks will be loaded here -->
            </div>
        </div>

        <div class="section">
            <h2>Recent Deliveries</h2>
            <div class="delivery-list" id="delivery-list">
                <!-- Deliveries will be loaded here -->
            </div>
        </div>

        <div class="section">
            <h2>Test Event</h2>
            <div class="webhook-form">
                <select id="test-event">
                    <option value="system.startup">System Startup</option>
                    <option value="data.created">Data Created</option>
                    <option value="data.updated">Data Updated</option>
                    <option value="process.completed">Process Completed</option>
                    <option value="alert.triggered">Alert Triggered</option>
                </select>
                <input type="text" id="test-data" placeholder='Event data (JSON, e.g., {"id": "123"})' />
                <button onclick="triggerTestEvent()">Trigger Event</button>
            </div>
        </div>
    </div>

    <script>
        // Load dashboard data
        async function loadDashboard() {
            // Load stats
            const stats = await fetch('/api/stats').then(r => r.json());
            document.getElementById('active-webhooks').textContent = stats.webhooks.active;
            document.getElementById('total-deliveries').textContent = stats.deliveries_24h.total;
            
            const successRate = stats.deliveries_24h.total > 0 
                ? Math.round((stats.deliveries_24h.successful / stats.deliveries_24h.total) * 100) 
                : 0;
            document.getElementById('success-rate').textContent = successRate + '%';
            document.getElementById('avg-duration').textContent = 
                Math.round(stats.deliveries_24h.avg_duration_ms) + 'ms';

            // Load webhooks
            const webhooks = await fetch('/api/webhooks').then(r => r.json());
            const webhookList = document.getElementById('webhook-list');
            webhookList.innerHTML = webhooks.webhooks.map(webhook => `
                <div class="webhook-item">
                    <div>
                        <div class="webhook-url">${webhook.url}</div>
                        <div class="webhook-events">${webhook.events.join(', ')}</div>
                    </div>
                    <div>
                        <span class="badge ${webhook.active ? 'badge-active' : 'badge-inactive'}">
                            ${webhook.active ? 'Active' : 'Inactive'}
                        </span>
                        <button onclick="deleteWebhook('${webhook.id}')" style="margin-left: 10px; background: #ef4444;">
                            Delete
                        </button>
                    </div>
                </div>
            `).join('');

            // Load recent deliveries
            const deliveries = await fetch('/api/deliveries').then(r => r.json());
            const deliveryList = document.getElementById('delivery-list');
            deliveryList.innerHTML = deliveries.deliveries.map(delivery => `
                <div class="delivery-item">
                    <div>
                        <div style="font-weight: 500;">${delivery.url}</div>
                        <div style="font-size: 14px; color: #666;">
                            ${new Date(delivery.timestamp).toLocaleString()}
                        </div>
                    </div>
                    <div class="status-${delivery.status}">
                        ${delivery.status} (${delivery.duration_ms ? Math.round(delivery.duration_ms) : '-'}ms)
                    </div>
                </div>
            `).join('');
        }

        // Register webhook
        async function registerWebhook() {
            const url = document.getElementById('webhook-url').value;
            const events = document.getElementById('webhook-events').value.split(',').map(e => e.trim());
            const secret = document.getElementById('webhook-secret').value;

            if (!url || events.length === 0) {
                alert('Please provide URL and events');
                return;
            }

            const response = await fetch('/api/webhooks', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    url: url,
                    events: events,
                    secret: secret || null
                })
            });

            if (response.ok) {
                document.getElementById('webhook-url').value = '';
                document.getElementById('webhook-events').value = '';
                document.getElementById('webhook-secret').value = '';
                loadDashboard();
            } else {
                const error = await response.json();
                alert('Error: ' + error.detail);
            }
        }

        // Delete webhook
        async function deleteWebhook(webhookId) {
            if (!confirm('Are you sure you want to delete this webhook?')) {
                return;
            }

            const response = await fetch(`/api/webhooks/${webhookId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                loadDashboard();
            }
        }

        // Trigger test event
        async function triggerTestEvent() {
            const event = document.getElementById('test-event').value;
            const dataStr = document.getElementById('test-data').value || '{}';
            
            try {
                const data = JSON.parse(dataStr);
                
                const response = await fetch('/api/events/trigger', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        event: event,
                        data: data
                    })
                });

                if (response.ok) {
                    const result = await response.json();
                    alert(`Event triggered to ${result.webhook_count} webhooks`);
                    setTimeout(loadDashboard, 2000);
                }
            } catch (e) {
                alert('Invalid JSON data');
            }
        }

        // Auto-refresh
        loadDashboard();
        setInterval(loadDashboard, 10000);
    </script>
</body>
</html>
"""


# Run server
def run_server(host: str = "0.0.0.0", port: int = 8000):
    """Run the webhook server"""
    uvicorn.run(
        "webhook_server:app",
        host=host,
        port=port,
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    print(f"Starting Webhook Server on http://localhost:8000")
    print(f"Dashboard available at http://localhost:8000/")
    print(f"API docs available at http://localhost:8000/docs")
    run_server()