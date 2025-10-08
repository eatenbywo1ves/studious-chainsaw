# Webhook Audio Tracker - Complete Reference

## 📡 HTTP API Endpoints

### Base URL: `http://localhost:3000`

---

## 1. Health & Status

### `GET /health`
Get server health and statistics

**Response:**
```json
{
  "status": "healthy",
  "uptime": 2637.7,
  "endpoints": [],
  "activeWorkflows": 1
}
```

---

## 2. Webhook Management

### `POST /webhook/register`
Create a new webhook endpoint with custom audio profile

**Request:**
```json
{
  "name": "GitHub Push",
  "description": "Triggers on git push events",
  "audioProfile": "development",
  "workflowId": "optional-workflow-id"
}
```

**Response:**
```json
{
  "endpointId": "uuid-here",
  "url": "http://localhost:3000/webhook/{endpointId}",
  "wsUrl": "ws://localhost:3001"
}
```

**Usage Example:**
```bash
curl -X POST http://localhost:3000/webhook/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Build Complete","audioProfile":"development"}'
```

### `GET /webhooks`
List all registered webhooks

**Response:**
```json
[
  {
    "id": "uuid",
    "name": "GitHub Push",
    "description": "Triggers on git push events",
    "audioProfile": "development",
    "created": "2025-10-01T14:00:00.000Z",
    "eventCount": 5
  }
]
```

### `ALL /webhook/:endpointId`
Trigger a registered webhook (accepts GET, POST, PUT, DELETE, etc.)

**Request:**
```json
{
  "type": "build_success",
  "status": "success",
  "message": "Build completed successfully"
}
```

**Response:**
```json
{
  "success": true,
  "eventId": "uuid",
  "message": "Webhook received and processed"
}
```

---

## 3. Workflow Management

### `POST /workflow/start`
Start a new workflow with audio tracking

**Request:**
```json
{
  "name": "Deploy Application",
  "steps": ["build", "test", "deploy", "verify"],
  "audioProfile": "workflow"
}
```

**Response:**
```json
{
  "workflowId": "uuid",
  "workflow": {
    "id": "uuid",
    "name": "Deploy Application",
    "steps": ["build", "test", "deploy", "verify"],
    "currentStep": 0,
    "audioProfile": "workflow",
    "status": "active",
    "started": "2025-10-01T14:00:00.000Z",
    "events": []
  }
}
```

### `POST /workflow/:workflowId/step`
Update a workflow step status (triggers audio)

**Request:**
```json
{
  "stepName": "build",
  "status": "completed",
  "data": {
    "duration": 45,
    "artifacts": ["app.zip"]
  }
}
```

**Statuses:**
- `in_progress` - Step started
- `completed` - Step succeeded (plays success sound)
- `failed` - Step failed (plays failure sound)

**Response:**
```json
{
  "success": true
}
```

### `GET /workflows`
List all active workflows

**Response:**
```json
[
  {
    "id": "uuid",
    "name": "Deploy Application",
    "steps": ["build", "test", "deploy"],
    "currentStep": 1,
    "audioProfile": "workflow",
    "status": "active",
    "started": "2025-10-01T14:00:00.000Z",
    "events": [...]
  }
]
```

---

## 4. Audio Configuration

### `POST /audio/configure`
Configure custom audio profiles

**Request:**
```json
{
  "profile": "custom",
  "sounds": {
    "my_event": {
      "frequency": 880,
      "duration": 300,
      "type": "sine"
    },
    "my_sequence": {
      "frequencies": [440, 554, 659],
      "duration": 500,
      "type": "sine"
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "profile": "custom"
}
```

---

## 🎵 Audio Events & Profiles

### Profile: `default`
Subtle notification sounds

| Event | Frequency | Duration | Type |
|-------|-----------|----------|------|
| `webhook_received` | 440 Hz | 100ms | sine |
| `webhook_success` | 523 Hz | 150ms | sine |
| `webhook_error` | 220 Hz | 300ms | sawtooth |
| `test` | 440 Hz | 200ms | sine |

---

### Profile: `workflow`
Melodic sounds for workflows

| Event | Frequencies | Duration | Type |
|-------|-------------|----------|------|
| `workflow_start` | 523→659→784 Hz | 500ms | sine |
| `step_complete` | 440→554→659 Hz | 200ms | sine |
| `step_failed` | 330→294→220 Hz | 400ms | sawtooth |
| `step_progress` | 494 Hz | 100ms | sine |
| `workflow_complete` | 523→659→784→1047 Hz | 800ms | sine |

---

### Profile: `alert`
Attention-grabbing sounds

| Event | Frequencies | Duration | Type |
|-------|-------------|----------|------|
| `critical` | 880→440→880 Hz | 1000ms | square |
| `warning` | 660→550 Hz | 600ms | triangle |
| `info` | 440 Hz | 300ms | sine |

---

### Profile: `development` ⭐
Sounds for dev events **including Claude Code**

| Event | Frequencies | Duration | Type |
|-------|-------------|----------|------|
| **Claude Code Events** |
| `claude_task_start` | 523→659 Hz | 300ms | sine |
| `claude_task_complete` | 523→659→784 Hz | 400ms | sine |
| `claude_error` | 330→220 Hz | 500ms | sawtooth |
| `claude_tool_use` | 440 Hz | 100ms | sine |
| **Build Events** |
| `build_start` | 261 Hz | 200ms | sine |
| `build_success` | 261→329→392→523 Hz | 600ms | sine |
| `build_failed` | 440→220 Hz | 800ms | square |
| **Test Events** |
| `test_pass` | 523→659 Hz | 300ms | sine |
| `test_fail` | 330→220 Hz | 500ms | sawtooth |
| **Deployment Events** |
| `deploy_start` | 392→494→587 Hz | 400ms | sine |
| `deploy_complete` | 392→494→587→784 Hz | 1000ms | sine |
| **Git Events** |
| `git_push` | 440 Hz | 150ms | sine |
| `git_merge` | 440→554 Hz | 300ms | sine |
| **Pull Request Events** |
| `pr_opened` | 659→784 Hz | 400ms | sine |
| `pr_merged` | 523→659→784→1047 Hz | 800ms | sine |

---

### Profile: `monitoring`
System health sounds

| Event | Frequencies | Duration | Type |
|-------|-------------|----------|------|
| `health_check` | 440 Hz | 50ms | sine |
| `metric_threshold` | 550→660 Hz | 400ms | triangle |
| `error_spike` | 880→440→880 Hz | 600ms | square |
| `latency_warning` | 330 Hz | 500ms | sawtooth |
| `traffic_surge` | 440→550→660 Hz | 300ms | sine |

---

### Profile: `communication`
Chat/messaging sounds

| Event | Frequencies | Duration | Type |
|-------|-------------|----------|------|
| `message_received` | 659 Hz | 100ms | sine |
| `mention` | 659→784 Hz | 200ms | sine |
| `dm_received` | 523→659 Hz | 250ms | sine |
| `user_joined` | 392→523 Hz | 300ms | sine |
| `user_left` | 523→392 Hz | 300ms | sine |

---

## 🔧 MCP Tools (After Claude Code Restart)

### Available via Claude Code:

1. **`play_audio_cue`**
   - Play an audio cue for events
   - Parameters: `event_type`, `profile`
   - Example: "Play a claude_task_start audio cue"

2. **`start_workflow`**
   - Start tracking a workflow
   - Parameters: `name`, `steps`, `audio_profile`
   - Example: "Start a workflow called 'Build App' with steps: compile, test, deploy"

3. **`update_workflow_step`**
   - Update workflow step status
   - Parameters: `workflow_id`, `step_name`, `status`, `data`
   - Example: "Update workflow step 'compile' to completed"

4. **`register_webhook`**
   - Create a new webhook endpoint
   - Parameters: `name`, `description`, `audio_profile`
   - Example: "Register a webhook for GitHub push events"

5. **`configure_audio`**
   - Adjust audio settings
   - Parameters: `muted`, `volume`
   - Example: "Mute the audio tracker"

6. **`get_tracker_status`**
   - Check server health
   - No parameters
   - Example: "What's the status of the webhook tracker?"

---

## 🌐 WebSocket Connection

### URL: `ws://localhost:3001`

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:3001');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};
```

**Message Types:**
- `initial_state` - Initial webhooks and workflows
- `webhook_event` - New webhook triggered
- `workflow_step` - Workflow step updated

**Send Commands:**
```javascript
ws.send(JSON.stringify({
  type: 'test_audio',
  soundType: 'test',
  profile: 'default'
}));

ws.send(JSON.stringify({
  type: 'mute',
  muted: true
}));
```

---

## 📋 Complete Usage Examples

### Example 1: CI/CD Pipeline Integration

```bash
# Register webhook
WEBHOOK=$(curl -X POST http://localhost:3000/webhook/register \
  -H "Content-Type: application/json" \
  -d '{"name":"CI Pipeline","audioProfile":"development"}' | jq -r '.url')

# Trigger on different events
curl -X POST "$WEBHOOK" -H "Content-Type: application/json" \
  -d '{"type":"build_start"}'

curl -X POST "$WEBHOOK" -H "Content-Type: application/json" \
  -d '{"type":"test_pass"}'

curl -X POST "$WEBHOOK" -H "Content-Type: application/json" \
  -d '{"type":"deploy_complete"}'
```

### Example 2: Workflow Tracking

```bash
# Start workflow
WF_ID=$(curl -X POST http://localhost:3000/workflow/start \
  -H "Content-Type: application/json" \
  -d '{"name":"Deploy v2.0","steps":["build","test","stage","prod"],"audioProfile":"workflow"}' \
  | jq -r '.workflowId')

# Update steps
curl -X POST "http://localhost:3000/workflow/$WF_ID/step" \
  -H "Content-Type: application/json" \
  -d '{"stepName":"build","status":"completed"}'

curl -X POST "http://localhost:3000/workflow/$WF_ID/step" \
  -H "Content-Type: application/json" \
  -d '{"stepName":"test","status":"in_progress"}'
```

### Example 3: GitHub Actions Integration

```yaml
# .github/workflows/deploy.yml
- name: Notify Start
  run: |
    curl -X POST http://your-server:3000/webhook/register \
      -H "Content-Type: application/json" \
      -d '{"type":"build_start"}'

- name: Notify Success
  if: success()
  run: |
    curl -X POST $WEBHOOK_URL \
      -d '{"type":"build_success"}'

- name: Notify Failure
  if: failure()
  run: |
    curl -X POST $WEBHOOK_URL \
      -d '{"type":"build_failed"}'
```

---

## 🎯 Currently Active

**Server Status:** Running  
**Registered Webhooks:** 0  
**Active Workflows:** 1  
**Dashboard:** http://localhost:3000/  

---

**Ready to track your development workflow with audio feedback!** 🎵
