# 🎵 Webhook Audio Tracker

A real-time webhook monitoring system with audio cues for workflow tracking. This system provides multi-sensory awareness of system events through customizable audio profiles and a visual dashboard.

## Features

### 🔊 Audio Feedback System
- **Multiple Audio Profiles**: Default, Workflow, Alert, Development, Monitoring, Communication
- **Platform Support**: Windows (PowerShell beeps), Unix (sox/ffplay), Fallback (console beep)
- **Smart Queue Management**: Sequential playback prevents audio overlap
- **Volume Control**: Adjustable volume with mute option

### 📡 Webhook Management
- **Dynamic Endpoint Registration**: Create webhooks on-the-fly
- **Event Type Detection**: Automatic sound mapping based on event content
- **Custom Audio Profiles**: Assign specific sound profiles to each webhook

### 🔄 Workflow Tracking
- **Multi-step Workflows**: Define and track complex processes
- **Real-time Progress**: Visual and audio feedback for each step
- **Pattern Detection**: Identifies bottlenecks and optimization opportunities
- **Performance Metrics**: Success rates, duration tracking, and statistics

### 📊 Real-time Dashboard
- **WebSocket Updates**: Instant event notifications
- **Visual Feedback**: Animated progress bars and status indicators
- **Event Log**: Searchable history with filtering
- **Keyboard Shortcuts**: Quick access to common actions

## Installation

```bash
# Navigate to the webhook-audio-tracker directory
cd C:\Users\Corbin\development\mcp-servers\webhook-audio-tracker

# Install dependencies
npm install

# Start the server
npm start
```

## Quick Start

### 1. Start the Server
```bash
node server.js
```

The server will start on:
- HTTP Server: `http://localhost:3000`
- WebSocket: `ws://localhost:3001`
- Dashboard: `http://localhost:3000/`

### 2. Register a Webhook
```javascript
// Using curl
curl -X POST http://localhost:3000/webhook/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyApp",
    "description": "Webhook for my application",
    "audioProfile": "default"
  }'

// Response:
{
  "endpointId": "uuid-here",
  "url": "http://localhost:3000/webhook/uuid-here",
  "wsUrl": "ws://localhost:3001"
}
```

### 3. Send Events to Your Webhook
```javascript
// Send a webhook event
curl -X POST http://localhost:3000/webhook/your-endpoint-id \
  -H "Content-Type: application/json" \
  -d '{
    "type": "build_success",
    "status": "success",
    "message": "Build completed successfully"
  }'
```

## Audio Profiles

### Default Profile
Basic notification sounds for general webhooks:
- `webhook_received`: Single tone (440Hz)
- `webhook_success`: Higher tone (523Hz)
- `webhook_error`: Low warning tone (220Hz)

### Workflow Profile
Melodic sounds for process tracking:
- `workflow_start`: Rising three-note chord
- `step_complete`: Pleasant two-note progression
- `step_failed`: Descending warning tones
- `workflow_complete`: Victory fanfare

### Development Profile
Distinctive sounds for CI/CD events:
- `build_start`: Low starting tone
- `build_success`: Rising four-note success melody
- `build_failed`: Alert pattern
- `test_pass`: Quick success beep
- `test_fail`: Warning sound
- `deploy_complete`: Extended celebration melody

### Alert Profile
Attention-grabbing sounds for critical events:
- `critical`: Loud alternating tones
- `warning`: Medium urgency alert
- `info`: Simple notification

### Monitoring Profile
Status-based sounds for system monitoring:
- `health_check`: Quick pulse
- `metric_threshold`: Threshold warning
- `error_spike`: Critical alert pattern
- `latency_warning`: Slow warning tone

### Communication Profile
Social interaction sounds:
- `message_received`: Quick notification
- `mention`: Two-tone alert
- `dm_received`: Personal message sound
- `user_joined`: Welcome tone
- `user_left`: Departure tone

## Integration Examples

### GitHub Integration
```javascript
const WebhookIntegrations = require('./examples');
const integrations = new WebhookIntegrations();

// Setup GitHub webhook
const github = await integrations.setupGitHubIntegration();

// Trigger events with audio feedback
await github.push('main', 3);
await github.pullRequest('opened', { number: 42, title: 'New feature' });
await github.workflow('completed', 'CI Pipeline');
```

### CI/CD Pipeline
```javascript
const { pipeline, workflowId } = await integrations.setupCICDIntegration();

// Track build process with audio cues
await pipeline.startBuild();
await pipeline.updateStep('Run Tests', 'completed', { passed: 42 });
await pipeline.completeBuild(true);
await pipeline.deploy('production', 'v1.2.3');
```

### Monitoring System
```javascript
const monitoring = await integrations.setupMonitoringIntegration();

// Alert on metrics
await monitoring.metricAlert('cpu_usage', 85, 70);
await monitoring.errorSpike('api-gateway', 150, '5m');
await monitoring.latencyWarning('/api/users', 2500);
```

## Workflow Management

### Creating a Workflow
```javascript
POST /workflow/start
{
  "name": "Deploy Pipeline",
  "steps": ["Build", "Test", "Deploy", "Verify"],
  "audioProfile": "workflow"
}
```

### Updating Workflow Progress
```javascript
POST /workflow/{workflowId}/step
{
  "stepName": "Test",
  "status": "completed",
  "data": {
    "testsRun": 150,
    "testsPassed": 150
  }
}
```

## Dashboard Features

### Keyboard Shortcuts
- `Ctrl+W`: Register new webhook
- `Ctrl+F`: Start new workflow
- `Ctrl+T`: Test audio
- `Ctrl+L`: Clear event log

### Visual Indicators
- **Green Pulse**: Active/Healthy status
- **Yellow Pulse**: In-progress operations
- **Red Pulse**: Errors or failures
- **Progress Bars**: Workflow completion status
- **Step Dots**: Individual step status in workflows

## API Endpoints

### Webhooks
- `POST /webhook/register` - Register new webhook endpoint
- `GET /webhooks` - List all registered webhooks
- `POST /webhook/:endpointId` - Receive webhook event

### Workflows
- `POST /workflow/start` - Start new workflow
- `POST /workflow/:workflowId/step` - Update workflow step
- `GET /workflows` - List all workflows

### Audio
- `POST /audio/configure` - Configure audio profile
- WebSocket message: `{ type: 'test_audio', profile: 'default' }`
- WebSocket message: `{ type: 'mute', muted: true/false }`

### System
- `GET /health` - Health check endpoint
- `GET /` - Dashboard interface

## Configuration

### Environment Variables
```bash
PORT=3000          # HTTP server port
WS_PORT=3001       # WebSocket server port
```

### Custom Audio Profiles
```javascript
POST /audio/configure
{
  "profile": "custom",
  "sounds": {
    "my_event": {
      "frequency": 880,
      "duration": 200,
      "type": "sine"
    },
    "my_sequence": {
      "frequencies": [523, 659, 784],
      "duration": 600,
      "type": "sine"
    }
  }
}
```

## Use Cases

### 1. DevOps Monitoring
- Build status notifications
- Deployment progress tracking
- Test suite completion alerts
- Infrastructure health monitoring

### 2. E-commerce Operations
- Order processing workflow
- Payment status updates
- Inventory alerts
- Shipping notifications

### 3. Team Collaboration
- PR/Issue notifications
- Mention alerts
- Meeting reminders
- Standup notifications

### 4. System Administration
- Server health checks
- Backup completion
- Error spike detection
- Resource threshold alerts

## Running the Demo

```bash
# Run the example integrations demo
node examples.js
```

This will:
1. Register multiple webhook endpoints
2. Simulate various events
3. Trigger different audio profiles
4. Demonstrate workflow tracking

## Troubleshooting

### No Audio on Windows
- Ensure PowerShell is accessible from command line
- Check Windows audio settings
- Try running as administrator

### No Audio on Unix/Linux
- Install sox: `sudo apt-get install sox`
- Or install ffmpeg: `sudo apt-get install ffmpeg`
- Check audio permissions

### WebSocket Connection Issues
- Verify firewall settings
- Check if ports 3000 and 3001 are available
- Ensure no other services are using these ports

### Dashboard Not Loading
- Clear browser cache
- Check browser console for errors
- Verify server is running

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐
│  External       │────▶│   Webhook    │────▶│     Audio      │
│  Services       │     │   Receiver   │     │    Manager     │
└─────────────────┘     └──────────────┘     └────────────────┘
                              │                       │
                              ▼                       ▼
                        ┌──────────────┐     ┌────────────────┐
                        │   Workflow   │     │   WebSocket    │
                        │   Tracker    │────▶│    Clients     │
                        └──────────────┘     └────────────────┘
                              │                       │
                              ▼                       ▼
                        ┌──────────────┐     ┌────────────────┐
                        │   Event      │     │   Dashboard    │
                        │   Logger     │     │      UI        │
                        └──────────────┘     └────────────────┘
```

## Contributing

Feel free to extend the system with:
- Additional audio profiles
- New integration examples
- Enhanced dashboard features
- Mobile app notifications
- Cloud service integrations

## License

MIT