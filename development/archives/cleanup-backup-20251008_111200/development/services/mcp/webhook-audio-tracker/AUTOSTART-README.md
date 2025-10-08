# Webhook Audio Tracker - Autostart Configuration

This guide explains how to configure the Webhook Audio Tracker to start automatically when you launch Claude Code or log into Windows.

## Quick Setup

### Option 1: Windows Startup (Recommended)

Run this to start the tracker automatically when you log into Windows:

```batch
setup-autostart.bat
```

This creates a Windows Task Scheduler entry that runs the tracker silently in the background at login.

### Option 2: Manual Background Start

To start the tracker manually in the background (no window):

```batch
start-background.vbs
```

Or double-click `start-background.vbs` in File Explorer.

### Option 3: Normal Start (With Console Window)

To start with a visible console window:

```batch
start.bat
```

## Verification

After setting up autostart:

1. Check if it's running by visiting: http://localhost:3000/
2. You should see the Webhook Audio Tracker Dashboard
3. The WebSocket should connect on port 3001

## Managing Autostart

### Check if autostart is enabled:
```batch
schtasks /query /tn "WebhookAudioTracker"
```

### Remove autostart:
```batch
remove-autostart.bat
```

### Stop the running tracker:
```batch
taskkill /IM node.exe /FI "WINDOWTITLE eq Webhook Audio Tracker*"
```

Or use Task Manager to end the `node.exe` process running `server.js`.

## Ports Used

- **3000**: HTTP Server (Dashboard)
- **3001**: WebSocket Server (Real-time updates)

## Troubleshooting

### Tracker won't start automatically
- Ensure you ran `setup-autostart.bat` as Administrator
- Check Windows Task Scheduler for the "WebhookAudioTracker" task
- Verify no other application is using ports 3000 or 3001

### Can't access dashboard
- Check if the server is running: `tasklist | findstr node.exe`
- Verify ports are available: `netstat -ano | findstr ":3000"`
- Try starting manually with `start.bat` to see error messages

### Multiple instances running
- Stop all instances: `taskkill /IM node.exe /F`
- Then start fresh with `start-background.vbs`

## Integration with Claude Code

While this tracker runs as a separate service, you can integrate it with your Claude Code workflow:

1. The tracker will run in the background
2. Access the dashboard at http://localhost:3000/ anytime
3. Your workflows and webhooks will be tracked automatically
4. Audio cues will play for different events

## Files Created

- `start-background.vbs` - Silent background launcher
- `setup-autostart.bat` - Configure Windows autostart
- `remove-autostart.bat` - Remove Windows autostart
- `AUTOSTART-README.md` - This file
