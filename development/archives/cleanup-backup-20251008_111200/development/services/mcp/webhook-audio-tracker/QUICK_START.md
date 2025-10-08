# Webhook Audio Tracker - Quick Start

## ✅ Installation Complete!

Everything is set up and running. Here's what to do next:

---

## 🚀 Immediate Next Step

**RESTART CLAUDE CODE** to activate the MCP integration.

After restarting, you can use commands like:
- "Play a test audio cue"
- "Start a workflow for my task"
- "Check the audio tracker status"

---

## 📊 Dashboard

**URL:** http://localhost:3000/

The dashboard is already open in your browser showing:
- Active workflows
- Registered webhooks
- Event log
- Audio visualizer
- Statistics

---

## 🎵 Test Audio Now

### Via Dashboard:
1. Go to http://localhost:3000/
2. Click "Test Audio" button
3. Listen for beep sounds

### Via API:
```bash
curl -X POST http://localhost:3000/workflow/start \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","audioProfile":"workflow"}'
```

You should hear a melodic sequence (523Hz → 659Hz → 784Hz).

---

## 🔧 If No Audio:

1. **Check system volume** - Make sure Windows volume is up
2. **Test PowerShell beep:**
   ```powershell
   [console]::beep(440, 200)
   ```
3. **Check server logs** - Should show no errors in the background process

---

## 🎯 Available Audio Events

### Claude Code Events (development profile):
- `claude_task_start` - Starting a task
- `claude_task_complete` - Task finished
- `claude_error` - Error occurred  
- `claude_tool_use` - Tool executed

### Development Events:
- `build_start`, `build_success`, `build_failed`
- `test_pass`, `test_fail`
- `git_push`, `git_merge`
- `pr_opened`, `pr_merged`
- `deploy_start`, `deploy_complete`

### Workflow Events:
- `workflow_start` - Workflow begins
- `step_complete` - Step completed
- `step_failed` - Step failed
- `workflow_complete` - All done!

---

## 🔄 Auto-Start (Optional)

To start the tracker automatically when you log in:

```batch
cd C:\Users\Corbin\development\services\mcp\webhook-audio-tracker
setup-autostart.bat
```

Run as Administrator for best results.

---

## 📁 Key Files

- **Server:** Running in background (PID check: `tasklist | findstr node`)
- **Dashboard:** http://localhost:3000/
- **Config:** `C:\Users\Corbin\.claude\config.json`
- **Logs:** `webhook-events.log`

---

## 🎮 Example Usage (After Restart)

**In Claude Code:**

```
Play a claude_task_start audio cue using the development profile
```

```
Start tracking a workflow called "Build Feature" with steps: design, implement, test, deploy
```

```
What's the current status of the webhook audio tracker?
```

---

## ⚡ Quick Commands

**Check if running:**
```bash
curl http://localhost:3000/health
```

**Stop server:**
```bash
taskkill /IM node.exe /F
```

**Restart server:**
```bash
cd C:\Users\Corbin\development\services\mcp\webhook-audio-tracker
start.bat
```

**Start in background:**
```bash
wscript C:\Users\Corbin\development\services\mcp\webhook-audio-tracker\start-background.vbs
```

---

## 🆘 Troubleshooting

**MCP tools not showing up after restart?**
- Verify: `cat C:\Users\Corbin\.claude\config.json`
- Should contain `webhook-audio-tracker` entry

**Audio not playing?**
- Test: Dashboard → "Test Audio" button
- Test: `powershell -c "[console]::beep(440,200)"`
- Check: Windows volume mixer

**Server not responding?**
- Check: `tasklist | findstr node`
- Restart: `start.bat`

---

**You're all set! 🎉**

Restart Claude Code and enjoy audio feedback for your development workflow!
