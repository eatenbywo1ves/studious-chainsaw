# Activate Docker Log Rotation

## Current Status

✅ **Configuration Complete**
- daemon.json updated with log rotation settings
- Configuration validated (valid JSON)
- Backup created: `C:\Users\Corbin\.docker\daemon.json.backup.20251023_055522`
- Test container verified log rotation works correctly

⏳ **Activation Pending**
- Requires Docker Desktop restart to apply to all containers
- Current containers: 92 running

---

## Activation Methods

### Method 1: GUI Restart (Recommended - Simplest)

1. **Right-click** Docker Desktop icon in Windows system tray (bottom-right)
2. Click **"Restart"**
3. Wait 1-2 minutes for Docker to restart
4. Verify: All containers will automatically restart with existing settings
5. **New containers** will automatically use log rotation

**Downtime**: ~1-2 minutes

---

### Method 2: PowerShell Script (Recommended - Most Comprehensive)

Open **PowerShell as Administrator**:

```powershell
# Right-click PowerShell → Run as Administrator
cd C:\Users\Corbin\development
.\apply-docker-log-rotation.ps1
```

This script will:
- ✅ Display current configuration
- ✅ Confirm restart with user
- ✅ Safely restart Docker Desktop
- ✅ Wait for Docker to be ready
- ✅ Create test container to verify log rotation
- ✅ Display verification results

**Downtime**: ~1-2 minutes

---

### Method 3: Manual Service Restart

Open **Command Prompt as Administrator**:

```cmd
rem Stop Docker Desktop
taskkill /F /IM "Docker Desktop.exe"

rem Wait for graceful shutdown
timeout /t 5

rem Restart Docker service
net stop com.docker.service
net start com.docker.service

rem Start Docker Desktop GUI
start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
```

**Downtime**: ~1-2 minutes

---

## Verification After Restart

### Check Daemon Configuration is Active

```powershell
docker info --format '{{.LoggingDriver}}'
# Expected: json-file
```

### Verify New Container Uses Log Rotation

```powershell
# Create test container
docker run -d --name verify-logs busybox sh -c 'while true; do echo "Test"; sleep 1; done'

# Check log configuration
docker inspect verify-logs --format '{{json .HostConfig.LogConfig}}' | ConvertFrom-Json

# Expected output:
# Type   : json-file
# Config : @{compress=true; max-file=5; max-size=10m}

# Cleanup
docker stop verify-logs
docker rm verify-logs
```

---

## What Happens to Existing Containers?

**Important**: Existing containers will **NOT** automatically get log rotation until they are recreated.

### Apply Log Rotation to Existing Critical Containers

For each critical container, recreate it to apply log rotation:

```powershell
# Example: Recreate Prometheus with log rotation
docker-compose -f C:\Users\Corbin\development\docker-compose-minimal-monitoring.yml up -d --force-recreate prometheus

# Or recreate entire monitoring stack
docker-compose -f C:\Users\Corbin\development\monitoring\docker-compose.monitoring.yml down
docker-compose -f C:\Users\Corbin\development\monitoring\docker-compose.monitoring.yml up -d
```

**Note**: Only recreate containers when you can tolerate brief downtime for that service.

---

## Configuration Details

**File**: `C:\Users\Corbin\.docker\daemon.json`

```json
{
  "builder": {
    "gc": {
      "defaultKeepStorage": "20GB",
      "enabled": true
    }
  },
  "experimental": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5",
    "compress": "true"
  }
}
```

**Settings Explained**:
- `max-size: "10m"` - Rotate when log file reaches 10MB
- `max-file: "5"` - Keep 5 rotated log files
- `compress: "true"` - Compress rotated logs with gzip
- **Total**: Maximum 50MB of logs per container

---

## Rollback (If Needed)

If you need to revert to the previous configuration:

```powershell
# Restore backup
Copy-Item "C:\Users\Corbin\.docker\daemon.json.backup.20251023_055522" "C:\Users\Corbin\.docker\daemon.json"

# Restart Docker (using Method 1, 2, or 3 above)
```

---

## Expected Behavior After Activation

### For NEW Containers
- ✅ Automatically use log rotation
- ✅ Logs capped at 50MB per container
- ✅ Rotated logs compressed with gzip
- ✅ No configuration needed in docker-compose files

### For EXISTING Containers
- ⚠️ Will continue using old settings (unlimited logs)
- ⚠️ Must be recreated to apply new log rotation
- ⚠️ Plan recreation during maintenance windows

---

## Monitoring Log Rotation

### Check Current Log Size for a Container

```powershell
# Get log file path
$logPath = docker inspect prometheus --format '{{.LogPath}}'

# Check size
Get-Item $logPath | Select-Object Name, Length, LastWriteTime
```

### Monitor All Container Log Sizes

```powershell
docker ps --format "{{.Names}}" | ForEach-Object {
    $logPath = docker inspect $_ --format '{{.LogPath}}'
    if (Test-Path $logPath) {
        $size = (Get-Item $logPath).Length / 1MB
        Write-Host "$_: $([math]::Round($size, 2)) MB"
    }
}
```

---

## Next Steps After Activation

1. ✅ **Immediate**: Restart Docker Desktop (Method 1 or 2)
2. ✅ **Within 1 week**: Recreate critical containers to apply log rotation
3. ✅ **Within 1 month**: Monitor disk usage to verify log rotation is working
4. ✅ **Ongoing**: New containers automatically get log rotation

---

## Support

If you encounter issues:

1. **Check daemon.json syntax**:
   ```powershell
   Get-Content C:\Users\Corbin\.docker\daemon.json | ConvertFrom-Json
   ```

2. **Check Docker Desktop logs**:
   - Open Docker Desktop
   - Click gear icon (Settings)
   - Troubleshoot → Show logs

3. **Rollback if needed**: Use backup file (instructions above)

---

**Status**: ✅ Configuration ready, activation pending Docker restart

**Recommended Action**: Use **Method 1** (GUI restart) for simplest activation
