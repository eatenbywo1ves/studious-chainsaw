# Docker Volume Backup System

**B-MAD Implementation - Phase 2: Volume Backup Automation**

## Overview

Automated backup and restoration system for critical Docker volumes with compression, metadata tracking, and Windows Task Scheduler integration.

## Features

- ✅ **Automated Daily Backups**: Windows Task Scheduler integration
- ✅ **Compression**: gzip compression (~74% size reduction for time-series data)
- ✅ **Metadata Tracking**: JSON metadata files with backup details
- ✅ **Volume Verification**: Integrity checking for backup files
- ✅ **Selective Backup**: Backup specific volumes or all critical volumes
- ✅ **Safe Restoration**: Confirmation prompts before overwriting data

## Quick Start

### List Available Backups
```powershell
.\docker-volume-backup.ps1 -Action List
```

### Backup Single Volume
```powershell
.\docker-volume-backup.ps1 -Action Backup -VolumeName monitoring_prometheus_data
```

### Backup All Critical Volumes
```powershell
.\docker-volume-backup.ps1 -Action Backup
```

### Restore Volume
```powershell
.\docker-volume-backup.ps1 -Action Restore -VolumeName monitoring_prometheus_data -BackupFile monitoring_prometheus_data_20251023_055901.tar.gz
```

### Verify Backup Integrity
```powershell
.\docker-volume-backup.ps1 -Action Verify -BackupFile monitoring_prometheus_data_20251023_055901.tar.gz
```

## Automated Scheduling

### Setup Daily Automated Backups
Run as Administrator:
```powershell
.\setup-backup-automation.ps1
```

This creates a Windows scheduled task that runs daily at 2:00 AM.

### Custom Backup Time
```powershell
.\setup-backup-automation.ps1 -BackupTime "03:30"
```

### Manually Trigger Scheduled Backup
```powershell
schtasks /run /tn "DockerVolumeBackup-Daily"
```

### View Scheduled Task Status
```powershell
Get-ScheduledTask -TaskName "DockerVolumeBackup-Daily" | Get-ScheduledTaskInfo
```

## Critical Volumes (Auto-backed up)

The following volumes are automatically backed up when using `-Action Backup` without specifying a volume:

- `development_prometheus_data` - Prometheus metrics data
- `development_grafana_data` - Grafana dashboards and settings
- `development_postgres_data` - PostgreSQL database
- `development_redis_data` - Redis cache data
- `monitoring_prometheus_data` - Monitoring stack Prometheus data
- `monitoring_grafana_data` - Monitoring stack Grafana data

## Backup Storage Location

Default: `C:\Users\Corbin\development\backups\docker-volumes`

Change location:
```powershell
.\docker-volume-backup.ps1 -Action Backup -BackupDir "D:\Backups\Docker"
```

## Backup File Format

### Naming Convention
```
<volume_name>_<timestamp>.tar.gz
```

Example: `monitoring_prometheus_data_20251023_055901.tar.gz`

### Metadata Files
Each backup includes a `.meta.json` file with:
- Volume name
- Timestamp
- Original size
- Backup size
- Hostname

Example: `monitoring_prometheus_data_20251023_055901.tar.gz.meta.json`

## Performance Benchmarks

Based on test backup of `monitoring_prometheus_data` (356.4MB):

| Metric | Value |
|--------|-------|
| Original Size | 356.4 MB |
| Compressed Size | 91 MB |
| Compression Ratio | 74.5% |
| Backup Time | 47 seconds |
| Throughput | ~7.6 MB/s |

## Restoration Process

### Safety Features
1. **Confirmation Prompt**: Requires typing "YES" to confirm restoration
2. **Data Overwrite Warning**: Clearly warns that existing data will be deleted
3. **Backup Verification**: Checks that backup file exists and is valid .tar.gz format
4. **Volume Creation**: Auto-creates volume if it doesn't exist

### Restoration Example
```powershell
PS> .\docker-volume-backup.ps1 -Action Restore -VolumeName test_volume -BackupFile monitoring_prometheus_data_20251023_055901.tar.gz

[2025-10-23 06:00:00] [WARNING] Starting restore of volume: test_volume
[2025-10-23 06:00:00] [WARNING] WARNING: Volume test_volume exists and will be OVERWRITTEN!
Type 'YES' to confirm restoration (this will DELETE existing data): YES
[2025-10-23 06:00:01] [INFO] Restoring from: C:\Users\Corbin\development\backups\docker-volumes\monitoring_prometheus_data_20251023_055901.tar.gz (91 MB)
[2025-10-23 06:00:45] [SUCCESS] Restore completed successfully for volume: test_volume
```

## Troubleshooting

### Backup Fails with Network Error
**Issue**: Cannot pull alpine/busybox image

**Solution**: Script now uses `busybox:latest` which is typically cached locally. If needed, pull manually:
```powershell
docker pull busybox:latest
```

### Permission Denied Errors
**Issue**: Cannot access backup directory

**Solution**: Run PowerShell as Administrator or adjust backup directory permissions:
```powershell
.\docker-volume-backup.ps1 -BackupDir "C:\Temp\Backups"
```

### Volume Not Found
**Issue**: Backup fails with "Volume does not exist"

**Solution**: List all volumes and verify name:
```powershell
docker volume ls
```

### Insufficient Disk Space
**Issue**: Backup fails during compression

**Solution**: Check available space and clean old backups:
```powershell
# Check backup directory size
Get-ChildItem "C:\Users\Corbin\development\backups\docker-volumes" | Measure-Object -Property Length -Sum

# Delete old backups (older than 30 days)
Get-ChildItem "C:\Users\Corbin\development\backups\docker-volumes\*.tar.gz" |
    Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-30)} |
    Remove-Item
```

## Backup Retention Policy

Recommended retention policy:

| Frequency | Retention |
|-----------|-----------|
| Daily | 7 days |
| Weekly | 4 weeks |
| Monthly | 12 months |

### Implement Retention Policy
Create a cleanup script:
```powershell
# Keep last 7 daily backups
Get-ChildItem "C:\Users\Corbin\development\backups\docker-volumes\*.tar.gz" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip 7 |
    Remove-Item -WhatIf  # Remove -WhatIf to actually delete
```

## Integration with Monitoring

### Monitor Backup Success via Prometheus

Create a simple wrapper script that posts metrics:
```powershell
# backup-with-metrics.ps1
$result = & "C:\Users\Corbin\development\docker-volume-backup.ps1" -Action Backup
$exitCode = $LASTEXITCODE

# Post to Prometheus Pushgateway
$metrics = @"
docker_backup_success{job=\"docker-volumes\"} $(if($exitCode -eq 0){"1"}else{"0"})
docker_backup_timestamp{job=\"docker-volumes\"} $([DateTimeOffset]::Now.ToUnixTimeSeconds())
"@

Invoke-WebRequest -Uri "http://localhost:9091/metrics/job/docker-volumes" -Method POST -Body $metrics
```

## Security Considerations

1. **Backup Encryption**: Backups are NOT encrypted by default
   - For sensitive data, consider encrypting backup directory
   - Use BitLocker on backup drive

2. **Access Control**: Backup files contain sensitive data
   - Restrict backup directory permissions
   - Only SYSTEM and Administrators should have access

3. **Off-site Backups**: Local backups don't protect against hardware failure
   - Consider syncing to cloud storage (Azure, AWS S3)
   - Use encrypted transfer (rsync over SSH, rclone)

## Advanced Usage

### Backup to Network Share
```powershell
.\docker-volume-backup.ps1 -Action Backup -BackupDir "\\\\nas.local\\backups\\docker"
```

### Parallel Backups (Multiple Volumes)
```powershell
$volumes = @("development_prometheus_data", "development_grafana_data")
$volumes | ForEach-Object -Parallel {
    & "C:\Users\Corbin\development\docker-volume-backup.ps1" -Action Backup -VolumeName $_
} -ThrottleLimit 4
```

### Email Notifications on Failure
Add to scheduled task:
```powershell
# In setup-backup-automation.ps1, modify action:
$script = @"
`$result = & 'C:\Users\Corbin\development\docker-volume-backup.ps1' -Action Backup
if (`$LASTEXITCODE -ne 0) {
    Send-MailMessage -To 'admin@example.com' -From 'backups@example.com' `
        -Subject 'Docker Backup Failed' -Body 'Check logs' -SmtpServer 'smtp.example.com'
}
"@
```

## Files

| File | Purpose |
|------|---------|
| `docker-volume-backup.ps1` | Main backup/restore script |
| `setup-backup-automation.ps1` | Scheduled task setup |
| `DOCKER_VOLUME_BACKUP_README.md` | This documentation |
| `backups/docker-volumes/*.tar.gz` | Backup files |
| `backups/docker-volumes/*.meta.json` | Backup metadata |

## Next Steps

- ✅ **Phase 2 Complete**: Volume backup automation implemented
- ⏳ **Phase 3 Pending**: Docker daemon log rotation configuration
- ⏳ **Phase 4 Pending**: Log rotation verification

## Support

For issues or questions about this backup system:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review backup logs in `docker-volume-backup.ps1` output
3. Check Windows Event Viewer for scheduled task logs
