# Schedule Automated Secret Rotation
# D3FEND D3-KM Compliance - Automated Secret Rotation Scheduler
#
# This script creates a Windows Scheduled Task to rotate secrets monthly
# Recommended: Run on the 1st of each month at 2 AM

param(
    [string]$Environment = "development",
    [string]$Frequency = "Monthly",  # Daily, Weekly, Monthly
    [int]$DayOfMonth = 1,
    [string]$Time = "02:00"
)

Write-Host "=============================================" -ForegroundColor Blue
Write-Host "Secret Rotation Scheduler - D3FEND D3-KM" -ForegroundColor Blue
Write-Host "=============================================" -ForegroundColor Blue
Write-Host ""

# Configuration
$TaskName = "CatalyticSecurity-SecretRotation-$Environment"
$ScriptPath = Join-Path $PSScriptRoot "rotate-secrets.sh"
$BashPath = "C:\Program Files\Git\bin\bash.exe"
$WorkingDir = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
$LogFile = Join-Path $PSScriptRoot "logs\rotation-$Environment.log"

# Verify script exists
if (-not (Test-Path $ScriptPath)) {
    Write-Host "[!] Rotation script not found: $ScriptPath" -ForegroundColor Red
    exit 1
}

# Verify bash exists
if (-not (Test-Path $BashPath)) {
    Write-Host "[!] Git Bash not found at: $BashPath" -ForegroundColor Red
    Write-Host "    Install Git for Windows: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

# Create log directory
$LogDir = Split-Path $LogFile
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

Write-Host "[*] Configuration:" -ForegroundColor Cyan
Write-Host "  Task Name: $TaskName"
Write-Host "  Environment: $Environment"
Write-Host "  Frequency: $Frequency"
Write-Host "  Schedule: Day $DayOfMonth at $Time"
Write-Host "  Script: $ScriptPath"
Write-Host "  Log File: $LogFile"
Write-Host ""

# Build trigger based on frequency
$TriggerArgs = @{
    At = $Time
}

switch ($Frequency) {
    "Daily" {
        $TriggerArgs.Daily = $true
    }
    "Weekly" {
        $TriggerArgs.Weekly = $true
        $TriggerArgs.DaysOfWeek = "Monday"
    }
    "Monthly" {
        # Monthly on specific day
        $TriggerArgs.Daily = $true
    }
}

# Remove existing task if it exists
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
    Write-Host "[*] Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Create action
$ActionArgs = "-c `"cd '$WorkingDir' && bash '$ScriptPath' $Environment >> '$LogFile' 2>&1`""
$Action = New-ScheduledTaskAction `
    -Execute $BashPath `
    -Argument $ActionArgs `
    -WorkingDirectory $WorkingDir

# Create trigger
if ($Frequency -eq "Monthly") {
    # For monthly, use a custom trigger XML
    $TriggerXml = @"
<Triggers>
  <CalendarTrigger>
    <StartBoundary>2025-10-01T$Time:00</StartBoundary>
    <Enabled>true</Enabled>
    <ScheduleByMonth>
      <DaysOfMonth>
        <Day>$DayOfMonth</Day>
      </DaysOfMonth>
      <Months>
        <January /><February /><March /><April /><May /><June />
        <July /><August /><September /><October /><November /><December />
      </Months>
    </ScheduleByMonth>
  </CalendarTrigger>
</Triggers>
"@
    $Trigger = $null  # Will be set via XML
} else {
    $Trigger = New-ScheduledTaskTrigger @TriggerArgs
}

# Create settings
$Settings = New-ScheduledTaskSettings `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

# Create principal (run as SYSTEM)
$Principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# Register task
Write-Host "[*] Creating scheduled task..." -ForegroundColor Cyan

if ($Frequency -eq "Monthly") {
    # Register with XML for monthly schedule
    $TaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  $TriggerXml
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$BashPath</Command>
      <Arguments>$ActionArgs</Arguments>
      <WorkingDirectory>$WorkingDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

    # Save to temp file
    $TempXml = Join-Path $env:TEMP "$TaskName.xml"
    $TaskXml | Out-File -FilePath $TempXml -Encoding UTF8

    # Register from XML
    Register-ScheduledTask -TaskName $TaskName -Xml (Get-Content $TempXml | Out-String) -Force | Out-Null
    Remove-Item $TempXml
} else {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Settings $Settings `
        -Principal $Principal `
        -Force | Out-Null
}

Write-Host "[✓] Scheduled task created successfully" -ForegroundColor Green
Write-Host ""

# Verify task was created
$Task = Get-ScheduledTask -TaskName $TaskName
if ($Task) {
    Write-Host "=== Task Details ===" -ForegroundColor Cyan
    Write-Host "  Name: $($Task.TaskName)"
    Write-Host "  State: $($Task.State)"
    Write-Host "  Next Run: $((Get-ScheduledTaskInfo -TaskName $TaskName).NextRunTime)"
    Write-Host ""

    # Show trigger details
    Write-Host "=== Trigger Details ===" -ForegroundColor Cyan
    $TaskInfo = Get-ScheduledTask -TaskName $TaskName
    foreach ($Trigger in $TaskInfo.Triggers) {
        if ($Trigger.CimClass.CimClassName -eq "MSFT_TaskCalendarTrigger") {
            Write-Host "  Type: Calendar Trigger (Monthly)"
            Write-Host "  Day of Month: $DayOfMonth"
            Write-Host "  Time: $Time"
        } else {
            Write-Host "  Type: $($Trigger.CimClass.CimClassName)"
        }
    }
    Write-Host ""
} else {
    Write-Host "[!] Task creation may have failed" -ForegroundColor Red
    exit 1
}

Write-Host "=== Management Commands ===" -ForegroundColor Yellow
Write-Host ""
Write-Host "View task:"
Write-Host "  Get-ScheduledTask -TaskName '$TaskName' | Format-List *"
Write-Host ""
Write-Host "Run task immediately:"
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host ""
Write-Host "View last run result:"
Write-Host "  Get-ScheduledTaskInfo -TaskName '$TaskName' | Select-Object LastRunTime, LastTaskResult"
Write-Host ""
Write-Host "View rotation log:"
Write-Host "  Get-Content '$LogFile' -Tail 50"
Write-Host ""
Write-Host "Disable task:"
Write-Host "  Disable-ScheduledTask -TaskName '$TaskName'"
Write-Host ""
Write-Host "Remove task:"
Write-Host "  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
Write-Host ""

Write-Host "=============================================" -ForegroundColor Blue
Write-Host "Secret rotation scheduled successfully!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Blue
