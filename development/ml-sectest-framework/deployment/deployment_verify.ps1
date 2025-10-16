#!/usr/bin/env pwsh
<#
.SYNOPSIS
    ML-SecTest Deployment Verification Script

.DESCRIPTION
    Automated verification script for ML-SecTest framework deployment.
    Validates all deployment components, checks system health, and generates
    comprehensive verification reports.

.PARAMETER CheckAll
    Run all verification checks

.PARAMETER CheckContainers
    Verify Docker containers running and healthy

.PARAMETER CheckMetrics
    Verify metrics endpoint and Prometheus integration

.PARAMETER CheckMonitoring
    Verify Grafana dashboards and AlertManager

.PARAMETER CheckScreenshots
    Verify all required screenshots captured

.PARAMETER GenerateReport
    Generate comprehensive verification report

.EXAMPLE
    .\deployment_verify.ps1 -CheckAll
    Run all verification checks

.EXAMPLE
    .\deployment_verify.ps1 -CheckContainers -CheckMetrics
    Run specific verification checks

.NOTES
    Version: 1.0.0
    Date: 2025-10-14
    Author: Claude Code
    Requires: PowerShell 5.1+, Docker, curl
#>

[CmdletBinding()]
param (
    [Parameter(HelpMessage="Run all verification checks")]
    [switch]$CheckAll,

    [Parameter(HelpMessage="Verify Docker containers")]
    [switch]$CheckContainers,

    [Parameter(HelpMessage="Verify metrics endpoint")]
    [switch]$CheckMetrics,

    [Parameter(HelpMessage="Verify monitoring integration")]
    [switch]$CheckMonitoring,

    [Parameter(HelpMessage="Verify screenshots")]
    [switch]$CheckScreenshots,

    [Parameter(HelpMessage="Generate verification report")]
    [switch]$GenerateReport
)

# Script configuration
$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"
$script:Checks = @()
$script:Passed = 0
$script:Failed = 0
$script:Warnings = 0

# ASCII banner
$banner = @"

╔══════════════════════════════════════════════════════════════╗
║         ML-SECTEST DEPLOYMENT VERIFICATION SCRIPT            ║
║                      Version 1.0.0                           ║
╚══════════════════════════════════════════════════════════════╝

"@

Write-Host $banner -ForegroundColor Cyan

# Helper functions
function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "Info"    { "[INFO]   " }
        "Success" { "[✓]      " }
        "Warning" { "[⚠]      " }
        "Error"   { "[✗]      " }
    }

    $color = switch ($Level) {
        "Info"    { "White" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
    }

    $logMessage = "$timestamp $prefix $Message"
    Write-Host $logMessage -ForegroundColor $color

    # Add to checks array
    $script:Checks += [PSCustomObject]@{
        Timestamp = $timestamp
        Level = $Level
        Message = $Message
    }

    # Update counters
    switch ($Level) {
        "Success" { $script:Passed++ }
        "Error"   { $script:Failed++ }
        "Warning" { $script:Warnings++ }
    }
}

function Test-Command {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

function Invoke-SafeCurl {
    param(
        [string]$Url,
        [string]$Method = "GET"
    )

    try {
        $response = curl -s -X $Method $Url 2>&1
        return $response
    } catch {
        return $null
    }
}

# Main verification functions

function Test-Prerequisites {
    Write-Host "`n=== PREREQUISITE CHECKS ===" -ForegroundColor Cyan

    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        Write-Status "PowerShell version: $($psVersion.ToString())" -Level Success
    } else {
        Write-Status "PowerShell version too old: $($psVersion.ToString()) (need 5.1+)" -Level Error
    }

    # Check Docker
    if (Test-Command "docker") {
        Write-Status "Docker command available" -Level Success
        try {
            $dockerVersion = docker --version
            Write-Status "Docker version: $dockerVersion" -Level Success
        } catch {
            Write-Status "Docker daemon not responding" -Level Error
        }
    } else {
        Write-Status "Docker command not found" -Level Error
    }

    # Check curl
    if (Test-Command "curl") {
        Write-Status "curl command available" -Level Success
    } else {
        Write-Status "curl command not found" -Level Warning
    }

    # Check Python
    if (Test-Command "python") {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "3.13") {
            Write-Status "Python version: $pythonVersion" -Level Success
        } else {
            Write-Status "Python version: $pythonVersion (expected 3.13)" -Level Warning
        }
    } else {
        Write-Status "Python command not found" -Level Warning
    }

    # Check Git
    if (Test-Command "git") {
        Write-Status "Git command available" -Level Success
        $gitBranch = git branch --show-current
        if ($gitBranch -eq "feat/todo-deployment-phase-1") {
            Write-Status "Git branch: $gitBranch" -Level Success
        } else {
            Write-Status "Git branch: $gitBranch (expected: feat/todo-deployment-phase-1)" -Level Warning
        }
    } else {
        Write-Status "Git command not found" -Level Warning
    }
}

function Test-DockerContainers {
    Write-Host "`n=== DOCKER CONTAINER CHECKS ===" -ForegroundColor Cyan

    # Check ML-SecTest containers
    $containers = docker ps --filter "name=ml-sectest" --format "{{.Names}}:{{.Status}}" 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Status "Failed to query Docker containers" -Level Error
        return
    }

    # Expected containers
    $expectedContainers = @("ml-sectest-agent", "ml-sectest-target")

    foreach ($expected in $expectedContainers) {
        $found = $containers | Where-Object { $_ -match $expected }
        if ($found) {
            if ($found -match "Up.*\(healthy\)") {
                Write-Status "Container $expected is running and healthy" -Level Success
            } elseif ($found -match "Up") {
                Write-Status "Container $expected is running (no health check)" -Level Success
            } else {
                Write-Status "Container $expected found but not running: $found" -Level Error
            }
        } else {
            Write-Status "Container $expected not found" -Level Error
        }
    }

    # Check container resource usage
    Write-Status "Checking container resource usage..." -Level Info
    $stats = docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" ml-sectest-agent ml-sectest-target 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Status "Resource stats:`n$stats" -Level Info

        # Parse CPU and memory usage
        if ($stats -match "ml-sectest-agent.*?([\d.]+)%.*?([\d.]+)") {
            $cpuPercent = [double]$matches[1]
            if ($cpuPercent -lt 90) {
                Write-Status "ml-sectest-agent CPU usage: $cpuPercent% (OK)" -Level Success
            } else {
                Write-Status "ml-sectest-agent CPU usage: $cpuPercent% (HIGH)" -Level Warning
            }
        }
    } else {
        Write-Status "Failed to get container stats" -Level Warning
    }

    # Check container logs for errors
    Write-Status "Checking container logs for errors..." -Level Info
    $agentLogs = docker logs ml-sectest-agent --tail 50 2>&1
    $errorCount = ($agentLogs | Select-String -Pattern "ERROR", "CRITICAL", "Exception", "Traceback").Count

    if ($errorCount -eq 0) {
        Write-Status "No errors found in recent logs" -Level Success
    } elseif ($errorCount -lt 5) {
        Write-Status "Found $errorCount errors in recent logs (review recommended)" -Level Warning
    } else {
        Write-Status "Found $errorCount errors in recent logs (investigation required)" -Level Error
    }
}

function Test-DockerNetworks {
    Write-Host "`n=== DOCKER NETWORK CHECKS ===" -ForegroundColor Cyan

    # Check sectest-network exists
    $networks = docker network ls --filter "name=sectest-network" --format "{{.Name}}" 2>&1

    if ($networks -match "sectest-network") {
        Write-Status "sectest-network exists" -Level Success

        # Verify network configuration
        $networkDetails = docker network inspect sectest-network 2>&1 | ConvertFrom-Json
        $subnet = $networkDetails.IPAM.Config[0].Subnet
        $gateway = $networkDetails.IPAM.Config[0].Gateway

        if ($subnet -eq "172.20.0.0/16") {
            Write-Status "sectest-network subnet: $subnet (correct)" -Level Success
        } else {
            Write-Status "sectest-network subnet: $subnet (expected: 172.20.0.0/16)" -Level Warning
        }

        if ($gateway -eq "172.20.0.1") {
            Write-Status "sectest-network gateway: $gateway (correct)" -Level Success
        } else {
            Write-Status "sectest-network gateway: $gateway (expected: 172.20.0.1)" -Level Warning
        }

        # Check connected containers
        $connectedContainers = $networkDetails.Containers
        if ($connectedContainers.Count -ge 2) {
            Write-Status "sectest-network has $($connectedContainers.Count) containers connected" -Level Success
        } else {
            Write-Status "sectest-network has only $($connectedContainers.Count) container(s) connected (expected: 2)" -Level Warning
        }
    } else {
        Write-Status "sectest-network not found" -Level Error
    }

    # Check catalytic-network connectivity
    $catalyticCheck = docker network inspect catalytic-network 2>&1 | ConvertFrom-Json
    $mlsectestConnected = $catalyticCheck.Containers | Where-Object { $_.Name -match "ml-sectest-agent" }

    if ($mlsectestConnected) {
        Write-Status "ml-sectest-agent connected to catalytic-network" -Level Success
    } else {
        Write-Status "ml-sectest-agent not connected to catalytic-network (metrics may not reach Prometheus)" -Level Warning
    }
}

function Test-DockerImages {
    Write-Host "`n=== DOCKER IMAGE CHECKS ===" -ForegroundColor Cyan

    # Check ML-SecTest images
    $images = docker images --filter "reference=ml-sectest" --format "{{.Repository}}:{{.Tag}}\t{{.Size}}" 2>&1

    if ($images -match "ml-sectest:latest") {
        Write-Status "ml-sectest:latest image exists" -Level Success
    } else {
        Write-Status "ml-sectest:latest image not found" -Level Error
    }

    if ($images -match "ml-sectest:1.0.0") {
        Write-Status "ml-sectest:1.0.0 image exists" -Level Success
    } else {
        Write-Status "ml-sectest:1.0.0 image not found" -Level Error
    }

    # Check image size
    if ($images -match "(\d+)MB") {
        $sizeInMB = [int]$matches[1]
        if ($sizeInMB -lt 600) {
            Write-Status "ml-sectest image size: $sizeInMB MB (reasonable)" -Level Success
        } else {
            Write-Status "ml-sectest image size: $sizeInMB MB (larger than expected 450MB)" -Level Warning
        }
    }

    # Check base images present
    $pythonImage = docker images --filter "reference=python:3.13-slim" --format "{{.Repository}}:{{.Tag}}" 2>&1
    if ($pythonImage) {
        Write-Status "Base image python:3.13-slim present" -Level Success
    } else {
        Write-Status "Base image python:3.13-slim not found" -Level Warning
    }

    $nginxImage = docker images --filter "reference=nginx:1.25-alpine" --format "{{.Repository}}:{{.Tag}}" 2>&1
    if ($nginxImage) {
        Write-Status "Base image nginx:1.25-alpine present" -Level Success
    } else {
        Write-Status "Base image nginx:1.25-alpine not found" -Level Warning
    }
}

function Test-MetricsEndpoint {
    Write-Host "`n=== METRICS ENDPOINT CHECKS ===" -ForegroundColor Cyan

    # Test metrics endpoint accessibility
    $metricsUrl = "http://localhost:8080/metrics"
    Write-Status "Testing metrics endpoint: $metricsUrl" -Level Info

    $metricsResponse = Invoke-SafeCurl -Url $metricsUrl

    if ($metricsResponse) {
        Write-Status "Metrics endpoint is accessible" -Level Success

        # Check for custom metrics
        $expectedMetrics = @(
            "mlsectest_executions_total",
            "mlsectest_duration_seconds",
            "mlsectest_vulnerabilities_found",
            "mlsectest_agent_health"
        )

        foreach ($metric in $expectedMetrics) {
            if ($metricsResponse -match $metric) {
                Write-Status "Metric $metric is present" -Level Success
            } else {
                Write-Status "Metric $metric is missing" -Level Error
            }
        }

        # Check agent health values
        $healthMetrics = $metricsResponse | Select-String -Pattern "mlsectest_agent_health\{agent=`"([^`"]+)`"\}\s+(\d+\.?\d*)"
        $healthyAgents = ($healthMetrics.Matches | Where-Object { $_.Groups[2].Value -eq "1" }).Count

        if ($healthyAgents -eq 6) {
            Write-Status "All 6 agents reporting healthy" -Level Success
        } elseif ($healthyAgents -gt 0) {
            Write-Status "Only $healthyAgents/6 agents reporting healthy" -Level Warning
        } else {
            Write-Status "No agents reporting healthy" -Level Error
        }
    } else {
        Write-Status "Metrics endpoint not accessible" -Level Error
        Write-Status "Possible causes: Container not running, port not exposed, exporter crashed" -Level Info
    }
}

function Test-PrometheusIntegration {
    Write-Host "`n=== PROMETHEUS INTEGRATION CHECKS ===" -ForegroundColor Cyan

    # Check Prometheus health
    $promHealthUrl = "http://localhost:9090/-/healthy"
    $promHealth = Invoke-SafeCurl -Url $promHealthUrl

    if ($promHealth -match "Prometheus is Healthy") {
        Write-Status "Prometheus is healthy" -Level Success
    } else {
        Write-Status "Prometheus health check failed" -Level Error
        return
    }

    # Check ML-SecTest target in Prometheus
    $targetsUrl = "http://localhost:9090/api/v1/targets"
    $targetsResponse = Invoke-SafeCurl -Url $targetsUrl

    if ($targetsResponse) {
        $targets = $targetsResponse | ConvertFrom-Json
        $mlsectestTarget = $targets.data.activeTargets | Where-Object { $_.labels.job -eq "ml-sectest" }

        if ($mlsectestTarget) {
            Write-Status "ML-SecTest target found in Prometheus" -Level Success

            if ($mlsectestTarget.health -eq "up") {
                Write-Status "ML-SecTest target health: UP" -Level Success
            } else {
                Write-Status "ML-SecTest target health: $($mlsectestTarget.health)" -Level Error
                Write-Status "Last error: $($mlsectestTarget.lastError)" -Level Info
            }

            $lastScrape = [DateTime]$mlsectestTarget.lastScrape
            $timeSinceLastScrape = (Get-Date) - $lastScrape

            if ($timeSinceLastScrape.TotalSeconds -lt 60) {
                Write-Status "Last scrape: $($timeSinceLastScrape.TotalSeconds) seconds ago (recent)" -Level Success
            } else {
                Write-Status "Last scrape: $($timeSinceLastScrape.TotalMinutes) minutes ago (stale)" -Level Warning
            }
        } else {
            Write-Status "ML-SecTest target not found in Prometheus" -Level Error
        }
    } else {
        Write-Status "Failed to query Prometheus targets" -Level Error
    }

    # Check if metrics are being collected
    $queryUrl = "http://localhost:9090/api/v1/query?query=mlsectest_executions_total"
    $queryResponse = Invoke-SafeCurl -Url $queryUrl

    if ($queryResponse) {
        $queryResult = $queryResponse | ConvertFrom-Json
        $resultCount = $queryResult.data.result.Count

        if ($resultCount -gt 0) {
            Write-Status "Prometheus has $resultCount time series for mlsectest_executions_total" -Level Success
        } else {
            Write-Status "No data found for mlsectest_executions_total (may need to run scans first)" -Level Warning
        }
    } else {
        Write-Status "Failed to query Prometheus metrics" -Level Error
    }

    # Check alert rules
    $rulesUrl = "http://localhost:9090/api/v1/rules"
    $rulesResponse = Invoke-SafeCurl -Url $rulesUrl

    if ($rulesResponse) {
        $rules = $rulesResponse | ConvertFrom-Json
        $mlsectestRules = $rules.data.groups | Where-Object { $_.name -eq "ml_sectest_alerts" }

        if ($mlsectestRules) {
            $ruleCount = $mlsectestRules.rules.Count
            Write-Status "Found $ruleCount ML-SecTest alert rules" -Level Success

            $firingAlerts = ($mlsectestRules.rules | Where-Object { $_.state -eq "firing" }).Count
            if ($firingAlerts -eq 0) {
                Write-Status "No alerts currently firing (good)" -Level Success
            } else {
                Write-Status "$firingAlerts alerts currently firing (investigate)" -Level Warning
            }
        } else {
            Write-Status "ML-SecTest alert rules not found" -Level Error
        }
    } else {
        Write-Status "Failed to query Prometheus rules" -Level Error
    }
}

function Test-GrafanaIntegration {
    Write-Host "`n=== GRAFANA INTEGRATION CHECKS ===" -ForegroundColor Cyan

    # Check Grafana health
    $grafanaHealthUrl = "http://localhost:3000/api/health"
    $grafanaHealth = Invoke-SafeCurl -Url $grafanaHealthUrl

    if ($grafanaHealth) {
        $health = $grafanaHealth | ConvertFrom-Json
        if ($health.database -eq "ok") {
            Write-Status "Grafana is healthy" -Level Success
        } else {
            Write-Status "Grafana database not healthy" -Level Error
        }
    } else {
        Write-Status "Grafana health check failed" -Level Error
        return
    }

    # Check ML-SecTest dashboard
    $dashboardSearchUrl = "http://localhost:3000/api/search?query=ML-SecTest"
    $dashboards = Invoke-SafeCurl -Url $dashboardSearchUrl

    if ($dashboards) {
        $dashboardList = $dashboards | ConvertFrom-Json

        if ($dashboardList.Count -gt 0) {
            Write-Status "Found $($dashboardList.Count) ML-SecTest dashboard(s)" -Level Success

            foreach ($dashboard in $dashboardList) {
                Write-Status "Dashboard: $($dashboard.title) (UID: $($dashboard.uid))" -Level Info
            }
        } else {
            Write-Status "No ML-SecTest dashboards found" -Level Error
        }
    } else {
        Write-Status "Failed to query Grafana dashboards" -Level Error
    }

    # Check Prometheus datasource
    $datasourcesUrl = "http://localhost:3000/api/datasources"
    $datasources = Invoke-SafeCurl -Url $datasourcesUrl

    if ($datasources) {
        $datasourceList = $datasources | ConvertFrom-Json
        $promDatasource = $datasourceList | Where-Object { $_.type -eq "prometheus" }

        if ($promDatasource) {
            Write-Status "Prometheus datasource configured in Grafana" -Level Success
        } else {
            Write-Status "Prometheus datasource not found in Grafana" -Level Error
        }
    } else {
        Write-Status "Failed to query Grafana datasources" -Level Warning
    }
}

function Test-AlertManager {
    Write-Host "`n=== ALERTMANAGER CHECKS ===" -ForegroundColor Cyan

    # Check AlertManager health
    $amHealthUrl = "http://localhost:9093/-/healthy"
    $amHealth = Invoke-SafeCurl -Url $amHealthUrl

    if ($amHealth -match "OK") {
        Write-Status "AlertManager is healthy" -Level Success
    } else {
        Write-Status "AlertManager health check failed" -Level Error
        return
    }

    # Check for recent alerts
    $alertsUrl = "http://localhost:9093/api/v2/alerts"
    $alerts = Invoke-SafeCurl -Url $alertsUrl

    if ($alerts) {
        $alertList = $alerts | ConvertFrom-Json
        $activeAlerts = ($alertList | Where-Object { $_.status.state -eq "active" }).Count

        if ($activeAlerts -eq 0) {
            Write-Status "No active alerts in AlertManager (good)" -Level Success
        } else {
            Write-Status "$activeAlerts active alerts in AlertManager (review)" -Level Warning
        }
    } else {
        Write-Status "Failed to query AlertManager" -Level Error
    }
}

function Test-MLSecTestFunctionality {
    Write-Host "`n=== ML-SECTEST FUNCTIONALITY CHECKS ===" -ForegroundColor Cyan

    # Check if docker-compose.yml exists
    $composeFile = "C:\Users\Corbin\development\ml-sectest-framework\docker-compose.yml"
    if (Test-Path $composeFile) {
        Write-Status "docker-compose.yml found" -Level Success
    } else {
        Write-Status "docker-compose.yml not found at $composeFile" -Level Error
        return
    }

    # Test list-challenges command
    Write-Status "Testing 'list-challenges' command..." -Level Info
    $listOutput = docker-compose -f $composeFile run --rm ml-sectest list-challenges 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Status "'list-challenges' command succeeded" -Level Success

        # Count agents
        $agentCount = ($listOutput | Select-String -Pattern "Agent").Count
        if ($agentCount -ge 6) {
            Write-Status "Found $agentCount agents listed" -Level Success
        } else {
            Write-Status "Only $agentCount agents listed (expected 6)" -Level Warning
        }
    } else {
        Write-Status "'list-challenges' command failed" -Level Error
    }

    # Check reports directory
    $reportsDir = "C:\Users\Corbin\development\ml-sectest-framework\reports"
    if (Test-Path $reportsDir) {
        $reportFiles = Get-ChildItem -Path $reportsDir -Filter "*.json" -ErrorAction SilentlyContinue
        $reportCount = $reportFiles.Count

        if ($reportCount -gt 0) {
            Write-Status "Found $reportCount report file(s) in reports/" -Level Success
            $latestReport = $reportFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            Write-Status "Latest report: $($latestReport.Name) ($(Get-Date $latestReport.LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss'))" -Level Info
        } else {
            Write-Status "No report files found (may need to run scans)" -Level Warning
        }
    } else {
        Write-Status "Reports directory not found" -Level Warning
    }

    # Check logs directory
    $logsDir = "C:\Users\Corbin\development\ml-sectest-framework\logs"
    if (Test-Path $logsDir) {
        $logFiles = Get-ChildItem -Path $logsDir -Filter "*.log" -ErrorAction SilentlyContinue
        $logCount = $logFiles.Count

        if ($logCount -gt 0) {
            Write-Status "Found $logCount log file(s) in logs/" -Level Success
        } else {
            Write-Status "No log files found" -Level Warning
        }
    } else {
        Write-Status "Logs directory not found" -Level Warning
    }
}

function Test-Screenshots {
    Write-Host "`n=== SCREENSHOT VERIFICATION ===" -ForegroundColor Cyan

    $screenshotDir = "C:\Users\Corbin\deployment\screenshots"

    if (!(Test-Path $screenshotDir)) {
        Write-Status "Screenshot directory not found: $screenshotDir" -Level Error
        return
    }

    # Expected screenshots (21 required + 4 phase summaries)
    $requiredScreenshots = @(
        "00_docker_desktop_baseline.png",
        "00_docker_ps_baseline.png",
        "00_docker_networks_baseline.png",
        "00_docker_images_baseline.png",
        "00_grafana_dashboards_baseline.png",
        "00_prometheus_targets_baseline.png",
        "00_mlsectest_directory_baseline.png",
        "00_git_status_baseline.png",
        "01_1_health_check.png",
        "01_2_network_created.png",
        "01_3_base_images_pulled.png",
        "01_4_resources.png",
        "01_phase_complete.png",
        "02_1_code_validation.png",
        "02_2_image_build.png",
        "02_3_containers_deployed.png",
        "02_4_functionality_tests.png",
        "02_5_security_validation.png",
        "02_phase_complete.png",
        "03_1_monitoring_baseline.png",
        "03_2_metrics_exporter.png",
        "03_3_prometheus_updated.png",
        "03_4_grafana_dashboard.png",
        "03_5_alert_rules.png",
        "03_phase_complete.png",
        "04_1_e2e_scan.png",
        "04_2_alert_testing.png",
        "04_3_documentation.png",
        "04_4_git_commit.png",
        "04_phase_complete.png"
    )

    $foundScreenshots = Get-ChildItem -Path $screenshotDir -Filter "*.png" -ErrorAction SilentlyContinue
    $foundCount = $foundScreenshots.Count
    $requiredCount = $requiredScreenshots.Count

    Write-Status "Found $foundCount screenshot(s) (required: $requiredCount)" -Level Info

    $missingScreenshots = @()
    foreach ($required in $requiredScreenshots) {
        $found = $foundScreenshots | Where-Object { $_.Name -eq $required }
        if ($found) {
            # Check file size (should not be empty, not too large)
            $sizeInMB = [math]::Round($found.Length / 1MB, 2)
            if ($sizeInMB -gt 0 -and $sizeInMB -lt 20) {
                # Size OK, not logging individual success to reduce noise
            } else {
                Write-Status "Screenshot $required has unusual size: $sizeInMB MB" -Level Warning
            }
        } else {
            $missingScreenshots += $required
        }
    }

    if ($missingScreenshots.Count -eq 0) {
        Write-Status "All $requiredCount required screenshots present" -Level Success
    } else {
        Write-Status "Missing $($missingScreenshots.Count) screenshot(s):" -Level Error
        foreach ($missing in $missingScreenshots) {
            Write-Status "  - $missing" -Level Info
        }
    }

    # Calculate total screenshot size
    $totalSizeInMB = [math]::Round(($foundScreenshots | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
    Write-Status "Total screenshot size: $totalSizeInMB MB" -Level Info
}

function Test-Documentation {
    Write-Host "`n=== DOCUMENTATION CHECKS ===" -ForegroundColor Cyan

    $requiredDocs = @{
        "SYSTEMATIC_DEPLOYMENT_PLAN.md" = "C:\Users\Corbin\SYSTEMATIC_DEPLOYMENT_PLAN.md"
        "DEPLOYMENT_CHECKLIST.md" = "C:\Users\Corbin\DEPLOYMENT_CHECKLIST.md"
        "VISUAL_VERIFICATION_GUIDE.md" = "C:\Users\Corbin\VISUAL_VERIFICATION_GUIDE.md"
        "DEPLOYMENT_RUNBOOK.md" = "C:\Users\Corbin\DEPLOYMENT_RUNBOOK.md"
        "deployment_verify.ps1" = "C:\Users\Corbin\deployment_verify.ps1"
    }

    foreach ($doc in $requiredDocs.GetEnumerator()) {
        if (Test-Path $doc.Value) {
            $fileInfo = Get-Item $doc.Value
            $sizeInKB = [math]::Round($fileInfo.Length / 1KB, 2)
            Write-Status "$($doc.Key) exists ($sizeInKB KB)" -Level Success
        } else {
            Write-Status "$($doc.Key) not found at $($doc.Value)" -Level Error
        }
    }

    # Check deployment logs directory
    $logsDir = "C:\Users\Corbin\deployment\logs"
    if (Test-Path $logsDir) {
        $logFiles = Get-ChildItem -Path $logsDir -Filter "deployment_*.log" -ErrorAction SilentlyContinue
        if ($logFiles.Count -gt 0) {
            Write-Status "Found $($logFiles.Count) deployment log file(s)" -Level Success
        } else {
            Write-Status "No deployment log files found" -Level Warning
        }
    } else {
        Write-Status "Deployment logs directory not found" -Level Warning
    }
}

function Test-GitStatus {
    Write-Host "`n=== GIT STATUS CHECKS ===" -ForegroundColor Cyan

    # Check Git repository
    $gitDir = "C:\Users\Corbin\.git"
    if (Test-Path $gitDir) {
        Write-Status "Git repository found" -Level Success
    } else {
        Write-Status "Git repository not found" -Level Error
        return
    }

    # Check current branch
    $branch = git branch --show-current 2>&1
    if ($branch -eq "feat/todo-deployment-phase-1") {
        Write-Status "On correct branch: $branch" -Level Success
    } else {
        Write-Status "On branch: $branch (expected: feat/todo-deployment-phase-1)" -Level Warning
    }

    # Check for ML-SecTest tag
    $tags = git tag -l "*ml-sectest*" 2>&1
    if ($tags -match "v1.0.0-ml-sectest") {
        Write-Status "Deployment tag v1.0.0-ml-sectest exists" -Level Success
    } else {
        Write-Status "Deployment tag v1.0.0-ml-sectest not found" -Level Warning
    }

    # Check recent commits
    $recentCommits = git log --oneline -5 2>&1
    $deploymentCommit = $recentCommits | Select-String -Pattern "ML-SecTest", "ml-sectest", "deployment"
    if ($deploymentCommit) {
        Write-Status "Found deployment-related commit in recent history" -Level Success
    } else {
        Write-Status "No deployment-related commit found in recent history" -Level Warning
    }
}

function New-VerificationReport {
    Write-Host "`n=== GENERATING VERIFICATION REPORT ===" -ForegroundColor Cyan

    $reportPath = "C:\Users\Corbin\deployment\VERIFICATION_REPORT_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').md"

    $reportContent = @"
# ML-SECTEST DEPLOYMENT VERIFICATION REPORT

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Script Version:** 1.0.0
**Operator:** $env:USERNAME

---

## EXECUTIVE SUMMARY

| Metric | Value |
|--------|-------|
| **Total Checks** | $($script:Checks.Count) |
| **Passed** | $script:Passed |
| **Failed** | $script:Failed |
| **Warnings** | $script:Warnings |
| **Success Rate** | $([math]::Round(($script:Passed / $script:Checks.Count) * 100, 2))% |

### Overall Status
$(if ($script:Failed -eq 0) {
"✅ **DEPLOYMENT VERIFIED** - All critical checks passed"
} elseif ($script:Failed -lt 5) {
"⚠️ **DEPLOYMENT PARTIAL** - Some checks failed, review required"
} else {
"❌ **DEPLOYMENT FAILED** - Critical issues found, remediation required"
})

---

## DETAILED RESULTS

$(
foreach ($check in $script:Checks) {
    $icon = switch ($check.Level) {
        "Success" { "✅" }
        "Warning" { "⚠️" }
        "Error"   { "❌" }
        "Info"    { "ℹ️" }
    }
    "- $icon [$($check.Level)] $($check.Message)"
}
)

---

## RECOMMENDATIONS

$(if ($script:Failed -gt 0) {
"### Critical Issues
The following issues require immediate attention:
$(
    $script:Checks | Where-Object { $_.Level -eq "Error" } | ForEach-Object {
        "- $($_.Message)"
    }
)
"
} else {
"No critical issues found."
})

$(if ($script:Warnings -gt 0) {
"### Warnings
The following warnings should be reviewed:
$(
    $script:Checks | Where-Object { $_.Level -eq "Warning" } | ForEach-Object {
        "- $($_.Message)"
    }
)
"
} else {
"No warnings."
})

---

## NEXT STEPS

1. Review any failed checks and remediate issues
2. Re-run verification after remediation
3. Update deployment documentation with any deviations
4. Schedule post-deployment monitoring review
5. Brief team on deployment status

---

## VERIFICATION CHECKLIST

- [$(if ($script:Checks | Where-Object { $_.Message -match "Docker.*running" -and $_.Level -eq "Success" }) {"x"} else {" "})] Docker containers running and healthy
- [$(if ($script:Checks | Where-Object { $_.Message -match "Metrics endpoint.*accessible" -and $_.Level -eq "Success" }) {"x"} else {" "})] Metrics endpoint accessible
- [$(if ($script:Checks | Where-Object { $_.Message -match "ML-SecTest target.*UP" -and $_.Level -eq "Success" }) {"x"} else {" "})] Prometheus scraping ML-SecTest
- [$(if ($script:Checks | Where-Object { $_.Message -match "ML-SecTest dashboard" -and $_.Level -eq "Success" }) {"x"} else {" "})] Grafana dashboard created
- [$(if ($script:Checks | Where-Object { $_.Message -match "alert rules" -and $_.Level -eq "Success" }) {"x"} else {" "})] Alert rules configured
- [$(if ($script:Checks | Where-Object { $_.Message -match "All.*agents.*healthy" -and $_.Level -eq "Success" }) {"x"} else {" "})] All 6 agents healthy
- [$(if ($script:Checks | Where-Object { $_.Message -match "All.*screenshots.*present" -and $_.Level -eq "Success" }) {"x"} else {" "})] All screenshots captured
- [$(if ($script:Checks | Where-Object { $_.Message -match "deployment tag" -and $_.Level -eq "Success" }) {"x"} else {" "})] Git commit and tag created

---

**End of Report**
"@

    $reportContent | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Status "Verification report saved to: $reportPath" -Level Success

    return $reportPath
}

# Main execution
function Main {
    $startTime = Get-Date

    Write-Host "`nStarting verification at $startTime`n" -ForegroundColor Cyan

    # Always run prerequisites
    Test-Prerequisites

    # Run specified checks
    if ($CheckAll -or $CheckContainers) {
        Test-DockerContainers
        Test-DockerNetworks
        Test-DockerImages
        Test-MLSecTestFunctionality
    }

    if ($CheckAll -or $CheckMetrics) {
        Test-MetricsEndpoint
    }

    if ($CheckAll -or $CheckMonitoring) {
        Test-PrometheusIntegration
        Test-GrafanaIntegration
        Test-AlertManager
    }

    if ($CheckAll -or $CheckScreenshots) {
        Test-Screenshots
    }

    if ($CheckAll) {
        Test-Documentation
        Test-GitStatus
    }

    # Summary
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "VERIFICATION SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan

    Write-Host "`nTotal Checks:  $($script:Checks.Count)" -ForegroundColor White
    Write-Host "Passed:        $script:Passed" -ForegroundColor Green
    Write-Host "Failed:        $script:Failed" -ForegroundColor Red
    Write-Host "Warnings:      $script:Warnings" -ForegroundColor Yellow

    $successRate = if ($script:Checks.Count -gt 0) {
        [math]::Round(($script:Passed / $script:Checks.Count) * 100, 2)
    } else { 0 }
    Write-Host "Success Rate:  $successRate%" -ForegroundColor White

    # Overall status
    Write-Host "`nOverall Status: " -NoNewline
    if ($script:Failed -eq 0) {
        Write-Host "✅ DEPLOYMENT VERIFIED" -ForegroundColor Green
    } elseif ($script:Failed -lt 5) {
        Write-Host "⚠️ DEPLOYMENT PARTIAL" -ForegroundColor Yellow
    } else {
        Write-Host "❌ DEPLOYMENT FAILED" -ForegroundColor Red
    }

    # Generate report if requested
    if ($GenerateReport -or $CheckAll) {
        $reportPath = New-VerificationReport
        Write-Host "`nDetailed report: $reportPath" -ForegroundColor Cyan
    }

    $endTime = Get-Date
    $duration = $endTime - $startTime
    Write-Host "`nVerification completed in $($duration.TotalSeconds) seconds`n" -ForegroundColor Cyan

    # Exit with appropriate code
    if ($script:Failed -gt 0) {
        exit 1
    } else {
        exit 0
    }
}

# Run main if no specific checks requested (default to CheckAll)
if (-not ($CheckContainers -or $CheckMetrics -or $CheckMonitoring -or $CheckScreenshots)) {
    $CheckAll = $true
}

Main
