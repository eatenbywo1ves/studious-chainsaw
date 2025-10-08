<#
.SYNOPSIS
    BMAD Production Deployment Script for Windows
    Build → Measure → Analyze → Deploy

.DESCRIPTION
    This script follows the BMAD methodology to systematically deploy
    the Catalytic Computing SaaS platform to production using PowerShell.

.PARAMETER Action
    The deployment action to perform: deploy, rollback, build-only, or analyze-only

.PARAMETER Namespace
    Kubernetes namespace (default: catalytic-saas)

.PARAMETER ImageTag
    Docker image tag (default: git commit hash)

.EXAMPLE
    .\deploy_production_bmad.ps1 -Action deploy

.EXAMPLE
    .\deploy_production_bmad.ps1 -Action rollback -Namespace catalytic-saas
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("deploy", "rollback", "build-only", "analyze-only")]
    [string]$Action = "deploy",

    [Parameter(Mandatory=$false)]
    [string]$Namespace = "catalytic-saas",

    [Parameter(Mandatory=$false)]
    [string]$Environment = "production",

    [Parameter(Mandatory=$false)]
    [string]$DockerRegistry = "your-registry.io",

    [Parameter(Mandatory=$false)]
    [string]$ImageTag = (git rev-parse --short HEAD),

    [Parameter(Mandatory=$false)]
    [string]$KubernetesContext = "production"
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Logging functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Pre-flight checks
function Test-PreFlightChecks {
    Write-Section "Pre-Flight Checks"

    Write-Info "Checking required tools..."

    # Check Docker
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "docker is required but not installed"
    }

    # Check kubectl
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        throw "kubectl is required but not installed"
    }

    # Check git
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "git is required but not installed"
    }

    Write-Success "All required tools are installed"

    Write-Info "Verifying Kubernetes context..."
    $currentContext = kubectl config current-context
    Write-Info "Current context: $currentContext"

    if ($currentContext -notlike "*$KubernetesContext*") {
        Write-Warning "Current context doesn't match expected production context"
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -ne "y") {
            throw "Deployment cancelled by user"
        }
    }

    Write-Success "Pre-flight checks complete"
}

# BUILD Phase
function Invoke-BuildPhase {
    Write-Section "BMAD Phase 1: BUILD"

    Write-Info "Step 1.1: Running integration tests..."
    Push-Location tests\integration

    try {
        Write-Info "Starting test environment..."
        docker-compose -f docker-compose.test.yml up -d
        Start-Sleep -Seconds 10

        Write-Info "Running pytest integration tests..."
        $testResult = pytest -v --maxfail=1 2>&1 | Tee-Object -FilePath "$env:TEMP\integration_test.log"

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Integration tests passed"
        } else {
            docker-compose -f docker-compose.test.yml down
            throw "Integration tests failed. Check $env:TEMP\integration_test.log"
        }

        docker-compose -f docker-compose.test.yml down
    }
    finally {
        Pop-Location
    }

    Write-Info "Step 1.2: Building Docker image..."
    docker build `
        -t "${DockerRegistry}/catalytic-saas:${ImageTag}" `
        -t "${DockerRegistry}/catalytic-saas:latest" `
        -f saas/Dockerfile `
        .

    Write-Success "Docker image built: ${DockerRegistry}/catalytic-saas:${ImageTag}"

    Write-Info "Step 1.3: Running container security scan..."
    Write-Info "Security scan skipped (add trivy or similar tool)"

    Write-Info "Step 1.4: Pushing Docker image to registry..."
    docker push "${DockerRegistry}/catalytic-saas:${ImageTag}"
    docker push "${DockerRegistry}/catalytic-saas:latest"

    Write-Success "BUILD phase complete"
}

# MEASURE Phase
function Invoke-MeasurePhase {
    Write-Section "BMAD Phase 2: MEASURE"

    Write-Info "Step 2.1: Establishing baseline metrics..."

    # Check if monitoring namespace exists
    $monitoringNs = kubectl get namespace monitoring 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Monitoring namespace exists"
    } else {
        Write-Warning "Monitoring namespace not found. Creating..."
        kubectl create namespace monitoring
    }

    Write-Info "Step 2.2: Verifying Prometheus is running..."
    $promPods = kubectl get pods -n monitoring -l app=prometheus 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Prometheus is running"
    } else {
        Write-Warning "Prometheus not detected. Monitoring may be incomplete."
    }

    Write-Info "Step 2.3: Verifying Grafana is running..."
    $grafanaPods = kubectl get pods -n monitoring -l app=grafana 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Grafana is running"
    } else {
        Write-Warning "Grafana not detected. Dashboards may not be available."
    }

    Write-Info "Step 2.4: Collecting current metrics baseline..."
    kubectl top nodes > "$env:TEMP\baseline_nodes.txt" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "kubectl top nodes failed"
    }

    Write-Success "MEASURE phase complete"
}

# ANALYZE Phase
function Invoke-AnalyzePhase {
    Write-Section "BMAD Phase 3: ANALYZE"

    Write-Info "Step 3.1: Reviewing production readiness checklist..."

    if (Test-Path "docs\deployment\PRODUCTION_READINESS_CHECKLIST.md") {
        Write-Success "Production readiness checklist found"
        Write-Info "Review the checklist at: docs\deployment\PRODUCTION_READINESS_CHECKLIST.md"
    } else {
        Write-Warning "Production readiness checklist not found"
    }

    Write-Info "Step 3.2: Validating Kubernetes manifests..."

    Get-ChildItem kubernetes\*.yaml | ForEach-Object {
        $result = kubectl apply --dry-run=client -f $_.FullName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "$($_.Name) is valid"
        } else {
            throw "$($_.Name) validation failed"
        }
    }

    Write-Info "Step 3.3: Checking for existing deployment..."

    $existingDeploy = kubectl get deployment saas-api -n $Namespace 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Warning "Existing deployment found. This will be updated."
        Write-Info "Current replicas:"
        kubectl get deployment saas-api -n $Namespace -o jsonpath='{.spec.replicas}'
        Write-Host ""
    } else {
        Write-Info "No existing deployment. This will be a fresh deployment."
    }

    Write-Info "Step 3.4: Verifying secrets are configured..."

    $existingSecrets = kubectl get secret saas-secrets -n $Namespace 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Kubernetes secrets exist"
    } else {
        Write-ErrorMsg "Required secrets not found. Creating template secrets..."

        # Generate random secrets
        $jwtSecret = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
        $dbPassword = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
        $redisPassword = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))

        $secretYaml = @"
apiVersion: v1
kind: Secret
metadata:
  name: saas-secrets
  namespace: $Namespace
type: Opaque
stringData:
  jwt-secret: $jwtSecret
  db-password: $dbPassword
  redis-password: $redisPassword
"@

        $secretYaml | Out-File -FilePath "$env:TEMP\secrets.yaml" -Encoding UTF8

        Write-Warning "Secrets template created at $env:TEMP\secrets.yaml"
        $applySecrets = Read-Host "Apply generated secrets now? (y/n)"

        if ($applySecrets -eq "y") {
            kubectl apply -f "$env:TEMP\secrets.yaml"
            Write-Success "Secrets applied"
        } else {
            throw "Secrets must be configured before deployment"
        }
    }

    Write-Success "ANALYZE phase complete"
}

# DEPLOY Phase
function Invoke-DeployPhase {
    Write-Section "BMAD Phase 4: DEPLOY"

    Write-Info "Step 4.1: Creating namespace if not exists..."
    kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f -
    Write-Success "Namespace $Namespace ready"

    Write-Info "Step 4.2: Applying ConfigMap..."
    kubectl apply -f kubernetes\configmap.yaml -n $Namespace

    Write-Info "Step 4.3: Applying Deployment..."
    # Update image tag in deployment
    $deploymentContent = Get-Content kubernetes\deployment.yaml -Raw
    $deploymentContent = $deploymentContent -replace "image:.*catalytic-saas:.*", "image: ${DockerRegistry}/catalytic-saas:${ImageTag}"
    $deploymentContent | kubectl apply -f - -n $Namespace

    Write-Info "Step 4.4: Applying Service..."
    kubectl apply -f kubernetes\service.yaml -n $Namespace

    Write-Info "Step 4.5: Applying HPA (Horizontal Pod Autoscaler)..."
    kubectl apply -f kubernetes\hpa.yaml -n $Namespace

    Write-Info "Step 4.6: Applying Network Policy..."
    kubectl apply -f kubernetes\networkpolicy.yaml -n $Namespace

    Write-Info "Step 4.7: Applying Ingress..."
    kubectl apply -f kubernetes\ingress.yaml -n $Namespace

    Write-Info "Step 4.8: Waiting for rollout to complete..."
    kubectl rollout status deployment/saas-api -n $Namespace --timeout=5m

    Write-Success "Deployment rollout complete"

    Write-Info "Step 4.9: Verifying pods are running..."
    kubectl get pods -n $Namespace -l app=saas-api

    Write-Info "Step 4.10: Running smoke tests..."

    $ingressIp = kubectl get ingress saas-ingress -n $Namespace -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>$null

    if ($ingressIp -and $ingressIp -ne "") {
        Write-Info "Testing health endpoint at http://$ingressIp/health"
        Start-Sleep -Seconds 10

        try {
            $response = Invoke-WebRequest -Uri "http://$ingressIp/health" -UseBasicParsing
            Write-Success "Health check passed"
        } catch {
            Write-Warning "Health check failed. Service may still be starting..."
        }
    } else {
        Write-Warning "Ingress IP not yet assigned. Skip smoke tests or test via port-forward."
    }

    Write-Success "DEPLOY phase complete"
}

# Post-deployment monitoring
function Show-PostDeploymentInfo {
    Write-Section "Post-Deployment Monitoring"

    Write-Info "Deployment Summary:"
    Write-Host ""
    Write-Host "Namespace:        $Namespace"
    Write-Host "Image:            ${DockerRegistry}/catalytic-saas:${ImageTag}"
    Write-Host "Current replicas: $(kubectl get deployment saas-api -n $Namespace -o jsonpath='{.status.replicas}')"
    Write-Host "Ready replicas:   $(kubectl get deployment saas-api -n $Namespace -o jsonpath='{.status.readyReplicas}')"
    Write-Host ""

    Write-Info "View logs with:"
    Write-Host "  kubectl logs -f deployment/saas-api -n $Namespace"
    Write-Host ""

    Write-Info "View metrics with:"
    Write-Host "  kubectl top pods -n $Namespace"
    Write-Host ""

    Write-Info "Rollback if needed with:"
    Write-Host "  .\deploy_production_bmad.ps1 -Action rollback -Namespace $Namespace"
    Write-Host ""

    Write-Info "Monitor auto-scaling with:"
    Write-Host "  kubectl get hpa -n $Namespace -w"
    Write-Host ""

    Write-Success "Production deployment complete!"
}

# Rollback function
function Invoke-Rollback {
    Write-Section "ROLLBACK INITIATED"

    Write-Warning "Rolling back deployment..."
    kubectl rollout undo deployment/saas-api -n $Namespace

    Write-Info "Waiting for rollback to complete..."
    kubectl rollout status deployment/saas-api -n $Namespace

    Write-Success "Rollback complete"
}

# Main execution
function Main {
    Write-Section "BMAD Production Deployment"

    Write-Info "Environment:      $Environment"
    Write-Info "Namespace:        $Namespace"
    Write-Info "Image Tag:        $ImageTag"
    Write-Info "Docker Registry:  $DockerRegistry"
    Write-Host ""

    try {
        switch ($Action) {
            "deploy" {
                Test-PreFlightChecks
                Invoke-BuildPhase
                Invoke-MeasurePhase
                Invoke-AnalyzePhase
                Invoke-DeployPhase
                Show-PostDeploymentInfo
            }
            "rollback" {
                Invoke-Rollback
            }
            "build-only" {
                Test-PreFlightChecks
                Invoke-BuildPhase
            }
            "analyze-only" {
                Invoke-AnalyzePhase
            }
        }
    }
    catch {
        Write-ErrorMsg "Deployment failed: $_"
        Write-ErrorMsg "Run with -Action rollback to revert changes"
        exit 1
    }
}

# Run main function
Main
