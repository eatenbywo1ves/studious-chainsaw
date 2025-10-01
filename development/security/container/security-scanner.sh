#!/bin/bash
# Container Security Scanner Script
# Performs comprehensive security scanning of Docker images

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPORTS_DIR="$PROJECT_DIR/security/reports"
DATE=$(date +%Y%m%d-%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Create reports directory
mkdir -p "$REPORTS_DIR"

# Function to scan image with Trivy
scan_image() {
    local image_name="$1"
    local report_name="$2"
    local report_file="$REPORTS_DIR/${report_name}-${DATE}.json"
    local summary_file="$REPORTS_DIR/${report_name}-${DATE}-summary.txt"
    
    log "Scanning $image_name..."
    
    # Run Trivy scan
    if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$REPORTS_DIR:/reports" \
        aquasec/trivy:latest image \
        --format json \
        --output "/reports/$(basename "$report_file")" \
        "$image_name"; then
        
        # Generate human-readable summary
        docker run --rm -v "$REPORTS_DIR:/reports" \
            aquasec/trivy:latest image \
            --format table \
            --output "/reports/$(basename "$summary_file")" \
            "$image_name"
        
        # Count vulnerabilities
        local critical=$(jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID' "$report_file" 2>/dev/null | wc -l || echo "0")
        local high=$(jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | .VulnerabilityID' "$report_file" 2>/dev/null | wc -l || echo "0")
        local medium=$(jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM") | .VulnerabilityID' "$report_file" 2>/dev/null | wc -l || echo "0")
        
        if [[ $critical -gt 0 ]]; then
            error "$image_name has $critical CRITICAL vulnerabilities"
            return 1
        elif [[ $high -gt 0 ]]; then
            warning "$image_name has $high HIGH vulnerabilities"
        else
            success "$image_name scan completed - $medium medium vulnerabilities found"
        fi
        
        log "Report saved to: $report_file"
        log "Summary saved to: $summary_file"
        
    else
        error "Failed to scan $image_name"
        return 1
    fi
}

# Function to scan for secrets
scan_secrets() {
    local image_name="$1"
    local report_name="$2"
    local report_file="$REPORTS_DIR/secrets-${report_name}-${DATE}.json"
    
    log "Scanning $image_name for secrets..."
    
    # Run gitleaks scan on image
    if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        zricethezav/gitleaks:latest detect \
        --source "docker://$image_name" \
        --report-format json \
        --report-path "/tmp/secrets-report.json" 2>/dev/null || true; then
        
        # Copy report if it exists
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$REPORTS_DIR:/reports" \
            zricethezav/gitleaks:latest cat /tmp/secrets-report.json > "$report_file" 2>/dev/null || echo "[]" > "$report_file"
        
        local secrets_count=$(jq length "$report_file" 2>/dev/null || echo "0")
        
        if [[ $secrets_count -gt 0 ]]; then
            error "$image_name contains $secrets_count potential secrets"
            return 1
        else
            success "$image_name secrets scan completed - no secrets found"
        fi
        
        log "Secrets report saved to: $report_file"
    else
        warning "Secrets scanning failed for $image_name"
    fi
}

# Function to check image configuration
check_image_config() {
    local image_name="$1"
    local report_name="$2"
    
    log "Checking $image_name configuration..."
    
    # Check if image runs as root
    local user=$(docker inspect "$image_name" --format '{{.Config.User}}' 2>/dev/null || echo "")
    if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
        error "$image_name runs as root user"
        return 1
    else
        success "$image_name runs as non-root user: $user"
    fi
    
    # Check for privileged mode requirements
    local privileged=$(docker inspect "$image_name" --format '{{.HostConfig.Privileged}}' 2>/dev/null || echo "false")
    if [[ "$privileged" == "true" ]]; then
        error "$image_name requires privileged mode"
        return 1
    else
        success "$image_name does not require privileged mode"
    fi
}

# Main scanning function
main() {
    log "Starting comprehensive security scan..."
    
    local exit_code=0
    
    # List of images to scan
    local images=(
        "catalytic-computing:latest:catalytic-api"
        "catalytic-saas:latest:saas-api"
        "postgres:15-alpine:postgres"
        "redis:7-alpine:redis"
        "prom/prometheus:latest:prometheus"
        "grafana/grafana:latest:grafana"
    )
    
    # Build images first
    log "Building application images..."
    cd "$PROJECT_DIR"
    
    if docker compose build catalytic-api; then
        success "catalytic-api image built successfully"
    else
        error "Failed to build catalytic-api image"
        exit_code=1
    fi
    
    if docker compose build saas-api; then
        success "saas-api image built successfully"
    else
        error "Failed to build saas-api image"
        exit_code=1
    fi
    
    # Scan each image
    for image_info in "${images[@]}"; do
        IFS=':' read -r image_name image_tag report_name <<< "$image_info"
        local full_image_name="${image_name}:${image_tag}"
        
        log "Processing $full_image_name..."
        
        # Skip if image doesn't exist
        if ! docker image inspect "$full_image_name" >/dev/null 2>&1; then
            warning "$full_image_name not found, skipping..."
            continue
        fi
        
        # Run all scans
        if ! scan_image "$full_image_name" "$report_name"; then
            exit_code=1
        fi
        
        if ! scan_secrets "$full_image_name" "$report_name"; then
            exit_code=1
        fi
        
        if ! check_image_config "$full_image_name" "$report_name"; then
            exit_code=1
        fi
        
        echo "---"
    done
    
    # Generate consolidated report
    log "Generating consolidated security report..."
    local consolidated_report="$REPORTS_DIR/security-scan-consolidated-${DATE}.json"
    
    {
        echo "{"
        echo "  \"scan_date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "  \"scanned_images\": ["
        
        local first=true
        for image_info in "${images[@]}"; do
            IFS=':' read -r image_name image_tag report_name <<< "$image_info"
            local full_image_name="${image_name}:${image_tag}"
            
            if docker image inspect "$full_image_name" >/dev/null 2>&1; then
                if [[ $first == true ]]; then
                    first=false
                else
                    echo ","
                fi
                echo "    {"
                echo "      \"image\": \"$full_image_name\","
                echo "      \"report_name\": \"$report_name\","
                echo "      \"vulnerability_report\": \"${report_name}-${DATE}.json\","
                echo "      \"secrets_report\": \"secrets-${report_name}-${DATE}.json\""
                echo -n "    }"
            fi
        done
        
        echo ""
        echo "  ],"
        echo "  \"summary\": {"
        echo "    \"total_images_scanned\": $(find "$REPORTS_DIR" -name "*-${DATE}.json" -not -name "secrets-*" -not -name "security-scan-*" | wc -l),"
        echo "    \"critical_vulnerabilities\": $(find "$REPORTS_DIR" -name "*-${DATE}.json" -not -name "secrets-*" -not -name "security-scan-*" -exec jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID' {} \; 2>/dev/null | wc -l),"
        echo "    \"secrets_found\": $(find "$REPORTS_DIR" -name "secrets-*-${DATE}.json" -exec jq length {} \; 2>/dev/null | paste -sd+ - | bc)"
        echo "  }"
        echo "}"
    } > "$consolidated_report"
    
    log "Consolidated report saved to: $consolidated_report"
    
    # Final status
    if [[ $exit_code -eq 0 ]]; then
        success "Security scan completed successfully!"
    else
        error "Security scan completed with issues. Please review the reports."
    fi
    
    return $exit_code
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi
    
    if ! command -v bc &> /dev/null; then
        missing_deps+=("bc")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing_deps[*]}"
        error "Please install missing dependencies and try again"
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_dependencies
    main "$@"
fi