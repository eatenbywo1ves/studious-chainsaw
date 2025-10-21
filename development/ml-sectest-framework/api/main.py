"""
ML-SecTest Framework REST API
==============================
FastAPI-based REST API for the ML Security Testing Framework.
Provides endpoints for scanning targets, testing challenges, and retrieving results.

Author: ML-SecTest Team
Version: 1.0.0
License: MIT
"""

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, HttpUrl, Field, validator
from typing import List, Optional, Dict, Any, Literal
from datetime import datetime
from pathlib import Path
import uuid
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import SecurityOrchestrator
from utils import ReportGenerator

# Prometheus metrics
try:
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ============================================================================
# Application Configuration
# ============================================================================

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="ML-SecTest API",
    version="1.0.0",
    description="""
    **Automated ML Security Testing Framework API**

    This API provides programmatic access to the ML-SecTest multi-agent security
    testing framework. It enables automated vulnerability scanning of machine
    learning systems and AI applications.

    ## Features

    * 🔍 **Automated Security Scanning**: Test ML systems for vulnerabilities
    * 🤖 **Multi-Agent Architecture**: 6 specialized security testing agents
    * 🎯 **CTF Challenge Testing**: Test specific security challenges
    * 📊 **Comprehensive Reports**: HTML and JSON output formats
    * ⚡ **Async Execution**: Non-blocking background task processing
    * 🛡️ **Rate Limiting**: Prevents API abuse (10 scans/minute per IP)

    ## Agents

    1. **Prompt Injection Agent** - Tests for LLM prompt injection (OWASP LLM01)
    2. **Model Inversion Agent** - Tests for data extraction (OWASP ML03)
    3. **Data Poisoning Agent** - Tests for training data poisoning (OWASP ML02)
    4. **Model Extraction Agent** - Tests for model theft (OWASP LLM10)
    5. **Model Serialization Agent** - Tests for unsafe deserialization (OWASP ML06)
    6. **Adversarial Attack Agent** - Tests for adversarial examples
    """,
    contact={
        "name": "ML-SecTest Team",
        "url": "https://github.com/yourusername/ml-sectest-framework",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Configure rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware for web-based frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results (replace with Redis/DB in production)
scan_storage: Dict[str, Dict[str, Any]] = {}

# ============================================================================
# Pydantic Models (Request/Response Schemas)
# ============================================================================

class ScanRequest(BaseModel):
    """Request model for initiating a security scan."""

    target_url: HttpUrl = Field(
        ...,
        description="Target URL to scan for vulnerabilities",
        example="http://api.example.com/predict"
    )
    challenge_name: str = Field(
        default="custom",
        description="Challenge name or 'custom' for general scanning",
        example="vault"
    )
    agents: Optional[List[str]] = Field(
        default=None,
        description="Specific agents to run (null = all agents)",
        example=["prompt_injection", "model_inversion"]
    )
    parallel: bool = Field(
        default=False,
        description="Run agents in parallel for faster execution"
    )
    report_format: Literal["html", "json"] = Field(
        default="json",
        description="Output report format"
    )
    timeout: int = Field(
        default=300,
        ge=10,
        le=3600,
        description="Maximum scan timeout in seconds (10-3600)"
    )

    @validator('challenge_name')
    def validate_challenge_name(cls, v):
        """Validate challenge name is alphanumeric."""
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Challenge name must be alphanumeric (with _ or - allowed)')
        return v


class ScanResponse(BaseModel):
    """Response model for scan initiation."""

    scan_id: str = Field(..., description="Unique scan identifier")
    status: str = Field(..., description="Scan status")
    message: str = Field(..., description="Status message")
    created_at: datetime = Field(..., description="Scan creation timestamp")
    estimated_duration: int = Field(..., description="Estimated duration in seconds")


class ScanStatus(BaseModel):
    """Model for scan status information."""

    scan_id: str
    status: Literal["queued", "running", "completed", "failed"]
    progress: int = Field(ge=0, le=100, description="Progress percentage")
    target_url: str
    challenge_name: str
    created_at: datetime
    updated_at: datetime
    agents_completed: int
    agents_total: int
    vulnerabilities_found: int
    report_available: bool


class VulnerabilityInfo(BaseModel):
    """Model for vulnerability information."""

    type: str
    severity: Literal["low", "medium", "high", "critical"]
    agent: str
    description: str
    evidence: str
    remediation: Optional[str] = None


class ScanResult(BaseModel):
    """Complete scan result model."""

    scan_id: str
    status: str
    target_url: str
    challenge_name: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    vulnerabilities: List[VulnerabilityInfo]
    agents_run: List[str]
    report_path: Optional[str] = None
    summary: Dict[str, Any]


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    version: str
    agents_available: int
    timestamp: datetime


# ============================================================================
# Background Task Functions
# ============================================================================

def run_scan_task(
    scan_id: str,
    target_url: str,
    challenge_name: str,
    agents: Optional[List[str]],
    parallel: bool,
    report_format: str,
    timeout: int
):
    """
    Background task to execute security scan.

    Args:
        scan_id: Unique scan identifier
        target_url: Target URL to scan
        challenge_name: Challenge name
        agents: Specific agents to run (None = all)
        parallel: Run agents in parallel
        report_format: Output format (html/json)
        timeout: Maximum scan timeout
    """
    try:
        # Update status to running
        scan_storage[scan_id]["status"] = "running"
        scan_storage[scan_id]["updated_at"] = datetime.now()

        # Initialize orchestrator
        orchestrator = SecurityOrchestrator()

        # Configure agents
        if agents:
            # Filter agents based on request
            available_agents = orchestrator.agents
            orchestrator.agents = [a for a in available_agents if a.name.lower() in [ag.lower() for ag in agents]]

        scan_storage[scan_id]["agents_total"] = len(orchestrator.agents)

        # Run scan
        results = orchestrator.run_scan(
            target_url=str(target_url),
            challenge_name=challenge_name,
            parallel=parallel
        )

        # Generate report
        report_gen = ReportGenerator()
        report_path = f"reports/{scan_id}.{report_format}"

        if report_format == "html":
            report_gen.generate_html_report(results, output_file=report_path)
        else:
            report_gen.generate_json_report(results, output_file=report_path)

        # Extract vulnerabilities
        vulnerabilities = []
        for result in results:
            if result.get("vulnerabilities_found", []):
                for vuln in result["vulnerabilities_found"]:
                    vulnerabilities.append({
                        "type": vuln.get("type", "unknown"),
                        "severity": vuln.get("severity", "medium"),
                        "agent": result["agent_name"],
                        "description": vuln.get("description", ""),
                        "evidence": vuln.get("evidence", ""),
                        "remediation": vuln.get("remediation")
                    })

        # Update storage with completion
        scan_storage[scan_id].update({
            "status": "completed",
            "completed_at": datetime.now(),
            "duration_seconds": (datetime.now() - scan_storage[scan_id]["created_at"]).total_seconds(),
            "vulnerabilities": vulnerabilities,
            "agents_run": [a.name for a in orchestrator.agents],
            "agents_completed": len(results),
            "vulnerabilities_found": len(vulnerabilities),
            "report_path": report_path,
            "report_available": True,
            "progress": 100,
            "summary": {
                "total_agents": len(results),
                "total_vulnerabilities": len(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v["severity"] == "critical"),
                "high": sum(1 for v in vulnerabilities if v["severity"] == "high"),
                "medium": sum(1 for v in vulnerabilities if v["severity"] == "medium"),
                "low": sum(1 for v in vulnerabilities if v["severity"] == "low"),
            }
        })

    except Exception as e:
        # Update storage with error
        scan_storage[scan_id].update({
            "status": "failed",
            "error": str(e),
            "updated_at": datetime.now()
        })


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", tags=["General"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "ML-SecTest API",
        "version": "1.0.0",
        "description": "Automated ML Security Testing Framework",
        "documentation": "/docs",
        "redoc": "/redoc",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
async def health_check():
    """
    Health check endpoint.

    Returns:
        Health status with framework information
    """
    orchestrator = SecurityOrchestrator()

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        agents_available=len(orchestrator.agents),
        timestamp=datetime.now()
    )


@app.post("/api/v1/scan", response_model=ScanResponse, tags=["Scanning"])
@limiter.limit("10/minute")
async def create_scan(
    scan_request: ScanRequest,
    request: Request,
    background_tasks: BackgroundTasks
):
    """
    Initiate a new security scan.

    This endpoint queues a security scan to run in the background and returns
    immediately with a scan ID that can be used to check status and retrieve results.

    **Rate Limit:** 10 scans per minute per IP address

    Args:
        request: Scan configuration parameters
        background_tasks: FastAPI background task handler

    Returns:
        Scan initiation response with scan_id

    Raises:
        HTTPException: 429 if rate limit exceeded
    """
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())

    # Initialize scan storage
    scan_storage[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "progress": 0,
        "target_url": str(scan_request.target_url),
        "challenge_name": scan_request.challenge_name,
        "created_at": datetime.now(),
        "updated_at": datetime.now(),
        "agents_completed": 0,
        "agents_total": 6 if not scan_request.agents else len(scan_request.agents),
        "vulnerabilities_found": 0,
        "report_available": False
    }

    # Queue background task
    background_tasks.add_task(
        run_scan_task,
        scan_id=scan_id,
        target_url=str(scan_request.target_url),
        challenge_name=scan_request.challenge_name,
        agents=scan_request.agents,
        parallel=scan_request.parallel,
        report_format=scan_request.report_format,
        timeout=scan_request.timeout
    )

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Scan {scan_id} queued successfully",
        created_at=scan_storage[scan_id]["created_at"],
        estimated_duration=scan_request.timeout if not scan_request.parallel else scan_request.timeout // 2
    )


@app.get("/api/v1/scan/{scan_id}", response_model=ScanStatus, tags=["Scanning"])
async def get_scan_status(scan_id: str):
    """
    Get scan status and progress.

    Args:
        scan_id: Unique scan identifier

    Returns:
        Current scan status and progress information

    Raises:
        HTTPException: If scan_id not found
    """
    if scan_id not in scan_storage:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan = scan_storage[scan_id]

    return ScanStatus(**scan)


@app.get("/api/v1/scan/{scan_id}/results", response_model=ScanResult, tags=["Scanning"])
async def get_scan_results(scan_id: str):
    """
    Get complete scan results.

    Args:
        scan_id: Unique scan identifier

    Returns:
        Complete scan results including vulnerabilities

    Raises:
        HTTPException: If scan not found or not completed
    """
    if scan_id not in scan_storage:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan = scan_storage[scan_id]

    if scan["status"] not in ["completed", "failed"]:
        raise HTTPException(
            status_code=400,
            detail=f"Scan {scan_id} is {scan['status']}. Results not available yet."
        )

    return ScanResult(**scan)


@app.get("/api/v1/scan/{scan_id}/report", tags=["Scanning"])
async def get_scan_report(scan_id: str):
    """
    Download scan report file.

    Args:
        scan_id: Unique scan identifier

    Returns:
        Report file (HTML or JSON)

    Raises:
        HTTPException: If scan not found or report not available
    """
    if scan_id not in scan_storage:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan = scan_storage[scan_id]

    if not scan.get("report_available"):
        raise HTTPException(status_code=400, detail="Report not available yet")

    report_path = Path(scan["report_path"])

    if not report_path.exists():
        raise HTTPException(status_code=500, detail="Report file not found")

    media_type = "text/html" if report_path.suffix == ".html" else "application/json"

    return FileResponse(
        path=report_path,
        media_type=media_type,
        filename=f"scan_{scan_id}{report_path.suffix}"
    )


@app.get("/api/v1/scans", tags=["Scanning"])
async def list_scans(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results")
):
    """
    List all scans with optional filtering.

    Args:
        status: Filter by scan status (optional)
        limit: Maximum number of results to return

    Returns:
        List of scans
    """
    scans = list(scan_storage.values())

    if status:
        scans = [s for s in scans if s["status"] == status]

    # Sort by creation time (newest first)
    scans.sort(key=lambda x: x["created_at"], reverse=True)

    return {
        "total": len(scans),
        "scans": scans[:limit]
    }


@app.get("/api/v1/agents", tags=["Agents"])
async def list_agents():
    """
    List all available security testing agents.

    Returns:
        List of available agents with descriptions
    """
    orchestrator = SecurityOrchestrator()

    agents = []
    for agent in orchestrator.agents:
        agents.append({
            "name": agent.name,
            "description": agent.description if hasattr(agent, 'description') else "Security testing agent",
            "category": getattr(agent, 'category', 'general'),
        })

    return {
        "total": len(agents),
        "agents": agents
    }


@app.get("/metrics", tags=["Monitoring"], include_in_schema=True)
async def metrics():
    """
    Prometheus metrics endpoint.

    Exposes metrics for monitoring and alerting:
    - Scan execution metrics (requests, duration)
    - Agent performance metrics
    - Vulnerability detection counters
    - System health gauges
    - API request metrics

    This endpoint is designed to be scraped by Prometheus.
    Configure your prometheus.yml:

    ```yaml
    scrape_configs:
      - job_name: 'ml-sectest'
        static_configs:
          - targets: ['localhost:8081']
    ```

    Returns:
        Prometheus-formatted metrics (text/plain)
    """
    if not METRICS_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Metrics not available - prometheus_client not installed"
        )

    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )
