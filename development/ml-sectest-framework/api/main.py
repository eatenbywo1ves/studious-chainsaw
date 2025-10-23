"""
ML-SecTest Framework REST API
==============================
FastAPI-based REST API for the ML Security Testing Framework.
Provides endpoints for scanning targets, testing challenges, and retrieving results.

Author: ML-SecTest Team
Version: 1.0.0
License: MIT
"""

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, HttpUrl, Field, validator
from typing import List, Optional, Dict, Any, Literal
from datetime import datetime
from pathlib import Path
import uuid
import sys
import os
import csv
import json
import io

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import SecurityOrchestrator
from utils import ReportGenerator
from config import get_settings, validate_settings

# Prometheus metrics
try:
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, Counter, Histogram
    METRICS_AVAILABLE = True

    # Rate limiting metrics
    rate_limit_hits_total = Counter(
        'api_rate_limit_hits_total',
        'Total number of requests that hit rate limit check',
        ['endpoint', 'method']
    )

    rate_limit_blocks_total = Counter(
        'api_rate_limit_blocks_total',
        'Total number of requests blocked by rate limiting',
        ['endpoint', 'method']
    )

    rate_limit_check_duration = Histogram(
        'api_rate_limit_check_duration_seconds',
        'Time spent checking rate limits',
        ['endpoint']
    )

except ImportError:
    METRICS_AVAILABLE = False
    rate_limit_hits_total = None
    rate_limit_blocks_total = None
    rate_limit_check_duration = None

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

# ============================================================================
# Configuration
# ============================================================================

# Load settings (cached singleton)
settings = get_settings()

# Validate settings at module import
# This will print configuration summary and raise errors for invalid prod settings
try:
    validate_settings()
except ValueError as e:
    # In development, log warning; in production, this would crash
    if settings.ENVIRONMENT != "production":
        print(f"[WARNING] {e}")
    else:
        raise

# ============================================================================
# Logging Configuration
# ============================================================================

# Configure API request logging from settings
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format=settings.LOG_FORMAT,
    filename=settings.LOG_FILE if settings.LOG_FILE else None
)
logger = logging.getLogger("ml_sectest_api")

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging all API requests and responses.

    Logs:
    - Request method, path, client IP
    - Response status code
    - Request duration
    - Query parameters (if present)
    """

    async def dispatch(self, request: StarletteRequest, call_next):
        # Record start time
        start_time = time.time()

        # Extract request details
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path
        query_params = str(request.query_params) if request.query_params else ""

        # Log incoming request
        logger.info(
            f"Request: {method} {path} | Client: {client_ip}" +
            (f" | Params: {query_params}" if query_params else "")
        )

        # Process request
        try:
            response = await call_next(request)

            # Calculate duration
            duration = time.time() - start_time

            # Log response
            logger.info(
                f"Response: {method} {path} | Status: {response.status_code} | "
                f"Duration: {duration:.3f}s | Client: {client_ip}"
            )

            return response

        except Exception as e:
            # Log errors
            duration = time.time() - start_time
            logger.error(
                f"Error: {method} {path} | Exception: {str(e)} | "
                f"Duration: {duration:.3f}s | Client: {client_ip}"
            )
            raise

# ============================================================================
# Rate Limiting with Metrics
# ============================================================================

async def custom_rate_limit_handler(request: StarletteRequest, exc: RateLimitExceeded):
    """
    Custom rate limit exception handler that records metrics.

    Records:
    - Rate limit blocks in Prometheus
    - Logs blocked requests
    """
    # Record metrics if available
    if METRICS_AVAILABLE and rate_limit_blocks_total:
        rate_limit_blocks_total.labels(
            endpoint=request.url.path,
            method=request.method
        ).inc()

    # Log rate limit block
    client_ip = request.client.host if request.client else "unknown"
    logger.warning(
        f"Rate limit exceeded: {request.method} {request.url.path} | "
        f"Client: {client_ip} | Limit: {exc.detail}"
    )

    # Call default handler to return proper response
    return await _rate_limit_exceeded_handler(request, exc)

# ============================================================================
# Application Configuration
# ============================================================================

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# OpenAPI tag metadata for better documentation organization
tags_metadata = [
    {
        "name": "General",
        "description": "General API information and health checks. Use these endpoints to verify API availability and get basic information.",
    },
    {
        "name": "Scanning",
        "description": """
        **Security scanning operations.** Create scans, monitor progress, retrieve results.

        Scanning workflow:
        1. Create scan with `POST /api/v1/scan`
        2. Monitor status with `GET /api/v1/scan/{scan_id}`
        3. Retrieve results with `GET /api/v1/scan/{scan_id}/results`
        4. Download report with `GET /api/v1/scan/{scan_id}/report`
        """,
        "externalDocs": {
            "description": "Scanning Guide",
            "url": "https://github.com/yourusername/ml-sectest-framework/wiki/Scanning",
        },
    },
    {
        "name": "Agents",
        "description": "Agent management and information. List available security testing agents and their capabilities.",
    },
    {
        "name": "Monitoring",
        "description": """
        **Monitoring and metrics endpoints.** Prometheus metrics for production monitoring.

        Configure Prometheus to scrape `/metrics` endpoint for operational visibility.
        """,
        "externalDocs": {
            "description": "Prometheus Integration",
            "url": "https://prometheus.io/docs/introduction/overview/",
        },
    },
]

app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
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
    * 🛡️ **Rate Limiting**: Prevents API abuse (configurable)

    ## Agents

    1. **Prompt Injection Agent** - Tests for LLM prompt injection (OWASP LLM01)
    2. **Model Inversion Agent** - Tests for data extraction (OWASP ML03)
    3. **Data Poisoning Agent** - Tests for training data poisoning (OWASP ML02)
    4. **Model Extraction Agent** - Tests for model theft (OWASP LLM10)
    5. **Model Serialization Agent** - Tests for unsafe deserialization (OWASP ML06)
    6. **Adversarial Attack Agent** - Tests for adversarial examples
    """,
    openapi_tags=tags_metadata,
    contact={
        "name": "ML-SecTest Team",
        "url": "https://github.com/yourusername/ml-sectest-framework",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    debug=settings.DEBUG,
)

# Configure rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_handler)

# CORS middleware configuration from settings
logger.info(f"CORS configured with {len(settings.cors_origins_list)} origins from settings")
logger.info(f"CORS credentials: {settings.CORS_ALLOW_CREDENTIALS}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "Accept",
        "Origin",
        "User-Agent",
        "DNT",
        "Cache-Control",
        "X-Requested-With"
    ],
    max_age=settings.CORS_MAX_AGE,
)

# Request logging middleware
app.add_middleware(RequestLoggingMiddleware)

# In-memory storage for scan results (replace with Redis/DB in production)
scan_storage: Dict[str, Dict[str, Any]] = {}

# Batch scan storage
batch_storage: Dict[str, Dict[str, Any]] = {}

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


class BatchScanItem(BaseModel):
    """Single scan item in a batch."""

    target_url: HttpUrl
    challenge_name: Optional[str] = "custom"
    agents: Optional[List[str]] = None
    parallel: bool = False
    timeout: Optional[int] = 300


class BatchScanResponse(BaseModel):
    """Response model for batch scan initiation."""

    batch_id: str = Field(..., description="Unique batch identifier")
    status: str = Field(..., description="Batch status")
    message: str = Field(..., description="Status message")
    total_scans: int = Field(..., description="Total number of scans in batch")
    created_at: datetime = Field(..., description="Batch creation timestamp")
    scan_ids: List[str] = Field(..., description="List of individual scan IDs")


class BatchScanStatus(BaseModel):
    """Status model for batch scans."""

    batch_id: str
    status: Literal["queued", "running", "completed", "failed", "partial"]
    total_scans: int
    completed_scans: int
    failed_scans: int
    running_scans: int
    queued_scans: int
    progress: int = Field(ge=0, le=100, description="Overall progress percentage")
    created_at: datetime
    updated_at: datetime
    scan_ids: List[str]


class BatchScanResult(BaseModel):
    """Complete batch scan result model."""

    batch_id: str
    status: str
    total_scans: int
    completed_scans: int
    failed_scans: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    scan_results: List[Dict[str, Any]]
    summary: Dict[str, Any]


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


def parse_csv_file(file_content: bytes) -> List[BatchScanItem]:
    """
    Parse CSV file content into list of BatchScanItem objects.

    Expected CSV format:
    target_url,challenge_name,agents,parallel,timeout

    Args:
        file_content: Raw bytes of CSV file

    Returns:
        List of BatchScanItem objects

    Raises:
        ValueError: If CSV format is invalid
    """
    try:
        # Decode bytes to string
        csv_text = file_content.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(csv_text))

        scan_items = []
        for row in csv_reader:
            # Parse agents (comma-separated string to list)
            agents = None
            if 'agents' in row and row['agents']:
                agents = [a.strip() for a in row['agents'].split(',') if a.strip()]

            scan_item = BatchScanItem(
                target_url=row['target_url'],
                challenge_name=row.get('challenge_name', 'custom'),
                agents=agents,
                parallel=row.get('parallel', 'false').lower() == 'true',
                timeout=int(row.get('timeout', 300))
            )
            scan_items.append(scan_item)

        return scan_items

    except Exception as e:
        raise ValueError(f"Invalid CSV format: {str(e)}")


def parse_json_file(file_content: bytes) -> List[BatchScanItem]:
    """
    Parse JSON file content into list of BatchScanItem objects.

    Expected JSON format:
    [
      {
        "target_url": "http://example.com",
        "challenge_name": "custom",
        "agents": ["prompt_injection", "model_inversion"],
        "parallel": false,
        "timeout": 300
      }
    ]

    Args:
        file_content: Raw bytes of JSON file

    Returns:
        List of BatchScanItem objects

    Raises:
        ValueError: If JSON format is invalid
    """
    try:
        # Decode bytes to string and parse JSON
        json_text = file_content.decode('utf-8')
        json_data = json.loads(json_text)

        # Ensure it's a list
        if not isinstance(json_data, list):
            raise ValueError("JSON must be an array of scan configurations")

        scan_items = []
        for item in json_data:
            scan_item = BatchScanItem(**item)
            scan_items.append(scan_item)

        return scan_items

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {str(e)}")
    except Exception as e:
        raise ValueError(f"Invalid JSON structure: {str(e)}")


def run_batch_scan_task(batch_id: str, background_tasks: BackgroundTasks):
    """
    Background task to process batch scans.

    Args:
        batch_id: Unique batch identifier
        background_tasks: FastAPI background task handler
    """
    try:
        batch_storage[batch_id]["status"] = "running"
        batch_storage[batch_id]["updated_at"] = datetime.now()

        # Queue individual scans
        scan_ids = batch_storage[batch_id]["scan_ids"]

        for scan_id in scan_ids:
            if scan_id in scan_storage:
                scan = scan_storage[scan_id]

                # Queue the scan task
                background_tasks.add_task(
                    run_scan_task,
                    scan_id=scan_id,
                    target_url=scan["target_url"],
                    challenge_name=scan["challenge_name"],
                    agents=scan.get("agents"),
                    parallel=scan.get("parallel", False),
                    report_format=scan.get("report_format", "json"),
                    timeout=scan.get("timeout", 300)
                )

        # Batch is now running (individual scans are queued)
        batch_storage[batch_id]["status"] = "running"
        batch_storage[batch_id]["updated_at"] = datetime.now()

    except Exception as e:
        batch_storage[batch_id]["status"] = "failed"
        batch_storage[batch_id]["error"] = str(e)
        batch_storage[batch_id]["updated_at"] = datetime.now()


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
    # Record rate limit hit metrics
    if METRICS_AVAILABLE and rate_limit_hits_total:
        rate_limit_hits_total.labels(
            endpoint="/api/v1/scan",
            method="POST"
        ).inc()

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
# Batch Scan Endpoints
# ============================================================================

@app.post(
    "/api/v1/batch/scan",
    response_model=BatchScanResponse,
    tags=["Batch Scans"],
    summary="Upload batch scan file",
    description="Upload CSV or JSON file containing multiple scan configurations"
)
async def create_batch_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="CSV or JSON file with scan configurations")
):
    """
    Create a batch scan from uploaded file.

    **CSV Format:**
    ```csv
    target_url,challenge_name,agents,parallel,timeout
    http://example.com,custom,"prompt_injection,model_inversion",false,300
    http://test.com,ctf,"data_poisoning",true,600
    ```

    **JSON Format:**
    ```json
    [
      {
        "target_url": "http://example.com",
        "challenge_name": "custom",
        "agents": ["prompt_injection", "model_inversion"],
        "parallel": false,
        "timeout": 300
      }
    ]
    ```

    Returns:
        BatchScanResponse with batch ID and scan IDs
    """
    # Read file content
    file_content = await file.read()

    # Determine file type and parse
    if file.filename.endswith('.csv'):
        try:
            scan_items = parse_csv_file(file_content)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    elif file.filename.endswith('.json'):
        try:
            scan_items = parse_json_file(file_content)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only CSV and JSON files are supported."
        )

    if not scan_items:
        raise HTTPException(
            status_code=400,
            detail="No valid scan configurations found in file"
        )

    # Create batch ID
    batch_id = str(uuid.uuid4())
    scan_ids = []

    # Create individual scans
    for item in scan_items:
        scan_id = str(uuid.uuid4())
        scan_ids.append(scan_id)

        # Store scan configuration
        scan_storage[scan_id] = {
            "scan_id": scan_id,
            "target_url": str(item.target_url),
            "challenge_name": item.challenge_name,
            "agents": item.agents,
            "parallel": item.parallel,
            "timeout": item.timeout,
            "status": "queued",
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "report_format": "json"
        }

    # Create batch record
    batch_storage[batch_id] = {
        "batch_id": batch_id,
        "status": "queued",
        "total_scans": len(scan_items),
        "completed_scans": 0,
        "failed_scans": 0,
        "running_scans": 0,
        "queued_scans": len(scan_items),
        "created_at": datetime.now(),
        "updated_at": datetime.now(),
        "scan_ids": scan_ids,
        "scan_results": []
    }

    # Queue batch processing
    background_tasks.add_task(run_batch_scan_task, batch_id, background_tasks)

    return BatchScanResponse(
        batch_id=batch_id,
        status="queued",
        message=f"Batch scan created with {len(scan_items)} scans",
        total_scans=len(scan_items),
        created_at=batch_storage[batch_id]["created_at"],
        scan_ids=scan_ids
    )


@app.get(
    "/api/v1/batch/{batch_id}",
    response_model=BatchScanStatus,
    tags=["Batch Scans"],
    summary="Get batch scan status",
    description="Retrieve status information for a batch scan"
)
async def get_batch_status(batch_id: str):
    """
    Get the current status of a batch scan.

    Returns scan counts, progress percentage, and individual scan IDs.
    """
    if batch_id not in batch_storage:
        raise HTTPException(status_code=404, detail="Batch not found")

    batch = batch_storage[batch_id]

    # Count scan statuses
    completed = 0
    failed = 0
    running = 0
    queued = 0

    for scan_id in batch["scan_ids"]:
        if scan_id in scan_storage:
            status = scan_storage[scan_id]["status"]
            if status == "completed":
                completed += 1
            elif status == "failed":
                failed += 1
            elif status == "running":
                running += 1
            elif status == "queued":
                queued += 1

    # Update batch counts
    batch["completed_scans"] = completed
    batch["failed_scans"] = failed
    batch["running_scans"] = running
    batch["queued_scans"] = queued

    # Calculate progress
    total = batch["total_scans"]
    progress = int((completed + failed) / total * 100) if total > 0 else 0

    # Determine overall status
    if completed + failed == total:
        batch["status"] = "completed" if failed == 0 else "partial"
    elif running > 0:
        batch["status"] = "running"
    else:
        batch["status"] = "queued"

    batch["updated_at"] = datetime.now()

    return BatchScanStatus(
        batch_id=batch_id,
        status=batch["status"],
        total_scans=total,
        completed_scans=completed,
        failed_scans=failed,
        running_scans=running,
        queued_scans=queued,
        progress=progress,
        created_at=batch["created_at"],
        updated_at=batch["updated_at"],
        scan_ids=batch["scan_ids"]
    )


@app.get(
    "/api/v1/batch/{batch_id}/results",
    response_model=BatchScanResult,
    tags=["Batch Scans"],
    summary="Get batch scan results",
    description="Retrieve aggregated results from all scans in a batch"
)
async def get_batch_results(batch_id: str):
    """
    Get complete results for all scans in a batch.

    Includes individual scan results and aggregated summary statistics.
    """
    if batch_id not in batch_storage:
        raise HTTPException(status_code=404, detail="Batch not found")

    batch = batch_storage[batch_id]

    # Collect results from all scans
    scan_results = []
    total_vulnerabilities = 0
    vulnerability_types = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for scan_id in batch["scan_ids"]:
        if scan_id in scan_storage:
            scan = scan_storage[scan_id]
            scan_result = {
                "scan_id": scan_id,
                "target_url": scan["target_url"],
                "status": scan["status"],
                "created_at": scan["created_at"],
                "updated_at": scan["updated_at"]
            }

            # Add results if scan completed
            if scan["status"] == "completed" and "result" in scan:
                scan_result["result"] = scan["result"]

                # Aggregate vulnerability statistics
                if "vulnerabilities" in scan["result"]:
                    vulns = scan["result"]["vulnerabilities"]
                    total_vulnerabilities += len(vulns)

                    for vuln in vulns:
                        # Count by type
                        vuln_type = vuln.get("type", "unknown")
                        vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1

                        # Count by severity
                        severity = vuln.get("severity", "info").lower()
                        if severity in severity_counts:
                            severity_counts[severity] += 1

            scan_results.append(scan_result)

    # Calculate duration if completed
    duration = None
    completed_at = None
    if batch["status"] in ["completed", "partial"]:
        completed_at = batch["updated_at"]
        duration = (completed_at - batch["created_at"]).total_seconds()

    # Create summary
    summary = {
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerability_types": vulnerability_types,
        "severity_counts": severity_counts,
        "success_rate": (batch["completed_scans"] / batch["total_scans"] * 100) if batch["total_scans"] > 0 else 0
    }

    return BatchScanResult(
        batch_id=batch_id,
        status=batch["status"],
        total_scans=batch["total_scans"],
        completed_scans=batch["completed_scans"],
        failed_scans=batch["failed_scans"],
        created_at=batch["created_at"],
        completed_at=completed_at,
        duration_seconds=duration,
        scan_results=scan_results,
        summary=summary
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
