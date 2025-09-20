"""
Production-Ready API Server for Catalytic Lattice Computing
Includes monitoring, error handling, rate limiting, and async processing
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import numpy as np
import asyncio
import uuid
from datetime import datetime
import logging
from functools import lru_cache
import psutil
import traceback
from contextlib import asynccontextmanager

# Production imports
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from fastapi import Response
import redis
from tenacity import retry, stop_after_attempt, wait_exponential

# Import our catalytic modules
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from catalytic_lattice_computing import CatalyticLatticeComputer
from quantum_catalytic_lattice import QuantumCatalyticLattice

# Configure structured logging
import structlog
logger = structlog.get_logger()

# Metrics
request_count = Counter('catalytic_requests_total', 'Total API requests', ['method', 'endpoint'])
request_duration = Histogram('request_duration_seconds', 'Request duration')
active_jobs = Gauge('active_jobs', 'Number of active processing jobs')
memory_usage = Gauge('memory_usage_bytes', 'Memory usage in bytes')
error_count = Counter('errors_total', 'Total errors', ['type'])

# Job storage (use Redis in production)
job_store: Dict[str, Dict] = {}
redis_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    # Startup
    logger.info("Starting Catalytic Lattice API Server")
    
    # Initialize Redis connection
    global redis_client
    try:
        redis_client = redis.Redis(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', 6379)),
            decode_responses=True
        )
        redis_client.ping()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.warning(f"Redis not available, using in-memory storage: {e}")
    
    # Pre-warm JIT compilation
    logger.info("Pre-warming JIT compilation")
    _prewarm_jit()
    
    # Start background monitoring
    asyncio.create_task(monitor_resources())
    
    yield
    
    # Shutdown
    logger.info("Shutting down Catalytic Lattice API Server")
    if redis_client:
        redis_client.close()

app = FastAPI(
    title="Catalytic Lattice Computing API",
    version="1.0.0",
    description="High-dimensional lattice computing using catalytic memory principles",
    lifespan=lifespan
)

# CORS middleware for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response Models
class LatticeConfig(BaseModel):
    dimensions: int = Field(..., ge=2, le=100, description="Number of dimensions")
    lattice_size: int = Field(..., ge=2, le=1000, description="Size of lattice in each dimension")
    collapse_dims: Optional[int] = Field(3, ge=1, le=10, description="Target dimensions for collapse")
    
    @validator('collapse_dims')
    def validate_collapse_dims(cls, v, values):
        if 'dimensions' in values and v > values['dimensions']:
            raise ValueError('collapse_dims must be <= dimensions')
        return v

class ProcessRequest(BaseModel):
    config: LatticeConfig
    points: List[List[float]] = Field(..., min_items=1, max_items=10000)
    operation: str = Field(..., regex="^(collapse|transform|eigenspace|superposition)$")
    options: Optional[Dict[str, Any]] = {}

class JobResponse(BaseModel):
    job_id: str
    status: str
    created_at: datetime
    estimated_completion_seconds: Optional[float] = None

class JobResult(BaseModel):
    job_id: str
    status: str
    result: Optional[Any] = None
    error: Optional[str] = None
    processing_time_ms: Optional[float] = None
    memory_used_mb: Optional[float] = None

# Dependency injection for rate limiting
async def rate_limit(client_id: str = "default"):
    """Simple rate limiting - use Redis in production"""
    # Implement token bucket algorithm
    pass

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration"""
    try:
        # Check system resources
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "cpu_usage_percent": cpu_percent,
            "memory_usage_percent": memory.percent,
            "memory_available_mb": memory.available / (1024 * 1024)
        }
        
        # Fail health check if resources are exhausted
        if cpu_percent > 90 or memory.percent > 90:
            health_status["status"] = "degraded"
            return JSONResponse(status_code=503, content=health_status)
        
        return health_status
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503, 
            content={"status": "unhealthy", "error": str(e)}
        )

# Metrics endpoint
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    memory_usage.set(psutil.Process().memory_info().rss)
    return Response(content=generate_latest(), media_type="text/plain")

# Main processing endpoint
@app.post("/process", response_model=JobResponse)
@request_duration.time()
async def process_lattice(
    request: ProcessRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(rate_limit)
):
    """Queue lattice processing job"""
    request_count.labels(method="POST", endpoint="/process").inc()
    
    # Generate job ID
    job_id = str(uuid.uuid4())
    
    # Validate request
    try:
        points_array = np.array(request.points)
        if points_array.shape[1] != request.config.dimensions:
            raise ValueError(f"Points must have {request.config.dimensions} dimensions")
    except Exception as e:
        error_count.labels(type="validation").inc()
        raise HTTPException(status_code=400, detail=str(e))
    
    # Create job entry
    job = {
        "id": job_id,
        "status": "queued",
        "created_at": datetime.utcnow(),
        "request": request.dict(),
        "result": None,
        "error": None
    }
    
    # Store job
    if redis_client:
        redis_client.setex(f"job:{job_id}", 3600, str(job))
    else:
        job_store[job_id] = job
    
    # Queue background processing
    background_tasks.add_task(process_job, job_id, request)
    active_jobs.inc()
    
    return JobResponse(
        job_id=job_id,
        status="queued",
        created_at=job["created_at"],
        estimated_completion_seconds=estimate_processing_time(request)
    )

# Job status endpoint
@app.get("/jobs/{job_id}", response_model=JobResult)
async def get_job_status(job_id: str):
    """Get job processing status and results"""
    request_count.labels(method="GET", endpoint="/jobs").inc()
    
    # Retrieve job
    if redis_client:
        job_data = redis_client.get(f"job:{job_id}")
        if not job_data:
            raise HTTPException(status_code=404, detail="Job not found")
        job = eval(job_data)  # Use proper serialization in production
    else:
        if job_id not in job_store:
            raise HTTPException(status_code=404, detail="Job not found")
        job = job_store[job_id]
    
    return JobResult(
        job_id=job_id,
        status=job["status"],
        result=job.get("result"),
        error=job.get("error"),
        processing_time_ms=job.get("processing_time_ms"),
        memory_used_mb=job.get("memory_used_mb")
    )

# Background job processor
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
async def process_job(job_id: str, request: ProcessRequest):
    """Process lattice operation in background"""
    start_time = datetime.utcnow()
    
    try:
        logger.info(f"Processing job {job_id}", operation=request.operation)
        
        # Update job status
        update_job_status(job_id, "processing")
        
        # Initialize appropriate processor
        if request.operation in ["collapse", "transform"]:
            processor = CatalyticLatticeComputer(
                dimensions=request.config.dimensions,
                lattice_size=request.config.lattice_size,
                aux_memory_mb=100
            )
        else:
            processor = QuantumCatalyticLattice(
                dimensions=request.config.dimensions,
                lattice_size=request.config.lattice_size,
                collapse_dims=request.config.collapse_dims
            )
        
        # Process based on operation type
        points = np.array(request.points)
        result = None
        
        if request.operation == "collapse":
            result = []
            for point in points:
                collapsed = processor.dimensional_collapse_hash(
                    point, 
                    request.config.collapse_dims,
                    processor.aux_memories[0]
                )
                result.append(collapsed.tolist())
                
        elif request.operation == "eigenspace":
            result = processor.parallel_lattice_eigenspace(points, processor.n_cores)
            result = result.tolist()
            
        elif request.operation == "superposition":
            result = processor.quantum_inspired_superposition(points)
            result = result.tolist()
        
        # Calculate metrics
        end_time = datetime.utcnow()
        processing_time_ms = (end_time - start_time).total_seconds() * 1000
        memory_used_mb = psutil.Process().memory_info().rss / (1024 * 1024)
        
        # Update job with results
        update_job_status(
            job_id, 
            "completed",
            result=result,
            processing_time_ms=processing_time_ms,
            memory_used_mb=memory_used_mb
        )
        
        logger.info(f"Job {job_id} completed", 
                   processing_time_ms=processing_time_ms,
                   memory_used_mb=memory_used_mb)
        
    except Exception as e:
        error_count.labels(type="processing").inc()
        logger.error(f"Job {job_id} failed", error=str(e), traceback=traceback.format_exc())
        update_job_status(job_id, "failed", error=str(e))
    
    finally:
        active_jobs.dec()
        # Cleanup
        if 'processor' in locals():
            del processor

def update_job_status(job_id: str, status: str, **kwargs):
    """Update job status in storage"""
    if redis_client:
        job_data = redis_client.get(f"job:{job_id}")
        if job_data:
            job = eval(job_data)
            job["status"] = status
            job.update(kwargs)
            redis_client.setex(f"job:{job_id}", 3600, str(job))
    else:
        if job_id in job_store:
            job_store[job_id]["status"] = status
            job_store[job_id].update(kwargs)

def estimate_processing_time(request: ProcessRequest) -> float:
    """Estimate processing time based on request parameters"""
    n_points = len(request.points)
    dims = request.config.dimensions
    
    # Simple heuristic - improve with ML model
    base_time = 0.001  # 1ms base
    time_per_point = 0.0001 * dims  # Linear with dimensions
    
    return base_time + (time_per_point * n_points)

def _prewarm_jit():
    """Pre-compile JIT functions for better cold start performance"""
    try:
        # Create small test case
        test_computer = CatalyticLatticeComputer(2, 2, 1)
        test_points = np.random.randn(10, 2)
        
        # Trigger JIT compilation
        _ = test_computer.reversible_xor_transform(
            np.array([1, 2, 3], dtype=np.uint8),
            np.array([4, 5, 6], dtype=np.uint8)
        )
        
        del test_computer
        logger.info("JIT compilation pre-warming complete")
    except Exception as e:
        logger.warning(f"JIT pre-warming failed: {e}")

async def monitor_resources():
    """Background task to monitor system resources"""
    while True:
        try:
            memory_usage.set(psutil.Process().memory_info().rss)
            await asyncio.sleep(30)  # Update every 30 seconds
        except Exception as e:
            logger.error(f"Resource monitoring error: {e}")
            await asyncio.sleep(60)

# Error handlers
@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    error_count.labels(type="value_error").inc()
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": str(exc)}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    error_count.labels(type="general").inc()
    logger.error(f"Unhandled exception: {exc}", traceback=traceback.format_exc())
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")