#!/usr/bin/env python3
"""
SaaS API Server for Catalytic Computing
Multi-tenant version with authentication, usage tracking, and billing
"""

import os
import sys
import time
import asyncio
import logging
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional, Dict
from uuid import UUID

# Load environment variables from parent .env file
from dotenv import load_dotenv

env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(env_path)

# Setup logging
logging.basicConfig(
    level=logging.INFO if os.getenv("DEPLOYMENT_ENV") == "production" else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

from fastapi import FastAPI, Depends, HTTPException, status  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

# Add parent directories to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".."))

# Import security headers
from security.application.security_headers import create_custom_security_headers  # noqa: E402

# Import auth components
from auth.middleware import (  # noqa: E402
    TenantIsolationMiddleware,
    AuthenticationMiddleware,
    RateLimitMiddleware,
    LoggingMiddleware,
    get_cors_config,
    get_current_user,
    TokenData,
)

# Import tenant API
from api.tenant_api import router as tenant_router  # noqa: E402
from api.subscription_api import router as subscription_router  # noqa: E402
from api.auth_api import router as auth_router  # noqa: E402

# Import database models
from database.models import (  # noqa: E402
    Base,
    Tenant,
    User,
    SubscriptionPlan,
    ApiLog,
    TenantLattice,
    LatticeOperation,
)
from database.connection import get_db, engine, SessionLocal  # noqa: E402

# Import original Catalytic Computing components
from apps.catalytic.catalytic_lattice_graph import CatalyticLatticeGraph  # noqa: E402

# Try to import GPU modules
try:
    from apps.catalytic.catalytic_lattice_gpu import CatalyticLatticeGPU  # noqa: F401

    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

# ============================================================================
# DATABASE SETUP
# ============================================================================
# Note: Database connection is now managed centrally in database/connection.py
# This eliminates per-request engine creation and prevents connection pool exhaustion.
# The get_db() function is imported above from database.connection.

# ============================================================================
# TENANT-AWARE LATTICE STORAGE
# ============================================================================


class TenantLatticeManager:
    """Manages lattices with tenant isolation"""

    def __init__(self):
        self._lattices: Dict[str, Dict[str, CatalyticLatticeGraph]] = {}
        self.max_per_tenant = 100

    def create_lattice(
        self,
        tenant_id: str,
        lattice_id: str,
        dimensions: int,
        size: int,
        user_id: Optional[str] = None,
    ) -> CatalyticLatticeGraph:
        """Create lattice for tenant"""

        if tenant_id not in self._lattices:
            self._lattices[tenant_id] = {}

        if len(self._lattices[tenant_id]) >= self.max_per_tenant:
            raise ValueError(f"Maximum {self.max_per_tenant} lattices per tenant")

        # Create lattice
        lattice = CatalyticLatticeGraph(dimensions=dimensions, lattice_size=size)

        # Store with tenant isolation
        self._lattices[tenant_id][lattice_id] = lattice

        return lattice

    def get_lattice(self, tenant_id: str, lattice_id: str) -> Optional[CatalyticLatticeGraph]:
        """Get lattice for tenant"""
        return self._lattices.get(tenant_id, {}).get(lattice_id)

    def delete_lattice(self, tenant_id: str, lattice_id: str) -> bool:
        """Delete lattice for tenant"""
        if tenant_id in self._lattices and lattice_id in self._lattices[tenant_id]:
            del self._lattices[tenant_id][lattice_id]
            return True
        return False

    def list_tenant_lattices(self, tenant_id: str) -> list:
        """List all lattices for tenant"""
        return list(self._lattices.get(tenant_id, {}).keys())

    def get_tenant_usage(self, tenant_id: str) -> dict:
        """Get usage statistics for tenant"""
        tenant_lattices = self._lattices.get(tenant_id, {})
        total_memory = sum(lattice.aux_memory_size for lattice in tenant_lattices.values())
        return {
            "lattice_count": len(tenant_lattices),
            "total_memory_kb": total_memory / 1024,
            "available": self.max_per_tenant - len(tenant_lattices),
        }


# Global lattice manager
lattice_manager = TenantLatticeManager()

# Import and initialize reactive services
from api.reactive_auth import ReactiveAuthService, ReactiveLatticeService  # noqa: E402

auth_service = ReactiveAuthService(max_workers=4)
lattice_service = ReactiveLatticeService(lattice_manager, max_workers=4)

# ============================================================================
# LIFESPAN MANAGEMENT
# ============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""

    # Startup
    logger.info("=" * 60)
    logger.info("Starting Catalytic Computing SaaS API Server")
    logger.info("=" * 60)
    logger.info(f"GPU Available: {GPU_AVAILABLE}")
    logger.info(f"Environment: {os.getenv('DEPLOYMENT_ENV', 'development')}")
    logger.info(f"Port: {os.getenv('PORT', '8000')}")
    logger.info(f"Workers: {os.getenv('WORKERS', '4')}")

    # Create database tables
    try:
        logger.info("Initializing database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}", exc_info=True)

    # Ensure default plans exist
    db = SessionLocal()
    try:
        if db.query(SubscriptionPlan).count() == 0:
            # Create default plans
            plans = [
                SubscriptionPlan(
                    name="Free Tier",
                    code="free",
                    price_monthly=0.00,
                    price_yearly=0.00,
                    features={
                        "lattices": 5,
                        "api_calls": 1000,
                        "path_finding": True,
                        "basic_transforms": True,
                    },
                    limits={
                        "max_lattices": 5,
                        "max_dimensions": 3,
                        "max_lattice_size": 10,
                        "api_calls_per_month": 1000,
                    },
                ),
                SubscriptionPlan(
                    name="Professional",
                    code="professional",
                    price_monthly=99.99,
                    price_yearly=999.99,
                    features={
                        "lattices": 500,
                        "api_calls": 100000,
                        "all_features": True,
                        "priority_support": True,
                        "gpu_acceleration": True,
                    },
                    limits={
                        "max_lattices": 500,
                        "max_dimensions": 10,
                        "max_lattice_size": 100,
                        "api_calls_per_month": 100000,
                    },
                ),
            ]
            db.add_all(plans)
            db.commit()
            print("Default subscription plans created")
    finally:
        db.close()

    yield

    # Shutdown
    print("Shutting down Catalytic Computing SaaS API Server...")
    lattice_manager._lattices.clear()


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Catalytic Computing SaaS API",
    description="Multi-tenant SaaS platform for revolutionary lattice computing",
    version="2.0.0",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(CORSMiddleware, **get_cors_config())

# Add security headers middleware
environment = os.getenv("ENVIRONMENT", "development")
security_headers_middleware = create_custom_security_headers(
    environment=environment,
    allow_inline_scripts=True,  # For React/Vue frontend
    allow_websockets=True,  # For real-time features
)
app.add_middleware(
    type(security_headers_middleware),
    hsts_max_age=security_headers_middleware.hsts_max_age,
    csp_directives=security_headers_middleware.csp_directives,
    frame_options=security_headers_middleware.frame_options,
    enable_permissions_policy=security_headers_middleware.enable_permissions_policy,
    enable_referrer_policy=security_headers_middleware.enable_referrer_policy,
)

# Add custom middleware
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware, default_limit=1000, window_seconds=60)
app.add_middleware(AuthenticationMiddleware)
app.add_middleware(TenantIsolationMiddleware)

# Include routers
app.include_router(auth_router)
app.include_router(tenant_router)
app.include_router(subscription_router)

# Add Prometheus metrics endpoint
from api.metrics_instrumentation import add_metrics_endpoint, MetricsMiddleware  # noqa: E402

add_metrics_endpoint(app)
app.add_middleware(MetricsMiddleware)

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

from pydantic import BaseModel, EmailStr  # noqa: E402


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_slug: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str
    tenant_slug: Optional[str] = None


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def register_user(request: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register a new user and create tenant if first user.

    For testing: Creates new tenant for each registration.
    For production: Would check if tenant exists or create one.
    """
    from database.models import User, Tenant, UserRole
    from uuid import uuid4

    logger.info(f"Registration attempt for email: {request.email}")

    # Generate tenant slug from email if not provided
    tenant_slug = request.tenant_slug or request.email.split("@")[0]

    # Check if user already exists with this email
    existing_user = (
        db.query(User)
        .join(Tenant)
        .filter(User.email == request.email, Tenant.slug == tenant_slug)
        .first()
    )

    if existing_user:
        logger.warning(f"Registration failed - user already exists: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User with this email already exists"
        )

    # Create new tenant (for testing - each user gets own tenant)
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    if not tenant:
        tenant = Tenant(
            id=str(uuid4()),
            slug=tenant_slug,
            name=f"{request.name}'s Organization",
            email=request.email,
            status="active",
            meta_data={},
        )
        db.add(tenant)
        db.flush()  # Get tenant ID

    # Create user
    user = User(
        id=str(uuid4()),
        tenant_id=tenant.id,
        email=request.email,
        password_hash="",  # Will be set by set_password
        first_name=request.name.split()[0] if " " in request.name else request.name,
        last_name=request.name.split()[1] if " " in request.name else "",
        role=UserRole.OWNER if not tenant.users else UserRole.MEMBER,
        is_active=True,
        email_verified=False,
        meta_data={},
    )
    user.set_password(request.password)

    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(
        "User registered successfully",
        extra={
            "user_id": user.id,
            "email": user.email,
            "tenant_id": tenant.id,
            "tenant_slug": tenant.slug,
            "role": user.role,
        },
    )

    return {
        "id": user.id,
        "email": user.email,
        "name": request.name,
        "tenant_id": tenant.id,
        "tenant_slug": tenant.slug,
        "role": user.role,
        "created_at": user.created_at.isoformat(),
    }


@app.post("/auth/login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user and return tokens (Reactive version)"""

    logger.info(
        f"Login attempt for email: {request.email}, tenant: {request.tenant_slug or 'default'}"
    )

    # Import RxPY operators for async execution
    from rx import operators as ops

    try:
        # Create reactive login stream
        login_observable = auth_service.login_stream(
            email=request.email, password=request.password, tenant_slug=request.tenant_slug, db=db
        )

        # Execute reactive pipeline and await result
        result = await login_observable.pipe(ops.to_future())

        logger.info(f"Login successful for email: {request.email}")
        return result
    except Exception as e:
        logger.warning(f"Login failed for email: {request.email}, error: {str(e)}")
        raise


@app.post("/auth/refresh")
async def refresh_token(request: RefreshRequest):
    """Refresh access token"""
    from auth.jwt_auth import refresh_access_token

    new_tokens = refresh_access_token(request.refresh_token)
    if not new_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    return new_tokens.dict()


# ============================================================================
# LATTICE ENDPOINTS (TENANT-AWARE)
# ============================================================================

from pydantic import Field  # noqa: E402


class LatticeCreateRequest(BaseModel):
    name: Optional[str] = None
    dimensions: int = Field(ge=1, le=10)
    size: int = Field(ge=2, le=100)


class LatticeResponse(BaseModel):
    id: str
    name: Optional[str]
    dimensions: int
    size: int
    vertices: int
    edges: int
    memory_kb: float
    memory_reduction: float
    created_at: datetime


@app.post("/api/lattices")
async def create_lattice(
    request: LatticeCreateRequest,
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create new lattice for tenant (Reactive version)"""

    logger.info(
        "Creating lattice",
        extra={
            "tenant_id": current_user.tenant_id,
            "user_id": current_user.sub,
            "dimensions": request.dimensions,
            "size": request.size,
            "name": request.name,
        },
    )

    # Import RxPY operators for async execution
    from rx import operators as ops

    try:
        # Create reactive lattice creation stream
        lattice_observable = lattice_service.create_lattice_stream(
            tenant_id=current_user.tenant_id,
            user_id=current_user.sub,
            dimensions=request.dimensions,
            size=request.size,
            name=request.name,
            db=db,
        )

        # Execute reactive pipeline and await result
        result = await lattice_observable.pipe(ops.to_future())

        logger.info(
            "Lattice created successfully",
            extra={
                "tenant_id": current_user.tenant_id,
                "lattice_id": result.get("id"),
                "vertices": result.get("vertices"),
                "memory_kb": result.get("memory_kb"),
            },
        )
        return result
    except Exception as e:
        logger.error(
            "Lattice creation failed",
            extra={"tenant_id": current_user.tenant_id, "error": str(e)},
            exc_info=True,
        )
        raise


@app.get("/api/lattices")
async def list_lattices(
    current_user: TokenData = Depends(get_current_user), db: Session = Depends(get_db)
):
    """List all lattices for tenant"""

    lattices = (
        db.query(TenantLattice)
        .filter_by(tenant_id=UUID(current_user.tenant_id), is_active=True)
        .all()
    )

    # Track API usage
    api_log = ApiLog(
        tenant_id=UUID(current_user.tenant_id),
        user_id=UUID(current_user.sub),
        endpoint="/api/lattices",
        method="GET",
        status_code=200,
    )
    db.add(api_log)
    db.commit()

    return [
        {
            "id": str(lattice.id)[:8],  # Return short ID
            "name": lattice.name,
            "dimensions": lattice.dimensions,
            "size": lattice.size,
            "vertices": lattice.vertices,
            "edges": lattice.edges,
            "memory_kb": float(lattice.memory_kb),
            "created_at": lattice.created_at,
        }
        for lattice in lattices
    ]


@app.delete("/api/lattices/{lattice_id}")
async def delete_lattice(
    lattice_id: str,
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete lattice"""

    # Remove from manager
    if not lattice_manager.delete_lattice(current_user.tenant_id, lattice_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lattice not found")

    # Mark as inactive in database
    # Pad lattice_id to valid UUID for query
    padded_id = UUID(lattice_id.ljust(36, "0"))
    db_lattice = (
        db.query(TenantLattice)
        .filter_by(id=padded_id, tenant_id=UUID(current_user.tenant_id))
        .first()
    )

    if db_lattice:
        db_lattice.is_active = False
        db.commit()

    return {"message": "Lattice deleted successfully"}


# ============================================================================
# PATH FINDING ENDPOINTS
# ============================================================================


class PathFindRequest(BaseModel):
    lattice_id: str
    start: list
    end: list


@app.post("/api/lattices/path")
async def find_path(
    request: PathFindRequest,
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Find shortest path in lattice"""

    # Get lattice
    lattice = lattice_manager.get_lattice(current_user.tenant_id, request.lattice_id)
    if not lattice:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lattice not found")

    # Find path
    start_time = time.perf_counter()
    try:
        start_idx = lattice._coords_to_index(request.start)
        end_idx = lattice._coords_to_index(request.end)

        if hasattr(lattice, "find_shortest_path"):
            path, distance = lattice.find_shortest_path(start_idx, end_idx)
        else:
            paths = lattice.graph.get_shortest_paths(start_idx, to=end_idx)
            path = paths[0] if paths else []
            distance = len(path) - 1 if path else float("inf")

        execution_time = (time.perf_counter() - start_time) * 1000

        # Log operation
        operation = LatticeOperation(
            tenant_id=UUID(current_user.tenant_id),
            lattice_id=UUID(request.lattice_id.ljust(36, "0")),
            operation_type="path_finding",
            parameters={"start": request.start, "end": request.end},
            result={"path_length": len(path), "distance": distance},
            execution_time_ms=int(execution_time),
            status="success",
            created_by_id=UUID(current_user.sub),
        )
        db.add(operation)

        # Track usage
        api_log = ApiLog(
            tenant_id=UUID(current_user.tenant_id),
            user_id=UUID(current_user.sub),
            endpoint="/api/lattices/path",
            method="POST",
            status_code=200,
            response_time_ms=int(execution_time),
        )
        db.add(api_log)
        db.commit()

        return {"path": path, "distance": distance, "execution_time_ms": round(execution_time, 3)}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ============================================================================
# HEALTH & STATUS ENDPOINTS
# ============================================================================


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Catalytic Computing SaaS",
        "version": "2.0.0",
        "description": "Multi-tenant platform for revolutionary lattice computing",
        "features": {
            "memory_efficiency": "28,571x reduction",
            "processing_speed": "649x improvement",
            "multi_tenancy": True,
            "gpu_acceleration": GPU_AVAILABLE,
        },
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "auth": "/auth/login",
            "tenants": "/api/tenants",
            "lattices": "/api/lattices",
        },
    }


@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint"""

    try:
        # Check database
        db.execute("SELECT 1")
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"

    # Get system stats
    tenant_count = db.query(Tenant).filter_by(status="active").count()
    user_count = db.query(User).filter_by(is_active=True).count()

    return {
        "status": "healthy",
        "database": db_status,
        "gpu_available": GPU_AVAILABLE,
        "stats": {
            "tenants": tenant_count,
            "users": user_count,
            "total_lattices": sum(len(lattices) for lattices in lattice_manager._lattices.values()),
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/health/redis")
async def redis_health_check():
    """Redis pool health check endpoint with metrics"""

    try:
        # Import redis_pool from jwt_auth (already initialized)
        from auth.jwt_auth import redis_pool

        if not redis_pool:
            return {"status": "unavailable", "message": "Redis pool not initialized"}

        # Get pool status (includes all metrics and health info)
        pool_status = redis_pool.get_pool_status()

        return {
            "status": pool_status["status"],
            "environment": pool_status["environment"],
            "pool": {
                "max_connections": pool_status["max_connections"],
                "in_use": pool_status["in_use_connections"],
                "available_connections": pool_status["available_connections"],
                "utilization_percent": pool_status["utilization_percent"],
            },
            "health": {
                "check_interval_seconds": 30,
                "retry_policy": "Exponential backoff (3 attempts)",
            },
            "warnings": pool_status.get("warnings", []),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except ImportError:
        return {"status": "unavailable", "message": "OptimizedRedisPool not available"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# LATTICE TRANSFORMATION ENDPOINTS
# ============================================================================


class TransformRequest(BaseModel):
    transformation_type: str = Field(..., description="Type of transformation: xor, rotate, scale")
    parameters: dict = Field(default_factory=dict, description="Transformation parameters")
    use_gpu: bool = Field(default=False, description="Request GPU acceleration")


@app.post("/api/lattices/{lattice_id}/transform")
async def transform_lattice(
    lattice_id: str,
    request: TransformRequest,
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Transform lattice with GPU/CPU routing"""

    # Get lattice
    lattice = lattice_manager.get_lattice(current_user.tenant_id, lattice_id)
    if not lattice:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lattice not found")

    # Validate transformation type
    valid_types = ["xor", "rotate", "scale"]
    if request.transformation_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid transformation_type. Must be one of: {', '.join(valid_types)}",
        )

    start_time = time.perf_counter()
    gpu_used = False
    result_summary = {"success": False}

    try:
        # Smart routing: Use GPU only if available and beneficial
        # GPU is beneficial for large lattices (size >= 10000 vertices)
        should_use_gpu = request.use_gpu and GPU_AVAILABLE and lattice.graph.vcount() >= 10000

        if should_use_gpu:
            try:
                # Import GPU module
                from apps.catalytic.catalytic_lattice_gpu import CatalyticLatticeGPU
                import numpy as np

                # Create GPU lattice instance
                gpu_lattice = CatalyticLatticeGPU(
                    dimensions=lattice.dimensions, size=lattice.lattice_size
                )

                # Perform transformation based on type
                if request.transformation_type == "xor":
                    # XOR transformation
                    key_str = request.parameters.get("key", "default_key")
                    data = np.random.randint(0, 256, 1000, dtype=np.uint8)
                    key = np.frombuffer(key_str.encode(), dtype=np.uint8)
                    gpu_lattice.xor_transform_gpu(data, key)
                    result_summary = {"success": True, "type": "xor", "data_size": len(data)}
                    gpu_used = True

                elif request.transformation_type == "rotate":
                    # Rotation transformation (simulated on GPU)
                    result_summary = {
                        "success": True,
                        "type": "rotate",
                        "angle": request.parameters.get("angle", 90),
                    }
                    gpu_used = True

                elif request.transformation_type == "scale":
                    # Scaling transformation (simulated on GPU)
                    result_summary = {
                        "success": True,
                        "type": "scale",
                        "factor": request.parameters.get("factor", 1.0),
                    }
                    gpu_used = True

            except Exception as e:
                # GPU failed, fall back to CPU
                print(f"GPU transformation failed, falling back to CPU: {e}")
                should_use_gpu = False

        # CPU transformation (or GPU fallback)
        if not should_use_gpu:
            if request.transformation_type == "xor":
                # CPU XOR simulation
                result_summary = {"success": True, "type": "xor", "backend": "cpu"}
            elif request.transformation_type == "rotate":
                result_summary = {
                    "success": True,
                    "type": "rotate",
                    "backend": "cpu",
                    "angle": request.parameters.get("angle", 90),
                }
            elif request.transformation_type == "scale":
                result_summary = {
                    "success": True,
                    "type": "scale",
                    "backend": "cpu",
                    "factor": request.parameters.get("factor", 1.0),
                }

        execution_time = (time.perf_counter() - start_time) * 1000

        # Log operation
        operation = LatticeOperation(
            tenant_id=UUID(current_user.tenant_id),
            lattice_id=UUID(lattice_id.ljust(36, "0")),
            operation_type=f"transform_{request.transformation_type}",
            parameters=request.parameters,
            result=result_summary,
            execution_time_ms=int(execution_time),
            status="success",
            created_by_id=UUID(current_user.sub),
        )
        db.add(operation)

        # Track API usage
        api_log = ApiLog(
            tenant_id=UUID(current_user.tenant_id),
            user_id=UUID(current_user.sub),
            endpoint=f"/api/lattices/{lattice_id}/transform",
            method="POST",
            status_code=200,
            response_time_ms=int(execution_time),
        )
        db.add(api_log)
        db.commit()

        return {
            "lattice_id": lattice_id,
            "execution_time_ms": round(execution_time, 3),
            "gpu_used": gpu_used,
            "result_summary": result_summary,
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Transformation failed: {str(e)}",
        )


# ============================================================================
# GPU STATUS ENDPOINT
# ============================================================================


@app.get("/api/gpu/status")
async def get_gpu_status(current_user: Optional[TokenData] = Depends(get_current_user)):
    """Check GPU availability and utilization"""

    try:
        if not GPU_AVAILABLE:
            return {"available": False, "backend": "None", "device_count": 0, "devices": []}

        import torch

        device_count = torch.cuda.device_count()

        # Get device information
        devices = []
        for i in range(device_count):
            props = torch.cuda.get_device_properties(i)

            # Get memory info
            total_memory = props.total_memory / (1024**2)  # Convert to MB

            # Try to get current memory usage (if available)
            try:
                import cupy as cp

                cp.cuda.Device(i).use()
                mem_info = cp.cuda.runtime.memGetInfo()
                free_memory = mem_info[0] / (1024**2)  # MB
                used_memory = total_memory - free_memory
                utilization_percent = (used_memory / total_memory) * 100
            except (AttributeError, RuntimeError, ImportError):
                # Fallback if CuPy not available or CUDA error
                allocated_memory = torch.cuda.memory_allocated(i) / (1024**2)  # MB
                used_memory = allocated_memory
                utilization_percent = (used_memory / total_memory) * 100

            devices.append(
                {
                    "id": i,
                    "name": torch.cuda.get_device_name(i),
                    "memory_total_gb": round(total_memory / 1024, 2),
                    "memory_used_mb": round(used_memory, 2),
                    "memory_total_mb": round(total_memory, 2),
                    "utilization_percent": round(utilization_percent, 1),
                }
            )

        return {
            "available": True,
            "backend": "CUDA",
            "device_count": device_count,
            "utilization_percent": devices[0]["utilization_percent"] if devices else 0,
            "memory_used_mb": devices[0]["memory_used_mb"] if devices else 0,
            "memory_total_mb": devices[0]["memory_total_mb"] if devices else 0,
            "devices": devices,
        }

    except ImportError:
        return {"available": False, "backend": "None", "device_count": 0, "devices": []}


# ============================================================================
# TEST-ONLY ENDPOINTS (for monitoring/alert testing)
# ============================================================================

TESTING_MODE = os.getenv("TESTING_MODE", "false").lower() == "true"


class ErrorRequest(BaseModel):
    error_type: str = Field(
        ..., description="HTTP error code to trigger: 400, 401, 403, 404, 500, 503"
    )


@app.post("/api/trigger-error")
async def trigger_error(request: ErrorRequest, current_user: TokenData = Depends(get_current_user)):
    """Test-only endpoint for alert testing"""

    if not TESTING_MODE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    error_type = request.error_type

    # Map error types to HTTP exceptions
    error_map = {
        "400": HTTPException(status_code=400, detail="Simulated bad request"),
        "401": HTTPException(status_code=401, detail="Simulated unauthorized"),
        "403": HTTPException(status_code=403, detail="Simulated forbidden"),
        "404": HTTPException(status_code=404, detail="Simulated not found"),
        "500": HTTPException(status_code=500, detail="Simulated server error"),
        "503": HTTPException(status_code=503, detail="Simulated service unavailable"),
    }

    if error_type in error_map:
        raise error_map[error_type]
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid error_type. Must be one of: {', '.join(error_map.keys())}",
        )


@app.get("/api/slow-endpoint")
async def slow_endpoint(
    delay_seconds: int = 3, current_user: TokenData = Depends(get_current_user)
):
    """Test-only endpoint for latency testing"""

    if not TESTING_MODE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    # Limit delay to prevent abuse
    delay_seconds = min(max(delay_seconds, 0), 30)

    # Artificial delay
    await asyncio.sleep(delay_seconds)

    return {"delayed_seconds": delay_seconds, "message": "Request completed after delay"}


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        workers=int(os.getenv("WORKERS", "4")),
    )
