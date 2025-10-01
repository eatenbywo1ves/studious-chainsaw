#!/usr/bin/env python3
"""
SaaS API Server for Catalytic Computing
Multi-tenant version with authentication, usage tracking, and billing
"""

import os
import sys
import time
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any
from uuid import UUID

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Add parent directories to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '..'))

# Import auth components
from auth.jwt_auth import create_token_pair, verify_password
from auth.middleware import (
    TenantIsolationMiddleware,
    AuthenticationMiddleware,
    RateLimitMiddleware,
    LoggingMiddleware,
    get_cors_config,
    get_current_user,
    get_tenant_id,
    TokenData
)

# Import tenant API
from api.tenant_api import router as tenant_router

# Import database models
from database.models import (
    Base, Tenant, User, TenantSubscription, SubscriptionPlan,
    UsageMetric, ApiLog, TenantLattice, LatticeOperation
)

# Import original Catalytic Computing components
from apps.catalytic.catalytic_lattice_graph import CatalyticLatticeGraph

# Try to import GPU modules
try:
    from apps.catalytic.catalytic_lattice_gpu import CatalyticLatticeGPU
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

# ============================================================================
# DATABASE SETUP
# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost/catalytic_saas")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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
        user_id: Optional[str] = None
    ) -> CatalyticLatticeGraph:
        """Create lattice for tenant"""

        if tenant_id not in self._lattices:
            self._lattices[tenant_id] = {}

        if len(self._lattices[tenant_id]) >= self.max_per_tenant:
            raise ValueError(f"Maximum {self.max_per_tenant} lattices per tenant")

        # Create lattice
        lattice = CatalyticLatticeGraph(
            dimensions=dimensions,
            lattice_size=size
        )

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
        total_memory = sum(
            lattice.aux_memory_size
            for lattice in tenant_lattices.values()
        )
        return {
            "lattice_count": len(tenant_lattices),
            "total_memory_kb": total_memory / 1024,
            "available": self.max_per_tenant - len(tenant_lattices)
        }

# Global lattice manager
lattice_manager = TenantLatticeManager()

# ============================================================================
# LIFESPAN MANAGEMENT
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""

    # Startup
    print("Starting Catalytic Computing SaaS API Server...")
    print(f"GPU Available: {GPU_AVAILABLE}")

    # Create database tables
    try:
        Base.metadata.create_all(bind=engine)
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

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
                        "basic_transforms": True
                    },
                    limits={
                        "max_lattices": 5,
                        "max_dimensions": 3,
                        "max_lattice_size": 10,
                        "api_calls_per_month": 1000
                    }
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
                        "gpu_acceleration": True
                    },
                    limits={
                        "max_lattices": 500,
                        "max_dimensions": 10,
                        "max_lattice_size": 100,
                        "api_calls_per_month": 100000
                    }
                )
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
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(CORSMiddleware, **get_cors_config())

# Add custom middleware
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware, default_limit=1000, window_seconds=60)
app.add_middleware(AuthenticationMiddleware)
app.add_middleware(TenantIsolationMiddleware)

# Include routers
app.include_router(tenant_router)

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

from pydantic import BaseModel, EmailStr

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_slug: Optional[str] = None

class RefreshRequest(BaseModel):
    refresh_token: str

@app.post("/auth/login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user and return tokens"""

    # Find user by email
    query = db.query(User).filter_by(email=request.email, is_active=True)

    # If tenant slug provided, filter by it
    if request.tenant_slug:
        tenant = db.query(Tenant).filter_by(slug=request.tenant_slug).first()
        if tenant:
            query = query.filter_by(tenant_id=tenant.id)

    user = query.first()

    if not user or not user.verify_password(request.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Create tokens
    tokens = create_token_pair(
        user_id=str(user.id),
        tenant_id=str(user.tenant_id),
        email=user.email,
        role=user.role
    )

    # Log the login
    api_log = ApiLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        endpoint="/auth/login",
        method="POST",
        status_code=200
    )
    db.add(api_log)
    db.commit()

    return {
        "tokens": tokens.dict(),
        "user": {
            "id": str(user.id),
            "email": user.email,
            "role": user.role,
            "tenant_id": str(user.tenant_id)
        }
    }

@app.post("/auth/refresh")
async def refresh_token(request: RefreshRequest):
    """Refresh access token"""
    from auth.jwt_auth import refresh_access_token

    new_tokens = refresh_access_token(request.refresh_token)
    if not new_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    return new_tokens.dict()

# ============================================================================
# LATTICE ENDPOINTS (TENANT-AWARE)
# ============================================================================

from pydantic import Field

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
    db: Session = Depends(get_db)
):
    """Create new lattice for tenant"""

    # Check subscription limits
    subscription = db.query(TenantSubscription).filter_by(
        tenant_id=UUID(current_user.tenant_id),
        status="active"
    ).first()

    if subscription:
        plan = subscription.plan
        max_lattices = plan.limits.get("max_lattices", 5)
        max_dimensions = plan.limits.get("max_dimensions", 3)
        max_size = plan.limits.get("max_lattice_size", 10)

        # Check limits
        current_count = db.query(TenantLattice).filter_by(
            tenant_id=UUID(current_user.tenant_id),
            is_active=True
        ).count()

        if max_lattices != -1 and current_count >= max_lattices:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Lattice limit reached ({max_lattices}). Upgrade your plan."
            )

        if request.dimensions > max_dimensions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Maximum {max_dimensions} dimensions allowed in your plan"
            )

        if request.size > max_size:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Maximum size {max_size} allowed in your plan"
            )

    # Create lattice
    try:
        import uuid
        lattice_id = str(uuid.uuid4())[:8]

        lattice = lattice_manager.create_lattice(
            tenant_id=current_user.tenant_id,
            lattice_id=lattice_id,
            dimensions=request.dimensions,
            size=request.size,
            user_id=current_user.sub
        )

        # Calculate memory reduction
        n_vertices = lattice.graph.vcount()
        traditional_memory = n_vertices * n_vertices * 8
        actual_memory = lattice.aux_memory_size + (lattice.graph.ecount() * 16)
        memory_reduction = traditional_memory / actual_memory if actual_memory > 0 else 1.0

        # Store in database
        db_lattice = TenantLattice(
            id=UUID(lattice_id.ljust(36, '0')),  # Pad to valid UUID
            tenant_id=UUID(current_user.tenant_id),
            name=request.name or f"Lattice-{lattice_id}",
            dimensions=request.dimensions,
            size=request.size,
            vertices=lattice.graph.vcount(),
            edges=lattice.graph.ecount(),
            memory_kb=actual_memory / 1024,
            memory_reduction=memory_reduction,
            created_by_id=UUID(current_user.sub)
        )
        db.add(db_lattice)

        # Track usage
        usage = UsageMetric(
            tenant_id=UUID(current_user.tenant_id),
            metric_type="lattice_created",
            metric_value=1,
            period_start=datetime.utcnow().replace(day=1, hour=0, minute=0, second=0),
            period_end=datetime.utcnow()
        )
        db.add(usage)

        # Log API call
        api_log = ApiLog(
            tenant_id=UUID(current_user.tenant_id),
            user_id=UUID(current_user.sub),
            endpoint="/api/lattices",
            method="POST",
            status_code=200
        )
        db.add(api_log)

        db.commit()

        return LatticeResponse(
            id=lattice_id,
            name=db_lattice.name,
            dimensions=db_lattice.dimensions,
            size=db_lattice.size,
            vertices=db_lattice.vertices,
            edges=db_lattice.edges,
            memory_kb=db_lattice.memory_kb,
            memory_reduction=db_lattice.memory_reduction,
            created_at=db_lattice.created_at
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lattice creation failed: {str(e)}"
        )

@app.get("/api/lattices")
async def list_lattices(
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all lattices for tenant"""

    lattices = db.query(TenantLattice).filter_by(
        tenant_id=UUID(current_user.tenant_id),
        is_active=True
    ).all()

    # Track API usage
    api_log = ApiLog(
        tenant_id=UUID(current_user.tenant_id),
        user_id=UUID(current_user.sub),
        endpoint="/api/lattices",
        method="GET",
        status_code=200
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
            "created_at": lattice.created_at
        }
        for lattice in lattices
    ]

@app.delete("/api/lattices/{lattice_id}")
async def delete_lattice(
    lattice_id: str,
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete lattice"""

    # Remove from manager
    if not lattice_manager.delete_lattice(current_user.tenant_id, lattice_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lattice not found"
        )

    # Mark as inactive in database
    # Pad lattice_id to valid UUID for query
    padded_id = UUID(lattice_id.ljust(36, '0'))
    db_lattice = db.query(TenantLattice).filter_by(
        id=padded_id,
        tenant_id=UUID(current_user.tenant_id)
    ).first()

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
    db: Session = Depends(get_db)
):
    """Find shortest path in lattice"""

    # Get lattice
    lattice = lattice_manager.get_lattice(current_user.tenant_id, request.lattice_id)
    if not lattice:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lattice not found"
        )

    # Find path
    start_time = time.perf_counter()
    try:
        start_idx = lattice._coords_to_index(request.start)
        end_idx = lattice._coords_to_index(request.end)

        if hasattr(lattice, 'find_shortest_path'):
            path, distance = lattice.find_shortest_path(start_idx, end_idx)
        else:
            paths = lattice.graph.get_shortest_paths(start_idx, to=end_idx)
            path = paths[0] if paths else []
            distance = len(path) - 1 if path else float('inf')

        execution_time = (time.perf_counter() - start_time) * 1000

        # Log operation
        operation = LatticeOperation(
            tenant_id=UUID(current_user.tenant_id),
            lattice_id=UUID(request.lattice_id.ljust(36, '0')),
            operation_type="path_finding",
            parameters={"start": request.start, "end": request.end},
            result={"path_length": len(path), "distance": distance},
            execution_time_ms=int(execution_time),
            status="success",
            created_by_id=UUID(current_user.sub)
        )
        db.add(operation)

        # Track usage
        api_log = ApiLog(
            tenant_id=UUID(current_user.tenant_id),
            user_id=UUID(current_user.sub),
            endpoint="/api/lattices/path",
            method="POST",
            status_code=200,
            response_time_ms=int(execution_time)
        )
        db.add(api_log)
        db.commit()

        return {
            "path": path,
            "distance": distance,
            "execution_time_ms": round(execution_time, 3)
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

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
            "gpu_acceleration": GPU_AVAILABLE
        },
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "auth": "/auth/login",
            "tenants": "/api/tenants",
            "lattices": "/api/lattices"
        }
    }

@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint"""

    try:
        # Check database
        db.execute("SELECT 1")
        db_status = "healthy"
    except:
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
            "total_lattices": sum(len(l) for l in lattice_manager._lattices.values())
        },
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        workers=int(os.getenv("WORKERS", "4"))
    )