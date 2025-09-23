"""
Tenant Management API for Catalytic Computing SaaS
Handles tenant registration, user management, and subscriptions
"""

import os
from typing import List, Optional
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

# Import auth components
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.jwt_auth import (
    create_token_pair, hash_password, verify_password,
    TokenResponse, generate_api_key
)
from auth.middleware import (
    get_current_user, get_current_active_user, require_admin,
    get_tenant_id, TokenData
)

# Import database models
from database.models import (
    Tenant, TenantStatus, User, UserRole, TenantSubscription,
    SubscriptionStatus, SubscriptionPlan, ApiKey, UsageMetric,
    TenantLattice
)

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class TenantRegistration(BaseModel):
    """Tenant registration request"""
    company_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    domain: Optional[str] = None
    plan_code: str = "free"  # Default to free plan

    @validator('password')
    def validate_password(cls, v):
        """Ensure password meets security requirements"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class TenantResponse(BaseModel):
    """Tenant response model"""
    id: UUID
    slug: str
    name: str
    email: str
    domain: Optional[str]
    status: str
    subscription_plan: str
    created_at: datetime

    class Config:
        orm_mode = True

class UserCreate(BaseModel):
    """User creation request"""
    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    role: UserRole = UserRole.MEMBER

class UserUpdate(BaseModel):
    """User update request"""
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

class UserResponse(BaseModel):
    """User response model"""
    id: UUID
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    role: str
    is_active: bool
    email_verified: bool
    last_login: Optional[datetime]
    created_at: datetime

    class Config:
        orm_mode = True

class SubscriptionUpdate(BaseModel):
    """Subscription update request"""
    plan_code: str
    payment_method: Optional[str] = None

class ApiKeyCreate(BaseModel):
    """API key creation request"""
    name: str = Field(..., min_length=1, max_length=255)
    permissions: List[str] = []
    expires_in_days: Optional[int] = Field(None, gt=0, le=365)

class ApiKeyResponse(BaseModel):
    """API key response"""
    id: UUID
    name: str
    key: str  # Only returned on creation
    key_prefix: str
    permissions: List[str]
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        orm_mode = True

class UsageStatsResponse(BaseModel):
    """Usage statistics response"""
    period_start: datetime
    period_end: datetime
    api_calls: int
    lattices_created: int
    lattices_active: int
    storage_used_mb: float
    bandwidth_used_mb: float
    cost_estimate: float

# ============================================================================
# TENANT API ROUTER
# ============================================================================

router = APIRouter(prefix="/api/tenants", tags=["Tenants"])

def get_db():
    """Get database session - placeholder for actual implementation"""
    # This would be replaced with actual database session
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/catalytic_saas")
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/register", response_model=dict)
async def register_tenant(
    registration: TenantRegistration,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Register a new tenant with owner user"""

    try:
        # Generate unique slug from company name
        slug = registration.company_name.lower().replace(" ", "-").replace(".", "")
        slug = f"{slug}-{str(uuid4())[:8]}"

        # Create tenant
        tenant = Tenant(
            slug=slug,
            name=registration.company_name,
            email=registration.email,
            domain=registration.domain,
            status=TenantStatus.ACTIVE
        )
        db.add(tenant)
        db.flush()  # Get tenant ID

        # Get subscription plan
        plan = db.query(SubscriptionPlan).filter_by(
            code=registration.plan_code,
            is_active=True
        ).first()

        if not plan:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid plan code: {registration.plan_code}"
            )

        # Create subscription
        subscription = TenantSubscription(
            tenant_id=tenant.id,
            plan_id=plan.id,
            status=SubscriptionStatus.TRIAL if plan.code != "free" else SubscriptionStatus.ACTIVE,
            trial_ends_at=datetime.utcnow() + timedelta(days=14) if plan.code != "free" else None,
            current_period_end=datetime.utcnow() + timedelta(days=30)
        )
        db.add(subscription)

        # Create owner user
        owner = User(
            tenant_id=tenant.id,
            email=registration.email,
            first_name=registration.first_name,
            last_name=registration.last_name,
            role=UserRole.OWNER,
            is_active=True
        )
        owner.set_password(registration.password)
        db.add(owner)

        # Commit transaction
        db.commit()

        # Create tokens
        tokens = create_token_pair(
            user_id=str(owner.id),
            tenant_id=str(tenant.id),
            email=owner.email,
            role=owner.role
        )

        # Send welcome email in background
        background_tasks.add_task(
            send_welcome_email,
            registration.email,
            registration.first_name,
            tenant.slug
        )

        return {
            "tenant": {
                "id": str(tenant.id),
                "slug": tenant.slug,
                "name": tenant.name,
                "subscription_plan": plan.name
            },
            "user": {
                "id": str(owner.id),
                "email": owner.email,
                "role": owner.role
            },
            "tokens": tokens.dict()
        }

    except IntegrityError as e:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Registration failed: {str(e)}"
        )

@router.get("/current", response_model=TenantResponse)
async def get_current_tenant(
    current_user: TokenData = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get current tenant information"""

    tenant = db.query(Tenant).filter_by(
        id=UUID(current_user.tenant_id),
        status=TenantStatus.ACTIVE
    ).first()

    if not tenant:
        raise HTTPException(
            status_code=404,
            detail="Tenant not found"
        )

    # Get subscription plan name
    subscription = tenant.current_subscription
    plan_name = subscription.plan.name if subscription else "None"

    return TenantResponse(
        id=tenant.id,
        slug=tenant.slug,
        name=tenant.name,
        email=tenant.email,
        domain=tenant.domain,
        status=tenant.status,
        subscription_plan=plan_name,
        created_at=tenant.created_at
    )

@router.put("/current")
async def update_tenant(
    updates: dict,
    current_user: TokenData = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update tenant information"""

    tenant = db.query(Tenant).filter_by(
        id=UUID(current_user.tenant_id)
    ).first()

    if not tenant:
        raise HTTPException(
            status_code=404,
            detail="Tenant not found"
        )

    # Update allowed fields
    allowed_fields = ["name", "domain", "metadata"]
    for field, value in updates.items():
        if field in allowed_fields:
            setattr(tenant, field, value)

    try:
        db.commit()
        return {"message": "Tenant updated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=f"Update failed: {str(e)}"
        )

# ============================================================================
# USER MANAGEMENT
# ============================================================================

@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: TokenData = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create new user in tenant"""

    # Check if email already exists in tenant
    existing = db.query(User).filter_by(
        tenant_id=UUID(current_user.tenant_id),
        email=user_data.email
    ).first()

    if existing:
        raise HTTPException(
            status_code=400,
            detail="User with this email already exists"
        )

    # Create user
    user = User(
        tenant_id=UUID(current_user.tenant_id),
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        role=user_data.role,
        is_active=True
    )
    user.set_password(user_data.password)

    try:
        db.add(user)
        db.commit()
        db.refresh(user)

        return UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            is_active=user.is_active,
            email_verified=user.email_verified,
            last_login=user.last_login,
            created_at=user.created_at
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"User creation failed: {str(e)}"
        )

@router.get("/users", response_model=List[UserResponse])
async def list_users(
    current_user: TokenData = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """List all users in tenant"""

    users = db.query(User).filter_by(
        tenant_id=UUID(current_user.tenant_id)
    ).offset(skip).limit(limit).all()

    return [
        UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            is_active=user.is_active,
            email_verified=user.email_verified,
            last_login=user.last_login,
            created_at=user.created_at
        )
        for user in users
    ]

@router.put("/users/{user_id}")
async def update_user(
    user_id: UUID,
    updates: UserUpdate,
    current_user: TokenData = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update user information"""

    user = db.query(User).filter_by(
        id=user_id,
        tenant_id=UUID(current_user.tenant_id)
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Prevent demoting the last owner
    if updates.role and user.role == UserRole.OWNER:
        owner_count = db.query(User).filter_by(
            tenant_id=UUID(current_user.tenant_id),
            role=UserRole.OWNER
        ).count()

        if owner_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot demote the last owner"
            )

    # Apply updates
    for field, value in updates.dict(exclude_unset=True).items():
        setattr(user, field, value)

    try:
        db.commit()
        return {"message": "User updated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Update failed: {str(e)}"
        )

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: UUID,
    current_user: TokenData = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete user from tenant"""

    user = db.query(User).filter_by(
        id=user_id,
        tenant_id=UUID(current_user.tenant_id)
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Prevent deleting the last owner
    if user.role == UserRole.OWNER:
        owner_count = db.query(User).filter_by(
            tenant_id=UUID(current_user.tenant_id),
            role=UserRole.OWNER
        ).count()

        if owner_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the last owner"
            )

    try:
        db.delete(user)
        db.commit()
        return {"message": "User deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Deletion failed: {str(e)}"
        )

# ============================================================================
# API KEY MANAGEMENT
# ============================================================================

@router.post("/api-keys", response_model=ApiKeyResponse)
async def create_api_key(
    key_data: ApiKeyCreate,
    current_user: TokenData = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create new API key for tenant"""

    # Generate API key
    api_key, key_hash = generate_api_key(
        tenant_id=current_user.tenant_id,
        name=key_data.name,
        permissions=key_data.permissions
    )

    # Calculate expiration
    expires_at = None
    if key_data.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)

    # Store in database
    key_record = ApiKey(
        tenant_id=UUID(current_user.tenant_id),
        name=key_data.name,
        key_hash=key_hash,
        key_prefix=api_key[:10],  # Store prefix for identification
        permissions=key_data.permissions,
        expires_at=expires_at,
        created_by_id=UUID(current_user.sub),
        is_active=True
    )

    try:
        db.add(key_record)
        db.commit()
        db.refresh(key_record)

        return ApiKeyResponse(
            id=key_record.id,
            name=key_record.name,
            key=api_key,  # Only returned on creation
            key_prefix=key_record.key_prefix,
            permissions=key_record.permissions,
            expires_at=key_record.expires_at,
            created_at=key_record.created_at
        )

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"API key creation failed: {str(e)}"
        )

@router.get("/api-keys")
async def list_api_keys(
    current_user: TokenData = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all API keys for tenant"""

    keys = db.query(ApiKey).filter_by(
        tenant_id=UUID(current_user.tenant_id),
        is_active=True
    ).all()

    return [
        {
            "id": str(key.id),
            "name": key.name,
            "key_prefix": key.key_prefix,
            "permissions": key.permissions,
            "last_used_at": key.last_used_at,
            "expires_at": key.expires_at,
            "created_at": key.created_at
        }
        for key in keys
    ]

@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: UUID,
    current_user: TokenData = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Revoke API key"""

    key = db.query(ApiKey).filter_by(
        id=key_id,
        tenant_id=UUID(current_user.tenant_id)
    ).first()

    if not key:
        raise HTTPException(
            status_code=404,
            detail="API key not found"
        )

    key.is_active = False

    try:
        db.commit()
        return {"message": "API key revoked successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Revocation failed: {str(e)}"
        )

# ============================================================================
# USAGE & BILLING
# ============================================================================

@router.get("/usage", response_model=UsageStatsResponse)
async def get_usage_stats(
    current_user: TokenData = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    period: str = "current"  # current, last_month, custom
):
    """Get usage statistics for tenant"""

    # Determine period
    if period == "current":
        period_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        period_end = (period_start + timedelta(days=32)).replace(day=1)
    else:
        # Handle other periods
        period_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        period_end = datetime.utcnow()

    # Get usage metrics
    api_calls = db.query(UsageMetric).filter_by(
        tenant_id=UUID(current_user.tenant_id),
        metric_type="api_calls"
    ).filter(
        UsageMetric.period_start >= period_start,
        UsageMetric.period_end <= period_end
    ).all()

    total_api_calls = sum(m.metric_value for m in api_calls)

    # Get lattice counts
    lattices_active = db.query(TenantLattice).filter_by(
        tenant_id=UUID(current_user.tenant_id),
        is_active=True
    ).count()

    lattices_created = db.query(TenantLattice).filter_by(
        tenant_id=UUID(current_user.tenant_id)
    ).filter(
        TenantLattice.created_at >= period_start,
        TenantLattice.created_at < period_end
    ).count()

    # Calculate costs (simplified)
    cost_estimate = (
        total_api_calls * 0.0001 +  # $0.0001 per API call
        lattices_active * 0.01 +     # $0.01 per active lattice per month
        lattices_created * 0.001     # $0.001 per lattice creation
    )

    return UsageStatsResponse(
        period_start=period_start,
        period_end=period_end,
        api_calls=total_api_calls,
        lattices_created=lattices_created,
        lattices_active=lattices_active,
        storage_used_mb=0.0,  # Would calculate from actual storage
        bandwidth_used_mb=0.0,  # Would calculate from actual bandwidth
        cost_estimate=round(cost_estimate, 2)
    )

@router.put("/subscription")
async def update_subscription(
    update: SubscriptionUpdate,
    current_user: TokenData = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update tenant subscription plan"""

    # Get current subscription
    subscription = db.query(TenantSubscription).filter_by(
        tenant_id=UUID(current_user.tenant_id),
        status=SubscriptionStatus.ACTIVE
    ).first()

    if not subscription:
        raise HTTPException(
            status_code=404,
            detail="No active subscription found"
        )

    # Get new plan
    new_plan = db.query(SubscriptionPlan).filter_by(
        code=update.plan_code,
        is_active=True
    ).first()

    if not new_plan:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan code: {update.plan_code}"
        )

    # Update subscription
    subscription.plan_id = new_plan.id
    subscription.updated_at = datetime.utcnow()

    try:
        db.commit()
        return {
            "message": "Subscription updated successfully",
            "new_plan": new_plan.name
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Update failed: {str(e)}"
        )

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def send_welcome_email(email: str, name: str, tenant_slug: str):
    """Send welcome email to new tenant owner"""
    # Placeholder for email service integration
    print(f"Sending welcome email to {name} at {email}")
    print(f"Tenant slug: {tenant_slug}")
    # Would integrate with email service like SendGrid, SES, etc.