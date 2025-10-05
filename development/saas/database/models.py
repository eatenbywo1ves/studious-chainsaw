"""
SQLAlchemy ORM Models for Catalytic Computing SaaS
Multi-tenant database models with tenant isolation
"""

from datetime import datetime
from typing import Optional
from uuid import uuid4
from enum import Enum

from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Date,
    ForeignKey, JSON, DECIMAL, Text, CheckConstraint, UniqueConstraint,
    Index, func
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from passlib.context import CryptContext

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Helper function to generate string UUIDs for SQLite compatibility
def generate_uuid():
    """Generate UUID as string for SQLite compatibility"""
    return str(uuid4())

# ============================================================================
# ENUMS
# ============================================================================

class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"

class SubscriptionStatus(str, Enum):
    ACTIVE = "active"
    TRIAL = "trial"
    PAST_DUE = "past_due"
    CANCELLED = "cancelled"
    EXPIRED = "expired"

class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"

class BillingStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    REFUNDED = "refunded"

# ============================================================================
# TENANT MODELS
# ============================================================================

class Tenant(Base):
    __tablename__ = 'tenants'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    slug = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    domain = Column(String(255))
    status = Column(String(20), default=TenantStatus.ACTIVE)
    meta_data = Column('metadata', JSON, default={})
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True))

    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    subscriptions = relationship("TenantSubscription", back_populates="tenant", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="tenant", cascade="all, delete-orphan")
    usage_metrics = relationship("UsageMetric", back_populates="tenant", cascade="all, delete-orphan")
    api_logs = relationship("ApiLog", back_populates="tenant", cascade="all, delete-orphan")
    billing_records = relationship("BillingRecord", back_populates="tenant", cascade="all, delete-orphan")
    lattices = relationship("TenantLattice", back_populates="tenant", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint('email', 'deleted_at', name='unique_active_email'),
        CheckConstraint("status IN ('active', 'suspended', 'deleted')", name='valid_tenant_status'),
    )

    @property
    def is_active(self) -> bool:
        return self.status == TenantStatus.ACTIVE

    @property
    def current_subscription(self) -> Optional['TenantSubscription']:
        """Get current active subscription"""
        return next((s for s in self.subscriptions if s.status == SubscriptionStatus.ACTIVE), None)

class SubscriptionPlan(Base):
    __tablename__ = 'subscription_plans'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    code = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    price_monthly = Column(DECIMAL(10, 2), nullable=False)
    price_yearly = Column(DECIMAL(10, 2))
    features = Column(JSON, nullable=False, default={})
    limits = Column(JSON, nullable=False, default={})
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    # Relationships
    subscriptions = relationship("TenantSubscription", back_populates="plan")

    def get_limit(self, key: str) -> int:
        """Get a specific limit value"""
        return self.limits.get(key, 0)

    def has_feature(self, feature: str) -> bool:
        """Check if plan has a specific feature"""
        return self.features.get(feature, False)

class TenantSubscription(Base):
    __tablename__ = 'tenant_subscriptions'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    plan_id = Column(String(36), ForeignKey('subscription_plans.id'), nullable=False)
    status = Column(String(20), default=SubscriptionStatus.ACTIVE)
    trial_ends_at = Column(DateTime(timezone=True))
    current_period_start = Column(DateTime(timezone=True), default=func.now())
    current_period_end = Column(DateTime(timezone=True))
    cancel_at_period_end = Column(Boolean, default=False)
    cancelled_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    # Relationships
    tenant = relationship("Tenant", back_populates="subscriptions")
    plan = relationship("SubscriptionPlan", back_populates="subscriptions")
    billing_records = relationship("BillingRecord", back_populates="subscription")

    __table_args__ = (
        UniqueConstraint('tenant_id', 'status', name='one_active_subscription'),
        CheckConstraint("status IN ('active', 'trial', 'past_due', 'cancelled', 'expired')",
                       name='valid_subscription_status'),
    )

    @property
    def is_trial(self) -> bool:
        return self.status == SubscriptionStatus.TRIAL and self.trial_ends_at and self.trial_ends_at > datetime.utcnow()

    @property
    def is_active(self) -> bool:
        return self.status == SubscriptionStatus.ACTIVE or self.is_trial

# ============================================================================
# AUTHENTICATION MODELS
# ============================================================================

class User(Base):
    __tablename__ = 'users'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    email = Column(String(255), nullable=False)
    username = Column(String(100))
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100))
    last_name = Column(String(100))
    role = Column(String(50), default=UserRole.MEMBER)
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    last_login = Column(DateTime(timezone=True))
    meta_data = Column('metadata', JSON, default={})
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    created_api_keys = relationship("ApiKey", back_populates="created_by")
    created_lattices = relationship("TenantLattice", back_populates="created_by")
    lattice_operations = relationship("LatticeOperation", back_populates="created_by")
    api_logs = relationship("ApiLog", back_populates="user")

    __table_args__ = (
        UniqueConstraint('tenant_id', 'email', name='unique_email_per_tenant'),
        CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer')", name='valid_user_role'),
        Index('idx_users_email', 'email'),
        Index('idx_users_tenant_id', 'tenant_id'),
    )

    def set_password(self, password: str):
        """Hash and set password"""
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(password, self.password_hash)

    @property
    def full_name(self) -> str:
        """Get user's full name"""
        parts = filter(None, [self.first_name, self.last_name])
        return " ".join(parts) or self.email

    @property
    def is_admin(self) -> bool:
        """Check if user has admin privileges"""
        return self.role in [UserRole.OWNER, UserRole.ADMIN]

class ApiKey(Base):
    __tablename__ = 'api_keys'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    key_prefix = Column(String(10), nullable=False)
    permissions = Column(JSON, default=[])
    last_used_at = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    created_by_id = Column(String(36), ForeignKey('users.id'))
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    # Relationships
    tenant = relationship("Tenant", back_populates="api_keys")
    created_by = relationship("User", back_populates="created_api_keys")
    api_logs = relationship("ApiLog", back_populates="api_key")

    __table_args__ = (
        Index('idx_api_keys_tenant_id', 'tenant_id'),
        Index('idx_api_keys_key_prefix', 'key_prefix'),
    )

    @property
    def is_expired(self) -> bool:
        """Check if API key is expired"""
        return self.expires_at and self.expires_at < datetime.utcnow()

    def has_permission(self, permission: str) -> bool:
        """Check if API key has specific permission"""
        return permission in self.permissions if self.permissions else False

class Session(Base):
    __tablename__ = 'sessions'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = Column(String(255), nullable=False, unique=True)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())

    # Relationships
    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index('idx_sessions_user_id', 'user_id'),
        Index('idx_sessions_expires', 'expires_at'),
    )

    @property
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return self.expires_at < datetime.utcnow()

# ============================================================================
# USAGE & BILLING MODELS
# ============================================================================

class UsageMetric(Base):
    __tablename__ = 'usage_metrics'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    metric_type = Column(String(50), nullable=False)
    metric_value = Column(Integer, nullable=False, default=0)
    meta_data = Column('metadata', JSON, default={})
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())

    # Relationships
    tenant = relationship("Tenant", back_populates="usage_metrics")

    __table_args__ = (
        UniqueConstraint('tenant_id', 'metric_type', 'period_start', 'period_end',
                         name='unique_metric_per_period'),
        Index('idx_usage_metrics_tenant_period', 'tenant_id', 'period_start', 'period_end'),
    )

class ApiLog(Base):
    __tablename__ = 'api_logs'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(String(36), ForeignKey('users.id'))
    api_key_id = Column(String(36), ForeignKey('api_keys.id'))
    endpoint = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer)
    response_time_ms = Column(Integer)
    request_size_bytes = Column(Integer)
    response_size_bytes = Column(Integer)
    ip_address = Column(String(45))
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), default=func.now())

    # Relationships
    tenant = relationship("Tenant", back_populates="api_logs")
    user = relationship("User", back_populates="api_logs")
    api_key = relationship("ApiKey", back_populates="api_logs")

    __table_args__ = (
        Index('idx_api_logs_tenant_created', 'tenant_id', 'created_at'),
        Index('idx_api_logs_endpoint', 'endpoint', 'created_at'),
    )

class BillingRecord(Base):
    __tablename__ = 'billing_records'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    subscription_id = Column(String(36), ForeignKey('tenant_subscriptions.id'))
    amount = Column(DECIMAL(10, 2), nullable=False)
    currency = Column(String(3), default='USD')
    description = Column(Text)
    status = Column(String(20), default=BillingStatus.PENDING)
    payment_method = Column(String(50))
    invoice_number = Column(String(100), unique=True)
    due_date = Column(Date)
    paid_at = Column(DateTime(timezone=True))
    meta_data = Column('metadata', JSON, default={})
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    # Relationships
    tenant = relationship("Tenant", back_populates="billing_records")
    subscription = relationship("TenantSubscription", back_populates="billing_records")

    __table_args__ = (
        CheckConstraint("status IN ('pending', 'paid', 'failed', 'refunded')",
                       name='valid_billing_status'),
        Index('idx_billing_records_tenant', 'tenant_id', 'created_at'),
    )

# ============================================================================
# LATTICE RESOURCE MODELS
# ============================================================================

class TenantLattice(Base):
    __tablename__ = 'tenant_lattices'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    name = Column(String(255))
    dimensions = Column(Integer, nullable=False)
    size = Column(Integer, nullable=False)
    vertices = Column(Integer, nullable=False)
    edges = Column(Integer, nullable=False)
    memory_kb = Column(DECIMAL(10, 2))
    memory_reduction = Column(DECIMAL(10, 2))
    meta_data = Column('metadata', JSON, default={})
    is_active = Column(Boolean, default=True)
    created_by_id = Column(String(36), ForeignKey('users.id'))
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    last_accessed_at = Column(DateTime(timezone=True), default=func.now())

    # Relationships
    tenant = relationship("Tenant", back_populates="lattices")
    created_by = relationship("User", back_populates="created_lattices")
    operations = relationship("LatticeOperation", back_populates="lattice", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("dimensions > 0 AND dimensions <= 10", name='valid_dimensions'),
        CheckConstraint("size > 0", name='valid_size'),
        Index('idx_tenant_lattices_tenant', 'tenant_id', 'is_active'),
    )

class LatticeOperation(Base):
    __tablename__ = 'lattice_operations'

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    lattice_id = Column(String(36), ForeignKey('tenant_lattices.id', ondelete='CASCADE'))
    operation_type = Column(String(50), nullable=False)
    parameters = Column(JSON, default={})
    result = Column(JSON, default={})
    execution_time_ms = Column(Integer)
    status = Column(String(20), default='success')
    error_message = Column(Text)
    created_by_id = Column(String(36), ForeignKey('users.id'))
    created_at = Column(DateTime(timezone=True), default=func.now())

    # Relationships
    tenant = relationship("Tenant")
    lattice = relationship("TenantLattice", back_populates="operations")
    created_by = relationship("User", back_populates="lattice_operations")

    __table_args__ = (
        Index('idx_lattice_operations_tenant', 'tenant_id', 'created_at'),
    )
