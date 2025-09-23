"""
Tenant Management System

Core tenant lifecycle and management with:
- Tenant creation and provisioning
- Status management and lifecycle
- Plan management and upgrades
- Metadata and configuration
- Cross-tenant isolation enforcement
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from libraries.database import DatabaseManager


class TenantStatus(Enum):
    """Tenant lifecycle status"""

    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    ARCHIVED = "archived"


class TenantPlan(Enum):
    """Tenant subscription plans"""

    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


@dataclass
class TenantMetadata:
    """Tenant metadata and settings"""

    organization_name: str
    industry: Optional[str] = None
    country: str = "US"
    timezone: str = "UTC"
    data_residency: str = "US"
    compliance_requirements: List[str] = field(default_factory=list)
    custom_settings: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "organization_name": self.organization_name,
            "industry": self.industry,
            "country": self.country,
            "timezone": self.timezone,
            "data_residency": self.data_residency,
            "compliance_requirements": self.compliance_requirements,
            "custom_settings": self.custom_settings,
        }


@dataclass
class Tenant:
    """Tenant representation"""

    tenant_id: str
    name: str
    slug: str  # URL-friendly identifier
    status: TenantStatus
    plan: TenantPlan
    metadata: TenantMetadata

    # Database isolation
    isolation_strategy: str = "schema_per_tenant"
    database_name: Optional[str] = None
    schema_name: Optional[str] = None

    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    activated_at: Optional[datetime] = None
    suspended_at: Optional[datetime] = None

    # Contacts
    primary_contact_email: Optional[str] = None
    admin_users: List[str] = field(default_factory=list)

    # Features and limits
    enabled_features: Set[str] = field(default_factory=set)
    feature_flags: Dict[str, bool] = field(default_factory=dict)

    def is_active(self) -> bool:
        """Check if tenant is active"""
        return self.status == TenantStatus.ACTIVE

    def can_access_feature(self, feature: str) -> bool:
        """Check if tenant can access feature"""
        if feature in self.enabled_features:
            return True
        return self.feature_flags.get(feature, False)

    def to_dict(self, include_metadata: bool = True) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "slug": self.slug,
            "status": self.status.value,
            "plan": self.plan.value,
            "isolation_strategy": self.isolation_strategy,
            "database_name": self.database_name,
            "schema_name": self.schema_name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "activated_at": (
                self.activated_at.isoformat() if self.activated_at else None
            ),
            "suspended_at": (
                self.suspended_at.isoformat() if self.suspended_at else None
            ),
            "primary_contact_email": self.primary_contact_email,
            "admin_users": self.admin_users,
            "enabled_features": list(self.enabled_features),
            "feature_flags": self.feature_flags,
        }

        if include_metadata:
            result["metadata"] = self.metadata.to_dict()

        return result


@dataclass
class TenantProvisioningRequest:
    """Tenant provisioning request"""

    name: str
    slug: str
    plan: TenantPlan
    metadata: TenantMetadata
    admin_email: str
    isolation_strategy: str = "schema_per_tenant"
    enable_features: List[str] = field(default_factory=list)

    def validate(self) -> List[str]:
        """Validate provisioning request"""
        errors = []

        if not self.name or len(self.name.strip()) < 2:
            errors.append("Tenant name must be at least 2 characters")

        if not self.slug or len(self.slug) < 3:
            errors.append("Tenant slug must be at least 3 characters")

        if not self.slug.replace("-", "").replace("_", "").isalnum():
            errors.append(
                "Tenant slug must contain only alphanumeric characters, hyphens, and underscores"
            )

        if "@" not in self.admin_email:
            errors.append("Valid admin email is required")

        if self.isolation_strategy not in [
            "schema_per_tenant",
            "database_per_tenant",
            "row_level_security",
        ]:
            errors.append("Invalid isolation strategy")

        return errors


class TenantManager:
    """
    Complete tenant management system
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

        # Storage (in production, use proper database)
        self.tenants: Dict[str, Tenant] = {}
        self.slug_to_tenant: Dict[str, str] = {}  # slug -> tenant_id

        # Provisioning queue
        self.provisioning_queue: List[TenantProvisioningRequest] = []

        # Available features
        self.available_features = {
            "advanced_analytics",
            "custom_integrations",
            "priority_support",
            "sso_integration",
            "audit_logs",
            "api_access",
            "webhook_notifications",
            "custom_branding",
            "data_export",
            "compliance_reporting",
        }

        # Plan features mapping
        self.plan_features = {
            TenantPlan.FREE: {"api_access"},
            TenantPlan.STARTER: {"api_access", "webhook_notifications", "data_export"},
            TenantPlan.PROFESSIONAL: {
                "api_access",
                "webhook_notifications",
                "data_export",
                "advanced_analytics",
                "audit_logs",
                "sso_integration",
            },
            TenantPlan.ENTERPRISE: {
                "api_access",
                "webhook_notifications",
                "data_export",
                "advanced_analytics",
                "audit_logs",
                "sso_integration",
                "custom_integrations",
                "priority_support",
                "custom_branding",
                "compliance_reporting",
            },
            TenantPlan.CUSTOM: self.available_features,  # All features
        }

    async def initialize(self):
        """Initialize tenant management system"""
        await self._create_tenant_tables()
        await self._load_existing_tenants()

    async def _create_tenant_tables(self):
        """Create tenant management tables"""
        async with self.db_manager.get_connection() as conn:
            # Tenants table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id UUID PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    slug VARCHAR(100) UNIQUE NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    plan VARCHAR(50) NOT NULL,
                    isolation_strategy VARCHAR(50) NOT NULL,
                    database_name VARCHAR(100),
                    schema_name VARCHAR(100),
                    metadata JSONB,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    activated_at TIMESTAMP WITH TIME ZONE,
                    suspended_at TIMESTAMP WITH TIME ZONE,
                    primary_contact_email VARCHAR(255),
                    admin_users JSONB DEFAULT '[]'::jsonb,
                    enabled_features JSONB DEFAULT '[]'::jsonb,
                    feature_flags JSONB DEFAULT '{}'::jsonb
                )
            """
            )

            # Tenant events for audit trail
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenant_events (
                    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    tenant_id UUID REFERENCES tenants(tenant_id),
                    event_type VARCHAR(100) NOT NULL,
                    event_data JSONB,
                    user_id VARCHAR(255),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """
            )

            # Create indexes
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tenant_events_tenant_id ON tenant_events(tenant_id)"
            )

    async def _load_existing_tenants(self):
        """Load existing tenants from database"""
        async with self.db_manager.get_connection() as conn:
            rows = await conn.fetch("SELECT * FROM tenants")

            for row in rows:
                tenant = self._row_to_tenant(row)
                self.tenants[tenant.tenant_id] = tenant
                self.slug_to_tenant[tenant.slug] = tenant.tenant_id

    def _row_to_tenant(self, row) -> Tenant:
        """Convert database row to Tenant object"""
        metadata_dict = row["metadata"] or {}
        metadata = TenantMetadata(
            organization_name=metadata_dict.get("organization_name", ""),
            industry=metadata_dict.get("industry"),
            country=metadata_dict.get("country", "US"),
            timezone=metadata_dict.get("timezone", "UTC"),
            data_residency=metadata_dict.get("data_residency", "US"),
            compliance_requirements=metadata_dict.get("compliance_requirements", []),
            custom_settings=metadata_dict.get("custom_settings", {}),
        )

        return Tenant(
            tenant_id=row["tenant_id"],
            name=row["name"],
            slug=row["slug"],
            status=TenantStatus(row["status"]),
            plan=TenantPlan(row["plan"]),
            metadata=metadata,
            isolation_strategy=row["isolation_strategy"],
            database_name=row["database_name"],
            schema_name=row["schema_name"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            activated_at=row["activated_at"],
            suspended_at=row["suspended_at"],
            primary_contact_email=row["primary_contact_email"],
            admin_users=row["admin_users"] or [],
            enabled_features=set(row["enabled_features"] or []),
            feature_flags=row["feature_flags"] or {},
        )

    async def create_tenant(self, request: TenantProvisioningRequest) -> Dict[str, Any]:
        """Create new tenant"""
        # Validate request
        errors = request.validate()
        if errors:
            return {"success": False, "errors": errors}

        # Check for existing slug
        if request.slug in self.slug_to_tenant:
            return {"success": False, "errors": ["Tenant slug already exists"]}

        # Generate tenant ID
        tenant_id = str(uuid.uuid4())

        # Determine enabled features based on plan
        enabled_features = self.plan_features.get(request.plan, set()).copy()
        enabled_features.update(request.enable_features)

        # Generate schema/database name based on isolation strategy
        schema_name = None
        database_name = None

        if request.isolation_strategy == "schema_per_tenant":
            schema_name = f"tenant_{request.slug}"
        elif request.isolation_strategy == "database_per_tenant":
            database_name = f"tenant_{request.slug}"

        # Create tenant object
        tenant = Tenant(
            tenant_id=tenant_id,
            name=request.name,
            slug=request.slug,
            status=TenantStatus.PENDING,
            plan=request.plan,
            metadata=request.metadata,
            isolation_strategy=request.isolation_strategy,
            database_name=database_name,
            schema_name=schema_name,
            primary_contact_email=request.admin_email,
            admin_users=[request.admin_email],
            enabled_features=enabled_features,
        )

        # Store in database
        await self._save_tenant(tenant)

        # Store in memory
        self.tenants[tenant_id] = tenant
        self.slug_to_tenant[request.slug] = tenant_id

        # Log tenant creation event
        await self._log_tenant_event(
            tenant_id,
            "tenant_created",
            {
                "plan": request.plan.value,
                "isolation_strategy": request.isolation_strategy,
                "admin_email": request.admin_email,
            },
        )

        # Queue for provisioning
        await self._provision_tenant_infrastructure(tenant)

        return {"success": True, "tenant_id": tenant_id, "tenant": tenant.to_dict()}

    async def _save_tenant(self, tenant: Tenant):
        """Save tenant to database"""
        async with self.db_manager.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO tenants (
                    tenant_id, name, slug, status, plan, isolation_strategy,
                    database_name, schema_name, metadata, created_at, updated_at,
                    activated_at, suspended_at, primary_contact_email,
                    admin_users, enabled_features, feature_flags
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                ON CONFLICT (tenant_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    status = EXCLUDED.status,
                    plan = EXCLUDED.plan,
                    metadata = EXCLUDED.metadata,
                    updated_at = EXCLUDED.updated_at,
                    activated_at = EXCLUDED.activated_at,
                    suspended_at = EXCLUDED.suspended_at,
                    primary_contact_email = EXCLUDED.primary_contact_email,
                    admin_users = EXCLUDED.admin_users,
                    enabled_features = EXCLUDED.enabled_features,
                    feature_flags = EXCLUDED.feature_flags
            """,
                tenant.tenant_id,
                tenant.name,
                tenant.slug,
                tenant.status.value,
                tenant.plan.value,
                tenant.isolation_strategy,
                tenant.database_name,
                tenant.schema_name,
                tenant.metadata.to_dict(),
                tenant.created_at,
                tenant.updated_at,
                tenant.activated_at,
                tenant.suspended_at,
                tenant.primary_contact_email,
                tenant.admin_users,
                list(tenant.enabled_features),
                tenant.feature_flags,
            )

    async def _provision_tenant_infrastructure(self, tenant: Tenant):
        """Provision tenant infrastructure based on isolation strategy"""
        try:
            if tenant.isolation_strategy == "schema_per_tenant":
                await self._create_tenant_schema(tenant)
            elif tenant.isolation_strategy == "database_per_tenant":
                await self._create_tenant_database(tenant)
            elif tenant.isolation_strategy == "row_level_security":
                await self._setup_row_level_security(tenant)

            # Activate tenant
            await self.activate_tenant(tenant.tenant_id)

        except Exception as e:
            # Mark tenant as failed
            tenant.status = TenantStatus.SUSPENDED
            await self._save_tenant(tenant)

            await self._log_tenant_event(
                tenant.tenant_id,
                "provisioning_failed",
                {"error": str(e), "isolation_strategy": tenant.isolation_strategy},
            )

            raise e

    async def _create_tenant_schema(self, tenant: Tenant):
        """Create dedicated schema for tenant"""
        async with self.db_manager.get_connection() as conn:
            # Create schema
            await conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{tenant.schema_name}"')

            # Create tenant-specific tables
            await self._create_tenant_tables_in_schema(conn, tenant.schema_name)

            # Set up permissions
            await conn.execute(
                f'GRANT USAGE ON SCHEMA "{tenant.schema_name}" TO tenant_user'
            )
            await conn.execute(
                f'GRANT ALL ON ALL TABLES IN SCHEMA "{tenant.schema_name}" TO tenant_user'
            )

    async def _create_tenant_database(self, tenant: Tenant):
        """Create dedicated database for tenant"""
        # This would require superuser privileges and database template
        # For now, implement basic structure
        async with self.db_manager.get_connection() as conn:
            # In production, this would create a new database
            # await conn.execute(f'CREATE DATABASE "{tenant.database_name}" WITH TEMPLATE tenant_template')

            # For now, create a schema as fallback
            schema_name = f"db_{tenant.slug}"
            await conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"')
            tenant.schema_name = schema_name
            await self._create_tenant_tables_in_schema(conn, schema_name)

    async def _setup_row_level_security(self, tenant: Tenant):
        """Set up row-level security for tenant"""
        async with self.db_manager.get_connection() as conn:
            # Enable RLS on shared tables
            shared_tables = ["agents", "tasks", "users"]

            for table in shared_tables:
                await conn.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")

                # Create policy for tenant isolation
                await conn.execute(
                    f"""
                    CREATE POLICY tenant_isolation_{table} ON {table}
                    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
                """
                )

    async def _create_tenant_tables_in_schema(self, conn, schema_name: str):
        """Create tenant-specific tables"""
        # Create basic tables for tenant
        tables = [
            f"""
            CREATE TABLE IF NOT EXISTS "{schema_name}".agents (
                agent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(255) NOT NULL,
                type VARCHAR(100) NOT NULL,
                configuration JSONB DEFAULT '{{}}'::jsonb,
                status VARCHAR(50) DEFAULT 'created',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            """,
            f"""
            CREATE TABLE IF NOT EXISTS "{schema_name}".tasks (
                task_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                agent_id UUID REFERENCES "{schema_name}".agents(agent_id),
                definition JSONB NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                priority INTEGER DEFAULT 5,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                completed_at TIMESTAMP WITH TIME ZONE
            )
            """,
            f"""
            CREATE TABLE IF NOT EXISTS "{schema_name}".events (
                event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                stream_id VARCHAR(255) NOT NULL,
                stream_version INTEGER NOT NULL,
                event_type VARCHAR(100) NOT NULL,
                event_data JSONB NOT NULL,
                metadata JSONB NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                UNIQUE(stream_id, stream_version)
            )
            """,
        ]

        for table_sql in tables:
            await conn.execute(table_sql)

    async def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID"""
        return self.tenants.get(tenant_id)

    async def get_tenant_by_slug(self, slug: str) -> Optional[Tenant]:
        """Get tenant by slug"""
        tenant_id = self.slug_to_tenant.get(slug)
        if tenant_id:
            return self.tenants.get(tenant_id)
        return None

    async def list_tenants(
        self,
        status: Optional[TenantStatus] = None,
        plan: Optional[TenantPlan] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Tenant]:
        """List tenants with optional filters"""
        tenants = list(self.tenants.values())

        if status:
            tenants = [t for t in tenants if t.status == status]

        if plan:
            tenants = [t for t in tenants if t.plan == plan]

        # Sort by creation date (newest first)
        tenants.sort(key=lambda t: t.created_at, reverse=True)

        return tenants[offset : offset + limit]

    async def activate_tenant(self, tenant_id: str) -> bool:
        """Activate tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        tenant.status = TenantStatus.ACTIVE
        tenant.activated_at = datetime.utcnow()
        tenant.updated_at = datetime.utcnow()

        await self._save_tenant(tenant)
        await self._log_tenant_event(tenant_id, "tenant_activated")

        return True

    async def suspend_tenant(self, tenant_id: str, reason: str = None) -> bool:
        """Suspend tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        tenant.status = TenantStatus.SUSPENDED
        tenant.suspended_at = datetime.utcnow()
        tenant.updated_at = datetime.utcnow()

        await self._save_tenant(tenant)
        await self._log_tenant_event(tenant_id, "tenant_suspended", {"reason": reason})

        return True

    async def upgrade_tenant_plan(self, tenant_id: str, new_plan: TenantPlan) -> bool:
        """Upgrade tenant plan"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        old_plan = tenant.plan
        tenant.plan = new_plan
        tenant.updated_at = datetime.utcnow()

        # Update enabled features
        tenant.enabled_features = self.plan_features.get(new_plan, set())

        await self._save_tenant(tenant)
        await self._log_tenant_event(
            tenant_id,
            "plan_upgraded",
            {"old_plan": old_plan.value, "new_plan": new_plan.value},
        )

        return True

    async def update_tenant_metadata(
        self, tenant_id: str, metadata: TenantMetadata
    ) -> bool:
        """Update tenant metadata"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        tenant.metadata = metadata
        tenant.updated_at = datetime.utcnow()

        await self._save_tenant(tenant)
        await self._log_tenant_event(tenant_id, "metadata_updated")

        return True

    async def add_tenant_admin(self, tenant_id: str, admin_email: str) -> bool:
        """Add admin user to tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        if admin_email not in tenant.admin_users:
            tenant.admin_users.append(admin_email)
            tenant.updated_at = datetime.utcnow()

            await self._save_tenant(tenant)
            await self._log_tenant_event(
                tenant_id, "admin_added", {"admin_email": admin_email}
            )

        return True

    async def remove_tenant_admin(self, tenant_id: str, admin_email: str) -> bool:
        """Remove admin user from tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        if admin_email in tenant.admin_users and len(tenant.admin_users) > 1:
            tenant.admin_users.remove(admin_email)
            tenant.updated_at = datetime.utcnow()

            await self._save_tenant(tenant)
            await self._log_tenant_event(
                tenant_id, "admin_removed", {"admin_email": admin_email}
            )

            return True

        return False  # Cannot remove last admin

    async def enable_tenant_feature(self, tenant_id: str, feature: str) -> bool:
        """Enable feature for tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant or feature not in self.available_features:
            return False

        tenant.enabled_features.add(feature)
        tenant.updated_at = datetime.utcnow()

        await self._save_tenant(tenant)
        await self._log_tenant_event(tenant_id, "feature_enabled", {"feature": feature})

        return True

    async def set_tenant_feature_flag(
        self, tenant_id: str, flag: str, value: bool
    ) -> bool:
        """Set tenant feature flag"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        tenant.feature_flags[flag] = value
        tenant.updated_at = datetime.utcnow()

        await self._save_tenant(tenant)
        await self._log_tenant_event(
            tenant_id, "feature_flag_set", {"flag": flag, "value": value}
        )

        return True

    async def _log_tenant_event(
        self,
        tenant_id: str,
        event_type: str,
        event_data: Dict[str, Any] = None,
        user_id: str = None,
    ):
        """Log tenant event for audit trail"""
        async with self.db_manager.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO tenant_events (tenant_id, event_type, event_data, user_id)
                VALUES ($1, $2, $3, $4)
            """,
                tenant_id,
                event_type,
                event_data or {},
                user_id,
            )

    async def get_tenant_events(
        self, tenant_id: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get tenant event history"""
        async with self.db_manager.get_connection() as conn:
            rows = await conn.fetch(
                """
                SELECT event_id, event_type, event_data, user_id, created_at
                FROM tenant_events
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                LIMIT $2
            """,
                tenant_id,
                limit,
            )

            return [
                {
                    "event_id": row["event_id"],
                    "event_type": row["event_type"],
                    "event_data": row["event_data"],
                    "user_id": row["user_id"],
                    "created_at": row["created_at"].isoformat(),
                }
                for row in rows
            ]

    def get_tenant_stats(self) -> Dict[str, Any]:
        """Get tenant system statistics"""
        total_tenants = len(self.tenants)

        status_counts = {}
        for status in TenantStatus:
            status_counts[status.value] = len(
                [t for t in self.tenants.values() if t.status == status]
            )

        plan_counts = {}
        for plan in TenantPlan:
            plan_counts[plan.value] = len(
                [t for t in self.tenants.values() if t.plan == plan]
            )

        return {
            "total_tenants": total_tenants,
            "status_distribution": status_counts,
            "plan_distribution": plan_counts,
            "available_features": list(self.available_features),
        }
