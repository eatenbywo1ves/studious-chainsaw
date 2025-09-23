"""
Resource Quota Management System

Enterprise quota management with:
- Resource quotas and limits
- Usage tracking and enforcement
- Billing integration
- Real-time quota monitoring
- Automated scaling and throttling
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List

from libraries.database import DatabaseManager


class QuotaType(Enum):
    """Types of resource quotas"""

    AGENTS = "agents"
    TASKS = "tasks"
    API_CALLS = "api_calls"
    STORAGE_GB = "storage_gb"
    BANDWIDTH_GB = "bandwidth_gb"
    CONCURRENT_TASKS = "concurrent_tasks"
    EVENTS_PER_HOUR = "events_per_hour"
    USERS = "users"
    INTEGRATIONS = "integrations"
    WEBHOOKS = "webhooks"


class QuotaPeriod(Enum):
    """Quota period types"""

    HOURLY = "hourly"
    DAILY = "daily"
    MONTHLY = "monthly"
    TOTAL = "total"  # Lifetime quota


@dataclass
class ResourceQuota:
    """Resource quota definition"""

    quota_id: str
    tenant_id: str
    quota_type: QuotaType
    limit: int
    period: QuotaPeriod

    # Soft limits and warnings
    soft_limit_percentage: float = 80.0
    warning_thresholds: List[float] = field(default_factory=lambda: [50.0, 75.0, 90.0])

    # Actions on quota exceeded
    block_on_exceeded: bool = True
    throttle_on_soft_limit: bool = False

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "quota_id": self.quota_id,
            "tenant_id": self.tenant_id,
            "quota_type": self.quota_type.value,
            "limit": self.limit,
            "period": self.period.value,
            "soft_limit_percentage": self.soft_limit_percentage,
            "warning_thresholds": self.warning_thresholds,
            "block_on_exceeded": self.block_on_exceeded,
            "throttle_on_soft_limit": self.throttle_on_soft_limit,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class UsageRecord:
    """Usage record for tracking consumption"""

    record_id: str
    tenant_id: str
    quota_type: QuotaType
    amount: int
    period_start: datetime
    period_end: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "tenant_id": self.tenant_id,
            "quota_type": self.quota_type.value,
            "amount": self.amount,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class QuotaViolation:
    """Quota violation event"""

    violation_id: str
    tenant_id: str
    quota_type: QuotaType
    current_usage: int
    quota_limit: int
    violation_type: str  # "exceeded", "soft_limit", "warning"
    action_taken: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "tenant_id": self.tenant_id,
            "quota_type": self.quota_type.value,
            "current_usage": self.current_usage,
            "quota_limit": self.quota_limit,
            "violation_type": self.violation_type,
            "action_taken": self.action_taken,
            "timestamp": self.timestamp.isoformat(),
        }


class UsageTracker:
    """Real-time usage tracking"""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

        # In-memory usage cache for real-time tracking
        self.current_usage: Dict[str, Dict[QuotaType, int]] = (
            {}
        )  # tenant_id -> quota_type -> usage

        # Period usage cache
        self.period_usage: Dict[str, Dict[str, int]] = {}  # cache_key -> usage

        # Callbacks for quota events
        self.violation_callbacks: List[Callable] = []
        self.warning_callbacks: List[Callable] = []

    async def initialize(self):
        """Initialize usage tracking"""
        await self._create_usage_tables()
        await self._load_current_usage()

    async def _create_usage_tables(self):
        """Create usage tracking tables"""
        async with self.db_manager.get_connection() as conn:
            # Usage records table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS quota_usage (
                    record_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    tenant_id UUID NOT NULL,
                    quota_type VARCHAR(50) NOT NULL,
                    amount INTEGER NOT NULL,
                    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
                    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
                    metadata JSONB DEFAULT '{}',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """
            )

            # Quota violations table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS quota_violations (
                    violation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    tenant_id UUID NOT NULL,
                    quota_type VARCHAR(50) NOT NULL,
                    current_usage INTEGER NOT NULL,
                    quota_limit INTEGER NOT NULL,
                    violation_type VARCHAR(50) NOT NULL,
                    action_taken VARCHAR(100),
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """
            )

            # Create indexes
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_quota_usage_tenant ON quota_usage(tenant_id, quota_type)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_quota_usage_period ON quota_usage(period_start, period_end)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_quota_violations_tenant ON quota_violations(tenant_id)"
            )

    async def _load_current_usage(self):
        """Load current usage from database"""
        # Load usage for current periods
        now = datetime.utcnow()

        # Load hourly usage
        hour_start = now.replace(minute=0, second=0, microsecond=0)
        await self._load_period_usage(QuotaPeriod.HOURLY, hour_start, now)

        # Load daily usage
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        await self._load_period_usage(QuotaPeriod.DAILY, day_start, now)

        # Load monthly usage
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        await self._load_period_usage(QuotaPeriod.MONTHLY, month_start, now)

    async def _load_period_usage(
        self, period: QuotaPeriod, start_time: datetime, end_time: datetime
    ):
        """Load usage for specific period"""
        async with self.db_manager.get_connection() as conn:
            rows = await conn.fetch(
                """
                SELECT tenant_id, quota_type, SUM(amount) as total_usage
                FROM quota_usage
                WHERE period_start >= $1 AND period_end <= $2
                GROUP BY tenant_id, quota_type
            """,
                start_time,
                end_time,
            )

            for row in rows:
                tenant_id = row["tenant_id"]
                quota_type = QuotaType(row["quota_type"])
                usage = row["total_usage"]

                cache_key = f"{tenant_id}:{quota_type.value}:{period.value}"
                self.period_usage[cache_key] = usage

    async def record_usage(
        self,
        tenant_id: str,
        quota_type: QuotaType,
        amount: int,
        metadata: Dict[str, Any] = None,
    ) -> bool:
        """Record resource usage"""
        now = datetime.utcnow()

        # Determine period boundaries
        periods = self._get_period_boundaries(now)

        # Update in-memory cache
        if tenant_id not in self.current_usage:
            self.current_usage[tenant_id] = {}

        current_amount = self.current_usage[tenant_id].get(quota_type, 0)
        self.current_usage[tenant_id][quota_type] = current_amount + amount

        # Update period caches
        for period, (start_time, end_time) in periods.items():
            cache_key = f"{tenant_id}:{quota_type.value}:{period.value}"
            current_period_usage = self.period_usage.get(cache_key, 0)
            self.period_usage[cache_key] = current_period_usage + amount

        # Store in database
        async with self.db_manager.get_connection() as conn:
            for period, (start_time, end_time) in periods.items():
                await conn.execute(
                    """
                    INSERT INTO quota_usage
                    (tenant_id, quota_type, amount, period_start, period_end, metadata)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """,
                    tenant_id,
                    quota_type.value,
                    amount,
                    start_time,
                    end_time,
                    metadata or {},
                )

        return True

    def _get_period_boundaries(self, timestamp: datetime) -> Dict[QuotaPeriod, tuple]:
        """Get period boundaries for timestamp"""
        boundaries = {}

        # Hourly period
        hour_start = timestamp.replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)
        boundaries[QuotaPeriod.HOURLY] = (hour_start, hour_end)

        # Daily period
        day_start = timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        boundaries[QuotaPeriod.DAILY] = (day_start, day_end)

        # Monthly period
        month_start = timestamp.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        if month_start.month == 12:
            month_end = month_start.replace(year=month_start.year + 1, month=1)
        else:
            month_end = month_start.replace(month=month_start.month + 1)
        boundaries[QuotaPeriod.MONTHLY] = (month_start, month_end)

        return boundaries

    async def get_usage(
        self, tenant_id: str, quota_type: QuotaType, period: QuotaPeriod
    ) -> int:
        """Get current usage for tenant and quota type"""
        if period == QuotaPeriod.TOTAL:
            # Get total historical usage
            async with self.db_manager.get_connection() as conn:
                result = await conn.fetchval(
                    """
                    SELECT COALESCE(SUM(amount), 0)
                    FROM quota_usage
                    WHERE tenant_id = $1 AND quota_type = $2
                """,
                    tenant_id,
                    quota_type.value,
                )
                return result or 0

        cache_key = f"{tenant_id}:{quota_type.value}:{period.value}"
        return self.period_usage.get(cache_key, 0)

    def add_violation_callback(self, callback: Callable):
        """Add callback for quota violations"""
        self.violation_callbacks.append(callback)

    def add_warning_callback(self, callback: Callable):
        """Add callback for quota warnings"""
        self.warning_callbacks.append(callback)

    async def _trigger_violation_callbacks(self, violation: QuotaViolation):
        """Trigger violation callbacks"""
        for callback in self.violation_callbacks:
            try:
                await callback(violation)
            except Exception as e:
                print(f"Error in violation callback: {e}")

    async def _trigger_warning_callbacks(
        self, tenant_id: str, quota_type: QuotaType, usage_percentage: float
    ):
        """Trigger warning callbacks"""
        for callback in self.warning_callbacks:
            try:
                await callback(tenant_id, quota_type, usage_percentage)
            except Exception as e:
                print(f"Error in warning callback: {e}")


class QuotaManager:
    """
    Complete quota management system
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.usage_tracker = UsageTracker(db_manager)

        # Storage
        self.quotas: Dict[str, ResourceQuota] = {}
        self.tenant_quotas: Dict[str, List[str]] = {}  # tenant_id -> quota_ids

        # Default quotas by plan
        self.default_quotas = self._initialize_default_quotas()

    def _initialize_default_quotas(self) -> Dict[str, Dict[QuotaType, int]]:
        """Initialize default quotas by plan"""
        return {
            "free": {
                QuotaType.AGENTS: 5,
                QuotaType.TASKS: 100,
                QuotaType.API_CALLS: 1000,
                QuotaType.STORAGE_GB: 1,
                QuotaType.CONCURRENT_TASKS: 2,
                QuotaType.EVENTS_PER_HOUR: 500,
                QuotaType.USERS: 1,
            },
            "starter": {
                QuotaType.AGENTS: 25,
                QuotaType.TASKS: 1000,
                QuotaType.API_CALLS: 10000,
                QuotaType.STORAGE_GB: 10,
                QuotaType.CONCURRENT_TASKS: 10,
                QuotaType.EVENTS_PER_HOUR: 5000,
                QuotaType.USERS: 5,
            },
            "professional": {
                QuotaType.AGENTS: 100,
                QuotaType.TASKS: 10000,
                QuotaType.API_CALLS: 100000,
                QuotaType.STORAGE_GB: 100,
                QuotaType.CONCURRENT_TASKS: 50,
                QuotaType.EVENTS_PER_HOUR: 50000,
                QuotaType.USERS: 25,
            },
            "enterprise": {
                QuotaType.AGENTS: 1000,
                QuotaType.TASKS: 100000,
                QuotaType.API_CALLS: 1000000,
                QuotaType.STORAGE_GB: 1000,
                QuotaType.CONCURRENT_TASKS: 200,
                QuotaType.EVENTS_PER_HOUR: 500000,
                QuotaType.USERS: 100,
            },
        }

    async def initialize(self):
        """Initialize quota management"""
        await self.usage_tracker.initialize()
        await self._create_quota_tables()
        await self._load_existing_quotas()

        # Set up quota violation callbacks
        self.usage_tracker.add_violation_callback(self._handle_quota_violation)
        self.usage_tracker.add_warning_callback(self._handle_quota_warning)

    async def _create_quota_tables(self):
        """Create quota management tables"""
        async with self.db_manager.get_connection() as conn:
            # Quotas table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenant_quotas (
                    quota_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    tenant_id UUID NOT NULL,
                    quota_type VARCHAR(50) NOT NULL,
                    quota_limit INTEGER NOT NULL,
                    period VARCHAR(50) NOT NULL,
                    soft_limit_percentage FLOAT DEFAULT 80.0,
                    warning_thresholds JSONB DEFAULT '[50.0, 75.0, 90.0]',
                    block_on_exceeded BOOLEAN DEFAULT true,
                    throttle_on_soft_limit BOOLEAN DEFAULT false,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    UNIQUE(tenant_id, quota_type, period)
                )
            """
            )

            # Create indexes
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tenant_quotas_tenant ON tenant_quotas(tenant_id)"
            )

    async def _load_existing_quotas(self):
        """Load existing quotas from database"""
        async with self.db_manager.get_connection() as conn:
            rows = await conn.fetch("SELECT * FROM tenant_quotas")

            for row in rows:
                quota = ResourceQuota(
                    quota_id=row["quota_id"],
                    tenant_id=row["tenant_id"],
                    quota_type=QuotaType(row["quota_type"]),
                    limit=row["quota_limit"],
                    period=QuotaPeriod(row["period"]),
                    soft_limit_percentage=row["soft_limit_percentage"],
                    warning_thresholds=row["warning_thresholds"],
                    block_on_exceeded=row["block_on_exceeded"],
                    throttle_on_soft_limit=row["throttle_on_soft_limit"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )

                self.quotas[quota.quota_id] = quota

                if quota.tenant_id not in self.tenant_quotas:
                    self.tenant_quotas[quota.tenant_id] = []
                self.tenant_quotas[quota.tenant_id].append(quota.quota_id)

    async def set_tenant_quotas_from_plan(self, tenant_id: str, plan: str) -> bool:
        """Set tenant quotas based on plan"""
        plan_quotas = self.default_quotas.get(plan.lower(), {})

        for quota_type, limit in plan_quotas.items():
            await self.set_quota(tenant_id, quota_type, limit, QuotaPeriod.MONTHLY)

        return True

    async def set_quota(
        self,
        tenant_id: str,
        quota_type: QuotaType,
        limit: int,
        period: QuotaPeriod,
        **kwargs,
    ) -> str:
        """Set quota for tenant"""
        import uuid

        quota_id = str(uuid.uuid4())

        quota = ResourceQuota(
            quota_id=quota_id,
            tenant_id=tenant_id,
            quota_type=quota_type,
            limit=limit,
            period=period,
            **kwargs,
        )

        # Save to database
        async with self.db_manager.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO tenant_quotas
                (quota_id, tenant_id, quota_type, quota_limit, period,
                 soft_limit_percentage, warning_thresholds, block_on_exceeded, throttle_on_soft_limit)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (tenant_id, quota_type, period) DO UPDATE SET
                    quota_limit = EXCLUDED.quota_limit,
                    soft_limit_percentage = EXCLUDED.soft_limit_percentage,
                    warning_thresholds = EXCLUDED.warning_thresholds,
                    block_on_exceeded = EXCLUDED.block_on_exceeded,
                    throttle_on_soft_limit = EXCLUDED.throttle_on_soft_limit,
                    updated_at = NOW()
            """,
                quota_id,
                tenant_id,
                quota_type.value,
                limit,
                period.value,
                quota.soft_limit_percentage,
                quota.warning_thresholds,
                quota.block_on_exceeded,
                quota.throttle_on_soft_limit,
            )

        # Store in memory
        self.quotas[quota_id] = quota
        if tenant_id not in self.tenant_quotas:
            self.tenant_quotas[tenant_id] = []
        if quota_id not in self.tenant_quotas[tenant_id]:
            self.tenant_quotas[tenant_id].append(quota_id)

        return quota_id

    async def check_quota(
        self, tenant_id: str, quota_type: QuotaType, requested_amount: int = 1
    ) -> Dict[str, Any]:
        """Check if tenant can consume requested amount"""
        # Find applicable quota
        applicable_quotas = []
        tenant_quota_ids = self.tenant_quotas.get(tenant_id, [])

        for quota_id in tenant_quota_ids:
            quota = self.quotas.get(quota_id)
            if quota and quota.quota_type == quota_type:
                applicable_quotas.append(quota)

        if not applicable_quotas:
            # No quota set - allow by default (could be changed to deny)
            return {"allowed": True, "reason": "no_quota_set"}

        # Check each applicable quota
        for quota in applicable_quotas:
            current_usage = await self.usage_tracker.get_usage(
                tenant_id, quota_type, quota.period
            )

            new_usage = current_usage + requested_amount

            # Check hard limit
            if new_usage > quota.limit:
                return {
                    "allowed": False,
                    "reason": "quota_exceeded",
                    "quota_type": quota_type.value,
                    "current_usage": current_usage,
                    "requested": requested_amount,
                    "limit": quota.limit,
                    "period": quota.period.value,
                }

            # Check soft limit
            soft_limit = int(quota.limit * (quota.soft_limit_percentage / 100))
            if new_usage > soft_limit and quota.throttle_on_soft_limit:
                return {
                    "allowed": False,
                    "reason": "soft_limit_exceeded",
                    "quota_type": quota_type.value,
                    "current_usage": current_usage,
                    "requested": requested_amount,
                    "soft_limit": soft_limit,
                    "limit": quota.limit,
                    "period": quota.period.value,
                }

        return {"allowed": True}

    async def consume_quota(
        self,
        tenant_id: str,
        quota_type: QuotaType,
        amount: int = 1,
        metadata: Dict[str, Any] = None,
    ) -> bool:
        """Consume quota if available"""
        # Check quota first
        check_result = await self.check_quota(tenant_id, quota_type, amount)

        if not check_result["allowed"]:
            return False

        # Record usage
        await self.usage_tracker.record_usage(tenant_id, quota_type, amount, metadata)

        # Check for warnings
        await self._check_quota_warnings(tenant_id, quota_type)

        return True

    async def _check_quota_warnings(self, tenant_id: str, quota_type: QuotaType):
        """Check and trigger quota warnings"""
        tenant_quota_ids = self.tenant_quotas.get(tenant_id, [])

        for quota_id in tenant_quota_ids:
            quota = self.quotas.get(quota_id)
            if not quota or quota.quota_type != quota_type:
                continue

            current_usage = await self.usage_tracker.get_usage(
                tenant_id, quota_type, quota.period
            )

            usage_percentage = (current_usage / quota.limit) * 100

            # Check warning thresholds
            for threshold in quota.warning_thresholds:
                if usage_percentage >= threshold:
                    await self.usage_tracker._trigger_warning_callbacks(
                        tenant_id, quota_type, usage_percentage
                    )
                    break

    async def get_tenant_quotas(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get all quotas for tenant"""
        tenant_quota_ids = self.tenant_quotas.get(tenant_id, [])
        quotas = []

        for quota_id in tenant_quota_ids:
            quota = self.quotas.get(quota_id)
            if quota:
                current_usage = await self.usage_tracker.get_usage(
                    tenant_id, quota.quota_type, quota.period
                )

                quota_dict = quota.to_dict()
                quota_dict["current_usage"] = current_usage
                quota_dict["usage_percentage"] = (
                    (current_usage / quota.limit) * 100 if quota.limit > 0 else 0
                )
                quotas.append(quota_dict)

        return quotas

    async def get_quota_usage_report(
        self, tenant_id: str, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Generate quota usage report"""
        async with self.db_manager.get_connection() as conn:
            # Get usage by quota type
            usage_by_type = await conn.fetch(
                """
                SELECT quota_type, SUM(amount) as total_usage, COUNT(*) as usage_events
                FROM quota_usage
                WHERE tenant_id = $1 AND period_start >= $2 AND period_end <= $3
                GROUP BY quota_type
            """,
                tenant_id,
                start_date,
                end_date,
            )

            # Get violations
            violations = await conn.fetch(
                """
                SELECT quota_type, violation_type, COUNT(*) as violation_count
                FROM quota_violations
                WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
                GROUP BY quota_type, violation_type
            """,
                tenant_id,
                start_date,
                end_date,
            )

        return {
            "tenant_id": tenant_id,
            "report_period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            "usage_by_type": [
                {
                    "quota_type": row["quota_type"],
                    "total_usage": row["total_usage"],
                    "usage_events": row["usage_events"],
                }
                for row in usage_by_type
            ],
            "violations": [
                {
                    "quota_type": row["quota_type"],
                    "violation_type": row["violation_type"],
                    "count": row["violation_count"],
                }
                for row in violations
            ],
        }

    async def _handle_quota_violation(self, violation: QuotaViolation):
        """Handle quota violation"""
        # Log violation
        async with self.db_manager.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO quota_violations
                (tenant_id, quota_type, current_usage, quota_limit, violation_type, action_taken)
                VALUES ($1, $2, $3, $4, $5, $6)
            """,
                violation.tenant_id,
                violation.quota_type.value,
                violation.current_usage,
                violation.quota_limit,
                violation.violation_type,
                violation.action_taken,
            )

        # Additional actions could include:
        # - Sending notifications
        # - Triggering billing events
        # - Suspending tenant services
        print(
            f"Quota violation: {violation.tenant_id} exceeded {violation.quota_type.value} limit"
        )

    async def _handle_quota_warning(
        self, tenant_id: str, quota_type: QuotaType, usage_percentage: float
    ):
        """Handle quota warning"""
        print(
            f"Quota warning: {tenant_id} at {usage_percentage:.1f}% of {quota_type.value} quota"
        )

    def get_quota_stats(self) -> Dict[str, Any]:
        """Get quota system statistics"""
        return {
            "total_quotas": len(self.quotas),
            "tenants_with_quotas": len(self.tenant_quotas),
            "quota_types": [qt.value for qt in QuotaType],
            "quota_periods": [qp.value for qp in QuotaPeriod],
        }
