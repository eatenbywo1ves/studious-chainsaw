"""
Multi-Tenant Architecture Framework

Enterprise-grade multi-tenancy with:
- Tenant isolation strategies (schema-per-tenant, database-per-tenant)
- Resource quotas and billing integration
- Tenant-specific configurations and customizations
- Cross-tenant security boundaries
- Data residency compliance
- Tenant lifecycle management
"""

from .billing import BillingCycle, BillingManager, BillingPlan, Invoice
from .configuration import ConfigurationManager, TenantConfiguration
from .isolation import (
    DatabasePerTenant,
    IsolationStrategy,
    RowLevelSecurity,
    SchemaPerTenant,
)
from .middleware import TenantContext, TenantMiddleware
from .quotas import QuotaManager, QuotaType, ResourceQuota, UsageTracker
from .tenant_manager import Tenant, TenantManager, TenantPlan, TenantStatus

__all__ = [
    "TenantManager",
    "Tenant",
    "TenantStatus",
    "TenantPlan",
    "IsolationStrategy",
    "SchemaPerTenant",
    "DatabasePerTenant",
    "RowLevelSecurity",
    "QuotaManager",
    "ResourceQuota",
    "QuotaType",
    "UsageTracker",
    "BillingManager",
    "BillingPlan",
    "Invoice",
    "BillingCycle",
    "TenantConfiguration",
    "ConfigurationManager",
    "TenantMiddleware",
    "TenantContext",
]
