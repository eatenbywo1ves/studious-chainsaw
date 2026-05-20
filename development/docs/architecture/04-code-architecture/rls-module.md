# Row-Level Security Module - Code Architecture

## Overview
The RLS module implements PostgreSQL Row-Level Security for multi-tenant data isolation, ensuring each tenant can only access their own data.

## Class Responsibilities

### RLSMiddleware
**Location**: `middleware/rls_middleware.py`

Sets tenant context for each request.

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from sqlalchemy.ext.asyncio import AsyncSession
from contextvars import ContextVar
from uuid import UUID

class RLSMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, session_factory: RLSSessionFactory):
        super().__init__(app)
        self._session_factory = session_factory

    async def dispatch(self, request: Request, call_next):
        tenant_id = getattr(request.state, "tenant_id", None)

        if tenant_id:
            # Set tenant context for this request
            token = TenantContext.set(UUID(tenant_id))
            try:
                response = await call_next(request)
            finally:
                TenantContext.reset(token)
        else:
            response = await call_next(request)

        return response
```

### TenantContext
**Location**: `core/tenant_context.py`

Thread-safe tenant ID storage using contextvars.

```python
from contextvars import ContextVar, Token
from uuid import UUID
from typing import Optional

class TenantContext:
    """
    Thread-safe storage for current tenant ID.
    Uses contextvars for async-safe context propagation.
    """
    _current_tenant: ContextVar[Optional[UUID]] = ContextVar(
        "current_tenant",
        default=None
    )

    @classmethod
    def get(cls) -> Optional[UUID]:
        """Get current tenant ID."""
        return cls._current_tenant.get()

    @classmethod
    def set(cls, tenant_id: UUID) -> Token:
        """
        Set tenant ID for current context.
        Returns token for reset.
        """
        return cls._current_tenant.set(tenant_id)

    @classmethod
    def reset(cls, token: Token) -> None:
        """Reset to previous value."""
        cls._current_tenant.reset(token)

    @classmethod
    def require(cls) -> UUID:
        """Get tenant ID or raise if not set."""
        tenant_id = cls.get()
        if tenant_id is None:
            raise TenantContextNotSetError(
                "Tenant context not set. Ensure RLSMiddleware is active."
            )
        return tenant_id
```

### RLSSessionFactory
**Location**: `database/session_factory.py`

Creates database sessions with RLS configured.

```python
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import text
from typing import AsyncGenerator

class RLSSessionFactory:
    def __init__(self, database_url: str):
        self._engine = create_async_engine(
            database_url,
            pool_size=20,
            max_overflow=10,
            pool_pre_ping=True
        )
        self._session_maker = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

    async def create_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Create session with RLS context set."""
        async with self._session_maker() as session:
            await self._configure_rls(session)
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def _configure_rls(self, session: AsyncSession) -> None:
        """Set PostgreSQL session variable for RLS."""
        tenant_id = TenantContext.get()
        if tenant_id:
            await session.execute(
                text("SET LOCAL app.tenant_id = :tenant_id"),
                {"tenant_id": str(tenant_id)}
            )
        else:
            # Clear any previous tenant context
            await session.execute(
                text("SET LOCAL app.tenant_id = ''")
            )
```

### Database Schema
**Location**: `database/models.py`

Base model with tenant isolation.

```python
from sqlalchemy import Column, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, declared_attr
import uuid

Base = declarative_base()

class TenantMixin:
    """Mixin for tenant-scoped tables."""

    @declared_attr
    def tenant_id(cls):
        return Column(
            UUID(as_uuid=True),
            nullable=False,
            index=True
        )

    @declared_attr
    def __table_args__(cls):
        return (
            Index(f"ix_{cls.__tablename__}_tenant_id", "tenant_id"),
        )


class User(Base, TenantMixin):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())


class Subscription(Base, TenantMixin):
    __tablename__ = "subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    stripe_subscription_id = Column(String(255), unique=True)
    status = Column(String(50))
    current_period_end = Column(DateTime)


class AnalysisJob(Base, TenantMixin):
    __tablename__ = "analysis_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    status = Column(String(50))
    result = Column(JSONB)
    created_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime)
```

### PostgreSQL RLS Policies
**Location**: `migrations/versions/002_enable_rls.sql`

```sql
-- Enable RLS on tenant-scoped tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_jobs ENABLE ROW LEVEL SECURITY;

-- Create isolation policies
CREATE POLICY tenant_isolation_users ON users
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation_subscriptions ON subscriptions
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY tenant_isolation_jobs ON analysis_jobs
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Grant permissions to application role
GRANT ALL ON users TO app_user;
GRANT ALL ON subscriptions TO app_user;
GRANT ALL ON analysis_jobs TO app_user;

-- Ensure RLS is enforced even for table owner
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY;
ALTER TABLE analysis_jobs FORCE ROW LEVEL SECURITY;
```

### BaseRepository
**Location**: `repositories/base_repository.py`

Repository pattern with automatic RLS.

```python
from typing import TypeVar, Generic, Optional, List, Type
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from sqlalchemy.orm import DeclarativeMeta
from uuid import UUID

T = TypeVar("T", bound=DeclarativeMeta)

class BaseRepository(Generic[T]):
    """
    Base repository with automatic tenant isolation via PostgreSQL RLS.
    All queries are automatically filtered by tenant_id.
    """

    def __init__(self, session: AsyncSession, model: Type[T]):
        self._session = session
        self._model = model

    async def find_by_id(self, id: UUID) -> Optional[T]:
        """Find entity by ID (automatically tenant-scoped)."""
        stmt = select(self._model).where(self._model.id == id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def find_all(self, limit: int = 100, offset: int = 0) -> List[T]:
        """Find all entities (automatically tenant-scoped)."""
        stmt = select(self._model).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def create(self, entity: T) -> T:
        """
        Create new entity.
        Note: tenant_id must be set before calling this.
        RLS WITH CHECK ensures it matches current tenant.
        """
        self._session.add(entity)
        await self._session.flush()
        await self._session.refresh(entity)
        return entity

    async def update(self, entity: T) -> T:
        """Update entity (RLS ensures tenant ownership)."""
        await self._session.flush()
        await self._session.refresh(entity)
        return entity

    async def delete(self, id: UUID) -> bool:
        """Delete entity by ID (RLS ensures tenant ownership)."""
        stmt = delete(self._model).where(self._model.id == id)
        result = await self._session.execute(stmt)
        return result.rowcount > 0
```

## Request Flow

```
┌──────────────┐
│   Request    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│JWTMiddleware │ ─── Extracts tenant_id from token
└──────┬───────┘
       │
       ▼
┌──────────────┐
│RLSMiddleware │ ─── Sets TenantContext
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Controller   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Repository  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│SessionFactory│ ─── SET LOCAL app.tenant_id = ?
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  PostgreSQL  │ ─── RLS policy filters query
│  + RLS       │
└──────────────┘
```

## Security Guarantees

| Guarantee | Implementation |
|-----------|---------------|
| No cross-tenant access | PostgreSQL RLS policy USING clause |
| No cross-tenant writes | PostgreSQL RLS policy WITH CHECK clause |
| No policy bypass | FORCE ROW LEVEL SECURITY on all tables |
| Audit trail | tenant_id indexed for efficient queries |
| Default deny | Empty tenant context returns no rows |

## Testing RLS

```python
import pytest
from uuid import uuid4

@pytest.mark.asyncio
async def test_rls_isolation(session_factory):
    tenant_a = uuid4()
    tenant_b = uuid4()

    # Create user as tenant A
    TenantContext.set(tenant_a)
    async with session_factory.create_session() as session:
        user_a = User(id=uuid4(), tenant_id=tenant_a, email="a@test.com")
        session.add(user_a)
        await session.commit()

    # Try to read as tenant B - should not find user
    TenantContext.set(tenant_b)
    async with session_factory.create_session() as session:
        result = await session.execute(select(User))
        users = result.scalars().all()
        assert len(users) == 0  # Tenant B cannot see Tenant A's data

    # Read as tenant A - should find user
    TenantContext.set(tenant_a)
    async with session_factory.create_session() as session:
        result = await session.execute(select(User))
        users = result.scalars().all()
        assert len(users) == 1
        assert users[0].id == user_a.id
```

---
**Last Updated**: 2024-10-15
