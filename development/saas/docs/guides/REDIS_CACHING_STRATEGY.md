# Redis Caching Strategy - Catalytic Computing SaaS

## Executive Summary

**Goal:** Reduce database load and improve API response times through strategic Redis caching.

**Current State:**
- ✅ Redis caching for JWT tokens and sessions
- ❌ No caching for subscription plans, usage limits, tenant configs

**Target State:**
- ✅ Multi-layer caching strategy
- ✅ 5-10x faster API responses
- ✅ 70-90% reduction in database queries
- ✅ Intelligent cache invalidation

---

## Caching Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   API REQUEST                           │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              REDIS CACHE LAYERS                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │ L1: Auth Tokens (existing)                        │  │
│  │ - JWT tokens: 15 min TTL                          │  │
│  │ - Session data: 7 day TTL                         │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ L2: Subscription Data (NEW)                       │  │
│  │ - Subscription plans: 1 hour TTL                  │  │
│  │ - Active subscriptions: 5 min TTL                 │  │
│  │ - Feature flags: 5 min TTL                        │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ L3: Usage & Limits (NEW)                          │  │
│  │ - Usage counters: 1 min TTL                       │  │
│  │ - Limit checks: 30 sec TTL                        │  │
│  │ - API quotas: Real-time (Redis counter)           │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ L4: Tenant Config (NEW)                           │  │
│  │ - Tenant metadata: 10 min TTL                     │  │
│  │ - API keys: 5 min TTL                             │  │
│  │ - User permissions: 5 min TTL                     │  │
│  └───────────────────────────────────────────────────┘  │
└────────────────────┬────────────────────────────────────┘
                     │ Cache MISS
                     ▼
┌─────────────────────────────────────────────────────────┐
│              PostgreSQL DATABASE                        │
│  - Fetch from DB                                        │
│  - Update cache                                         │
│  - Return to API                                        │
└─────────────────────────────────────────────────────────┘
```

---

## Cache Key Design

### Naming Convention

```
{namespace}:{entity}:{identifier}[:{attribute}]

Examples:
- auth:token:abc123xyz
- sub:plan:free
- sub:active:tenant-uuid
- usage:api_calls:tenant-uuid:2025-01
- tenant:config:tenant-uuid
- user:perms:user-uuid
- apikey:valid:sk_live_prefix
```

### Key Prefixes

| Prefix | Description | TTL | Invalidation |
|--------|-------------|-----|--------------|
| `auth:` | Authentication tokens | 15 min | On logout |
| `sub:plan:` | Subscription plans | 1 hour | On plan update |
| `sub:active:` | Active subscriptions | 5 min | On subscription change |
| `usage:` | Usage counters | 1 min | On API call |
| `limit:` | Limit check results | 30 sec | On limit change |
| `tenant:` | Tenant configurations | 10 min | On tenant update |
| `user:` | User data & permissions | 5 min | On user update |
| `apikey:` | API key validations | 5 min | On key rotation |
| `feature:` | Feature flags | 5 min | On feature toggle |

---

## What to Cache

### High Priority (Cache Everything)

#### 1. Subscription Plans (Read-Heavy, Rarely Changes)

**Cache:**
```json
{
  "sub:plan:free": {
    "id": "uuid",
    "name": "Free Tier",
    "code": "free",
    "price_monthly": 0.00,
    "features": {"lattices": 5, "api_calls": 1000},
    "limits": {"max_lattices": 5, "api_calls_per_month": 1000}
  }
}
```

**TTL:** 1 hour (plans change infrequently)

**Invalidation:** On plan update (admin action)

**Performance Gain:** ⭐⭐⭐⭐⭐ (checked on every API call)

#### 2. Active Subscription per Tenant

**Cache:**
```json
{
  "sub:active:tenant-uuid": {
    "subscription_id": "uuid",
    "plan_code": "professional",
    "status": "active",
    "plan_limits": {"max_lattices": 500, "api_calls_per_month": 100000},
    "plan_features": {"all_features": true, "gpu_acceleration": true}
  }
}
```

**TTL:** 5 minutes (balances freshness vs performance)

**Invalidation:** On subscription change, upgrade, downgrade

**Performance Gain:** ⭐⭐⭐⭐⭐ (checked on every API call)

#### 3. Usage Counters (Real-Time with Redis)

**Cache:**
```redis
# Use Redis native counters (INCR command)
usage:api_calls:tenant-uuid:2025-01  →  42350  (TTL: end of month)
usage:lattices:tenant-uuid  →  127  (TTL: none, updated on create/delete)
```

**TTL:**
- Monthly counters: Until end of month
- Resource counts: No expiry (updated on change)

**Invalidation:** Real-time increments on each API call/resource creation

**Performance Gain:** ⭐⭐⭐⭐⭐ (database writes become Redis increments)

#### 4. Limit Check Results

**Cache:**
```json
{
  "limit:check:tenant-uuid:api_calls": {
    "limit": 100000,
    "current": 42350,
    "exceeded": false,
    "percentage": 42.35
  }
}
```

**TTL:** 30 seconds (frequent checks, short TTL for accuracy)

**Invalidation:** On usage update (or rely on TTL expiry)

**Performance Gain:** ⭐⭐⭐⭐ (checked on every rate-limited endpoint)

### Medium Priority (Selective Caching)

#### 5. Tenant Configuration

**Cache:**
```json
{
  "tenant:config:tenant-uuid": {
    "id": "uuid",
    "slug": "acme-corp",
    "name": "Acme Corporation",
    "status": "active",
    "metadata": {"custom_domain": "api.acme.com"}
  }
}
```

**TTL:** 10 minutes

**Invalidation:** On tenant settings update

**Performance Gain:** ⭐⭐⭐ (tenant info needed for many operations)

#### 6. API Key Validation

**Cache:**
```json
{
  "apikey:valid:sk_live_abc123": {
    "tenant_id": "uuid",
    "key_id": "uuid",
    "is_active": true,
    "permissions": ["read", "write"],
    "expires_at": null
  }
}
```

**TTL:** 5 minutes

**Invalidation:** On API key rotation, deactivation

**Performance Gain:** ⭐⭐⭐⭐ (API key auth is very common)

#### 7. User Permissions & Roles

**Cache:**
```json
{
  "user:perms:user-uuid": {
    "tenant_id": "uuid",
    "role": "admin",
    "is_active": true,
    "permissions": ["manage_users", "view_billing", "create_lattices"]
  }
}
```

**TTL:** 5 minutes

**Invalidation:** On role change, permission update

**Performance Gain:** ⭐⭐⭐ (authorization checks on protected endpoints)

### Low Priority (Consider Later)

#### 8. Lattice Metadata (Hot Data)

**Cache:** Recently accessed lattices

**TTL:** 5 minutes

**Performance Gain:** ⭐⭐ (access patterns vary)

#### 9. Aggregated Analytics

**Cache:** Dashboard query results

**TTL:** 1-5 minutes

**Performance Gain:** ⭐⭐ (dashboard load only)

---

## Implementation

### Redis Client Configuration

```python
# services/cache_service.py
import redis
import json
import logging
from typing import Optional, Any, Dict
from datetime import timedelta
from functools import wraps

logger = logging.getLogger(__name__)

class CacheService:
    """Unified caching service for all Redis operations"""

    def __init__(self, redis_url: str):
        self.redis = redis.from_url(
            redis_url,
            decode_responses=True,  # Auto-decode bytes to strings
            socket_timeout=5,
            socket_connect_timeout=5,
            retry_on_timeout=True
        )
        self.default_ttl = 300  # 5 minutes

    # ========================================================================
    # CORE OPERATIONS
    # ========================================================================

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache, return None if not found"""
        try:
            value = self.redis.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.warning(f"Cache GET error for {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL (seconds)"""
        try:
            ttl = ttl or self.default_ttl
            serialized = json.dumps(value)
            return self.redis.setex(key, ttl, serialized)
        except Exception as e:
            logger.error(f"Cache SET error for {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            return bool(self.redis.delete(key))
        except Exception as e:
            logger.error(f"Cache DELETE error for {key}: {e}")
            return False

    def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern (use carefully!)"""
        try:
            keys = self.redis.keys(pattern)
            if keys:
                return self.redis.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Cache DELETE_PATTERN error for {pattern}: {e}")
            return 0

    def increment(self, key: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        """Increment counter, set TTL if key is new"""
        try:
            value = self.redis.incr(key, amount)
            if value == amount and ttl:  # First increment, set TTL
                self.redis.expire(key, ttl)
            return value
        except Exception as e:
            logger.error(f"Cache INCREMENT error for {key}: {e}")
            return 0

    # ========================================================================
    # HIGH-LEVEL HELPERS
    # ========================================================================

    def get_or_set(self, key: str, fetch_func: callable, ttl: Optional[int] = None) -> Optional[Any]:
        """Get from cache or fetch from database and cache"""
        # Try cache first
        cached = self.get(key)
        if cached is not None:
            logger.debug(f"Cache HIT: {key}")
            return cached

        # Cache miss - fetch from database
        logger.debug(f"Cache MISS: {key}")
        value = fetch_func()

        if value is not None:
            self.set(key, value, ttl)

        return value

    # ========================================================================
    # SUBSCRIPTION CACHING
    # ========================================================================

    def get_subscription_plan(self, plan_code: str) -> Optional[Dict]:
        """Get subscription plan from cache or DB"""
        key = f"sub:plan:{plan_code}"
        return self.get(key)

    def cache_subscription_plan(self, plan_code: str, plan_data: Dict) -> bool:
        """Cache subscription plan for 1 hour"""
        key = f"sub:plan:{plan_code}"
        return self.set(key, plan_data, ttl=3600)

    def get_active_subscription(self, tenant_id: str) -> Optional[Dict]:
        """Get tenant's active subscription from cache"""
        key = f"sub:active:{tenant_id}"
        return self.get(key)

    def cache_active_subscription(self, tenant_id: str, subscription_data: Dict) -> bool:
        """Cache active subscription for 5 minutes"""
        key = f"sub:active:{tenant_id}"
        return self.set(key, subscription_data, ttl=300)

    def invalidate_subscription(self, tenant_id: str):
        """Invalidate subscription cache on changes"""
        self.delete(f"sub:active:{tenant_id}")
        self.delete_pattern(f"limit:check:{tenant_id}:*")  # Also clear limit checks

    # ========================================================================
    # USAGE TRACKING
    # ========================================================================

    def increment_api_calls(self, tenant_id: str, period: str = None) -> int:
        """Increment API call counter for tenant"""
        from datetime import datetime
        period = period or datetime.now().strftime('%Y-%m')
        key = f"usage:api_calls:{tenant_id}:{period}"

        # Calculate TTL: until end of current month
        from calendar import monthrange
        year, month = map(int, period.split('-'))
        days_in_month = monthrange(year, month)[1]
        last_day = datetime(year, month, days_in_month, 23, 59, 59)
        ttl = int((last_day - datetime.now()).total_seconds())

        return self.increment(key, amount=1, ttl=ttl)

    def get_usage_count(self, tenant_id: str, metric_type: str, period: str = None) -> int:
        """Get current usage count"""
        from datetime import datetime
        period = period or datetime.now().strftime('%Y-%m')
        key = f"usage:{metric_type}:{tenant_id}:{period}"

        try:
            value = self.redis.get(key)
            return int(value) if value else 0
        except Exception:
            return 0

    def cache_limit_check(self, tenant_id: str, limit_key: str, result: Dict) -> bool:
        """Cache limit check result for 30 seconds"""
        key = f"limit:check:{tenant_id}:{limit_key}"
        return self.set(key, result, ttl=30)

    def get_limit_check(self, tenant_id: str, limit_key: str) -> Optional[Dict]:
        """Get cached limit check result"""
        key = f"limit:check:{tenant_id}:{limit_key}"
        return self.get(key)

    # ========================================================================
    # TENANT & USER CACHING
    # ========================================================================

    def cache_tenant_config(self, tenant_id: str, config: Dict) -> bool:
        """Cache tenant configuration for 10 minutes"""
        key = f"tenant:config:{tenant_id}"
        return self.set(key, config, ttl=600)

    def get_tenant_config(self, tenant_id: str) -> Optional[Dict]:
        """Get tenant configuration from cache"""
        key = f"tenant:config:{tenant_id}"
        return self.get(key)

    def invalidate_tenant(self, tenant_id: str):
        """Invalidate all tenant-related caches"""
        self.delete_pattern(f"tenant:{tenant_id}:*")
        self.delete_pattern(f"sub:active:{tenant_id}")
        self.delete_pattern(f"user:*:{tenant_id}:*")

    def cache_api_key(self, key_prefix: str, key_data: Dict) -> bool:
        """Cache API key validation for 5 minutes"""
        key = f"apikey:valid:{key_prefix}"
        return self.set(key, key_data, ttl=300)

    def get_api_key(self, key_prefix: str) -> Optional[Dict]:
        """Get API key validation from cache"""
        key = f"apikey:valid:{key_prefix}"
        return self.get(key)

    def invalidate_api_key(self, key_prefix: str):
        """Invalidate API key cache"""
        self.delete(f"apikey:valid:{key_prefix}")

    # ========================================================================
    # DECORATORS
    # ========================================================================

    def cached(self, key_prefix: str, ttl: int = 300):
        """Decorator to cache function results"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Build cache key from function name and arguments
                cache_key = f"{key_prefix}:{func.__name__}:{hash(str(args) + str(kwargs))}"

                # Try cache first
                cached_result = self.get(cache_key)
                if cached_result is not None:
                    return cached_result

                # Cache miss - execute function
                result = func(*args, **kwargs)

                # Cache result
                if result is not None:
                    self.set(cache_key, result, ttl=ttl)

                return result
            return wrapper
        return decorator


# Global cache service instance
cache_service: Optional[CacheService] = None

def get_cache_service() -> CacheService:
    """Get or create cache service instance"""
    global cache_service
    if cache_service is None:
        from shared.config import get_settings
        settings = get_settings()
        cache_service = CacheService(settings.redis_url)
    return cache_service
```

---

## Cache Invalidation Patterns

### Pattern 1: Write-Through Cache

**When:** Creating/updating data

**Strategy:**
1. Write to database
2. Update cache immediately
3. Return response

```python
def update_tenant_subscription(tenant_id: str, new_plan_id: str):
    # 1. Write to database
    db.execute(
        "UPDATE tenant_subscriptions SET plan_id = :plan WHERE tenant_id = :tenant",
        {"plan": new_plan_id, "tenant": tenant_id}
    )

    # 2. Invalidate cache
    cache = get_cache_service()
    cache.invalidate_subscription(tenant_id)

    # 3. Optionally: warm cache immediately
    new_subscription = db.query(...).first()
    cache.cache_active_subscription(tenant_id, new_subscription.to_dict())
```

### Pattern 2: Cache-Aside (Lazy Loading)

**When:** Reading data

**Strategy:**
1. Check cache
2. If miss, fetch from DB
3. Store in cache
4. Return data

```python
def get_tenant_subscription(tenant_id: str):
    cache = get_cache_service()

    # Try cache first
    subscription = cache.get_active_subscription(tenant_id)
    if subscription:
        return subscription

    # Cache miss - fetch from DB
    subscription = db.query(TenantSubscription).filter_by(
        tenant_id=tenant_id,
        status='active'
    ).first()

    if subscription:
        # Cache for next time
        cache.cache_active_subscription(tenant_id, subscription.to_dict())

    return subscription
```

### Pattern 3: Time-Based Expiration

**When:** Data changes infrequently

**Strategy:**
- Set appropriate TTL
- Let cache expire naturally
- No manual invalidation needed

```python
# Subscription plans rarely change
cache.cache_subscription_plan("professional", plan_data, ttl=3600)  # 1 hour
```

### Pattern 4: Event-Driven Invalidation

**When:** External events trigger changes

**Strategy:**
- Listen for events (e.g., webhooks, pub/sub)
- Invalidate affected caches
- Let next read repopulate

```python
# Stripe webhook: subscription updated
@app.post("/webhooks/stripe")
def stripe_webhook(event: dict):
    if event["type"] == "customer.subscription.updated":
        tenant_id = get_tenant_from_stripe_customer(event["data"]["customer"])
        cache = get_cache_service()
        cache.invalidate_subscription(tenant_id)
```

---

## Integration Examples

### Example 1: API Request with Caching

```python
# api/routes.py
from fastapi import Depends, HTTPException
from services.cache_service import get_cache_service

@app.get("/api/lattices")
async def list_lattices(
    tenant_id: str = Depends(get_current_tenant),
    cache: CacheService = Depends(get_cache_service)
):
    # 1. Check subscription & limits (from cache)
    subscription = cache.get_or_set(
        f"sub:active:{tenant_id}",
        lambda: db.query(TenantSubscription).filter_by(
            tenant_id=tenant_id, status='active'
        ).first().to_dict(),
        ttl=300
    )

    # 2. Check usage (from Redis counter)
    usage = cache.get_usage_count(tenant_id, "api_calls")

    # 3. Validate limit (cached result)
    limit_check = cache.get_limit_check(tenant_id, "api_calls")
    if not limit_check:
        limit = subscription["plan_limits"]["api_calls_per_month"]
        limit_check = {
            "limit": limit,
            "current": usage,
            "exceeded": usage >= limit
        }
        cache.cache_limit_check(tenant_id, "api_calls", limit_check)

    if limit_check["exceeded"]:
        raise HTTPException(429, "API call limit exceeded")

    # 4. Increment counter
    cache.increment_api_calls(tenant_id)

    # 5. Fetch lattices (could also be cached if needed)
    lattices = db.query(TenantLattice).filter_by(
        tenant_id=tenant_id, is_active=True
    ).all()

    return {"lattices": [l.to_dict() for l in lattices]}
```

### Example 2: Subscription Check Middleware

```python
# middleware/subscription_check.py
from fastapi import Request
from services.cache_service import get_cache_service

async def check_subscription_middleware(request: Request, call_next):
    tenant_id = request.state.tenant_id  # From auth middleware

    cache = get_cache_service()

    # Get subscription from cache (or DB)
    subscription = cache.get_or_set(
        f"sub:active:{tenant_id}",
        lambda: fetch_active_subscription(tenant_id),
        ttl=300
    )

    if not subscription or subscription["status"] != "active":
        return JSONResponse(
            status_code=402,
            content={"error": "Active subscription required"}
        )

    # Store in request state for downstream use
    request.state.subscription = subscription

    response = await call_next(request)
    return response
```

---

## Performance Monitoring

### Redis Metrics to Track

```python
# monitoring/cache_metrics.py
def get_cache_stats():
    """Get Redis performance metrics"""
    cache = get_cache_service()

    info = cache.redis.info()

    return {
        "connected_clients": info["connected_clients"],
        "used_memory": info["used_memory_human"],
        "total_commands_processed": info["total_commands_processed"],
        "keyspace_hits": info.get("keyspace_hits", 0),
        "keyspace_misses": info.get("keyspace_misses", 0),
        "hit_rate": calculate_hit_rate(
            info.get("keyspace_hits", 0),
            info.get("keyspace_misses", 0)
        )
    }

def calculate_hit_rate(hits, misses):
    total = hits + misses
    return (hits / total * 100) if total > 0 else 0
```

### Cache Hit Rate Monitoring

```python
# Prometheus metrics
from prometheus_client import Counter, Histogram

cache_hits = Counter('cache_hits_total', 'Total cache hits', ['cache_type'])
cache_misses = Counter('cache_misses_total', 'Total cache misses', ['cache_type'])
cache_latency = Histogram('cache_latency_seconds', 'Cache operation latency', ['operation'])

# In cache_service.py
def get(self, key: str) -> Optional[Any]:
    with cache_latency.labels(operation='get').time():
        value = self.redis.get(key)
        if value:
            cache_hits.labels(cache_type=key.split(':')[0]).inc()
            return json.loads(value)
        cache_misses.labels(cache_type=key.split(':')[0]).inc()
        return None
```

---

## Testing Strategy

### Unit Tests

```python
# tests/test_cache_service.py
import pytest
from services.cache_service import CacheService

def test_cache_set_get():
    cache = CacheService("redis://localhost")
    cache.set("test:key", {"value": 123}, ttl=60)
    result = cache.get("test:key")
    assert result == {"value": 123}

def test_cache_miss_returns_none():
    cache = CacheService("redis://localhost")
    result = cache.get("nonexistent:key")
    assert result is None

def test_increment_counter():
    cache = CacheService("redis://localhost")
    key = "test:counter"
    cache.delete(key)  # Clean slate

    assert cache.increment(key) == 1
    assert cache.increment(key) == 2
    assert cache.increment(key, amount=5) == 7
```

### Integration Tests

```python
# tests/test_subscription_caching.py
def test_subscription_cached_on_first_access(client, test_tenant):
    # First request - cache miss
    response = client.get(f"/api/subscription", headers=auth_headers(test_tenant))
    assert response.status_code == 200

    # Verify cached
    cache = get_cache_service()
    cached = cache.get_active_subscription(test_tenant.id)
    assert cached is not None
    assert cached["plan_code"] == test_tenant.subscription.plan.code

def test_subscription_invalidated_on_update(client, test_tenant):
    # Cache subscription
    cache = get_cache_service()
    cache.cache_active_subscription(test_tenant.id, {"plan_code": "free"})

    # Update subscription
    response = client.post(
        f"/api/subscription/upgrade",
        json={"plan": "professional"},
        headers=auth_headers(test_tenant)
    )
    assert response.status_code == 200

    # Verify cache invalidated
    cached = cache.get_active_subscription(test_tenant.id)
    assert cached is None  # Should be invalidated
```

---

## Deployment Checklist

- [ ] Install Redis 6+ on production server
- [ ] Configure Redis persistence (RDB + AOF)
- [ ] Set up Redis password authentication
- [ ] Configure memory limits (`maxmemory` policy)
- [ ] Deploy cache_service.py module
- [ ] Integrate caching into API endpoints
- [ ] Set up cache monitoring (Prometheus/Grafana)
- [ ] Configure cache invalidation on all write operations
- [ ] Load test with caching enabled
- [ ] Monitor hit rates and adjust TTLs

---

## Expected Performance Improvements

| Endpoint | Before (avg) | After (avg) | Improvement |
|----------|--------------|-------------|-------------|
| GET /api/subscription | 45ms | 5ms | **9x faster** |
| GET /api/lattices | 80ms | 15ms | **5.3x faster** |
| POST /api/lattice | 120ms | 95ms | **1.3x faster** |
| Limit check | 25ms | 2ms | **12.5x faster** |

**Overall API throughput: 5-10x improvement**

---

## Next Steps

1. Review and approve caching strategy
2. Deploy cache_service.py implementation
3. Integrate caching into critical endpoints
4. Monitor cache hit rates
5. Tune TTLs based on actual usage patterns

**Files to Create:**
- `services/cache_service.py` - Core caching implementation
- `middleware/cache_middleware.py` - Request-level caching
- `monitoring/cache_metrics.py` - Performance tracking