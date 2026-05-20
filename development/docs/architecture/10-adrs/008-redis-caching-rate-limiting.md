# ADR-008: Redis for Caching and Rate Limiting

**Status**: Accepted | **Date**: 2024-10-03 | **Deciders**: Architecture Team

## Decision
Use **Redis 7** for caching, session storage, JWT blacklist, and rate limiting.

## Rationale
- In-memory speed (sub-millisecond operations)
- Persistence options (AOF + RDB)
- Lua scripting for atomic operations (rate limiting)
- Pub/sub for inter-service communication

## Use Cases
| Database | Purpose | TTL |
|----------|---------|-----|
| 0 | JWT blacklist | Token expiry |
| 1 | Session cache | 24 hours |
| 2 | Rate limiting | 1 minute |
| 3 | Result cache | 1 hour |

## Rate Limiting (Lua)
```lua
-- Sliding window rate limiter
local count = redis.call('ZCARD', key)
if count < limit then
    redis.call('ZADD', key, now, now)
    return 1  -- Allowed
end
return 0  -- Blocked
```

## Alternatives Rejected
- **Memcached**: No persistence, no Lua scripting
- **Application memory**: Not distributed, lost on restart

---
**Last Updated**: 2024-10-15
