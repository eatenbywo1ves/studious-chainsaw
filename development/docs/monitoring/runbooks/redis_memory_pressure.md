# Alert Runbook: Redis Memory Pressure

## Alert Details

- **Alert Name**: RedisMemoryHigh
- **Severity**: Warning
- **Threshold**: Memory usage > 90% of max memory
- **Duration**: 5 minutes
- **Category**: Performance

## Description

Redis memory usage has exceeded 90% of the configured maximum. This can lead to evictions, performance degradation, or service failures.

## Impact

- Cache evictions may increase
- Performance degradation
- Potential out-of-memory crashes
- Failed write operations
- Increased database load (cache misses)

## Diagnosis

### Check Redis Memory Status

```bash
# Check memory usage
docker exec catalytic-redis redis-cli INFO memory

# Check memory metrics
curl -s 'http://localhost:9090/api/v1/query?query=redis_memory_used_bytes/redis_memory_max_bytes*100' | jq

# Check keyspace size
docker exec catalytic-redis redis-cli INFO keyspace

# Check largest keys
docker exec catalytic-redis redis-cli --bigkeys
```

### Check Cache Hit Rate

```bash
# Check cache performance
curl -s 'http://localhost:9090/api/v1/query?query=rate(cache_hits_total[5m])/(rate(cache_hits_total[5m])+rate(cache_misses_total[5m]))*100' | jq
```

### Identify Memory-Heavy Keys

```bash
# Sample keys to find large ones
docker exec catalytic-redis redis-cli --bigkeys

# Get key count by pattern
docker exec catalytic-redis redis-cli DBSIZE
```

## Resolution

### Immediate Actions

1. **Increase Memory Limit** (temporary)
   ```bash
   # Edit docker-compose.yml
   # Update redis maxmemory setting
   docker-compose restart redis
   ```

2. **Manually Flush Unnecessary Keys**
   ```bash
   # Flush specific database (if using multiple)
   docker exec catalytic-redis redis-cli -n 1 FLUSHDB

   # Delete keys by pattern (CAREFUL!)
   docker exec catalytic-redis redis-cli --scan --pattern "temp:*" | xargs -L 100 docker exec -i catalytic-redis redis-cli DEL
   ```

3. **Enable Key Eviction** (if not already enabled)
   ```bash
   # Set eviction policy
   docker exec catalytic-redis redis-cli CONFIG SET maxmemory-policy allkeys-lru
   ```

### Short-term Actions

1. **Review Key Expiration**
   ```python
   # Ensure all cache keys have TTL
   redis_client.setex("key", 3600, "value")  # 1 hour TTL

   # Don't use SET without expiration
   # redis_client.set("key", "value")  # BAD - never expires
   ```

2. **Optimize Data Structures**
   ```python
   # Use hashes for structured data instead of JSON strings
   # BAD
   redis_client.set(f"user:{user_id}", json.dumps(user_data))

   # GOOD
   redis_client.hmset(f"user:{user_id}", user_data)
   ```

3. **Implement Cache Compression**
   ```python
   import zlib
   import pickle

   def cache_set_compressed(key, value, ttl):
       serialized = pickle.dumps(value)
       compressed = zlib.compress(serialized)
       redis_client.setex(key, ttl, compressed)
   ```

### Long-term Actions

1. **Implement Cache Tiering**
   - Use local in-memory cache (LRU) for hot data
   - Use Redis for shared cache
   - Move cold data to database

2. **Scale Redis**
   ```bash
   # Use Redis Cluster for horizontal scaling
   # Or Redis Sentinel for HA
   ```

3. **Regular Monitoring**
   - Set up daily memory usage reports
   - Track key count growth
   - Monitor eviction rates

4. **Cache Pruning Strategy**
   ```python
   # Scheduled cleanup job
   def cleanup_old_cache():
       # Remove keys older than X days
       for key in redis_client.scan_iter("temp:*"):
           ttl = redis_client.ttl(key)
           if ttl == -1:  # No expiration
               redis_client.delete(key)
   ```

## Prevention

1. **Set TTL on All Keys**
2. **Monitor cache hit/miss ratio**
3. **Regular cache audits**
4. **Implement cache warming strategies**
5. **Use appropriate data structures**

## Related Alerts

- `RedisCacheMissRateHigh`: Poor cache efficiency
- `HighDatabaseQueryLatency`: Increased DB load from cache misses
- `HighAPILatency`: Cache issues can slow API

## Escalation

- Level 1: On-call engineer
- Level 2: Backend team lead
- Level 3: Infrastructure team

## Additional Resources

- [Redis Memory Optimization]: https://redis.io/docs/manual/eviction/
- [Grafana Dashboard]: http://localhost:3000
- [Redis Logs]: `docker logs catalytic-redis`

## Changelog

- 2025-10-06: Initial runbook creation
