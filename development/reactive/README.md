# Reactive Programming with RxPy

**Status**: ✅ Learning Project Complete (Week 1)
**Purpose**: Master reactive programming patterns using RxPy
**Based On**: Real webhook manager refactoring
**Testing**: Marble diagram test suite

---

## Overview

This project demonstrates a complete transformation from imperative async code to reactive programming patterns using RxPy. The core example refactors a production webhook manager (~488 lines) into declarative reactive streams.

## Project Structure

```
reactive/
├── core/                    # Core implementations
│   ├── webhook_manager_reactive.py  # Main reactive refactoring
│   └── __init__.py
├── operators/               # Custom RxPy operators
│   └── __init__.py
├── patterns/                # Common reactive patterns
│   ├── advanced_operators.py
│   ├── hot_cold_observables.py
│   └── __init__.py
├── metrics/                 # Performance metrics
│   ├── collect_baseline.py
│   └── __init__.py
├── tests/                   # Marble diagram tests
│   └── test_webhook_manager_reactive.py
├── docs/                    # Learning documentation
│   ├── COMPLETE_GUIDE.md    # Comprehensive guide
│   ├── BMAD_PLAN.md         # BMAD patterns
│   └── flowcharts.py        # Visual diagrams
├── WEEK1_DAY2_COMPLETION_REPORT.md
├── WEEK1_FINAL_SUMMARY.md
└── webhooks_config.yaml     # Configuration
```

## Quick Start

### Prerequisites

```bash
pip install rxpy pytest pytest-asyncio
```

### Run the Reactive Webhook Manager

```python
from core.webhook_manager_reactive import ReactiveWebhookManager

# Initialize
manager = ReactiveWebhookManager(config_path="webhooks_config.yaml")

# Send webhooks through reactive stream
await manager.send_webhook({
    "event_name": "user.created",
    "data": {"user_id": "123"},
    "priority": "high"
})

# Metrics automatically collected
print(manager.get_metrics())
```

### Run Marble Diagram Tests

```bash
cd C:/Users/Corbin/development/reactive
pytest tests/ -v
```

## Key Concepts Demonstrated

### 1. **Imperative → Reactive Transformation**

**Before (Imperative):**
```python
async def _delivery_worker(self, worker_id: int):
    while self.running:
        priority, payload = await self.delivery_queue.get()
        endpoints = self.endpoints.get(payload.event_name, [])
        for endpoint in endpoints:
            if endpoint.active:
                task = self._deliver_webhook(payload, endpoint)
                delivery_tasks.append(task)
        await asyncio.gather(*delivery_tasks)
```

**After (Reactive):**
```python
self.webhook_stream.pipe(
    ops.group_by(lambda payload: payload.priority.value),
    ops.flat_map(lambda group: group.pipe(
        ops.flat_map(lambda p: self._create_delivery_pairs(p)),
        ops.filter(lambda pair: self._check_circuit_breaker(pair[1].url)),
        ops.flat_map(lambda pair: self._deliver_webhook_reactive(pair[0], pair[1]),
                     max_concurrent=10),
        ops.retry(5),
        ops.catch(lambda error, source: self._handle_delivery_error(error, source))
    ))
).subscribe(on_next=self._on_delivery_success)
```

### 2. **Marble Diagram Testing**

Visual testing using time-based diagrams:

```python
# Input:   -a-b-c-|
# Output:  -----c-|  (debounced by 30ms)

source = scheduler.create_hot_observable(
    ReactiveTest.on_next(10, "a"),
    ReactiveTest.on_next(20, "b"),
    ReactiveTest.on_next(30, "c"),
    ReactiveTest.on_completed(70)
)

results = scheduler.start(lambda: source.pipe(ops.debounce(30)))

# Assert exact timing
assert results.messages == [
    ReactiveTest.on_next(60, "c"),  # Emitted after 30ms quiet period
    ReactiveTest.on_completed(70)
]
```

### 3. **Reactive Patterns Covered**

#### Core Operators
- `map()` - Transform each item
- `filter()` - Selective emission
- `flat_map()` - Flatten nested observables
- `group_by()` - Group by key function
- `merge()` - Combine multiple streams

#### Advanced Patterns
- **Backpressure**: `buffer()`, `throttle()`
- **Error Handling**: `retry()`, `catch()`, `finally()`
- **Time-Based**: `debounce()`, `delay()`, `timeout()`
- **Windowing**: `window()`, `window_with_time()`
- **Stateful**: `scan()`, `distinct_until_changed()`

#### Circuit Breaker Pattern
```python
def _check_circuit_breaker(self, url: str) -> bool:
    """Check if endpoint circuit is open (failing)"""
    failures = self.circuit_state.get(url, 0)
    return failures < 5  # Open circuit after 5 failures
```

### 4. **Hot vs Cold Observables**

**Cold Observable** (Starts on subscribe):
```python
cold = rx.of(1, 2, 3)
cold.subscribe(print)  # Prints: 1, 2, 3
```

**Hot Observable** (Always emitting):
```python
subject = Subject()
subject.subscribe(print)  # Observer 1
subject.on_next(1)        # Both see this
subject.subscribe(print)  # Observer 2
subject.on_next(2)        # Both see this
```

## Benefits of Reactive Approach

### ✅ **Declarative Data Flow**
- Code reads like the data pipeline it represents
- Easy to visualize: "Group by priority → Filter by circuit breaker → Deliver with retry"

### ✅ **Automatic Backpressure**
- Built-in buffering strategies
- No manual queue management
- Prevents memory exhaustion

### ✅ **Built-in Retry Logic**
```python
.pipe(
    ops.retry(5),  # Automatic retry with exponential backoff
    ops.catch(handle_error)
)
```

### ✅ **Composable Error Handling**
```python
.pipe(
    ops.catch(lambda err, src: rx.empty()),  # Ignore errors
    ops.finally(cleanup)  # Always cleanup
)
```

### ✅ **Time-Based Operations**
```python
.pipe(
    ops.debounce(0.3),  # Wait for quiet period
    ops.timeout(5.0),   # Max wait time
    ops.delay(0.1)      # Artificial delay
)
```

### ✅ **Testable with Marble Diagrams**
- Synchronous tests for async code
- Precise timing control
- Visual test documentation

## Real-World Use Cases

### 1. **Webhook Delivery** (Current Implementation)
- Priority-based delivery
- Circuit breaker protection
- Automatic retries
- Concurrency limiting

### 2. **Event Processing Pipelines**
```python
events_stream.pipe(
    ops.filter(lambda e: e.type == "order"),
    ops.flat_map(enrich_with_user_data),
    ops.buffer_with_time(1.0),  # Batch every second
    ops.flat_map(bulk_insert_to_db)
)
```

### 3. **Real-Time Analytics**
```python
click_stream.pipe(
    ops.window_with_time(60),  # 60-second windows
    ops.flat_map(lambda window: window.pipe(ops.count())),
    ops.subscribe(update_dashboard)
)
```

### 4. **Rate Limiting**
```python
api_requests.pipe(
    ops.throttle_first(1.0),  # Max 1 request per second
    ops.flat_map(execute_request)
)
```

## Testing Strategy

### Comprehensive Test Coverage

**8 Core Tests:**
1. ✅ Priority grouping (high/medium/low)
2. ✅ Circuit breaker filtering
3. ✅ Retry logic with backoff
4. ✅ Backpressure buffering
5. ✅ Time window aggregation
6. ✅ Debounce operator
7. ✅ Error recovery patterns
8. ✅ Distinct until changed

**Run all tests:**
```bash
pytest tests/ -v --cov=core
```

**Coverage report:**
```bash
pytest --cov=core --cov-report=html
# Open htmlcov/index.html
```

## Performance Metrics

The project includes baseline metrics collection:

```python
from metrics.collect_baseline import collect_baseline

metrics = await collect_baseline(
    num_webhooks=1000,
    num_endpoints=10,
    concurrency=50
)

print(f"Throughput: {metrics['throughput_per_sec']} req/s")
print(f"P95 latency: {metrics['p95_latency_ms']}ms")
print(f"Success rate: {metrics['success_rate']}%")
```

## Configuration

**webhooks_config.yaml:**
```yaml
manager:
  max_concurrent_deliveries: 10
  retry_attempts: 5
  circuit_breaker_threshold: 5
  backpressure_buffer_size: 1000

endpoints:
  - name: "primary"
    url: "https://api.example.com/webhooks"
    active: true
    priority: "high"

  - name: "analytics"
    url: "https://analytics.example.com/events"
    active: true
    priority: "low"
```

## Learning Path

### Week 1 Completion ✅

**Day 1-2**: Core refactoring
- [WEEK1_DAY2_COMPLETION_REPORT.md](WEEK1_DAY2_COMPLETION_REPORT.md)

**Day 3-7**: Testing & patterns
- [WEEK1_FINAL_SUMMARY.md](WEEK1_FINAL_SUMMARY.md)

### Recommended Study Order

1. **[docs/COMPLETE_GUIDE.md](docs/COMPLETE_GUIDE.md)** - Start here!
   - Core concepts
   - Step-by-step refactoring
   - Common patterns

2. **[core/webhook_manager_reactive.py](core/webhook_manager_reactive.py)**
   - Production example
   - Real-world patterns
   - Performance optimizations

3. **[tests/test_webhook_manager_reactive.py](tests/)**
   - Marble diagram syntax
   - Testing strategies
   - Edge cases

4. **[patterns/](patterns/)**
   - Advanced operators
   - Hot/cold observables
   - Custom operators

5. **[docs/BMAD_PLAN.md](docs/BMAD_PLAN.md)**
   - BMAD pattern applications
   - Architecture patterns

## Dependencies

```python
# requirements.txt
rxpy>=4.0.0           # Reactive extensions
pytest>=7.0.0         # Testing framework
pytest-asyncio>=0.21  # Async test support
pyyaml>=6.0           # Config parsing
```

## Integration with Main Platform

### SaaS Event Bus
```python
# saas/events/reactive_bus.py
from reactive.core import ReactiveWebhookManager

event_bus = ReactiveWebhookManager(config_path="production.yaml")
```

### Monitoring Integration
```python
webhook_stream.pipe(
    ops.tap(lambda payload: prometheus_counter.inc()),
    ops.tap(lambda payload: log_to_grafana(payload))
)
```

## Advanced Topics

### Custom Operators

Create reusable operators:

```python
def rate_limit(rate_per_second: float):
    """Custom rate limiting operator"""
    def _rate_limit(source):
        return source.pipe(
            ops.zip(rx.interval(1.0 / rate_per_second)),
            ops.map(lambda x: x[0])  # Drop the interval value
        )
    return _rate_limit

# Usage
stream.pipe(rate_limit(10))  # Max 10 items/second
```

### Schedulers

Control execution context:

```python
from rx.scheduler import ThreadPoolScheduler, NewThreadScheduler

# CPU-intensive work
stream.pipe(
    ops.observe_on(ThreadPoolScheduler(max_workers=4))
)

# I/O operations
stream.pipe(
    ops.observe_on(NewThreadScheduler())
)
```

## Migration Guide

### From Imperative Async

1. **Identify async loops** → Convert to observables
2. **Manual error handling** → Use `retry()` and `catch()`
3. **Queue management** → Use `buffer()` and backpressure
4. **Worker pools** → Use `flat_map(max_concurrent=N)`
5. **Timeouts** → Use `timeout()` operator

### Common Pitfalls

❌ **Don't**: Create observers inside loops
✅ **Do**: Use operators like `flat_map()`

❌ **Don't**: Mix promises and observables unnecessarily
✅ **Do**: Convert promises once at boundaries

❌ **Don't**: Forget to unsubscribe
✅ **Do**: Use context managers or `dispose()`

## Resources

### RxPy Documentation
- [Official Docs](https://rxpy.readthedocs.io/)
- [Operators Reference](https://rxpy.readthedocs.io/en/latest/operators.html)
- [Marble Diagrams](https://rxmarbles.com/)

### Learning Materials
- ReactiveX tutorials
- RxJS documentation (concepts apply)
- Marble diagram visualizer

## Next Steps

### Planned Enhancements
- [ ] Add distributed tracing
- [ ] Implement custom backpressure strategies
- [ ] Create operator composition library
- [ ] Add GraphQL subscription support
- [ ] Build real-time dashboard with reactive updates

## Related Projects

- **[saas/](../saas/)**: Production SaaS platform
- **[defensive_agents/](../defensive_agents/)**: Security agent framework
- **[ml-sectest-framework/](../ml-sectest-framework/)**: ML security testing

---

**Project Status**: ✅ Week 1 Complete
**Coverage**: 98% (based on WEEK1_FINAL_SUMMARY.md)
**Last Updated**: 2025-10-09
**Maintainer**: Corbin
