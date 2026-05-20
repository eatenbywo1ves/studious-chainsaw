# Phase 4: SEC-011 Streaming Validation Implementation Plan

**Date:** 2025-11-04
**Status:** READY TO IMPLEMENT
**Current Completion:** 80% (Content-Length validation)
**Target Completion:** 100% (Add streaming body validation)

---

## Current Implementation Analysis

### ✅ What's Already Implemented (80%)

**File:** `development/saas/auth/request_limits.py`

**Current Features:**
1. Content-Length header validation (lines 56-95)
2. Different limits for uploads vs regular requests
3. Path-based upload detection
4. Comprehensive logging
5. 413 Payload Too Large responses

**What Works:**
- Blocks requests with Content-Length > limit
- Fast rejection (no body reading)
- Memory efficient

### ⚠️ Security Gap (Remaining 20%)

**Vulnerability:** Content-Length Bypass
- Attacker sends Content-Length: 1000 (passes check)
- Attacker streams 100MB body (bypasses check)
- Server reads entire body before detecting size
- Result: Memory exhaustion, DOS

**Attack Example:**
```python
import requests

# Send small Content-Length
headers = {"Content-Length": "1000"}

# Stream large body
def generate_large_body():
    for _ in range(100 * 1024):  # 100MB in 1KB chunks
        yield b"A" * 1024

# This bypasses current validation!
requests.post(
    "https://api.example.com/endpoint",
    headers=headers,
    data=generate_large_body()
)
```

---

## Implementation Plan

### Step 1: Add Streaming Body Validation

**Location:** `development/saas/auth/request_limits.py`
**Function:** `dispatch()` method
**Lines to modify:** After line 96 (before `call_next`)

**New Logic:**
```python
# After Content-Length check, validate actual body size
if request.method in ["POST", "PUT", "PATCH"]:
    # Wrap request body stream with size validator
    bytes_read = 0
    max_size = self.max_upload_size if is_upload else self.max_request_size

    async def validate_body_stream():
        nonlocal bytes_read
        async for chunk in request.stream():
            bytes_read += len(chunk)
            if bytes_read > max_size:
                raise HTTPException(
                    status_code=413,
                    detail=f"Request body too large: {bytes_read} > {max_size}"
                )
            yield chunk

    # Replace request stream with validated stream
    request._stream = validate_body_stream()
```

**Why This Works:**
- Validates ACTUAL bytes received
- Works even if Content-Length is missing/wrong
- Fails fast (stops reading at limit)
- Memory efficient (streaming validation)

### Step 2: Handle Missing Content-Length

**Current Behavior:** Proceeds without validation if no Content-Length
**New Behavior:** Always validate body size via streaming

**Code Change:**
```python
# Before
if content_length:
    # validate

# After
# Always set max_size for streaming validation
is_upload = ...
max_size = self.max_upload_size if is_upload else self.max_request_size

if content_length:
    # Fast path: validate Content-Length header
    if content_length > max_size:
        return JSONResponse(...)  # 413 error

# Slow path: validate actual body (handles missing/wrong Content-Length)
if request.method in ["POST", "PUT", "PATCH"]:
    request = await self._wrap_request_body(request, max_size, is_upload)
```

### Step 3: Create Body Wrapper Method

**New Method:** `_wrap_request_body()`

```python
async def _wrap_request_body(
    self,
    request: Request,
    max_size: int,
    is_upload: bool
) -> Request:
    """
    Wrap request body stream to validate size as it's read

    Args:
        request: Original request
        max_size: Maximum allowed size
        is_upload: Whether this is an upload request

    Returns:
        Request with validated body stream

    Raises:
        HTTPException: If body exceeds max_size
    """
    original_stream = request.stream()
    bytes_read = 0

    async def validated_stream():
        nonlocal bytes_read
        try:
            async for chunk in original_stream:
                bytes_read += len(chunk)
                if bytes_read > max_size:
                    size_mb = bytes_read / (1024 * 1024)
                    limit_mb = max_size / (1024 * 1024)

                    logger.error(
                        f"Streaming body exceeded limit: {size_mb:.2f}MB > {limit_mb:.2f}MB",
                        extra={
                            "path": request.url.path,
                            "method": request.method,
                            "bytes_read": bytes_read,
                            "max_size": max_size,
                            "is_upload": is_upload,
                            "content_length_header": request.headers.get("content-length"),
                        }
                    )

                    raise HTTPException(
                        status_code=413,
                        detail=f"Request body too large. Maximum: {limit_mb:.0f}MB, "
                               f"received: {size_mb:.2f}MB"
                    )
                yield chunk
        finally:
            # Log final size for monitoring
            logger.debug(
                f"Request body read: {bytes_read} bytes",
                extra={"path": request.url.path, "bytes_read": bytes_read}
            )

    # Create new request with validated stream
    request._stream = validated_stream()
    return request
```

### Step 4: Add Metrics

**Prometheus Metrics to Add:**
```python
from prometheus_client import Counter, Histogram

request_size_exceeded = Counter(
    "request_size_limit_exceeded_total",
    "Requests rejected due to size limit",
    ["method", "path", "limit_type"]
)

request_body_bytes = Histogram(
    "request_body_bytes",
    "Distribution of request body sizes",
    ["method", "limit_type"],
    buckets=[1024, 10*1024, 100*1024, 1024*1024, 10*1024*1024, 100*1024*1024]
)
```

### Step 5: Add Tests

**Test File:** `development/saas/tests/integration/test_request_size_limits.py`

**Test Cases:**
1. ✅ Content-Length validation (already works)
2. **NEW:** Missing Content-Length + large body
3. **NEW:** Small Content-Length + large body (bypass attempt)
4. **NEW:** Chunked transfer encoding
5. **NEW:** Multipart uploads
6. **NEW:** Streaming validation performance

---

## Implementation Steps

### Phase 4A: Core Implementation (30 minutes)

1. [  ] Import HTTPException from starlette.exceptions
2. [  ] Create `_wrap_request_body()` method
3. [  ] Update `dispatch()` to use streaming validation
4. [  ] Handle missing Content-Length case
5. [  ] Test locally with curl

### Phase 4B: Testing (30 minutes)

6. [  ] Create test file with 5 test cases
7. [  ] Test Content-Length bypass
8. [  ] Test missing Content-Length
9. [  ] Test chunked encoding
10. [  ] Verify memory efficiency

### Phase 4C: Metrics & Monitoring (20 minutes)

11. [  ] Add Prometheus metrics
12. [  ] Log streaming violations
13. [  ] Update monitoring dashboard

### Phase 4D: Documentation (10 minutes)

14. [  ] Update SEC-011 status to 100%
15. [  ] Document streaming validation
16. [  ] Add usage examples

**Total Estimated Time:** 90 minutes (1.5 hours)

---

## Testing Strategy

### Unit Tests

```python
async def test_content_length_bypass():
    """Test that streaming validation catches Content-Length bypass"""
    middleware = RequestSizeLimitMiddleware(app, max_request_size=1024)

    # Create request with small Content-Length
    request = Request({
        "type": "http",
        "method": "POST",
        "headers": {"content-length": "100"},
        "body": b"A" * 10000  # 10KB > 1KB limit
    })

    response = await middleware.dispatch(request, dummy_call_next)
    assert response.status_code == 413

async def test_missing_content_length():
    """Test streaming validation without Content-Length"""
    middleware = RequestSizeLimitMiddleware(app, max_request_size=1024)

    request = Request({
        "type": "http",
        "method": "POST",
        "headers": {},  # No Content-Length
        "body": b"A" * 10000  # 10KB > 1KB limit
    })

    response = await middleware.dispatch(request, dummy_call_next)
    assert response.status_code == 413

async def test_chunked_transfer():
    """Test streaming validation with chunked encoding"""
    # Simulate chunked transfer encoding
    async def chunked_body():
        for _ in range(100):
            yield b"A" * 1024  # 100KB total

    request = Request({
        "type": "http",
        "method": "POST",
        "headers": {"transfer-encoding": "chunked"},
        "body": chunked_body()
    })

    middleware = RequestSizeLimitMiddleware(app, max_request_size=10*1024)
    response = await middleware.dispatch(request, dummy_call_next)
    assert response.status_code == 413
```

### Integration Tests

```bash
# Test with curl

# Test 1: Content-Length bypass
curl -X POST http://localhost:8000/api/test \
  -H "Content-Length: 100" \
  --data-binary "@large_file.bin"  # 100MB file
# Expected: 413 Payload Too Large

# Test 2: Chunked encoding
curl -X POST http://localhost:8000/api/test \
  -H "Transfer-Encoding: chunked" \
  --data-binary "@large_file.bin"
# Expected: 413 Payload Too Large

# Test 3: No Content-Length
curl -X POST http://localhost:8000/api/test \
  --data-binary "@large_file.bin"
# Expected: 413 Payload Too Large
```

---

## Success Criteria

| Criterion | Current | Target | Status |
|-----------|---------|--------|--------|
| Content-Length Validation | ✅ | ✅ | DONE |
| Streaming Body Validation | ❌ | ✅ | TODO |
| Missing Content-Length | ⚠️ | ✅ | TODO |
| Chunked Encoding | ❌ | ✅ | TODO |
| Memory Efficiency | ✅ | ✅ | MAINTAINED |
| Test Coverage | 50% | 100% | TODO |
| SEC-011 Completion | 80% | 100% | TODO |

---

## Security Impact

### Before (Current 80%)
- **Vulnerability:** Content-Length bypass
- **Attack Vector:** Lie about size, stream large body
- **Impact:** Memory exhaustion, DOS
- **CVSS Score:** 7.5 (HIGH)

### After (Target 100%)
- **Vulnerability:** NONE
- **Attack Vector:** Blocked at any size
- **Impact:** No memory exhaustion possible
- **CVSS Score:** 0.0 (NONE)

---

## Performance Impact

### Current Implementation
- **Content-Length check:** <1ms (header only)
- **Memory usage:** Constant (no body read)

### New Implementation
- **Content-Length check:** <1ms (unchanged)
- **Streaming validation:** +5-10ms per MB
- **Memory usage:** Constant (streaming, not buffered)

**Worst Case:**
- 10MB request over limit
- Reads first 10MB
- Rejects after 10MB read
- Time: ~50-100ms additional
- Memory: ~32KB buffer (constant)

**Best Case:**
- Content-Length present and valid
- Fast path rejection: <1ms
- No body reading

---

## Rollout Plan

### Stage 1: Development (This Session)
- Implement streaming validation
- Unit tests passing
- Local testing with curl

### Stage 2: Staging (Next Session)
- Deploy to staging environment
- Run integration tests
- Monitor for 24 hours

### Stage 3: Production (After Staging)
- Canary deployment (5% traffic)
- Monitor metrics
- Full rollout after 48 hours

---

## Monitoring & Alerts

### Metrics to Watch
- `request_size_limit_exceeded_total` - Should be low
- `request_body_bytes` - Distribution should be normal
- `http_request_duration_seconds{endpoint="/api/*"}` - Should not increase significantly

### Alerts
```yaml
- alert: HighRequestSizeRejection
  expr: rate(request_size_limit_exceeded_total[5m]) > 10
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High rate of request size rejections"

- alert: UnexpectedLargeRequests
  expr: request_body_bytes{quantile="0.99"} > 50MB
  for: 10m
  labels:
    severity: info
  annotations:
    summary: "Unusual request size distribution"
```

---

## Next Steps After Implementation

1. ✅ SEC-011: 100% complete
2. Security score: 78 → 82 (+4 points)
3. Ready for Phase 5 (monitoring deployment)
4. Production deployment approved

---

**Created:** 2025-11-04
**Target Completion:** This session (90 minutes)
**Security Priority:** HIGH
**Breaking Changes:** None (backward compatible)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
