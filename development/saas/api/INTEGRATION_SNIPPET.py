"""
READY-TO-PASTE CODE SNIPPETS FOR METRICS INTEGRATION
Copy and paste these into saas_server.py at the indicated locations
"""

# ============================================================================
# SNIPPET 1: IMPORTS (Add after line 26, after security headers import)
# ============================================================================

SNIPPET_1 = """
from api.metrics_instrumentation import (
    add_metrics_endpoint,
    MetricsMiddleware
)
"""


# ============================================================================
# SNIPPET 2: METRICS ENDPOINT (Add after line 258, after tenant_router)
# ============================================================================

SNIPPET_2 = """
# Add Prometheus metrics endpoint
add_metrics_endpoint(app)
"""


# ============================================================================
# SNIPPET 3: METRICS MIDDLEWARE (Add after line 252, after LoggingMiddleware)
# ============================================================================

SNIPPET_3 = """
# Add metrics tracking middleware (PLACE THIS FIRST, before other middleware)
app.add_middleware(MetricsMiddleware)
"""


# ============================================================================
# SNIPPET 4: AUTHENTICATION TRACKING (Update login endpoint around line 289)
# ============================================================================

# BEFORE (current code):
"""
if not user or not user.verify_password(request.password):
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials"
    )
"""

# AFTER (with metrics):
"""
if not user or not user.verify_password(request.password):
    # Track failed login attempt
    track_authentication(request.tenant_slug or 'default', success=False)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials"
    )

# Track successful login (add this AFTER password verification succeeds)
track_authentication(request.tenant_slug or 'default', success=True)
"""


# ============================================================================
# MINIMAL 3-LINE INTEGRATION (Easiest option)
# ============================================================================

# Add these 3 lines after line 258 (after app.include_router(tenant_router)):

MINIMAL_INTEGRATION = """
from api.metrics_instrumentation import add_metrics_endpoint, MetricsMiddleware
add_metrics_endpoint(app)
app.add_middleware(MetricsMiddleware)
"""

# That's it! /metrics endpoint is now available at http://localhost:8000/metrics


# ============================================================================
# VERIFICATION COMMANDS
# ============================================================================

# After integration, run these commands to verify:
"""
# 1. Check metrics endpoint
curl http://localhost:8000/metrics

# 2. Make a test request
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test"}'

# 3. Check metrics again (should see http_requests_total increment)
curl http://localhost:8000/metrics | grep http_requests_total

# 4. Check Prometheus targets
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job=="saas-api")'
"""
