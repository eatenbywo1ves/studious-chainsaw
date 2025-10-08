#!/usr/bin/env python3
"""
Mock Authentication Server for Load Testing
Provides simple JWT auth endpoints without database dependencies
"""

from datetime import datetime, timedelta
from typing import Optional
import jwt
from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import uvicorn

# Configuration
SECRET_KEY = "test_secret_key_for_load_testing_only"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# In-memory storage for revoked tokens (blacklist)
revoked_tokens = set()

# In-memory rate limiting
rate_limit_data = {}

# Create FastAPI app
app = FastAPI(title="Mock Auth Server for Load Testing")

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# MODELS
# ============================================================================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# ============================================================================
# JWT UTILITIES
# ============================================================================

def create_access_token(email: str) -> str:
    """Create JWT access token"""
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,
        "exp": expire,
        "type": "access"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(email: str) -> str:
    """Create JWT refresh token"""
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": email,
        "exp": expire,
        "type": "refresh"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[str]:
    """Verify JWT token and return email"""
    try:
        # Check if token is revoked
        if token in revoked_tokens:
            return None

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        return email
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ============================================================================
# DEPENDENCIES
# ============================================================================

def get_current_user(authorization: Optional[str] = Header(None)):
    """Extract and verify JWT token from Authorization header"""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme"
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format"
        )

    email = verify_token(token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    return email

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "Mock Auth Server",
        "status": "running",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """
    Mock login endpoint
    Accepts any email/password combination matching pattern:
    - Email: loadtest_user_N@example.com
    - Password: Any of the test passwords
    """
    # For load testing, accept any valid email format
    # In production, this would validate against database

    # Simple validation: accept any email with valid format
    email = request.email

    # Create tokens
    access_token = create_access_token(email)
    refresh_token = create_refresh_token(email)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest):
    """Refresh access token using refresh token"""
    email = verify_token(request.refresh_token)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    # Create new tokens
    access_token = create_access_token(email)
    refresh_token = create_refresh_token(email)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )

@app.post("/auth/logout")
async def logout(current_user: str = Depends(get_current_user), authorization: str = Header(...)):
    """Logout and revoke token"""
    try:
        scheme, token = authorization.split()
        # Add token to revoked list
        revoked_tokens.add(token)

        return {
            "message": "Successfully logged out",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

@app.get("/api/protected")
async def protected_endpoint(current_user: str = Depends(get_current_user)):
    """Protected endpoint requiring valid JWT"""
    return {
        "message": "Access granted",
        "user": current_user,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health():
    """Health check for monitoring"""
    return {
        "status": "healthy",
        "revoked_tokens_count": len(revoked_tokens),
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("Mock Authentication Server for Load Testing")
    print("=" * 80)
    print("Endpoints:")
    print("   POST /auth/login - Login and get tokens")
    print("   POST /auth/refresh - Refresh access token")
    print("   POST /auth/logout - Logout and revoke token")
    print("   GET  /api/protected - Protected endpoint (requires token)")
    print("   GET  /health - Health check")
    print("=" * 80)
    print("Note: This is a mock server for load testing only")
    print("   - Accepts any valid email format")
    print("   - No real authentication or database")
    print("   - Tokens stored in memory (lost on restart)")
    print("=" * 80)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
