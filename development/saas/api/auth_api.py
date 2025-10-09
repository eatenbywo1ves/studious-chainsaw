"""
Authentication API
Provides JWT verification and authentication endpoints for frontend
"""

import os
import sys
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

# Add parent directories to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.jwt_auth import verify_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["authentication"])

# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class TokenVerifyRequest(BaseModel):
    """Request to verify a JWT token"""

    token: str
    token_type: str = "access"


class TokenVerifyResponse(BaseModel):
    """Response from token verification"""

    sub: str
    tenant_id: str
    email: str
    role: str
    type: str
    jti: Optional[str] = None
    iat: Optional[int] = None
    exp: Optional[int] = None


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================


@router.post("/verify", response_model=TokenVerifyResponse)
async def verify_jwt_token(request: TokenVerifyRequest):
    """
    Verify a JWT token and return the decoded payload

    This endpoint is called by the Next.js frontend to verify
    JWT tokens for API routes that require authentication.
    """
    logger.debug("Token verification requested", extra={"token_type": request.token_type})

    try:
        # Verify token using backend JWT verification
        token_data = verify_token(request.token, request.token_type)

        if not token_data:
            logger.warning("Token verification failed", extra={"token_type": request.token_type})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
            )

        # Convert TokenData to response model
        logger.info(
            "Token verified successfully",
            extra={
                "user_id": token_data.sub,
                "tenant_id": token_data.tenant_id,
                "token_type": token_data.type,
            },
        )

        return TokenVerifyResponse(
            sub=token_data.sub,
            tenant_id=token_data.tenant_id,
            email=token_data.email,
            role=token_data.role,
            type=token_data.type,
            jti=token_data.jti,
            iat=int(token_data.iat.timestamp()) if token_data.iat else None,
            exp=int(token_data.exp.timestamp()) if token_data.exp else None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error verifying token", extra={"token_type": request.token_type, "error": str(e)}, exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error verifying token: {str(e)}",
        )


@router.get("/health")
async def auth_health_check():
    """
    Health check endpoint for authentication service
    """
    logger.debug("Authentication health check")
    return {
        "status": "healthy",
        "service": "authentication",
        "endpoints": ["/api/auth/verify - Verify JWT tokens"],
    }
