// Authentication utilities for Next.js API routes
// Verifies JWT tokens by calling the Python FastAPI backend

import { NextRequest } from 'next/server';
import { apiClient } from './api-client';

export interface TokenData {
  sub: string // User ID
  tenant_id: string
  email: string
  role: string
  type: string
  jti?: string
  iat?: number
  exp?: number
}

export interface VerifyTokenResult {
  success: boolean
  data?: TokenData
  error?: string
}

/**
 * Extract Bearer token from Authorization header
 */
export function extractBearerToken(request: NextRequest): string | null {
  const authHeader = request.headers.get('authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  return authHeader.substring(7);
}

/**
 * Verify JWT token by calling the backend API
 */
export async function verifyToken(token: string, tokenType: string = 'access'): Promise<VerifyTokenResult> {
  try {
    // Call backend verification endpoint
    const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/auth/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        token,
        token_type: tokenType
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
      return {
        success: false,
        error: errorData.detail || 'Token verification failed'
      };
    }

    const data = await response.json();

    return {
      success: true,
      data: {
        sub: data.sub,
        tenant_id: data.tenant_id,
        email: data.email,
        role: data.role,
        type: data.type,
        jti: data.jti,
        iat: data.iat,
        exp: data.exp
      }
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Token verification failed'
    };
  }
}

/**
 * Verify request authentication and return user data
 * This is a convenience function for API routes
 */
export async function verifyRequestAuth(request: NextRequest, requireAdmin: boolean = false): Promise<{
  authenticated: boolean
  user?: TokenData
  error?: string
  statusCode?: number
}> {
  // Extract token
  const token = extractBearerToken(request);

  if (!token) {
    return {
      authenticated: false,
      error: 'No authorization token provided',
      statusCode: 401
    };
  }

  // Verify token
  const verifyResult = await verifyToken(token, 'access');

  if (!verifyResult.success || !verifyResult.data) {
    return {
      authenticated: false,
      error: verifyResult.error || 'Invalid token',
      statusCode: 401
    };
  }

  // Check admin role if required
  if (requireAdmin && verifyResult.data.role !== 'admin' && verifyResult.data.role !== 'owner') {
    return {
      authenticated: false,
      error: 'Admin access required',
      statusCode: 403
    };
  }

  return {
    authenticated: true,
    user: verifyResult.data
  };
}

/**
 * Verify that a user owns a specific customer/resource
 */
export async function verifyResourceOwnership(
  request: NextRequest,
  resourceUserId: string,
  resourceTenantId?: string
): Promise<{
  authorized: boolean
  user?: TokenData
  error?: string
  statusCode?: number
}> {
  const authResult = await verifyRequestAuth(request);

  if (!authResult.authenticated || !authResult.user) {
    return {
      authorized: false,
      error: authResult.error,
      statusCode: authResult.statusCode
    };
  }

  const user = authResult.user;

  // Check if user ID matches
  if (user.sub !== resourceUserId) {
    return {
      authorized: false,
      error: 'You do not have permission to access this resource',
      statusCode: 403
    };
  }

  // Check tenant isolation if tenant ID provided
  if (resourceTenantId && user.tenant_id !== resourceTenantId) {
    return {
      authorized: false,
      error: 'Tenant mismatch',
      statusCode: 403
    };
  }

  return {
    authorized: true,
    user
  };
}

/**
 * Get user ID from token for metadata purposes
 * Does NOT verify the token - use verifyRequestAuth for authentication
 */
export function extractUserIdFromToken(token: string): string | null {
  try {
    // Simple base64 decode of JWT payload (without verification)
    // This is ONLY for extracting metadata, not for authentication
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    return payload.sub || null;
  } catch {
    return null;
  }
}

/**
 * Helper to create standardized unauthorized response
 */
export function unauthorizedResponse(message: string = 'Unauthorized') {
  return new Response(
    JSON.stringify({ error: message }),
    {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    }
  );
}

/**
 * Helper to create standardized forbidden response
 */
export function forbiddenResponse(message: string = 'Forbidden') {
  return new Response(
    JSON.stringify({ error: message }),
    {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    }
  );
}
