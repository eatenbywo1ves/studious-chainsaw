import { NextRequest, NextResponse } from 'next/server';
import { stripe } from '../config/route';
import { verifyResourceOwnership, unauthorizedResponse, forbiddenResponse } from '@/lib/auth';

// POST /api/stripe/portal - Create billing portal session
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { customerId, returnUrl, userId } = body;

    // Validate required fields
    if (!customerId) {
      return NextResponse.json(
        { error: 'Customer ID is required' },
        { status: 400 }
      );
    }

    // Verify JWT token and ensure user owns this customer
    // First, get the customer to extract the user_id from metadata
    const customer = await stripe.customers.retrieve(customerId);
    const customerUserId = typeof customer !== 'string' && !customer.deleted
      ? customer.metadata?.user_id
      : userId;

    if (!customerUserId) {
      return NextResponse.json(
        { error: 'Invalid customer or missing user_id' },
        { status: 400 }
      );
    }

    const authResult = await verifyResourceOwnership(request, customerUserId);
    if (!authResult.authorized || !authResult.user) {
      if (authResult.statusCode === 403) {
        return forbiddenResponse(authResult.error);
      }
      return unauthorizedResponse(authResult.error);
    }

    // Create billing portal session
    // Note: To use a configuration object, you must first create it via stripe.billingPortal.configurations.create()
    // and then reference it by ID. For simplicity, we'll use the default configuration.
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: returnUrl || `${request.nextUrl.origin}/dashboard`
    });

    return NextResponse.json({
      url: portalSession.url,
      sessionId: portalSession.id
    });
  } catch (error) {
    console.error('Error creating billing portal session:', error);
    return NextResponse.json(
      { error: 'Failed to create billing portal session' },
      { status: 500 }
    );
  }
}

// GET /api/stripe/portal - Get portal configuration
export async function GET(request: NextRequest) {
  try {
    // Verify JWT token
    const { verifyRequestAuth } = await import('@/lib/auth');
    const authResult = await verifyRequestAuth(request);
    if (!authResult.authenticated || !authResult.user) {
      return unauthorizedResponse(authResult.error);
    }

    // List portal configurations
    const configurations = await stripe.billingPortal.configurations.list({
      limit: 10
    });

    return NextResponse.json({
      configurations: configurations.data.map(config => ({
        id: config.id,
        is_default: config.is_default,
        features: config.features,
        business_profile: config.business_profile
      }))
    });
  } catch (error) {
    console.error('Error fetching portal configurations:', error);
    return NextResponse.json(
      { error: 'Failed to fetch portal configurations' },
      { status: 500 }
    );
  }
}
