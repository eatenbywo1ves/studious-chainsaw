import { NextRequest, NextResponse } from 'next/server';
import { emailService, EmailHelpers } from '@/lib/email/email-service';
import { verifyRequestAuth, unauthorizedResponse } from '@/lib/auth';

// POST /api/email/send - Send emails via API
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { type, ...data } = body;

    // Verify JWT token
    const authResult = await verifyRequestAuth(request);
    if (!authResult.authenticated || !authResult.user) {
      return unauthorizedResponse(authResult.error);
    }

    let result;

    switch (type) {
      case 'welcome':
        const { userEmail, userName, planCode } = data;
        if (!userEmail || !userName || !planCode) {
          return NextResponse.json(
            { error: 'Missing required fields: userEmail, userName, planCode' },
            { status: 400 }
          );
        }
        result = await EmailHelpers.sendWelcomeEmail(userEmail, userName, planCode);
        break;

      case 'password-reset':
        const { email, resetToken } = data;
        if (!email || !resetToken) {
          return NextResponse.json(
            { error: 'Missing required fields: email, resetToken' },
            { status: 400 }
          );
        }
        result = await EmailHelpers.sendPasswordResetEmail(email, resetToken);
        break;

      case 'payment-success':
        const { userEmail: paymentEmail, amount, currency } = data;
        if (!paymentEmail || amount === undefined || !currency) {
          return NextResponse.json(
            { error: 'Missing required fields: userEmail, amount, currency' },
            { status: 400 }
          );
        }
        result = await EmailHelpers.sendPaymentSuccessEmail(paymentEmail, amount, currency);
        break;

      case 'payment-failed':
        const { userEmail: failedPaymentEmail, amount: failedAmount, currency: failedCurrency } = data;
        if (!failedPaymentEmail || failedAmount === undefined || !failedCurrency) {
          return NextResponse.json(
            { error: 'Missing required fields: userEmail, amount, currency' },
            { status: 400 }
          );
        }
        result = await EmailHelpers.sendPaymentFailedEmail(failedPaymentEmail, failedAmount, failedCurrency);
        break;

      case 'trial-ending':
        const { userEmail: trialEmail, daysLeft } = data;
        if (!trialEmail || daysLeft === undefined) {
          return NextResponse.json(
            { error: 'Missing required fields: userEmail, daysLeft' },
            { status: 400 }
          );
        }
        result = await EmailHelpers.sendTrialEndingEmail(trialEmail, daysLeft);
        break;

      case 'account-suspended':
        const { userEmail: suspendedEmail, reason } = data;
        if (!suspendedEmail || !reason) {
          return NextResponse.json(
            { error: 'Missing required fields: userEmail, reason' },
            { status: 400 }
          );
        }
        result = await EmailHelpers.sendAccountSuspendedEmail(suspendedEmail, reason);
        break;

      case 'custom':
        const { to, subject, html, text, template, templateData } = data;
        if (!to || (!subject && !template)) {
          return NextResponse.json(
            { error: 'Missing required fields: to, and either subject or template' },
            { status: 400 }
          );
        }

        if (template) {
          result = await emailService.sendTemplatedEmail(template, to, templateData || {});
        } else {
          result = await emailService.sendEmail({
            to,
            subject,
            html,
            text
          });
        }
        break;

      default:
        return NextResponse.json(
          { error: 'Invalid email type' },
          { status: 400 }
        );
    }

    if (result.success) {
      return NextResponse.json({
        success: true,
        messageId: result.messageId,
        provider: result.provider
      });
    } else {
      return NextResponse.json(
        {
          success: false,
          error: result.error,
          provider: result.provider
        },
        { status: 500 }
      );
    }
  } catch (error) {
    console.error('Error sending email:', error);
    return NextResponse.json(
      { error: 'Failed to send email' },
      { status: 500 }
    );
  }
}

// GET /api/email/send - Get email service status
export async function GET(request: NextRequest) {
  try {
    // Verify JWT token
    const authResult = await verifyRequestAuth(request);
    if (!authResult.authenticated || !authResult.user) {
      return unauthorizedResponse(authResult.error);
    }

    const status = await emailService.getServiceStatus();

    return NextResponse.json({
      status,
      availableProviders: Object.keys(status).filter(provider => status[provider as keyof typeof status]),
      supportedEmailTypes: [
        'welcome',
        'password-reset',
        'payment-success',
        'payment-failed',
        'trial-ending',
        'account-suspended',
        'custom'
      ]
    });
  } catch (error) {
    console.error('Error getting email service status:', error);
    return NextResponse.json(
      { error: 'Failed to get email service status' },
      { status: 500 }
    );
  }
}
