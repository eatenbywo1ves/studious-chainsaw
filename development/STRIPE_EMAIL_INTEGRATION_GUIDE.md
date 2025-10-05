# Stripe & Email Integration Guide
**Catalytic Computing SaaS Platform**
**Version**: 1.0.0
**Date**: October 5, 2025

---

## Table of Contents

1. [Overview](#overview)
2. [Stripe Integration](#stripe-integration)
3. [Email Service Integration](#email-service-integration)
4. [PostgreSQL Migration](#postgresql-migration)
5. [Production Deployment](#production-deployment)
6. [Testing & Validation](#testing--validation)

---

## Overview

This guide walks through the complete integration of Stripe payments, email notifications, and PostgreSQL migration for production deployment.

### Prerequisites

- ✅ Backend API running on port 8000
- ✅ Frontend running on port 3000
- ✅ Redis configured and running
- ✅ SQLite database initialized with subscription plans
- ✅ All validation checks passing (7/7)

### Integration Steps

We'll complete these integrations in order:
1. **Stripe** - Payment processing and subscription management
2. **Email** - Transactional emails and notifications
3. **PostgreSQL** - Production database migration (optional)

---

## Stripe Integration

### Step 1: Create Stripe Account

**Option A: Create New Account**
1. Go to https://dashboard.stripe.com/register
2. Complete registration
3. Verify email address
4. Complete business profile

**Option B: Use Existing Account**
1. Log in to https://dashboard.stripe.com/
2. Switch to Test Mode (toggle in top right)

### Step 2: Obtain API Keys

1. Navigate to **Developers** → **API keys**
2. Copy your keys:
   - **Publishable key**: `pk_test_...`
   - **Secret key**: `sk_test_...` (click "Reveal test key")

3. Add to `.env` file:
```bash
# Stripe Configuration (Test Mode)
STRIPE_SECRET_KEY=sk_test_YOUR_ACTUAL_SECRET_KEY_HERE
STRIPE_PUBLISHABLE_KEY=pk_test_YOUR_ACTUAL_PUBLISHABLE_KEY_HERE
```

4. Add to `frontend/.env.local`:
```bash
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_YOUR_ACTUAL_PUBLISHABLE_KEY_HERE
```

### Step 3: Create Products and Prices

Run the automated setup script:

```bash
cd C:/Users/Corbin/development/saas
python setup_stripe.py
```

**What this script does**:
- Tests Stripe connection
- Lists existing products
- Creates 4 products matching database plans:
  - Free ($0/month)
  - Starter ($29/month, $290/year)
  - Professional ($99/month, $990/year)
  - Enterprise ($499/month, $4,990/year)
- Generates price IDs
- Updates `.env` with product/price IDs

**Expected Output**:
```
TESTING STRIPE CONNECTION
[OK] Connected to Stripe
  Account ID: acct_xxxxx
  Charges Enabled: True

CREATING STRIPE PRODUCTS AND PRICES

Creating: Free
[OK] Created product: Free (ID: prod_xxxxx)
  [OK] Created price: $0.00/month (ID: price_xxxxx)

Creating: Starter
[OK] Created product: Starter (ID: prod_xxxxx)
  [OK] Created price: $29.00/month (ID: price_xxxxx)
  [OK] Created price: $290.00/year (ID: price_xxxxx)

... (continues for all plans)
```

### Step 4: Configure Webhooks

Webhooks allow Stripe to notify your application about payment events.

#### Development (Local Testing)

**Install Stripe CLI**:
```bash
# Windows (PowerShell)
scoop install stripe

# Mac
brew install stripe/stripe-cli/stripe

# Or download from https://github.com/stripe/stripe-cli/releases
```

**Forward webhooks to localhost**:
```bash
stripe login
stripe listen --forward-to http://localhost:3000/api/stripe/webhooks
```

This will output a webhook secret starting with `whsec_...`

**Add to `.env`**:
```bash
STRIPE_WEBHOOK_SECRET=whsec_YOUR_WEBHOOK_SECRET_FROM_CLI
```

#### Production (Live Webhooks)

1. Go to **Developers** → **Webhooks**
2. Click **Add endpoint**
3. Enter endpoint URL: `https://yourdomain.com/api/stripe/webhooks`
4. Select events to listen for:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
   - `customer.updated`
5. Click **Add endpoint**
6. Copy the **Signing secret** (starts with `whsec_...`)
7. Add to production `.env`

### Step 5: Test Checkout Flow

1. Start backend (if not running):
```bash
cd C:/Users/Corbin/development/saas
uvicorn api.saas_server:app --reload
```

2. Start frontend (if not running):
```bash
cd C:/Users/Corbin/development/saas/frontend
npm run dev
```

3. Open frontend: http://localhost:3000

4. Navigate to pricing page

5. Click "Subscribe" on any plan

6. Test with Stripe test cards:
   - **Success**: `4242 4242 4242 4242`
   - **Decline**: `4000 0000 0000 0002`
   - **3D Secure**: `4000 0025 0000 3155`
   - Use any future expiry date (e.g., 12/34)
   - Use any 3-digit CVC

7. Verify:
   - Checkout completes successfully
   - Redirect back to your app
   - Subscription created in database
   - Webhook received and processed

### Step 6: Verify Integration

```bash
# Check backend logs for webhook events
curl http://localhost:8000/api/subscriptions/status/{tenant_id}

# View in Stripe Dashboard
# Go to Payments → All payments
# Go to Customers → All customers
```

---

## Email Service Integration

### Option 1: SendGrid (Recommended)

#### Setup SendGrid

1. **Create Account**
   - Go to https://signup.sendgrid.com/
   - Complete registration
   - Verify email address

2. **Create API Key**
   - Navigate to **Settings** → **API Keys**
   - Click **Create API Key**
   - Name: "Catalytic SaaS Production"
   - Permissions: **Full Access** (or **Mail Send** minimum)
   - Click **Create & View**
   - Copy the API key (starts with `SG.`)

3. **Verify Sender Email**
   - Navigate to **Settings** → **Sender Authentication**
   - Option A: **Single Sender Verification** (quick, for testing)
     - Click **Verify a Single Sender**
     - Enter your email (e.g., noreply@yourdomain.com)
     - Check email and click verification link
   - Option B: **Domain Authentication** (recommended for production)
     - Click **Authenticate Your Domain**
     - Follow DNS configuration steps

4. **Configure Environment**

Add to `.env`:
```bash
# Email Configuration - SendGrid
SENDGRID_API_KEY=SG.YOUR_ACTUAL_API_KEY_HERE
EMAIL_FROM=noreply@yourdomain.com
EMAIL_FROM_NAME=Catalytic Computing
```

#### Test SendGrid

```bash
cd C:/Users/Corbin/development/saas
python setup_email.py
```

Enter your email when prompted to receive a test email.

**Expected Output**:
```
TESTING SENDGRID
Sending test email to: your-email@example.com
[OK] Email sent successfully via SendGrid
  Status Code: 202
  Message ID: abc123...
```

### Option 2: AWS SES

#### Setup AWS SES

1. **AWS Account**
   - Sign up at https://aws.amazon.com/
   - Or log in to existing account

2. **Create IAM User**
   - Go to **IAM** → **Users** → **Add user**
   - Username: "catalytic-ses-user"
   - Access type: **Programmatic access**
   - Attach policy: **AmazonSESFullAccess**
   - Save Access Key ID and Secret Access Key

3. **Verify Email Address**
   - Go to **SES** → **Verified identities**
   - Click **Create identity**
   - Identity type: **Email address**
   - Enter email address
   - Click verification link in email

4. **Request Production Access** (optional)
   - By default, SES is in sandbox mode
   - Can only send to verified emails
   - To send to any email, request production access
   - Go to **Account dashboard** → **Request production access**

5. **Configure Environment**

Add to `.env`:
```bash
# Email Configuration - AWS SES
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_ACCESS_KEY
AWS_REGION=us-east-1
EMAIL_FROM=verified@yourdomain.com
EMAIL_FROM_NAME=Catalytic Computing
```

#### Test AWS SES

```bash
cd C:/Users/Corbin/development/saas
python setup_email.py
```

### Option 3: SMTP (Gmail Example)

#### Setup Gmail SMTP

1. **Enable 2-Factor Authentication**
   - Go to Google Account → Security
   - Enable 2-Step Verification

2. **Generate App Password**
   - Go to https://myaccount.google.com/apppasswords
   - Select app: **Mail**
   - Select device: **Other** (Custom name: "Catalytic SaaS")
   - Copy the 16-character password

3. **Configure Environment**

Add to `.env`:
```bash
# Email Configuration - SMTP (Gmail)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-16-char-app-password
EMAIL_FROM=your-email@gmail.com
EMAIL_FROM_NAME=Catalytic Computing
```

#### Test SMTP

```bash
cd C:/Users/Corbin/development/saas
python setup_email.py
```

### Email Templates

Email templates are defined in `frontend/src/lib/email/email-service.ts`.

**Available email types**:
- `welcome` - New user registration
- `password-reset` - Password reset link
- `payment-success` - Successful payment
- `payment-failed` - Failed payment
- `trial-ending` - Trial expiring soon
- `account-suspended` - Account suspension
- `custom` - Custom HTML email

**Test email sending via API**:
```bash
curl -X POST http://localhost:8000/api/email/send \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "type": "welcome",
    "userEmail": "user@example.com",
    "userName": "John Doe",
    "planCode": "starter"
  }'
```

---

## PostgreSQL Migration

### Step 1: Install PostgreSQL

**Windows**:
1. Download from https://www.postgresql.org/download/windows/
2. Run installer
3. Set password for postgres user
4. Default port: 5432

**Mac**:
```bash
brew install postgresql@14
brew services start postgresql@14
```

**Linux (Ubuntu/Debian)**:
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

### Step 2: Create Database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE catalytic_saas;

# Create user
CREATE USER catalytic WITH ENCRYPTED PASSWORD 'YourSecurePassword123!';

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE catalytic_saas TO catalytic;

# Exit
\q
```

### Step 3: Configure Connection

Add to `.env`:
```bash
# PostgreSQL Configuration
POSTGRESQL_URL=postgresql://catalytic:YourSecurePassword123!@localhost:5432/catalytic_saas
```

### Step 4: Test Connection

```bash
# Test connection
psql -h localhost -U catalytic -d catalytic_saas

# Or use migration script
cd C:/Users/Corbin/development/saas
python migrate_to_postgresql.py
```

### Step 5: Run Migration

```bash
cd C:/Users/Corbin/development/saas
python migrate_to_postgresql.py
```

**What this script does**:
1. Creates backup of SQLite database
2. Analyzes SQLite data (shows row counts)
3. Connects to PostgreSQL
4. Creates schema (11 tables)
5. Migrates data in correct order (respects foreign keys)
6. Verifies row counts match
7. Reports success/failure

**Expected Output**:
```
TESTING POSTGRESQL CONNECTION
[OK] Connected to PostgreSQL
  Version: PostgreSQL 14.x...

BACKING UP SQLITE DATABASE
[OK] Backup created: catalytic_saas_backup_20251005_180000.db
  Size: 192,512 bytes

ANALYZING SQLITE DATABASE
  subscription_plans.......................          4 rows
  tenants..................................          0 rows
  users....................................          0 rows
  ...

CREATING POSTGRESQL SCHEMA
[OK] Dropped existing tables
[OK] Created all tables

MIGRATING DATA
  subscription_plans.......................          4 rows migrated
  tenants..................................          0 rows (empty)
  ...

VERIFYING MIGRATION
  subscription_plans....................... [OK] 4 rows
  ...

[OK] Migration verification passed!
```

### Step 6: Update Environment

After successful migration, update `.env`:

```bash
# Comment out SQLite
# DATABASE_URL=sqlite:///C:/Users/Corbin/development/saas/catalytic_saas.db

# Use PostgreSQL
DATABASE_URL=postgresql://catalytic:YourSecurePassword123!@localhost:5432/catalytic_saas
```

### Step 7: Restart Backend

```bash
cd C:/Users/Corbin/development/saas

# Stop current backend (Ctrl+C)

# Restart with PostgreSQL
uvicorn api.saas_server:app --reload --port 8000
```

### Step 8: Validate

```bash
cd C:/Users/Corbin/development/saas
python validate-deployment.py
```

All checks should still pass (7/7).

---

## Production Deployment

### Pre-Deployment Checklist

- [ ] Stripe production keys obtained
- [ ] Email service configured (SendGrid/SES)
- [ ] PostgreSQL database created
- [ ] Data migrated from SQLite
- [ ] All tests passing
- [ ] Environment variables configured
- [ ] SSL certificates obtained
- [ ] Domain configured

### Environment Configuration

Create `.env.production`:

```bash
# Security
JWT_PRIVATE_KEY_PATH=/path/to/production/jwt_private.pem
JWT_PUBLIC_KEY_PATH=/path/to/production/jwt_public.pem
SESSION_SECRET_KEY=<generate-new-secret>
CSRF_SECRET_KEY=<generate-new-secret>

# Database
DATABASE_URL=postgresql://catalytic:password@localhost:5432/catalytic_saas

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=<production-redis-password>

# Stripe (PRODUCTION KEYS)
STRIPE_SECRET_KEY=sk_live_YOUR_PRODUCTION_KEY
STRIPE_PUBLISHABLE_KEY=pk_live_YOUR_PRODUCTION_KEY
STRIPE_WEBHOOK_SECRET=whsec_YOUR_PRODUCTION_WEBHOOK_SECRET

# Email
SENDGRID_API_KEY=SG.YOUR_PRODUCTION_API_KEY
EMAIL_FROM=noreply@yourdomain.com

# Application
APP_ENV=production
DEBUG=false
LOG_LEVEL=WARNING
FRONTEND_URL=https://yourdomain.com
BACKEND_URL=https://api.yourdomain.com
```

### Deploy Backend

```bash
# Install production server
pip install gunicorn

# Run with Gunicorn
gunicorn api.saas_server:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile /var/log/catalytic/access.log \
  --error-logfile /var/log/catalytic/error.log \
  --daemon
```

### Deploy Frontend

```bash
cd frontend

# Build for production
npm run build

# Start production server
npm start

# Or use PM2
npm install -g pm2
pm2 start npm --name "catalytic-frontend" -- start
pm2 save
pm2 startup
```

### Configure Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/ssl/certs/yourdomain.crt;
    ssl_certificate_key /etc/ssl/private/yourdomain.key;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/ssl/certs/yourdomain.crt;
    ssl_certificate_key /etc/ssl/private/yourdomain.key;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Testing & Validation

### Integration Tests

```bash
# Test Stripe integration
curl -X POST http://localhost:8000/api/stripe/checkout \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"price_id": "price_xxxxx"}'

# Test email sending
curl -X POST http://localhost:8000/api/email/send \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "welcome",
    "userEmail": "test@example.com",
    "userName": "Test User",
    "planCode": "starter"
  }'

# Check subscription status
curl http://localhost:8000/api/subscriptions/status/TENANT_ID \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Health Checks

```bash
# Run full validation
cd C:/Users/Corbin/development/saas
python validate-deployment.py

# Backend health
curl http://localhost:8000/health

# Auth health
curl http://localhost:8000/api/auth/health
```

### End-to-End Test

1. Open frontend: http://localhost:3000
2. Register new account
3. Select subscription plan
4. Complete Stripe checkout (use test card: 4242 4242 4242 4242)
5. Verify:
   - Email received (welcome email)
   - Subscription active in database
   - Webhook processed
   - User can access protected features

---

## Troubleshooting

### Stripe Issues

**Problem**: "Invalid API Key"
- **Solution**: Verify `STRIPE_SECRET_KEY` in `.env` starts with `sk_test_` or `sk_live_`
- **Solution**: Ensure no extra spaces or quotes

**Problem**: Webhook not receiving events
- **Solution**: Check Stripe CLI is running: `stripe listen --forward-to http://localhost:3000/api/stripe/webhooks`
- **Solution**: Verify webhook secret matches in `.env`
- **Solution**: Check backend logs for webhook errors

**Problem**: Checkout session fails
- **Solution**: Verify price IDs are correct in environment
- **Solution**: Check product is active in Stripe dashboard
- **Solution**: Ensure mode matches (test/live)

### Email Issues

**Problem**: "Authentication failed"
- **Solution**: Verify API key or SMTP credentials
- **Solution**: For Gmail, ensure app password (not regular password)
- **Solution**: Check 2FA is enabled for Gmail

**Problem**: Emails not sending
- **Solution**: Run `python setup_email.py` to test configuration
- **Solution**: Check spam folder
- **Solution**: Verify sender email is verified (SendGrid/SES)

**Problem**: "Email not verified" (SES)
- **Solution**: Check SES verified identities
- **Solution**: Request production access if needed
- **Solution**: Verify both sender and recipient in sandbox mode

### PostgreSQL Issues

**Problem**: "Connection refused"
- **Solution**: Verify PostgreSQL is running: `pg_isready`
- **Solution**: Check port 5432 is open
- **Solution**: Verify connection string format

**Problem**: "Authentication failed"
- **Solution**: Verify username and password
- **Solution**: Check `pg_hba.conf` allows connections
- **Solution**: Ensure user has database privileges

**Problem**: Migration fails
- **Solution**: Check SQLite database exists
- **Solution**: Verify PostgreSQL schema is empty
- **Solution**: Check for foreign key violations
- **Solution**: Review migration logs for specific errors

---

## Next Steps

After completing this guide, you should have:

✅ Stripe test mode configured with products and prices
✅ Email service operational (SendGrid/SES/SMTP)
✅ PostgreSQL migration complete (optional)
✅ All services validated and healthy

**For Production Launch**:
1. Switch Stripe to live mode
2. Configure production email credentials
3. Set up production PostgreSQL
4. Deploy to production server
5. Configure SSL/TLS
6. Set up monitoring and alerts

**Support**:
- Stripe Documentation: https://stripe.com/docs
- SendGrid Docs: https://docs.sendgrid.com/
- AWS SES Docs: https://docs.aws.amazon.com/ses/
- PostgreSQL Docs: https://www.postgresql.org/docs/

---

**Integration Guide Version**: 1.0.0
**Platform**: Catalytic Computing SaaS
**Last Updated**: October 5, 2025
