#!/usr/bin/env python3
"""
Production Database Initialization Script
Creates all tables and seeds initial data for Catalytic Computing SaaS
"""

import os
import sys
from datetime import datetime, timezone
from decimal import Decimal

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import models
from database.models import (
    Base, Tenant, User, SubscriptionPlan, TenantSubscription,
    TenantStatus, UserRole, SubscriptionStatus
)
from auth.jwt_auth import hash_password


def get_database_url():
    """Get database URL from environment or use SQLite default"""
    return os.getenv(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(os.path.dirname(__file__), "catalytic_saas.db")}'
    )


def create_tables(engine):
    """Create all database tables"""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("[OK] All tables created successfully")


def seed_subscription_plans(session):
    """Create default subscription plans"""
    print("\nSeeding subscription plans...")

    plans = [
        {
            "name": "Free",
            "code": "free",
            "description": "Free tier for individual developers",
            "price_monthly": Decimal("0.00"),
            "price_yearly": Decimal("0.00"),
            "features": {
                "api_calls": "100/month",
                "support": "Community",
                "lattices": "Standard compute",
                "analytics": "Basic"
            },
            "limits": {
                "max_api_calls_per_month": 100,
                "max_lattices": 1,
                "max_users": 1,
                "max_storage_gb": 1
            }
        },
        {
            "name": "Starter",
            "code": "starter",
            "description": "For growing teams and projects",
            "price_monthly": Decimal("29.00"),
            "price_yearly": Decimal("290.00"),
            "features": {
                "api_calls": "1,000/month",
                "support": "Email",
                "lattices": "Enhanced management",
                "analytics": "Advanced"
            },
            "limits": {
                "max_api_calls_per_month": 1000,
                "max_lattices": 5,
                "max_users": 3,
                "max_storage_gb": 10
            }
        },
        {
            "name": "Professional",
            "code": "professional",
            "description": "For professional teams",
            "price_monthly": Decimal("99.00"),
            "price_yearly": Decimal("990.00"),
            "features": {
                "api_calls": "10,000/month",
                "support": "Priority",
                "lattices": "Advanced analytics",
                "analytics": "Custom",
                "custom_configurations": "Yes"
            },
            "limits": {
                "max_api_calls_per_month": 10000,
                "max_lattices": 25,
                "max_users": 10,
                "max_storage_gb": 100
            }
        },
        {
            "name": "Enterprise",
            "code": "enterprise",
            "description": "For large organizations",
            "price_monthly": Decimal("499.00"),
            "price_yearly": Decimal("4990.00"),
            "features": {
                "api_calls": "Unlimited",
                "support": "Dedicated",
                "lattices": "White-label options",
                "analytics": "Custom",
                "sla": "99.9% uptime guarantee",
                "custom_configurations": "Yes"
            },
            "limits": {
                "max_api_calls_per_month": -1,  # Unlimited
                "max_lattices": -1,
                "max_users": -1,
                "max_storage_gb": -1
            }
        }
    ]

    for plan_data in plans:
        # Check if plan already exists
        existing = session.query(SubscriptionPlan).filter_by(code=plan_data["code"]).first()
        if existing:
            print(f"  - Plan '{plan_data['name']}' already exists, skipping")
            continue

        plan = SubscriptionPlan(
            name=plan_data["name"],
            code=plan_data["code"],
            description=plan_data["description"],
            price_monthly=plan_data["price_monthly"],
            price_yearly=plan_data["price_yearly"],
            features=plan_data["features"],
            limits=plan_data["limits"],
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
        session.add(plan)
        print(f"  [OK] Created plan: {plan_data['name']} (${plan_data['price_monthly']}/month)")

    session.commit()
    print("[OK] Subscription plans seeded successfully")


def create_demo_tenant(session):
    """Create a demo tenant for testing (optional)"""
    demo_mode = os.getenv('CREATE_DEMO_TENANT', 'false').lower() == 'true'

    if not demo_mode:
        print("\nSkipping demo tenant creation (set CREATE_DEMO_TENANT=true to enable)")
        return

    print("\nCreating demo tenant...")

    # Check if demo tenant exists
    existing = session.query(Tenant).filter_by(slug="demo").first()
    if existing:
        print("  - Demo tenant already exists, skipping")
        return

    # Create demo tenant
    tenant = Tenant(
        slug="demo",
        name="Demo Organization",
        email="demo@catalyticcomputing.com",
        status=TenantStatus.ACTIVE,
        created_at=datetime.now(timezone.utc)
    )
    session.add(tenant)
    session.flush()

    # Create demo admin user
    admin_user = User(
        tenant_id=tenant.id,
        email="admin@demo.catalyticcomputing.com",
        username="demo_admin",
        password_hash=hash_password("DemoPassword123!"),
        role=UserRole.OWNER,
        is_active=True,
        email_verified=True,
        created_at=datetime.now(timezone.utc)
    )
    session.add(admin_user)
    session.flush()

    # Get free plan
    free_plan = session.query(SubscriptionPlan).filter_by(code="free").first()
    if free_plan:
        # Create subscription
        subscription = TenantSubscription(
            tenant_id=tenant.id,
            plan_id=free_plan.id,
            status=SubscriptionStatus.ACTIVE,
            current_period_start=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc)
        )
        session.add(subscription)

    session.commit()
    print(f"  [OK] Created demo tenant: {tenant.slug}")
    print(f"  [OK] Created admin user: {admin_user.email}")
    print(f"       Password: DemoPassword123!")


def show_database_stats(session):
    """Display database statistics"""
    print("\n" + "="*60)
    print("DATABASE STATISTICS")
    print("="*60)

    stats = {
        "Subscription Plans": session.query(SubscriptionPlan).count(),
        "Tenants": session.query(Tenant).count(),
        "Users": session.query(User).count(),
        "Active Subscriptions": session.query(TenantSubscription).filter_by(
            status=SubscriptionStatus.ACTIVE
        ).count()
    }

    for key, value in stats.items():
        print(f"{key:.<40} {value:>10}")

    print("="*60)


def main():
    """Main initialization function"""
    print("\n" + "="*60)
    print("CATALYTIC COMPUTING SAAS - DATABASE INITIALIZATION")
    print("="*60 + "\n")

    # Get database URL
    db_url = get_database_url()
    print(f"Database URL: {db_url}")

    # Check if using PostgreSQL or SQLite
    is_postgres = db_url.startswith('postgresql')
    db_type = "PostgreSQL" if is_postgres else "SQLite"
    print(f"Database Type: {db_type}")

    # Create engine
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False} if not is_postgres else {},
        echo=False
    )

    # Create tables
    create_tables(engine)

    # Create session
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    try:
        # Seed data
        seed_subscription_plans(session)
        create_demo_tenant(session)

        # Show stats
        show_database_stats(session)

        print("\n[SUCCESS] Database initialization complete!")
        print("\nNext steps:")
        print("1. Start the backend: uvicorn api.saas_server:app --reload")
        print("2. Access API docs: http://localhost:8000/docs")
        print("3. Start frontend: cd frontend && npm run dev")

        if os.getenv('CREATE_DEMO_TENANT', 'false').lower() == 'true':
            print("\nDemo credentials:")
            print("  Email: admin@demo.catalyticcomputing.com")
            print("  Password: DemoPassword123!")

    except Exception as e:
        session.rollback()
        print(f"\n❌ Error during initialization: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
