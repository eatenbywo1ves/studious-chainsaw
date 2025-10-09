"""
Subscription Management API
Handles subscription operations triggered by Stripe webhooks and user actions
"""

import os
import sys
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

# Add parent directories to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.models import (
    Tenant,
    User,
    TenantSubscription,
    SubscriptionPlan,
    SubscriptionStatus,
    TenantStatus,
)
from database.connection import get_db

router = APIRouter(prefix="/api/subscriptions", tags=["subscriptions"])

# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class SubscriptionCreateRequest(BaseModel):
    """Request to create a new subscription"""

    user_id: str
    tenant_id: str
    stripe_subscription_id: str
    stripe_customer_id: str
    plan_code: str
    status: str = "active"
    current_period_start: datetime
    current_period_end: datetime
    trial_start: Optional[datetime] = None
    trial_end: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class SubscriptionUpdateRequest(BaseModel):
    """Request to update an existing subscription"""

    stripe_subscription_id: str
    status: Optional[str] = None
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    cancel_at_period_end: Optional[bool] = None
    canceled_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class UserPlanUpdateRequest(BaseModel):
    """Request to update user's plan"""

    user_id: str
    tenant_id: str
    plan_code: str
    stripe_customer_id: Optional[str] = None


class CustomerUpdateRequest(BaseModel):
    """Request to update customer information"""

    user_id: str
    tenant_id: str
    stripe_customer_id: str
    email: Optional[EmailStr] = None
    name: Optional[str] = None


class SubscriptionSuspendRequest(BaseModel):
    """Request to suspend user access"""

    user_id: str
    tenant_id: str
    reason: str = "payment_failure"


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
# Note: get_db() is now imported from database.connection (centralized)


def get_plan_by_code(db: Session, plan_code: str) -> Optional[SubscriptionPlan]:
    """Get subscription plan by code"""
    return db.query(SubscriptionPlan).filter(SubscriptionPlan.code == plan_code).first()


def get_user_by_id(db: Session, user_id: str, tenant_id: str) -> Optional[User]:
    """Get user by ID and tenant ID"""
    return db.query(User).filter(User.id == user_id, User.tenant_id == tenant_id).first()


def get_tenant_by_id(db: Session, tenant_id: str) -> Optional[Tenant]:
    """Get tenant by ID"""
    return db.query(Tenant).filter(Tenant.id == tenant_id).first()


# ============================================================================
# SUBSCRIPTION ENDPOINTS
# ============================================================================


@router.post("/create")
async def create_subscription(request: SubscriptionCreateRequest, db: Session = Depends(get_db)):
    """
    Create a new subscription (called by Stripe webhook)
    """
    try:
        # Get user and plan
        user = get_user_by_id(db, request.user_id, request.tenant_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        plan = get_plan_by_code(db, request.plan_code)
        if not plan:
            raise HTTPException(status_code=404, detail=f"Plan not found: {request.plan_code}")

        # Check if subscription already exists
        existing_sub = (
            db.query(TenantSubscription)
            .filter(
                TenantSubscription.tenant_id == request.tenant_id,
                TenantSubscription.status == SubscriptionStatus.ACTIVE,
            )
            .first()
        )

        if existing_sub:
            # Update existing subscription
            existing_sub.plan_id = plan.id
            existing_sub.status = request.status
            existing_sub.current_period_start = request.current_period_start
            existing_sub.current_period_end = request.current_period_end
            if request.trial_start:
                existing_sub.trial_ends_at = request.trial_end
            existing_sub.updated_at = datetime.now(timezone.utc)
        else:
            # Create new subscription
            new_subscription = TenantSubscription(
                tenant_id=request.tenant_id,
                plan_id=plan.id,
                status=request.status,
                current_period_start=request.current_period_start,
                current_period_end=request.current_period_end,
                trial_ends_at=request.trial_end,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(new_subscription)

        # Update user's stripe customer ID if provided
        if request.stripe_customer_id and not user.meta_data.get("stripe_customer_id"):
            if not user.meta_data:
                user.meta_data = {}
            user.meta_data["stripe_customer_id"] = request.stripe_customer_id
            user.meta_data["stripe_subscription_id"] = request.stripe_subscription_id

        db.commit()

        return {
            "status": "success",
            "message": "Subscription created successfully",
            "tenant_id": request.tenant_id,
            "plan_code": request.plan_code,
        }

    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Database integrity error: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating subscription: {str(e)}")


@router.put("/update")
async def update_subscription(request: SubscriptionUpdateRequest, db: Session = Depends(get_db)):
    """
    Update an existing subscription (called by Stripe webhook)
    """
    try:
        # Find subscription by Stripe subscription ID in metadata
        subscriptions = (
            db.query(TenantSubscription)
            .join(User)
            .filter(
                User.meta_data.contains({"stripe_subscription_id": request.stripe_subscription_id})
            )
            .all()
        )

        if not subscriptions:
            raise HTTPException(status_code=404, detail="Subscription not found")

        subscription = subscriptions[0]

        # Update subscription fields
        if request.status:
            subscription.status = request.status
        if request.current_period_start:
            subscription.current_period_start = request.current_period_start
        if request.current_period_end:
            subscription.current_period_end = request.current_period_end
        if request.cancel_at_period_end is not None:
            subscription.cancel_at_period_end = request.cancel_at_period_end
        if request.canceled_at:
            subscription.cancelled_at = request.canceled_at

        subscription.updated_at = datetime.now(timezone.utc)
        db.commit()

        return {
            "status": "success",
            "message": "Subscription updated successfully",
            "subscription_id": request.stripe_subscription_id,
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating subscription: {str(e)}")


@router.delete("/cancel")
async def cancel_subscription(user_id: str, tenant_id: str, db: Session = Depends(get_db)):
    """
    Cancel a subscription (downgrade to free plan)
    """
    try:
        # Get active subscription
        subscription = (
            db.query(TenantSubscription)
            .filter(
                TenantSubscription.tenant_id == tenant_id,
                TenantSubscription.status == SubscriptionStatus.ACTIVE,
            )
            .first()
        )

        if not subscription:
            raise HTTPException(status_code=404, detail="Active subscription not found")

        # Get free plan
        free_plan = get_plan_by_code(db, "free")
        if not free_plan:
            raise HTTPException(status_code=500, detail="Free plan not configured")

        # Update subscription to cancelled
        subscription.status = SubscriptionStatus.CANCELLED
        subscription.cancelled_at = datetime.now(timezone.utc)
        subscription.updated_at = datetime.now(timezone.utc)

        # Create new free subscription
        free_subscription = TenantSubscription(
            tenant_id=tenant_id,
            plan_id=free_plan.id,
            status=SubscriptionStatus.ACTIVE,
            current_period_start=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(free_subscription)

        db.commit()

        return {
            "status": "success",
            "message": "Subscription cancelled, downgraded to free plan",
            "tenant_id": tenant_id,
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error cancelling subscription: {str(e)}")


@router.put("/update-customer")
async def update_customer_info(request: CustomerUpdateRequest, db: Session = Depends(get_db)):
    """
    Update customer information from Stripe webhook
    """
    try:
        user = get_user_by_id(db, request.user_id, request.tenant_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Update user metadata
        if not user.meta_data:
            user.meta_data = {}

        user.meta_data["stripe_customer_id"] = request.stripe_customer_id

        if request.email:
            user.email = request.email
        if request.name:
            user.username = request.name

        user.updated_at = datetime.now(timezone.utc)
        db.commit()

        return {
            "status": "success",
            "message": "Customer information updated",
            "user_id": request.user_id,
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating customer: {str(e)}")


@router.post("/suspend")
async def suspend_user_access(request: SubscriptionSuspendRequest, db: Session = Depends(get_db)):
    """
    Suspend user access due to payment failure
    """
    try:
        user = get_user_by_id(db, request.user_id, request.tenant_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        tenant = get_tenant_by_id(db, request.tenant_id)
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Suspend user
        user.is_active = False
        user.updated_at = datetime.now(timezone.utc)

        # Suspend tenant
        tenant.status = TenantStatus.SUSPENDED
        tenant.updated_at = datetime.now(timezone.utc)

        # Add suspension reason to metadata
        if not tenant.meta_data:
            tenant.meta_data = {}
        tenant.meta_data["suspension_reason"] = request.reason
        tenant.meta_data["suspended_at"] = datetime.now(timezone.utc).isoformat()

        db.commit()

        return {
            "status": "success",
            "message": "User access suspended",
            "user_id": request.user_id,
            "reason": request.reason,
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error suspending access: {str(e)}")


@router.get("/status/{tenant_id}")
async def get_subscription_status(tenant_id: str, db: Session = Depends(get_db)):
    """
    Get current subscription status for a tenant
    """
    subscription = (
        db.query(TenantSubscription)
        .filter(
            TenantSubscription.tenant_id == tenant_id,
            TenantSubscription.status == SubscriptionStatus.ACTIVE,
        )
        .first()
    )

    if not subscription:
        return {"status": "no_active_subscription", "plan_code": "free"}

    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == subscription.plan_id).first()

    return {
        "status": subscription.status,
        "plan_code": plan.code if plan else "unknown",
        "plan_name": plan.name if plan else "Unknown",
        "current_period_start": subscription.current_period_start.isoformat()
        if subscription.current_period_start
        else None,
        "current_period_end": subscription.current_period_end.isoformat()
        if subscription.current_period_end
        else None,
        "cancel_at_period_end": subscription.cancel_at_period_end,
        "trial_ends_at": subscription.trial_ends_at.isoformat()
        if subscription.trial_ends_at
        else None,
    }
