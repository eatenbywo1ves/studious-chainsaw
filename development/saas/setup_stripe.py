#!/usr/bin/env python3
"""
Stripe Setup and Configuration Script
Creates products and prices to match subscription plans in database
"""

import os
import sys
from decimal import Decimal
from dotenv import load_dotenv

# Load environment
load_dotenv()

try:
    import stripe
except ImportError:
    print("Error: stripe package not installed")
    print("Run: pip install stripe")
    sys.exit(1)

# Initialize Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

if not stripe.api_key or stripe.api_key == "sk_test_YOUR_SECRET_KEY_HERE":
    print("\n" + "=" * 70)
    print("STRIPE CONFIGURATION REQUIRED")
    print("=" * 70)
    print("\nTo use this script, you need to:")
    print("\n1. Create a Stripe account (or use existing):")
    print("   https://dashboard.stripe.com/register")
    print("\n2. Get your API keys from:")
    print("   https://dashboard.stripe.com/test/apikeys")
    print("\n3. Add to .env file:")
    print("   STRIPE_SECRET_KEY=sk_test_YOUR_SECRET_KEY")
    print("   STRIPE_PUBLISHABLE_KEY=pk_test_YOUR_PUBLISHABLE_KEY")
    print("\n4. Set up webhook endpoint:")
    print("   https://dashboard.stripe.com/test/webhooks")
    print("   Endpoint URL: http://localhost:3000/api/stripe/webhooks")
    print("   Events to listen for:")
    print("     - checkout.session.completed")
    print("     - customer.subscription.created")
    print("     - customer.subscription.updated")
    print("     - customer.subscription.deleted")
    print("     - invoice.payment_succeeded")
    print("     - invoice.payment_failed")
    print("     - customer.updated")
    print("\n5. Add webhook secret to .env:")
    print("   STRIPE_WEBHOOK_SECRET=whsec_YOUR_WEBHOOK_SECRET")
    print("\n" + "=" * 70 + "\n")
    sys.exit(1)


def create_product(name, description):
    """Create a Stripe product"""
    try:
        product = stripe.Product.create(
            name=name, description=description, metadata={"app": "catalytic_computing_saas"}
        )
        print(f"[OK] Created product: {name} (ID: {product.id})")
        return product
    except stripe.error.StripeError as e:
        print(f"[ERROR] Failed to create product {name}: {str(e)}")
        return None


def create_price(product_id, amount, interval, currency="usd"):
    """Create a Stripe price"""
    try:
        # Stripe expects amount in cents
        amount_cents = int(amount * 100)

        if amount_cents == 0:
            # Free tier - create without recurring
            price = stripe.Price.create(
                product=product_id, unit_amount=0, currency=currency, metadata={"plan": "free"}
            )
        else:
            price = stripe.Price.create(
                product=product_id,
                unit_amount=amount_cents,
                currency=currency,
                recurring={"interval": interval},
                metadata={"interval": interval},
            )

        print(f"  [OK] Created price: ${amount}/{interval} (ID: {price.id})")
        return price
    except stripe.error.StripeError as e:
        print(f"  [ERROR] Failed to create price: {str(e)}")
        return None


def setup_subscription_plans():
    """Create all subscription plans in Stripe"""
    print("\n" + "=" * 70)
    print("CREATING STRIPE PRODUCTS AND PRICES")
    print("=" * 70 + "\n")

    plans = [
        {
            "name": "Free",
            "description": "Free tier for individual developers - 100 API calls/month, 1 lattice, 1 user",
            "price_monthly": Decimal("0.00"),
            "price_yearly": Decimal("0.00"),
            "code": "free",
        },
        {
            "name": "Starter",
            "description": "For growing teams and projects - 1K API calls/month, 5 lattices, 3 users",
            "price_monthly": Decimal("29.00"),
            "price_yearly": Decimal("290.00"),
            "code": "starter",
        },
        {
            "name": "Professional",
            "description": "For professional teams - 10K API calls/month, 25 lattices, 10 users",
            "price_monthly": Decimal("99.00"),
            "price_yearly": Decimal("990.00"),
            "code": "professional",
        },
        {
            "name": "Enterprise",
            "description": "For large organizations - Unlimited resources, dedicated support",
            "price_monthly": Decimal("499.00"),
            "price_yearly": Decimal("4990.00"),
            "code": "enterprise",
        },
    ]

    results = {}

    for plan in plans:
        print(f"\nCreating: {plan['name']}")
        print("-" * 70)

        # Create product
        product = create_product(plan["name"], plan["description"])
        if not product:
            continue

        # Create monthly price
        monthly_price = create_price(product.id, plan["price_monthly"], "month")

        # Create yearly price (if not free)
        yearly_price = None
        if plan["price_yearly"] > 0:
            yearly_price = create_price(product.id, plan["price_yearly"], "year")

        results[plan["code"]] = {
            "product_id": product.id,
            "monthly_price_id": monthly_price.id if monthly_price else None,
            "yearly_price_id": yearly_price.id if yearly_price else None,
        }

    return results


def update_env_file(results):
    """Update .env file with Stripe price IDs"""
    print("\n" + "=" * 70)
    print("UPDATING ENVIRONMENT CONFIGURATION")
    print("=" * 70 + "\n")

    env_additions = "\n# Stripe Product and Price IDs (Generated)\n"

    for code, ids in results.items():
        env_additions += f"STRIPE_{code.upper()}_PRODUCT_ID={ids['product_id']}\n"
        if ids["monthly_price_id"]:
            env_additions += f"STRIPE_{code.upper()}_PRICE_MONTHLY_ID={ids['monthly_price_id']}\n"
        if ids["yearly_price_id"]:
            env_additions += f"STRIPE_{code.upper()}_PRICE_YEARLY_ID={ids['yearly_price_id']}\n"

    print("Add these to your .env file:")
    print(env_additions)

    # Optionally append to .env
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    response = input("\nWould you like to automatically append these to .env? (y/N): ")

    if response.lower() == "y":
        try:
            with open(env_path, "a") as f:
                f.write(env_additions)
            print("[OK] Updated .env file")
        except Exception as e:
            print(f"[ERROR] Failed to update .env: {str(e)}")


def list_existing_products():
    """List existing Stripe products"""
    print("\n" + "=" * 70)
    print("EXISTING STRIPE PRODUCTS")
    print("=" * 70 + "\n")

    try:
        products = stripe.Product.list(limit=100)

        if not products.data:
            print("No products found.")
            return

        for product in products.data:
            print(f"\nProduct: {product.name}")
            print(f"  ID: {product.id}")
            print(f"  Description: {product.description}")

            # List prices for this product
            prices = stripe.Price.list(product=product.id)
            for price in prices.data:
                amount = price.unit_amount / 100 if price.unit_amount else 0
                interval = (
                    price.recurring.get("interval", "one-time") if price.recurring else "one-time"
                )
                print(f"  Price: ${amount:.2f}/{interval} (ID: {price.id})")

    except stripe.error.StripeError as e:
        print(f"[ERROR] Failed to list products: {str(e)}")


def test_stripe_connection():
    """Test Stripe API connection"""
    print("\n" + "=" * 70)
    print("TESTING STRIPE CONNECTION")
    print("=" * 70 + "\n")

    try:
        account = stripe.Account.retrieve()
        print("[OK] Connected to Stripe")
        print(f"  Account ID: {account.id}")
        print(f"  Account Type: {account.type}")
        print(f"  Country: {account.country}")
        print(f"  Email: {account.email}")
        print(f"  Charges Enabled: {account.charges_enabled}")
        return True
    except stripe.error.AuthenticationError:
        print("[ERROR] Invalid API key")
        return False
    except stripe.error.StripeError as e:
        print(f"[ERROR] {str(e)}")
        return False


def main():
    """Main setup function"""
    print("\n" + "=" * 70)
    print("CATALYTIC COMPUTING SAAS - STRIPE SETUP")
    print("=" * 70)

    # Test connection
    if not test_stripe_connection():
        sys.exit(1)

    # Show existing products
    list_existing_products()

    # Ask to create new products
    print("\n" + "=" * 70)
    response = input("\nCreate subscription products and prices? (y/N): ")

    if response.lower() != "y":
        print("Setup cancelled.")
        sys.exit(0)

    # Create products and prices
    results = setup_subscription_plans()

    # Update .env file
    update_env_file(results)

    print("\n" + "=" * 70)
    print("STRIPE SETUP COMPLETE")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Test checkout flow: http://localhost:3000")
    print("2. Configure webhook endpoint in Stripe Dashboard")
    print("3. Add STRIPE_WEBHOOK_SECRET to .env")
    print("4. Test webhook delivery with Stripe CLI or test mode")
    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    main()
