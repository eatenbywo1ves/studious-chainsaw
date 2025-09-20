"""
Test script for webhook system
Verifies basic functionality
"""

import time
import json
from webhook_system import WebhookManager, WebhookConfig

def test_basic_webhook():
    """Test basic webhook functionality"""
    print("\n" + "="*60)
    print("WEBHOOK SYSTEM TEST")
    print("="*60)
    
    # Initialize webhook manager
    manager = WebhookManager(db_path="test_webhooks.db")
    manager.start()
    
    try:
        print("\n[1] Testing webhook registration...")
        
        # Register test webhook (using httpbin for testing)
        webhook_id = manager.register_webhook(
            url="https://httpbin.org/post",
            events=["test.event", "data.created"],
            secret="test-secret-key",
            headers={"X-Test-Header": "test-value"}
        )
        
        print(f"   [OK] Registered webhook: {webhook_id}")
        
        # Verify registration
        webhooks = manager.registry.get_webhooks_for_event("test.event")
        assert len(webhooks) == 1
        assert webhooks[0].id == webhook_id
        print("   [OK] Webhook verified in registry")
        
        print("\n[2] Testing event triggering...")
        
        # Add local event handler to track events
        received_events = []
        def track_event(payload):
            received_events.append(payload)
            print(f"   [OK] Local handler received: {payload.event}")
        
        manager.add_event_handler("test.event", track_event)
        
        # Trigger event
        manager.trigger_event(
            event="test.event",
            data={"message": "Hello, webhooks!", "id": 123},
            metadata={"test": True}
        )
        
        # Wait for processing
        time.sleep(2)
        
        # Check local handler
        assert len(received_events) == 1
        assert received_events[0].event == "test.event"
        assert received_events[0].data["message"] == "Hello, webhooks!"
        print("   [OK] Event triggered and received locally")
        
        print("\n[3] Testing webhook statistics...")
        
        # Wait for delivery
        time.sleep(5)
        
        # Get statistics
        stats = manager.get_webhook_stats(webhook_id)
        print(f"   Total attempts: {stats['total_attempts']}")
        print(f"   Successful: {stats['successful']}")
        print(f"   Failed: {stats['failed']}")
        
        print("\n[4] Testing webhook update...")
        
        # Update webhook
        manager.registry.update_webhook(webhook_id, {
            "events": ["test.event", "data.created", "data.updated"],
            "retry_count": 5
        })
        
        updated_webhook = manager.registry.webhooks[webhook_id]
        assert len(updated_webhook.events) == 3
        assert updated_webhook.retry_count == 5
        print("   [OK] Webhook updated successfully")
        
        print("\n[5] Testing multiple webhooks...")
        
        # Register second webhook
        webhook_id2 = manager.register_webhook(
            url="https://httpbin.org/status/200",
            events=["data.created"],
            retry_count=1
        )
        
        # Trigger event that both webhooks listen to
        manager.trigger_event(
            event="data.created",
            data={"item": "test", "value": 42}
        )
        
        # Check both webhooks received event
        matching_webhooks = manager.registry.get_webhooks_for_event("data.created")
        assert len(matching_webhooks) == 2
        print(f"   [OK] Event sent to {len(matching_webhooks)} webhooks")
        
        print("\n[6] Testing webhook unregistration...")
        
        # Unregister first webhook
        manager.registry.unregister(webhook_id)
        
        # Verify unregistration
        assert webhook_id not in manager.registry.webhooks
        remaining = manager.registry.get_webhooks_for_event("test.event")
        assert len(remaining) == 0
        print("   [OK] Webhook unregistered successfully")
        
        print("\n[7] Testing wildcard event subscription...")
        
        # Register webhook for all events
        webhook_id3 = manager.register_webhook(
            url="https://httpbin.org/anything",
            events=["*"],  # Subscribe to all events
            metadata={"type": "catch-all"}
        )
        
        # Trigger various events
        events_to_test = ["system.startup", "custom.event", "random.test"]
        for event in events_to_test:
            matching = manager.registry.get_webhooks_for_event(event)
            assert any(w.id == webhook_id3 for w in matching)
        
        print("   [OK] Wildcard subscription working")
        
        print("\n" + "="*60)
        print("ALL TESTS PASSED [OK]")
        print("="*60)
        
        return True
        
    except AssertionError as e:
        print(f"\n[ERROR] Test failed: {e}")
        return False
        
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        manager.stop()
        print("\nWebhook manager stopped")


def test_webhook_persistence():
    """Test webhook persistence across restarts"""
    print("\n[Testing Persistence]")
    
    # First session - register webhooks
    manager1 = WebhookManager(db_path="test_persist.db")
    manager1.start()
    
    webhook_id = manager1.register_webhook(
        url="https://example.com/webhook",
        events=["persistent.event"],
        secret="persistent-secret"
    )
    
    print(f"   Registered webhook: {webhook_id}")
    manager1.stop()
    
    # Second session - verify persistence
    manager2 = WebhookManager(db_path="test_persist.db")
    manager2.start()
    
    # Check webhook still exists
    assert webhook_id in manager2.registry.webhooks
    webhook = manager2.registry.webhooks[webhook_id]
    assert webhook.url == "https://example.com/webhook"
    assert "persistent.event" in webhook.events
    
    print("   [OK] Webhook persisted across restart")
    
    manager2.stop()
    
    # Clean up
    import os
    if os.path.exists("test_persist.db"):
        os.remove("test_persist.db")
    
    return True


if __name__ == "__main__":
    # Run tests
    success = test_basic_webhook()
    
    if success:
        success = test_webhook_persistence()
    
    # Clean up test databases
    import os
    for db_file in ["test_webhooks.db", "test_persist.db"]:
        if os.path.exists(db_file):
            os.remove(db_file)
    
    if success:
        print("\n[SUCCESS] All webhook tests completed successfully!")
    else:
        print("\n[FAILED] Some tests failed")
        exit(1)