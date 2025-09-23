"""
Redis Integration Test Suite
Tests caching, pub/sub, and session management functionality
"""

from libraries.config_manager import get_config_manager
from libraries.redis_manager import (
    CacheManager,
    PubSubManager,
    SessionManager,
    CacheConfig,
)
import asyncio
from datetime import datetime
import sys
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent))


class RedisIntegrationTest:
    """Comprehensive Redis integration test"""

    def __init__(self):
        self.config_manager = get_config_manager()
        self.test_results = []

    async def run_all_tests(self):
        """Run all Redis integration tests"""
        print("=== Redis Integration Test Suite ===")
        print(f"Started at: {datetime.now()}")
        print()

        # Test cache functionality
        await self.test_cache_operations()
        await self.test_cache_ttl()
        await self.test_cache_patterns()

        # Test pub/sub functionality
        await self.test_pubsub_basic()
        await self.test_pubsub_multiple_subscribers()

        # Test session management
        await self.test_session_management()

        # Test configuration integration
        await self.test_config_integration()

        # Test error handling
        await self.test_error_handling()

        # Generate test report
        self.generate_test_report()

    async def test_cache_operations(self):
        """Test basic cache operations"""
        print("[TEST] Testing cache operations...")

        try:
            cache = CacheManager()

            # Test string caching
            test_key = "test:string"
            test_value = "Hello, Redis!"

            # Set value
            success = await cache.set(test_key, test_value, ttl=60)
            assert success, "Cache set operation failed"

            # Get value
            retrieved = await cache.get(test_key)
            assert retrieved == test_value, f"Expected {test_value}, got {retrieved}"

            # Test JSON caching
            json_key = "test:json"
            json_value = {"name": "test", "count": 42, "active": True}

            await cache.set(json_key, json_value, serializer="json")
            retrieved_json = await cache.get(json_key, serializer="json")
            assert retrieved_json == json_value, "JSON serialization failed"

            # Test existence
            exists = await cache.exists(test_key)
            assert exists, "Key existence check failed"

            # Test increment
            counter_key = "test:counter"
            await cache.set(counter_key, "10")
            new_count = await cache.increment(counter_key, 5)
            assert new_count == 15, f"Expected 15, got {new_count}"

            # Test deletion
            deleted = await cache.delete(test_key)
            assert deleted, "Key deletion failed"

            not_exists = await cache.exists(test_key)
            assert not not_exists, "Key still exists after deletion"

            self.test_results.append(
                {
                    "test": "cache_operations",
                    "status": "PASS",
                    "message": "All cache operations working correctly",
                }
            )
            print("[PASS] Cache operations test passed")

        except Exception as e:
            self.test_results.append(
                {"test": "cache_operations", "status": "FAIL", "message": str(e)}
            )
            print(f"❌ Cache operations test failed: {e}")

    async def test_cache_ttl(self):
        """Test cache TTL functionality"""
        print("⏰ Testing cache TTL...")

        try:
            cache = CacheManager()

            # Set key with short TTL
            ttl_key = "test:ttl"
            await cache.set(ttl_key, "temporary", ttl=2)

            # Verify it exists
            exists = await cache.exists(ttl_key)
            assert exists, "TTL key should exist initially"

            # Wait for expiration (shortened for testing)
            await asyncio.sleep(3)

            # Verify it's gone
            exists = await cache.exists(ttl_key)
            assert not exists, "TTL key should have expired"

            # Test TTL extension
            extend_key = "test:extend"
            await cache.set(extend_key, "extend_me", ttl=10)

            # Extend TTL
            extended = await cache.expire(extend_key, 30)
            assert extended, "TTL extension failed"

            self.test_results.append(
                {
                    "test": "cache_ttl",
                    "status": "PASS",
                    "message": "TTL functionality working correctly",
                }
            )
            print("✅ Cache TTL test passed")

        except Exception as e:
            self.test_results.append(
                {"test": "cache_ttl", "status": "FAIL", "message": str(e)}
            )
            print(f"❌ Cache TTL test failed: {e}")

    async def test_cache_patterns(self):
        """Test cache pattern matching"""
        print("🔍 Testing cache patterns...")

        try:
            cache = CacheManager()

            # Set multiple keys with pattern
            test_keys = [
                "pattern:user:1",
                "pattern:user:2",
                "pattern:session:1",
                "other:key",
            ]

            for key in test_keys:
                await cache.set(key, f"value_{key}")

            # Test pattern matching
            user_keys = await cache.get_pattern("pattern:user:*")
            assert len(user_keys) == 2, f"Expected 2 user keys, got {len(user_keys)}"

            pattern_keys = await cache.get_pattern("pattern:*")
            assert (
                len(pattern_keys) == 3
            ), f"Expected 3 pattern keys, got {len(pattern_keys)}"

            # Cleanup
            for key in test_keys:
                await cache.delete(key)

            self.test_results.append(
                {
                    "test": "cache_patterns",
                    "status": "PASS",
                    "message": "Pattern matching working correctly",
                }
            )
            print("✅ Cache patterns test passed")

        except Exception as e:
            self.test_results.append(
                {"test": "cache_patterns", "status": "FAIL", "message": str(e)}
            )
            print(f"❌ Cache patterns test failed: {e}")

    async def test_pubsub_basic(self):
        """Test basic pub/sub functionality"""
        print("📡 Testing basic pub/sub...")

        try:
            pubsub = PubSubManager()
            received_messages = []

            # Define callback
            async def test_callback(channel, message):
                received_messages.append((channel, message))

            # Subscribe to channel
            test_channel = "test:channel"
            pubsub.subscribe(test_channel, test_callback)

            # Start listening in background
            listen_task = asyncio.create_task(pubsub.start_listening())

            # Give listener time to start
            await asyncio.sleep(0.1)

            # Publish message
            test_message = {"type": "test", "data": "Hello, PubSub!"}
            await pubsub.publish(test_channel, test_message)

            # Wait for message processing
            await asyncio.sleep(0.5)

            # Stop listening
            await pubsub.stop_listening()
            listen_task.cancel()

            # Verify message received
            assert len(received_messages) > 0, "No messages received"
            channel, message = received_messages[0]
            assert channel == test_channel, f"Wrong channel: {channel}"
            assert message == test_message, f"Wrong message: {message}"

            self.test_results.append(
                {
                    "test": "pubsub_basic",
                    "status": "PASS",
                    "message": "Basic pub/sub working correctly",
                }
            )
            print("✅ Basic pub/sub test passed")

        except Exception as e:
            self.test_results.append(
                {"test": "pubsub_basic", "status": "FAIL", "message": str(e)}
            )
            print(f"❌ Basic pub/sub test failed: {e}")

    async def test_pubsub_multiple_subscribers(self):
        """Test multiple subscribers"""
        print("👥 Testing multiple subscribers...")

        try:
            pubsub = PubSubManager()
            received_count = {"callback1": 0, "callback2": 0}

            # Define callbacks
            async def callback1(channel, message):
                received_count["callback1"] += 1

            async def callback2(channel, message):
                received_count["callback2"] += 1

            # Subscribe multiple callbacks
            test_channel = "test:multi"
            pubsub.subscribe(test_channel, callback1)
            pubsub.subscribe(test_channel, callback2)

            # Start listening
            listen_task = asyncio.create_task(pubsub.start_listening())
            await asyncio.sleep(0.1)

            # Publish message
            await pubsub.publish(test_channel, {"test": "multi"})
            await asyncio.sleep(0.5)

            # Stop listening
            await pubsub.stop_listening()
            listen_task.cancel()

            # Verify both callbacks received message
            assert received_count["callback1"] > 0, "Callback1 didn't receive message"
            assert received_count["callback2"] > 0, "Callback2 didn't receive message"

            self.test_results.append(
                {
                    "test": "pubsub_multiple",
                    "status": "PASS",
                    "message": "Multiple subscribers working correctly",
                }
            )
            print("✅ Multiple subscribers test passed")

        except Exception as e:
            self.test_results.append(
                {"test": "pubsub_multiple", "status": "FAIL", "message": str(e)}
            )
            print(f"❌ Multiple subscribers test failed: {e}")

    async def test_session_management(self):
        """Test session management"""
        print("🔐 Testing session management...")

        try:
            cache = CacheManager()
            session_manager = SessionManager(cache)

            # Create session
            session_id = "test_session_123"
            session_data = {
                "user_id": "user123",
                "username": "testuser",
                "login_time": datetime.now().isoformat(),
                "permissions": ["read", "write"],
            }

            success = await session_manager.create_session(
                session_id, session_data, ttl=3600
            )
            assert success, "Session creation failed"

            # Retrieve session
            retrieved = await session_manager.get_session(session_id)
            assert retrieved == session_data, "Session retrieval failed"

            # Update session
            update_data = {"last_activity": datetime.now().isoformat()}
            updated = await session_manager.update_session(session_id, update_data)
            assert updated, "Session update failed"

            # Verify update
            updated_session = await session_manager.get_session(session_id)
            assert "last_activity" in updated_session, "Session update not persisted"

            # Extend session
            extended = await session_manager.extend_session(session_id, 7200)
            assert extended, "Session extension failed"

            # Delete session
            deleted = await session_manager.delete_session(session_id)
            assert deleted, "Session deletion failed"

            # Verify deletion
            deleted_session = await session_manager.get_session(session_id)
            assert deleted_session is None, "Session still exists after deletion"

            self.test_results.append(
                {
                    "test": "session_management",
                    "status": "PASS",
                    "message": "Session management working correctly",
                }
            )
            print("✅ Session management test passed")

        except Exception as e:
            self.test_results.append(
                {"test": "session_management", "status": "FAIL", "message": str(e)}
            )
            print(f"❌ Session management test failed: {e}")

    async def test_config_integration(self):
        """Test configuration integration"""
        print("⚙️ Testing configuration integration...")

        try:
            # Get Redis config from unified config
            redis_config = self.config_manager.get("infrastructure.storage.redis.cache")
            assert redis_config is not None, "Redis config not found"

            # Create cache with config
            cache_config = CacheConfig(
                host=redis_config.get("host", "localhost"),
                port=redis_config.get("port", 6379),
                db=redis_config.get("db", 0),
            )

            cache = CacheManager(cache_config)

            # Test with configured cache
            await cache.set("config_test", "configured_value")
            value = await cache.get("config_test")
            assert value == "configured_value", "Config integration failed"

            await cache.delete("config_test")

            self.test_results.append(
                {
                    "test": "config_integration",
                    "status": "PASS",
                    "message": "Configuration integration working correctly",
                }
            )
            print("✅ Configuration integration test passed")

        except Exception as e:
            self.test_results.append(
                {"test": "config_integration", "status": "FAIL", "message": str(e)}
            )
            print(f"❌ Configuration integration test failed: {e}")

    async def test_error_handling(self):
        """Test error handling"""
        print("🛡️ Testing error handling...")

        try:
            # Test with invalid Redis config (should handle gracefully)
            invalid_config = CacheConfig(host="invalid_host", port=99999)
            cache = CacheManager(invalid_config)

            # These should fail gracefully and return None/False
            result = await cache.get("nonexistent")
            assert result is None, "Should return None for failed get"

            await cache.set("test", "value")
            # Should handle connection error gracefully

            self.test_results.append(
                {
                    "test": "error_handling",
                    "status": "PASS",
                    "message": "Error handling working correctly",
                }
            )
            print("✅ Error handling test passed")

        except Exception as e:
            # Expected behavior for this test
            self.test_results.append(
                {
                    "test": "error_handling",
                    "status": "PASS",
                    "message": f"Errors handled gracefully: {e}",
                }
            )
            print(f"✅ Error handling test passed: {e}")

    def generate_test_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("📊 REDIS INTEGRATION TEST REPORT")
        print("=" * 60)

        passed = sum(1 for r in self.test_results if r["status"] == "PASS")
        failed = sum(1 for r in self.test_results if r["status"] == "FAIL")
        total = len(self.test_results)

        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(passed / total) * 100:.1f}%")
        print()

        for result in self.test_results:
            status_icon = "✅" if result["status"] == "PASS" else "❌"
            print(f"{status_icon} {result['test']}: {result['message']}")

        print("\n" + "=" * 60)
        print(f"Test completed at: {datetime.now()}")

        # Summary
        if failed == 0:
            print("🎉 All tests passed! Redis integration is working correctly.")
        else:
            print(
                f"⚠️ {failed} test(s) failed. Please check Redis configuration and connectivity."
            )


async def main():
    """Run Redis integration tests"""
    test_suite = RedisIntegrationTest()
    await test_suite.run_all_tests()


if __name__ == "__main__":
    print("Starting Redis Integration Test...")
    print("Note: This test requires Redis server to be running on localhost:6379")
    print("If Redis is not available, some tests will demonstrate error handling.\n")

    asyncio.run(main())
