"""
Simple Redis Integration Test
Tests basic caching and pub/sub functionality without emoji characters
"""

from libraries.redis_manager import CacheManager, PubSubManager, SessionManager
import asyncio
import sys
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent))


async def test_cache_basic():
    """Test basic cache operations"""
    print("Testing basic cache operations...")

    try:
        cache = CacheManager()

        # Test set/get
        await cache.set("test:key", "test_value", ttl=60)
        value = await cache.get("test:key")

        if value == "test_value":
            print("PASS: Cache set/get working")
        else:
            print("FAIL: Cache set/get not working")

        # Test JSON
        json_data = {"name": "test", "count": 42}
        await cache.set("test:json", json_data)
        retrieved = await cache.get("test:json")

        if retrieved == json_data:
            print("PASS: JSON serialization working")
        else:
            print("FAIL: JSON serialization not working")

        # Cleanup
        await cache.delete("test:key")
        await cache.delete("test:json")

        return True

    except Exception as e:
        print(f"FAIL: Cache test failed - {e}")
        return False


async def test_pubsub_basic():
    """Test basic pub/sub"""
    print("Testing basic pub/sub...")

    try:
        pubsub = PubSubManager()
        messages_received = []

        async def test_callback(channel, message):
            messages_received.append((channel, message))

        # Subscribe
        pubsub.subscribe("test:channel", test_callback)

        # Start listening
        listen_task = asyncio.create_task(pubsub.start_listening())
        await asyncio.sleep(0.1)

        # Publish
        test_message = {"type": "test", "data": "hello"}
        await pubsub.publish("test:channel", test_message)
        await asyncio.sleep(0.5)

        # Stop
        await pubsub.stop_listening()
        listen_task.cancel()

        if len(messages_received) > 0:
            print("PASS: Pub/sub message received")
            return True
        else:
            print("FAIL: No pub/sub messages received")
            return False

    except Exception as e:
        print(f"FAIL: Pub/sub test failed - {e}")
        return False


async def test_session_basic():
    """Test session management"""
    print("Testing session management...")

    try:
        cache = CacheManager()
        session_mgr = SessionManager(cache)

        # Create session
        session_data = {"user": "test", "role": "admin"}
        success = await session_mgr.create_session("test_session", session_data)

        if not success:
            print("FAIL: Session creation failed")
            return False

        # Get session
        retrieved = await session_mgr.get_session("test_session")

        if retrieved == session_data:
            print("PASS: Session management working")
        else:
            print("FAIL: Session retrieval failed")
            return False

        # Cleanup
        await session_mgr.delete_session("test_session")
        return True

    except Exception as e:
        print(f"FAIL: Session test failed - {e}")
        return False


async def main():
    """Run all tests"""
    print("=== Simple Redis Integration Test ===")
    print("Note: Redis server should be running on localhost:6379")
    print("If Redis is not available, tests will show connection errors.\n")

    results = []

    # Run tests
    results.append(await test_cache_basic())
    results.append(await test_pubsub_basic())
    results.append(await test_session_basic())

    # Summary
    passed = sum(results)
    total = len(results)

    print("\n=== Test Results ===")
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("SUCCESS: All Redis integration tests passed!")
    else:
        print("WARNING: Some tests failed - check Redis connectivity")


if __name__ == "__main__":
    asyncio.run(main())
