"""
Advanced RxPy Operators for Webhook Management

This demonstrates sophisticated reactive patterns beyond basic map/filter:
- Debounce: Prevent rapid-fire webhooks
- Throttle: Rate limiting
- Window: Time-based batching
- Sample: Periodic snapshots
- Scan: Accumulation with state
- CombineLatest: Merge multiple streams
"""

import asyncio
import time
from typing import Dict, Any
from dataclasses import dataclass

from reactivex import Subject, operators as ops, interval, combine_latest
from reactivex.scheduler.eventloop import AsyncIOScheduler

# For visualization
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class WebhookEvent:
    """Simple webhook event for demonstrations"""

    event_type: str
    data: Dict[str, Any]
    timestamp: float
    source: str = "demo"


class AdvancedWebhookPatterns:
    """
    Demonstrates advanced reactive operators for real-world webhook scenarios
    """

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.event_stream = Subject()

    # ========================================================================
    # PATTERN 1: DEBOUNCE - Prevent Rapid-Fire Events
    # ========================================================================

    def demo_debounce(self):
        """
        DEBOUNCE: Only emit when event stream has been idle for X seconds

        Real-world use case:
        - Git repository has 100 commits pushed in 10 seconds
        - You only want to trigger CI/CD ONCE after pushes stop
        - Debounce(5 seconds) waits for 5s of silence before emitting

        Marble Diagram:
        Events:     -a-b-c----------d-e--------f-|
        Debounce:   --------c-----------e--------f-|
                    (only emit after 5 units of silence)
        """
        print("\n" + "=" * 80)
        print("PATTERN 1: DEBOUNCE - Smart Event Coalescing")
        print("=" * 80)

        print("\n💡 Scenario: Rapid git pushes should trigger ONE build, not 100")
        print("   Input: 5 commits in 2 seconds, then pause")
        print("   Output: 1 webhook after pause\n")

        results = []

        pipeline = self.event_stream.pipe(
            # Wait for 1 second of silence before emitting
            ops.debounce(1.0),
            ops.do_action(
                lambda event: logger.info(
                    f"🚀 DEBOUNCED EVENT: {event.event_type} (aggregated rapid events)"
                )
            ),
        )

        pipeline.subscribe(on_next=lambda e: results.append(e))

        # Simulate rapid events
        print("📤 Emitting rapid events...")
        for i in range(5):
            self.event_stream.on_next(
                WebhookEvent(
                    event_type="git.push", data={"commit": f"abc{i}"}, timestamp=time.time()
                )
            )
            time.sleep(0.1)  # 100ms apart

        print("   ⏸️  Waiting for debounce period...\n")
        time.sleep(1.5)  # Let debounce trigger

        assert len(results) == 1, "Should coalesce into 1 event"
        print(f"✅ Success: {len(results)} debounced event (instead of 5 rapid events)\n")

        return results

    # ========================================================================
    # PATTERN 2: THROTTLE - Rate Limiting
    # ========================================================================

    def demo_throttle(self):
        """
        THROTTLE: Emit at most once per time period (rate limiting)

        Real-world use case:
        - Health check endpoints sending status every 100ms
        - You only care about status once per 5 seconds
        - Throttle ensures maximum rate

        Marble Diagram:
        Events:     -a-b-c-d-e-f-g-h-i-j-|
        Throttle:   -a-----d-----g-----j-|
                    (1 event per 3 time units)
        """
        print("\n" + "=" * 80)
        print("PATTERN 2: THROTTLE - Rate Limiting")
        print("=" * 80)

        print("\n💡 Scenario: Health checks every 100ms, but we want max 1/second")
        print("   Input: 10 health checks in 1 second")
        print("   Output: ~1 health check per second\n")

        results = []

        pipeline = self.event_stream.pipe(
            # Maximum one event per second
            ops.throttle_first(1.0),
            ops.do_action(
                lambda event: logger.info(f"💓 THROTTLED HEALTH CHECK: {event.data['status']}")
            ),
        )

        pipeline.subscribe(on_next=lambda e: results.append(e))

        # Simulate rapid health checks
        print("📤 Emitting 10 rapid health checks...")
        for i in range(10):
            self.event_stream.on_next(
                WebhookEvent(
                    event_type="health.check",
                    data={"status": f"healthy_{i}"},
                    timestamp=time.time(),
                )
            )
            time.sleep(0.1)

        time.sleep(0.5)  # Let throttle process

        print(f"\n✅ Success: {len(results)} throttled events (instead of 10)\n")
        return results

    # ========================================================================
    # PATTERN 3: WINDOW - Time-Based Batching
    # ========================================================================

    def demo_window(self):
        """
        WINDOW: Group events into time-based windows

        Real-world use case:
        - Batch webhook deliveries for efficiency
        - Send metrics in 1-minute batches instead of individually
        - Reduce HTTP requests by grouping

        Marble Diagram:
        Events:     -a-b-c----d-e-f----g-h-i-|
        Window:     ------[abc]-----[def]-----[ghi]-|
                    (3-second windows)
        """
        print("\n" + "=" * 80)
        print("PATTERN 3: WINDOW - Time-Based Batching")
        print("=" * 80)

        print("\n💡 Scenario: Batch metrics into 2-second windows for efficiency")
        print("   Input: Individual metric events")
        print("   Output: Batched metric arrays\n")

        batches = []

        pipeline = self.event_stream.pipe(
            # Create 2-second windows
            ops.window_with_time(2.0),
            ops.flat_map(
                lambda window: window.pipe(
                    # Convert each window to a list
                    ops.to_iterable(),
                    ops.map(lambda events: list(events)),
                )
            ),
            ops.filter(lambda batch: len(batch) > 0),  # Skip empty windows
            ops.do_action(
                lambda batch: logger.info(f"📦 BATCHED METRICS: {len(batch)} events in window")
            ),
        )

        pipeline.subscribe(on_next=lambda b: batches.append(b))

        # Emit metrics over 5 seconds
        print("📤 Emitting metrics over 5 seconds...")
        time.time()
        for i in range(8):
            self.event_stream.on_next(
                WebhookEvent(event_type="metric.updated", data={"value": i}, timestamp=time.time())
            )
            time.sleep(0.6)  # Slower than window size

        time.sleep(2.5)  # Let final window complete

        print(f"\n✅ Success: {len(batches)} batches created\n")
        for idx, batch in enumerate(batches):
            print(f"   Batch {idx + 1}: {len(batch)} events")

        return batches

    # ========================================================================
    # PATTERN 4: SAMPLE - Periodic Snapshots
    # ========================================================================

    def demo_sample(self):
        """
        SAMPLE: Take periodic snapshots of stream

        Real-world use case:
        - Monitor changing state (like server metrics)
        - Only care about current value every N seconds
        - Ignore intermediate values

        Marble Diagram:
        Events:     -a-b-c-d-e-f-g-h-i-j-|
        Sample:     -----c-------g-----j-|
                    (sample every 5 units, take most recent)
        """
        print("\n" + "=" * 80)
        print("PATTERN 4: SAMPLE - Periodic Snapshots")
        print("=" * 80)

        print("\n💡 Scenario: Server metrics update constantly, sample every 2s")
        print("   Input: Continuous metric stream")
        print("   Output: Snapshot every 2 seconds\n")

        snapshots = []

        # Create a sampler that triggers every 2 seconds
        sampler = interval(2.0)

        pipeline = self.event_stream.pipe(
            ops.sample(sampler),
            ops.do_action(lambda event: logger.info(f"📸 SNAPSHOT: {event.data}")),
        )

        pipeline.subscribe(on_next=lambda e: snapshots.append(e))

        # Emit rapidly changing metrics
        print("📤 Emitting rapidly changing metrics...")
        for i in range(20):
            self.event_stream.on_next(
                WebhookEvent(
                    event_type="metrics.cpu", data={"cpu_percent": 40 + i}, timestamp=time.time()
                )
            )
            time.sleep(0.3)

        time.sleep(1)  # Let final sample happen

        print(f"\n✅ Success: {len(snapshots)} snapshots taken\n")
        return snapshots

    # ========================================================================
    # PATTERN 5: SCAN - Stateful Accumulation
    # ========================================================================

    def demo_scan(self):
        """
        SCAN: Accumulate state over time (like reduce, but emits intermediate results)

        Real-world use case:
        - Running total of webhook delivery counts
        - Cumulative error rates
        - State machine transitions

        Marble Diagram:
        Events:     -1--2--3--4--5-|
        Scan(+):    -1--3--6-10-15-|
                    (running sum)
        """
        print("\n" + "=" * 80)
        print("PATTERN 5: SCAN - Stateful Accumulation")
        print("=" * 80)

        print("\n💡 Scenario: Track running total of webhook deliveries")
        print("   Input: Individual delivery events")
        print("   Output: Cumulative count\n")

        totals = []

        pipeline = self.event_stream.pipe(
            # Accumulate delivery count
            ops.scan(
                lambda acc, event: {
                    "total_deliveries": acc["total_deliveries"] + 1,
                    "last_event": event.event_type,
                    "timestamp": event.timestamp,
                },
                seed={"total_deliveries": 0, "last_event": None, "timestamp": 0},
            ),
            ops.do_action(
                lambda state: logger.info(
                    f"📊 RUNNING TOTAL: {state['total_deliveries']} deliveries"
                )
            ),
        )

        pipeline.subscribe(on_next=lambda s: totals.append(s))

        # Emit delivery events
        print("📤 Emitting 5 delivery events...\n")
        for i in range(5):
            self.event_stream.on_next(
                WebhookEvent(
                    event_type="webhook.delivered",
                    data={"endpoint": f"http://api{i}.example.com"},
                    timestamp=time.time(),
                )
            )
            time.sleep(0.3)

        print(f"\n✅ Success: {len(totals)} running totals emitted")
        print(f"   Final count: {totals[-1]['total_deliveries']}\n")
        return totals

    # ========================================================================
    # PATTERN 6: COMBINE_LATEST - Merge Multiple Streams
    # ========================================================================

    def demo_combine_latest(self):
        """
        COMBINE_LATEST: Combine multiple streams into one

        Real-world use case:
        - Combine webhook events with system health status
        - Only deliver webhooks when system is healthy
        - React to changes in multiple data sources

        Marble Diagram:
        Stream A:    -a-----b-----c-|
        Stream B:    ---1-----2-----|
        Combined:    ---a1---b2---c2-|
                     (emits when either changes, with latest from both)
        """
        print("\n" + "=" * 80)
        print("PATTERN 6: COMBINE_LATEST - Multi-Stream Coordination")
        print("=" * 80)

        print("\n💡 Scenario: Only deliver webhooks when system is healthy")
        print("   Stream 1: Webhook events")
        print("   Stream 2: Health status")
        print("   Output: Events + health state\n")

        webhook_stream = Subject()
        health_stream = Subject()
        results = []

        pipeline = combine_latest(webhook_stream, health_stream).pipe(
            ops.filter(lambda combined: combined[1]["status"] == "healthy"),
            ops.map(
                lambda combined: {"event": combined[0], "health": combined[1], "allowed": True}
            ),
            ops.do_action(
                lambda result: logger.info(
                    f"✅ WEBHOOK ALLOWED: {result['event'].event_type} "
                    f"(system {result['health']['status']})"
                )
            ),
        )

        pipeline.subscribe(on_next=lambda r: results.append(r))

        # Start with healthy status
        print("📤 Initial state: healthy\n")
        health_stream.on_next({"status": "healthy", "cpu": 30})

        # Emit some webhooks
        print("📤 Emitting webhooks while healthy...")
        for i in range(3):
            webhook_stream.on_next(
                WebhookEvent(
                    event_type="git.push", data={"commit": f"abc{i}"}, timestamp=time.time()
                )
            )
            time.sleep(0.2)

        # System becomes unhealthy
        print("\n⚠️  System becomes unhealthy...")
        health_stream.on_next({"status": "unhealthy", "cpu": 95})

        # Try to emit webhook while unhealthy (should be blocked)
        print("📤 Attempting webhook while unhealthy...")
        webhook_stream.on_next(
            WebhookEvent(
                event_type="git.push", data={"commit": "should_be_blocked"}, timestamp=time.time()
            )
        )
        time.sleep(0.2)

        # System recovers
        print("\n✅ System recovers...")
        health_stream.on_next({"status": "healthy", "cpu": 40})

        # Emit final webhook
        print("📤 Emitting final webhook while healthy...")
        webhook_stream.on_next(
            WebhookEvent(
                event_type="git.push", data={"commit": "final_commit"}, timestamp=time.time()
            )
        )
        time.sleep(0.2)

        print(f"\n✅ Success: {len(results)} webhooks delivered (unhealthy ones blocked)\n")
        return results

    # ========================================================================
    # PATTERN 7: PARTITION - Split Stream by Predicate
    # ========================================================================

    def demo_partition(self):
        """
        PARTITION: Split one stream into two based on a condition

        Real-world use case:
        - Separate high-priority from low-priority webhooks
        - Route success/failure to different handlers
        - Split stream into hot/cold paths

        Marble Diagram:
        Input:        -H-L-H-L-H-|
        High:         -H---H---H-|
        Low:          ---L---L---|
        """
        print("\n" + "=" * 80)
        print("PATTERN 7: PARTITION - Stream Splitting")
        print("=" * 80)

        print("\n💡 Scenario: Route urgent webhooks to fast lane")
        print("   Input: Mixed priority webhooks")
        print("   Output: Separate streams for urgent/normal\n")

        urgent_results = []
        normal_results = []

        # Split into urgent and normal streams
        urgent_stream = self.event_stream.pipe(
            ops.filter(lambda e: e.data.get("priority") == "urgent"),
            ops.do_action(lambda e: logger.info(f"🚨 URGENT: {e.event_type}")),
        )

        normal_stream = self.event_stream.pipe(
            ops.filter(lambda e: e.data.get("priority") != "urgent"),
            ops.do_action(lambda e: logger.info(f"📬 NORMAL: {e.event_type}")),
        )

        urgent_stream.subscribe(on_next=lambda e: urgent_results.append(e))
        normal_stream.subscribe(on_next=lambda e: normal_results.append(e))

        # Emit mixed priority events
        print("📤 Emitting mixed priority events...\n")
        events = [
            ("urgent", "security.breach"),
            ("normal", "user.login"),
            ("urgent", "system.crash"),
            ("normal", "metric.update"),
            ("urgent", "payment.failed"),
        ]

        for priority, event_type in events:
            self.event_stream.on_next(
                WebhookEvent(
                    event_type=event_type, data={"priority": priority}, timestamp=time.time()
                )
            )
            time.sleep(0.2)

        print("\n✅ Success:")
        print(f"   Urgent lane: {len(urgent_results)} events")
        print(f"   Normal lane: {len(normal_results)} events\n")

        return urgent_results, normal_results


# ============================================================================
# DEMONSTRATION RUNNER
# ============================================================================


async def run_all_advanced_patterns():
    """Run all advanced operator demonstrations"""
    print("\n" + "=" * 80)
    print("ADVANCED RXPY OPERATORS FOR WEBHOOK MANAGEMENT")
    print("=" * 80)

    patterns = AdvancedWebhookPatterns()

    # Run each pattern
    patterns.demo_debounce()
    await asyncio.sleep(0.5)

    # Reset for next demo
    patterns = AdvancedWebhookPatterns()
    patterns.demo_throttle()
    await asyncio.sleep(0.5)

    patterns = AdvancedWebhookPatterns()
    patterns.demo_window()
    await asyncio.sleep(0.5)

    patterns = AdvancedWebhookPatterns()
    patterns.demo_sample()
    await asyncio.sleep(0.5)

    patterns = AdvancedWebhookPatterns()
    patterns.demo_scan()
    await asyncio.sleep(0.5)

    patterns = AdvancedWebhookPatterns()
    patterns.demo_combine_latest()
    await asyncio.sleep(0.5)

    patterns = AdvancedWebhookPatterns()
    patterns.demo_partition()

    print("\n" + "=" * 80)
    print("✅ ALL ADVANCED PATTERNS DEMONSTRATED")
    print("=" * 80)

    print("\n📚 OPERATOR SUMMARY:")
    print("""
    ┌──────────────────┬─────────────────────────────────────────────────┐
    │ OPERATOR         │ USE CASE                                        │
    ├──────────────────┼─────────────────────────────────────────────────┤
    │ debounce         │ Coalesce rapid events (git commits → 1 build)  │
    │ throttle         │ Rate limiting (max 1 event per second)          │
    │ window           │ Time-based batching (metrics aggregation)       │
    │ sample           │ Periodic snapshots (monitoring dashboards)      │
    │ scan             │ Accumulate state (running totals, state)        │
    │ combine_latest   │ Merge streams (events + health status)          │
    │ partition/filter │ Split streams (urgent vs normal routing)        │
    └──────────────────┴─────────────────────────────────────────────────┘
    """)

    print("\n💡 When to use each:")
    print("   • Too many events? → debounce or throttle")
    print("   • Need batching? → window or buffer")
    print("   • Need latest value? → sample or distinct_until_changed")
    print("   • Need state? → scan or reduce")
    print("   • Multiple sources? → combine_latest or merge")
    print("   • Need routing? → filter or partition\n")


if __name__ == "__main__":
    asyncio.run(run_all_advanced_patterns())
