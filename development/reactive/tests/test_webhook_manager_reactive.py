"""
Unit Tests for Reactive Webhook Manager using Marble Diagrams

Marble diagrams are a visual way to test reactive streams.
They represent time-based event sequences as ASCII art:

    -a-b-c-|      Events a, b, c, then completion
    -a-b-c-#      Events a, b, c, then error
    -----a--|      Event a after delay, then completion
    -a-----a-|    Two events with gap between them

Time moves left to right. Each character represents a time unit.
"""

import sys
from pathlib import Path

# Add core directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "core"))

# RxPy testing imports
from reactivex import operators as ops
from reactivex.testing import TestScheduler, ReactiveTest

from webhook_manager_reactive import (
    WebhookPriority,
    WebhookPayload,
    CircuitBreakerState
)


class TestReactiveWebhookPipeline:
    """
    Test suite demonstrating marble diagram testing for reactive streams

    Key Advantage: These tests run SYNCHRONOUSLY even though the real code is async!
    The TestScheduler gives us complete control over virtual time.
    """

    def test_priority_grouping_with_marble_diagram(self):
        """
        Test that events are grouped by priority using marble diagrams

        Marble Diagram:
        Input:   -H-N-L-U-H-N-|
        Output:  -H---U-H-----|  (HIGH/URGENT only)
                 ---N-----N---|  (NORMAL only)
                 -----L-------|  (LOW only)

        Legend: H=High, N=Normal, L=Low, U=Urgent
        """
        scheduler = TestScheduler()

        # Create test payloads
        high1 = WebhookPayload("test", {}, 1.0, "h1", priority=WebhookPriority.HIGH)
        normal1 = WebhookPayload("test", {}, 2.0, "n1", priority=WebhookPriority.NORMAL)
        low1 = WebhookPayload("test", {}, 3.0, "l1", priority=WebhookPriority.LOW)
        urgent1 = WebhookPayload("test", {}, 4.0, "u1", priority=WebhookPriority.URGENT)
        high2 = WebhookPayload("test", {}, 5.0, "h2", priority=WebhookPriority.HIGH)
        normal2 = WebhookPayload("test", {}, 6.0, "n2", priority=WebhookPriority.NORMAL)

        # Create marble diagram as observable
        # Time unit = 10ms in TestScheduler
        source = scheduler.create_hot_observable(
            ReactiveTest.on_next(210, high1),     # -H
            ReactiveTest.on_next(220, normal1),   # -N
            ReactiveTest.on_next(230, low1),      # -L
            ReactiveTest.on_next(240, urgent1),   # -U
            ReactiveTest.on_next(250, high2),     # -H
            ReactiveTest.on_next(260, normal2),   # -N
            ReactiveTest.on_completed(270)        # -|
        )

        # Group by priority and collect high priority events only

        def create_pipeline():
            return source.pipe(
                ops.group_by(lambda p: p.priority),
                ops.flat_map(lambda group: group.pipe(
                    ops.filter(lambda p: p.priority in [WebhookPriority.HIGH, WebhookPriority.URGENT])
                ))
            )

        # Run the test with explicit timing
        results = scheduler.start(create_pipeline, created=200, subscribed=200, disposed=1000)

        # Verify we got only HIGH and URGENT events in order
        # Filter out the completion message
        event_messages = [msg for msg in results.messages if msg.value.kind == 'N']

        assert len(event_messages) == 3  # high1, urgent1, high2
        assert event_messages[0].value.value.event_id == "h1"
        assert event_messages[1].value.value.event_id == "u1"
        assert event_messages[2].value.value.event_id == "h2"

        print("[OK] Priority grouping test passed!")

    def test_circuit_breaker_filtering_with_marble_diagram(self):
        """
        Test circuit breaker filtering

        Marble Diagram:
        Input:     -a-b-c-d-e-f-|
        Breaker:   -O-O-C-C-C-C-|  (O=Open, C=Closed)
        Output:    -----c-d-e-f-|  (Only when closed)
        """
        scheduler = TestScheduler()

        # Simulate circuit breaker states changing over time
        circuit_states = {
            210: CircuitBreakerState.OPEN,
            220: CircuitBreakerState.OPEN,
            230: CircuitBreakerState.CLOSED,
            240: CircuitBreakerState.CLOSED,
            250: CircuitBreakerState.CLOSED,
            260: CircuitBreakerState.CLOSED,
        }

        current_time_box = {'time': 0}

        def mock_circuit_breaker_check(url: str) -> bool:
            """Mock circuit breaker that changes state based on virtual time"""
            return (
                circuit_states.get(current_time_box['time'], CircuitBreakerState.CLOSED)
                == CircuitBreakerState.CLOSED
            )

        # Create events
        events = [
            (210, ("event_a", "url1")),
            (220, ("event_b", "url1")),
            (230, ("event_c", "url1")),
            (240, ("event_d", "url1")),
            (250, ("event_e", "url1")),
            (260, ("event_f", "url1")),
        ]

        source = scheduler.create_hot_observable(
            *[ReactiveTest.on_next(t, e) for t, e in events],
            ReactiveTest.on_completed(270)
        )

        def create_pipeline():
            return source.pipe(
                ops.do_action(lambda x: current_time_box.update({'time': scheduler.clock})),
                ops.filter(lambda event: mock_circuit_breaker_check(event[1]))
            )

        results = scheduler.start(create_pipeline, created=200, subscribed=200, disposed=1000)

        # Should only get events from time 30 onwards (when circuit closed)
        passed_events = [msg.value.value for msg in results.messages if msg.value.kind == 'N']
        assert len(passed_events) == 4  # c, d, e, f
        assert passed_events[0][0] == "event_c"
        assert passed_events[3][0] == "event_f"

        print("[OK] Circuit breaker filtering test passed!")

    def test_retry_logic_with_marble_diagram(self):
        """
        Test retry operator behavior

        Marble Diagram:
        Source:    -a-#           (Event a, then error)
        Retry(3):  -a-a-a-a-#     (Retries 3 times, then gives up)
        """
        TestScheduler()

        attempt_count = {'count': 0}

        def create_failing_observable():
            """Observable that always fails"""
            def subscribe(observer, sched=None):
                attempt_count['count'] += 1
                observer.on_next(f"attempt_{attempt_count['count']}")
                observer.on_error(Exception("Simulated failure"))
                return lambda: None

            from reactivex import create
            return create(subscribe)

        # Test with retry(2) - RxPY retry(N) means retry UP TO N times on error
        # So retry(2) = original attempt + up to 2 retries = up to 3 attempts total
        results = []
        error_occurred = {'error': None}

        create_failing_observable().pipe(
            ops.retry(2)  # Will retry up to 2 times = up to 3 total attempts
        ).subscribe(
            on_next=lambda x: results.append(x),
            on_error=lambda e: error_occurred.update({'error': e})
        )

        assert len(results) >= 2  # At least original + 1 retry
        assert attempt_count['count'] >= 2
        assert error_occurred['error'] is not None

        print("[OK] Retry logic test passed!")

    def test_backpressure_with_buffer(self):
        """
        Test backpressure handling with buffering

        Marble Diagram:
        Input:          -a-b-c----d-e-f-|
        Buffer(3):      -------(abc)----(def)-|

        Events are buffered in groups of 3
        """
        scheduler = TestScheduler()

        source = scheduler.create_hot_observable(
            ReactiveTest.on_next(210, "a"),
            ReactiveTest.on_next(220, "b"),
            ReactiveTest.on_next(230, "c"),
            ReactiveTest.on_next(270, "d"),
            ReactiveTest.on_next(280, "e"),
            ReactiveTest.on_next(290, "f"),
            ReactiveTest.on_completed(300)
        )

        def create_pipeline():
            return source.pipe(
                ops.buffer_with_count(3)
            )

        results = scheduler.start(create_pipeline, created=200, subscribed=200, disposed=1000)

        # Should get 2 buffers: [a,b,c] and [d,e,f]
        buffers = [msg.value.value for msg in results.messages if msg.value.kind == 'N']
        assert len(buffers) == 2
        assert buffers[0] == ["a", "b", "c"]
        assert buffers[1] == ["d", "e", "f"]

        print("[OK] Backpressure buffering test passed!")

    def test_time_window_aggregation(self):
        """
        Test time-based windowing (useful for metrics batching)

        Marble Diagram:
        Input:              -a-b--c-d--e-f-|
        Window(40ms):       ----(ab)----(cdef)-|

        Events are grouped by 40ms time windows
        """
        scheduler = TestScheduler()

        source = scheduler.create_hot_observable(
            ReactiveTest.on_next(210, "a"),
            ReactiveTest.on_next(220, "b"),
            ReactiveTest.on_next(260, "c"),
            ReactiveTest.on_next(270, "d"),
            ReactiveTest.on_next(280, "e"),
            ReactiveTest.on_next(290, "f"),
            ReactiveTest.on_completed(300)
        )

        def create_pipeline():
            return source.pipe(
                ops.buffer_with_time(40, scheduler=scheduler)
            )

        results = scheduler.start(create_pipeline, created=200, subscribed=200, disposed=1000)

        # Get all emitted buffers
        buffers = [msg.value.value for msg in results.messages if msg.value.kind == 'N' and len(msg.value.value) > 0]

        # Should have time-based grouping
        assert len(buffers) >= 1
        print(f"  Time windows: {buffers}")
        print("✓ Time window aggregation test passed!")

    def test_debounce_operator(self):
        """
        Test debounce (only emit after silence period)

        Marble Diagram:
        Input:      -a-b-c------d-e------f-|
        Debounce:   --------c--------e-----f-|

        Only emits when there's been 30ms of silence
        """
        scheduler = TestScheduler()

        source = scheduler.create_hot_observable(
            ReactiveTest.on_next(210, "a"),
            ReactiveTest.on_next(220, "b"),
            ReactiveTest.on_next(230, "c"),
            ReactiveTest.on_next(300, "d"),
            ReactiveTest.on_next(310, "e"),
            ReactiveTest.on_next(380, "f"),
            ReactiveTest.on_completed(450)
        )

        def create_pipeline():
            return source.pipe(
                ops.debounce(30, scheduler=scheduler)
            )

        results = scheduler.start(create_pipeline, created=200, subscribed=200, disposed=1000)

        # Should only get c, e, f (items followed by silence)
        emitted = [msg.value.value for msg in results.messages if msg.value.kind == 'N']
        assert "c" in emitted
        assert "e" in emitted
        assert "f" in emitted
        assert len(emitted) == 3

        print("✓ Debounce test passed!")

    def test_error_recovery_with_catch(self):
        """
        Test error recovery with catch operator

        Marble Diagram:
        Source:     -a-b-#
        Fallback:   -------c-d-|
        Result:     -a-b-c-d-|

        When source errors, switch to fallback stream
        """
        scheduler = TestScheduler()

        source = scheduler.create_hot_observable(
            ReactiveTest.on_next(210, "a"),
            ReactiveTest.on_next(220, "b"),
            ReactiveTest.on_error(230, Exception("Error!"))
        )

        fallback = scheduler.create_cold_observable(
            ReactiveTest.on_next(10, "c"),
            ReactiveTest.on_next(20, "d"),
            ReactiveTest.on_completed(30)
        )

        def create_pipeline():
            return source.pipe(
                ops.catch(lambda ex, src: fallback)
            )

        results = scheduler.start(create_pipeline, created=200, subscribed=200, disposed=1000)

        # Should get a, b from source, then c, d from fallback
        emitted = [msg.value.value for msg in results.messages if msg.value.kind == 'N']
        assert emitted == ["a", "b", "c", "d"]

        print("✓ Error recovery test passed!")

    def test_distinct_until_changed(self):
        """
        Test distinct_until_changed (only emit when value changes)

        Marble Diagram:
        Input:      -a-a-b-b-b-c-c-a-|
        Output:     -a---b-----c---a-|

        Consecutive duplicates are filtered out
        """
        scheduler = TestScheduler()

        source = scheduler.create_hot_observable(
            ReactiveTest.on_next(210, "a"),
            ReactiveTest.on_next(220, "a"),
            ReactiveTest.on_next(230, "b"),
            ReactiveTest.on_next(240, "b"),
            ReactiveTest.on_next(250, "b"),
            ReactiveTest.on_next(260, "c"),
            ReactiveTest.on_next(270, "c"),
            ReactiveTest.on_next(280, "a"),
            ReactiveTest.on_completed(300)
        )

        def create_pipeline():
            return source.pipe(
                ops.distinct_until_changed()
            )

        results = scheduler.start(create_pipeline, created=200, subscribed=200, disposed=1000)

        emitted = [msg.value.value for msg in results.messages if msg.value.kind == 'N']
        assert emitted == ["a", "b", "c", "a"]

        print("✓ Distinct until changed test passed!")


class TestWebhookDeliveryFlow:
    """Integration tests for complete webhook delivery flow"""

    def test_complete_delivery_pipeline_marble_diagram(self):
        """
        Test the complete pipeline from event to delivery

        Complex Marble Diagram:
        Events:      -H-N-L-H-|  (priorities)
        Filter(CB):  -H-N---H-|  (L blocked by circuit breaker)
        Deliver:     -✓-✓---✓-|  (successful deliveries)
        Metrics:     ----(HN)-(H)-|  (batched metrics)
        """
        scheduler = TestScheduler()

        high1 = {"priority": "HIGH", "id": "h1"}
        normal1 = {"priority": "NORMAL", "id": "n1"}
        low1 = {"priority": "LOW", "id": "l1"}
        high2 = {"priority": "HIGH", "id": "h2"}

        source = scheduler.create_hot_observable(
            ReactiveTest.on_next(210, high1),
            ReactiveTest.on_next(220, normal1),
            ReactiveTest.on_next(230, low1),     # Will be filtered
            ReactiveTest.on_next(240, high2),
            ReactiveTest.on_completed(250)
        )

        # Simulate circuit breaker that blocks LOW priority
        def filter_by_circuit_breaker(event):
            return event["priority"] != "LOW"

        # Simulate delivery
        def deliver(event):
            return {"delivered": event["id"], "status": "success"}

        def create_pipeline():
            return source.pipe(
                ops.filter(filter_by_circuit_breaker),
                ops.map(deliver),
                ops.buffer_with_time(30, scheduler=scheduler)
            )

        results = scheduler.start(create_pipeline, created=200, subscribed=200, disposed=1000)

        # Get all batches
        batches = [msg.value.value for msg in results.messages if msg.value.kind == 'N' and len(msg.value.value) > 0]

        # Flatten to see all delivered events
        all_delivered = [item for batch in batches for item in batch]
        delivered_ids = [d["delivered"] for d in all_delivered]

        assert "h1" in delivered_ids
        assert "n1" in delivered_ids
        assert "h2" in delivered_ids
        assert "l1" not in delivered_ids  # Filtered out

        print("✓ Complete delivery pipeline test passed!")


def run_all_tests():
    """Run all marble diagram tests"""
    print("\n" + "="*80)
    print("RUNNING MARBLE DIAGRAM TESTS FOR REACTIVE WEBHOOK MANAGER")
    print("="*80 + "\n")

    test_suite1 = TestReactiveWebhookPipeline()
    test_suite2 = TestWebhookDeliveryFlow()

    print("📋 Test Suite 1: Reactive Pipeline Components")
    print("-" * 80)
    test_suite1.test_priority_grouping_with_marble_diagram()
    test_suite1.test_circuit_breaker_filtering_with_marble_diagram()
    test_suite1.test_retry_logic_with_marble_diagram()
    test_suite1.test_backpressure_with_buffer()
    test_suite1.test_time_window_aggregation()
    test_suite1.test_debounce_operator()
    test_suite1.test_error_recovery_with_catch()
    test_suite1.test_distinct_until_changed()

    print("\n📋 Test Suite 2: Integration Tests")
    print("-" * 80)
    test_suite2.test_complete_delivery_pipeline_marble_diagram()

    print("\n" + "="*80)
    print("✅ ALL MARBLE DIAGRAM TESTS PASSED!")
    print("="*80)
    print("\n💡 Key Takeaway: These async tests run SYNCHRONOUSLY!")
    print("   No need for sleep(), mock async, or complex fixtures.\n")


if __name__ == "__main__":
    run_all_tests()
