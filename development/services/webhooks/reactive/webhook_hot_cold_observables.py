"""
Hot vs Cold Observables - The Critical Distinction in Reactive Programming

This is one of the most important concepts to understand in RxPy!

COLD Observable:
- Creates new data source for EACH subscriber
- Like a movie on-demand: each viewer gets their own stream from the beginning
- Examples: HTTP requests, file reads, database queries

HOT Observable:
- Shares SAME data source among ALL subscribers
- Like a live TV broadcast: all viewers see the same stream in real-time
- Examples: Mouse events, WebSocket messages, webhook events

Your webhook_manager_reactive.py uses HOT observables because:
- Multiple subscribers should see the SAME webhook events
- Events happen in real-time (you can't replay past events)
- Using share() operator makes a cold observable hot
"""

import time
from dataclasses import dataclass

from reactivex import Subject, create, operators as ops
from reactivex.subject import ReplaySubject, BehaviorSubject

import logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


@dataclass
class WebhookEvent:
    """Webhook event for demonstration"""
    event_id: str
    event_type: str
    timestamp: float


class HotVsColdDemonstration:
    """
    Demonstrates the difference between hot and cold observables
    using your webhook scenario
    """

    # ========================================================================
    # PART 1: COLD OBSERVABLE - Each Subscriber Gets Own Stream
    # ========================================================================

    def demo_cold_observable(self):
        """
        COLD Observable: Each subscriber gets independent execution

        Think of it like: "Execute this webhook fetch for each subscriber"
        """
        print("\n" + "="*80)
        print("COLD OBSERVABLE: Independent Execution Per Subscriber")
        print("="*80)

        print("\n📖 Concept: Each subscriber triggers NEW execution")
        print("   Like calling an API - each subscriber makes their own request\n")

        execution_count = {'count': 0}

        def create_webhook_observable():
            """
            This creates a COLD observable
            Each subscriber will trigger this function independently
            """
            def subscribe(observer, scheduler=None):
                execution_count['count'] += 1
                current_execution = execution_count['count']

                logger.info(f"🔵 EXECUTION #{current_execution} STARTED")

                # Simulate fetching webhooks from API
                events = [
                    WebhookEvent(f"evt_{current_execution}_1", "git.push", time.time()),
                    WebhookEvent(f"evt_{current_execution}_2", "git.push", time.time()),
                    WebhookEvent(f"evt_{current_execution}_3", "git.push", time.time()),
                ]

                for event in events:
                    logger.info(f"   → Emitting {event.event_id} (execution #{current_execution})")
                    observer.on_next(event)
                    time.sleep(0.3)

                observer.on_completed()
                logger.info(f"🔵 EXECUTION #{current_execution} COMPLETED\n")

                return lambda: None

            return create(subscribe)

        # Create the cold observable
        cold_webhook_stream = create_webhook_observable()

        # SUBSCRIBER 1
        print("👤 SUBSCRIBER 1 subscribes:")
        subscriber1_events = []
        cold_webhook_stream.subscribe(
            on_next=lambda e: subscriber1_events.append(e)
        )

        time.sleep(1.5)

        # SUBSCRIBER 2
        print("👤 SUBSCRIBER 2 subscribes:")
        subscriber2_events = []
        cold_webhook_stream.subscribe(
            on_next=lambda e: subscriber2_events.append(e)
        )

        time.sleep(1.5)

        print("="*80)
        print("RESULTS:")
        print(f"  Execution count: {execution_count['count']} (2 independent executions)")
        print(f"  Subscriber 1 got: {len(subscriber1_events)} events")
        print(f"  Subscriber 2 got: {len(subscriber2_events)} events")
        print("\n  ✅ Each subscriber triggered its OWN execution")
        print(f"     Event IDs are different: {subscriber1_events[0].event_id} vs {subscriber2_events[0].event_id}")
        print("="*80)

        return execution_count['count']

    # ========================================================================
    # PART 2: HOT OBSERVABLE - All Subscribers Share Stream
    # ========================================================================

    def demo_hot_observable(self):
        """
        HOT Observable: All subscribers share the SAME stream

        Think of it like: "All subscribers listen to same live webhook feed"
        """
        print("\n" + "="*80)
        print("HOT OBSERVABLE: Shared Execution For All Subscribers")
        print("="*80)

        print("\n📖 Concept: All subscribers share ONE execution")
        print("   Like a live stream - everyone sees the same events in real-time\n")

        # Subject is inherently HOT
        hot_webhook_stream = Subject()

        subscriber1_events = []
        subscriber2_events = []
        subscriber3_events = []

        # SUBSCRIBER 1 joins early
        print("👤 SUBSCRIBER 1 subscribes (early bird)")
        hot_webhook_stream.subscribe(
            on_next=lambda e: subscriber1_events.append(e)
        )

        # Emit some events
        print("\n📡 Broadcasting events 1-3...")
        for i in range(1, 4):
            event = WebhookEvent(f"live_evt_{i}", "docker.push", time.time())
            logger.info(f"   Broadcasting: {event.event_id}")
            hot_webhook_stream.on_next(event)
            time.sleep(0.2)

        # SUBSCRIBER 2 joins late
        print("\n👤 SUBSCRIBER 2 subscribes (joins late)")
        hot_webhook_stream.subscribe(
            on_next=lambda e: subscriber2_events.append(e)
        )

        # Emit more events
        print("\n📡 Broadcasting events 4-6...")
        for i in range(4, 7):
            event = WebhookEvent(f"live_evt_{i}", "k8s.deploy", time.time())
            logger.info(f"   Broadcasting: {event.event_id}")
            hot_webhook_stream.on_next(event)
            time.sleep(0.2)

        # SUBSCRIBER 3 joins very late
        print("\n👤 SUBSCRIBER 3 subscribes (very late)")
        hot_webhook_stream.subscribe(
            on_next=lambda e: subscriber3_events.append(e)
        )

        # Final event
        print("\n📡 Broadcasting final event 7...")
        event = WebhookEvent("live_evt_7", "webhook.test", time.time())
        logger.info(f"   Broadcasting: {event.event_id}")
        hot_webhook_stream.on_next(event)

        print("\n" + "="*80)
        print("RESULTS:")
        print("  Total events broadcast: 7")
        print(f"  Subscriber 1 received: {len(subscriber1_events)} (joined early)")
        print(f"  Subscriber 2 received: {len(subscriber2_events)} (joined mid-way)")
        print(f"  Subscriber 3 received: {len(subscriber3_events)} (joined late)")
        print("\n  ✅ All subscribers saw SAME events (same event IDs)")
        print("     But late subscribers MISSED earlier events (no replay)")
        print("="*80)

        return len(subscriber1_events), len(subscriber2_events), len(subscriber3_events)

    # ========================================================================
    # PART 3: REPLAY SUBJECT - Hot Observable with History
    # ========================================================================

    def demo_replay_subject(self):
        """
        REPLAY SUBJECT: Hot observable that replays past events to new subscribers

        This solves the "late subscriber missing events" problem
        """
        print("\n" + "="*80)
        print("REPLAY SUBJECT: Hot Observable with History Buffer")
        print("="*80)

        print("\n📖 Concept: New subscribers get recent history + live events")
        print("   Perfect for: Dashboard connections, monitoring systems\n")

        # ReplaySubject(buffer_size=3) keeps last 3 events
        replay_stream = ReplaySubject(buffer_size=3)

        subscriber1_events = []

        # Emit some events BEFORE anyone subscribes
        print("📡 Broadcasting events 1-5 (no subscribers yet)...")
        for i in range(1, 6):
            event = WebhookEvent(f"replay_evt_{i}", "metric.update", time.time())
            logger.info(f"   Broadcasting: {event.event_id}")
            replay_stream.on_next(event)
            time.sleep(0.1)

        # NOW subscriber joins late
        print("\n👤 SUBSCRIBER 1 joins late")
        print("   ⏪ Receiving buffered history (last 3 events)...\n")
        replay_stream.subscribe(
            on_next=lambda e: (
                subscriber1_events.append(e),
                logger.info(f"   Received: {e.event_id}")
            )
        )

        time.sleep(0.5)

        # Emit more events
        print("\n📡 Broadcasting new events 6-7...")
        for i in range(6, 8):
            event = WebhookEvent(f"replay_evt_{i}", "metric.update", time.time())
            logger.info(f"   Broadcasting: {event.event_id}")
            replay_stream.on_next(event)
            time.sleep(0.1)

        print("\n" + "="*80)
        print("RESULTS:")
        print("  Events broadcast before subscription: 5")
        print("  ReplaySubject buffer size: 3")
        print(f"  Subscriber received: {len(subscriber1_events)} events")
        print("    - 3 from history buffer (events 3, 4, 5)")
        print("    - 2 from live stream (events 6, 7)")
        print("\n  ✅ Late subscribers get recent history automatically!")
        print("="*80)

        return len(subscriber1_events)

    # ========================================================================
    # PART 4: BEHAVIOR SUBJECT - Hot Observable with Current Value
    # ========================================================================

    def demo_behavior_subject(self):
        """
        BEHAVIOR SUBJECT: Always has a "current value"

        Perfect for: System state, configuration, feature flags
        """
        print("\n" + "="*80)
        print("BEHAVIOR SUBJECT: Hot Observable with Current State")
        print("="*80)

        print("\n📖 Concept: Always has current value, new subscribers get it immediately")
        print("   Perfect for: Circuit breaker state, health status, config\n")

        # Initialize with default state
        circuit_breaker_state = BehaviorSubject("CLOSED")

        subscriber1_states = []
        subscriber2_states = []

        # SUBSCRIBER 1 joins
        print("👤 SUBSCRIBER 1 subscribes")
        circuit_breaker_state.subscribe(
            on_next=lambda state: (
                subscriber1_states.append(state),
                logger.info(f"   Sub1 sees state: {state}")
            )
        )

        time.sleep(0.3)

        # Update state
        print("\n⚠️  Circuit breaker transitions: CLOSED → OPEN")
        circuit_breaker_state.on_next("OPEN")
        time.sleep(0.3)

        # SUBSCRIBER 2 joins late
        print("\n👤 SUBSCRIBER 2 subscribes (late)")
        print("   Immediately receives current state:")
        circuit_breaker_state.subscribe(
            on_next=lambda state: (
                subscriber2_states.append(state),
                logger.info(f"   Sub2 sees state: {state}")
            )
        )

        time.sleep(0.3)

        # Another update
        print("\n✅ Circuit breaker transitions: OPEN → HALF_OPEN")
        circuit_breaker_state.on_next("HALF_OPEN")
        time.sleep(0.3)

        print("\n✅ Circuit breaker transitions: HALF_OPEN → CLOSED")
        circuit_breaker_state.on_next("CLOSED")

        print("\n" + "="*80)
        print("RESULTS:")
        print(f"  Subscriber 1 saw: {subscriber1_states}")
        print(f"  Subscriber 2 saw: {subscriber2_states}")
        print("\n  ✅ Sub2 immediately got current state when subscribing!")
        print("     Then both received all subsequent updates")
        print("="*80)

        return subscriber1_states, subscriber2_states

    # ========================================================================
    # PART 5: Making Cold Observable Hot with share()
    # ========================================================================

    def demo_share_operator(self):
        """
        SHARE: Convert cold observable to hot

        This is how your webhook_manager_reactive.py works!
        """
        print("\n" + "="*80)
        print("SHARE OPERATOR: Converting Cold to Hot")
        print("="*80)

        print("\n📖 Concept: share() makes cold observable hot")
        print("   Used in webhook_manager_reactive.py to share webhook stream\n")

        execution_count = {'count': 0}

        # Create cold observable
        def create_cold_webhook_stream():
            def subscribe(observer, scheduler=None):
                execution_count['count'] += 1
                logger.info(f"🔵 EXECUTION #{execution_count['count']} - Fetching webhooks...")

                events = [
                    WebhookEvent("shared_1", "event", time.time()),
                    WebhookEvent("shared_2", "event", time.time()),
                ]

                for event in events:
                    observer.on_next(event)
                    time.sleep(0.2)

                observer.on_completed()
                return lambda: None

            return create(subscribe)

        # Without share() - COLD
        print("❌ WITHOUT share() - Cold Observable:")
        cold_stream = create_cold_webhook_stream()

        cold_sub1_events = []
        cold_sub2_events = []

        print("👤 Subscriber 1 subscribes")
        cold_stream.subscribe(on_next=lambda e: cold_sub1_events.append(e))

        print("👤 Subscriber 2 subscribes")
        cold_stream.subscribe(on_next=lambda e: cold_sub2_events.append(e))

        time.sleep(1)

        print(f"\n  Result: {execution_count['count']} executions (wasteful!)\n")

        # Reset counter
        execution_count['count'] = 0

        # With share() - HOT
        print("✅ WITH share() - Hot Observable:")
        hot_stream = create_cold_webhook_stream().pipe(ops.share())

        hot_sub1_events = []
        hot_sub2_events = []

        print("👤 Subscriber 1 subscribes")
        hot_stream.subscribe(on_next=lambda e: hot_sub1_events.append(e))

        print("👤 Subscriber 2 subscribes")
        hot_stream.subscribe(on_next=lambda e: hot_sub2_events.append(e))

        time.sleep(1)

        print(f"\n  Result: {execution_count['count']} execution (efficient!)")

        print("\n" + "="*80)
        print("RESULTS:")
        print("  Cold (no share): 2 executions")
        print("  Hot (with share): 1 execution")
        print("\n  ✅ share() prevents duplicate work!")
        print("     This is why webhook_manager_reactive.py uses .pipe(ops.share())")
        print("="*80)

        return execution_count['count']


# ============================================================================
# PRACTICAL GUIDE
# ============================================================================

def print_decision_guide():
    """When to use hot vs cold observables"""
    print("\n" + "="*80)
    print("DECISION GUIDE: Hot vs Cold Observables")
    print("="*80)

    print("""
╔════════════════════════════════════════════════════════════════════════╗
║                        WHEN TO USE EACH                                ║
╠════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  🔵 COLD OBSERVABLE (create, from_iterable, etc)                      ║
║  ────────────────────────────────────────────────────────────────     ║
║   ✓ HTTP API requests (each subscriber needs fresh data)             ║
║   ✓ Database queries (read separate rows)                            ║
║   ✓ File reads (independent streams)                                 ║
║   ✓ Data transformations (map, filter on arrays)                     ║
║                                                                        ║
║   Example:                                                             ║
║     Observable.from_iterable([1, 2, 3])  # Each subscriber gets 1,2,3 ║
║                                                                        ║
║                                                                        ║
║  🔴 HOT OBSERVABLE (Subject, share())                                 ║
║  ────────────────────────────────────────────────────────────────     ║
║   ✓ Real-time events (webhooks, WebSocket, mouse clicks)             ║
║   ✓ Shared resources (single database connection)                    ║
║   ✓ Broadcast scenarios (all subscribers see same data)              ║
║   ✓ Event buses (pub/sub pattern)                                    ║
║                                                                        ║
║   Example:                                                             ║
║     webhook_stream = Subject()  # All subscribers share events        ║
║                                                                        ║
║                                                                        ║
║  🟡 REPLAY SUBJECT                                                    ║
║  ────────────────────────────────────────────────────────────────     ║
║   ✓ Late subscribers need recent history                             ║
║   ✓ Dashboard connections (show recent activity)                     ║
║   ✓ Audit logs (buffer last N events)                                ║
║                                                                        ║
║                                                                        ║
║  🟢 BEHAVIOR SUBJECT                                                  ║
║  ────────────────────────────────────────────────────────────────     ║
║   ✓ Current state (circuit breaker state)                            ║
║   ✓ Configuration values                                             ║
║   ✓ Feature flags                                                    ║
║   ✓ Health status                                                    ║
║                                                                        ║
╚════════════════════════════════════════════════════════════════════════╝
    """)

    print("\n📝 CODE EXAMPLE FROM YOUR WEBHOOK MANAGER:")
    print("""
    # HOT - All subscribers share the webhook stream
    self.webhook_stream = Subject()

    # Broadcast to all subscribers
    self.webhook_stream.on_next(payload)

    # Multiple handlers all see the SAME events
    self.webhook_stream.subscribe(delivery_handler)
    self.webhook_stream.subscribe(metrics_handler)
    self.webhook_stream.subscribe(logging_handler)
    """)

    print("\n🎯 KEY INSIGHT:")
    print("""
    Your webhook system MUST be HOT because:
    1. Webhooks are real-time events (not on-demand)
    2. Multiple subsystems need to react to SAME event
    3. You can't "replay" a webhook that already happened
    4. Events are broadcast, not pulled
    """)


# ============================================================================
# RUN ALL DEMONSTRATIONS
# ============================================================================

def run_all_demos():
    """Run all hot/cold demonstrations"""
    print("\n" + "="*80)
    print("HOT VS COLD OBSERVABLES - COMPREHENSIVE DEMONSTRATION")
    print("="*80)

    demo = HotVsColdDemonstration()

    # Run demos
    demo.demo_cold_observable()
    time.sleep(0.5)

    demo.demo_hot_observable()
    time.sleep(0.5)

    demo.demo_replay_subject()
    time.sleep(0.5)

    demo.demo_behavior_subject()
    time.sleep(0.5)

    demo.demo_share_operator()

    # Print decision guide
    print_decision_guide()

    print("\n" + "="*80)
    print("✅ ALL HOT/COLD DEMONSTRATIONS COMPLETE")
    print("="*80 + "\n")


if __name__ == "__main__":
    run_all_demos()
