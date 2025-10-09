"""
Visual Flowchart of the Reactive Webhook Pipeline

This creates ASCII art flowcharts showing how data flows through
the reactive pipeline in webhook_manager_reactive.py
"""


def print_main_delivery_pipeline():
    """
    Flowchart of the main webhook delivery pipeline
    Based on webhook_manager_reactive.py lines 204-247
    """
    print("\n" + "=" * 100)
    print("MAIN WEBHOOK DELIVERY PIPELINE FLOWCHART")
    print("=" * 100 + "\n")

    flowchart = r"""
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    WEBHOOK EVENT STREAM                                         │
│                                    (Hot Observable - Subject)                                   │
└──────────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                           │
                                           │  User calls: manager.trigger_event(...)
                                           │
                                           ▼
                        ┌──────────────────────────────────────────┐
                        │   ops.do_action(log incoming events)    │
                        │                                          │
                        │   ✓ Logs: "Event received: git.push"    │
                        └──────────────────┬───────────────────────┘
                                           │
                                           ▼
                        ┌──────────────────────────────────────────┐
                        │    ops.group_by(priority.value)          │
                        │                                          │
                        │   Splits into 4 sub-streams:             │
                        │   • URGENT (priority=4)                  │
                        │   • HIGH (priority=3)                    │
                        │   • NORMAL (priority=2)                  │
                        │   • LOW (priority=1)                     │
                        └──────────────────┬───────────────────────┘
                                           │
                                           ▼
                        ┌──────────────────────────────────────────┐
                        │         ops.flat_map (per priority)      │
                        │                                          │
                        │   For each priority stream, apply:       │
                        └──────────────────┬───────────────────────┘
                                           │
                   ┌───────────────────────┴────────────────────────┐
                   │                                                 │
                   ▼                                                 ▼
    ┌──────────────────────────────┐              ┌──────────────────────────────┐
    │  ops.flat_map(               │              │  ops.filter(                 │
    │    create_delivery_pairs)    │              │    check_circuit_breaker)    │
    │                              │              │                              │
    │  Transforms:                 │              │  Filters out:                │
    │  1 payload → N (payload,     │─────────────▶│  • Endpoints where circuit   │
    │  endpoint) pairs             │              │    breaker is OPEN           │
    │                              │              │  • Blocked URLs              │
    │  Example:                    │              │                              │
    │  git.push → [                │              │  Passes through:             │
    │    (payload, endpoint1),     │              │  • Circuit breaker CLOSED    │
    │    (payload, endpoint2),     │              │  • Circuit breaker HALF_OPEN │
    │    (payload, endpoint3)      │              │                              │
    │  ]                           │              │                              │
    └──────────────────────────────┘              └──────────┬───────────────────┘
                                                              │
                                                              ▼
                                           ┌──────────────────────────────────────┐
                                           │  ops.flat_map(                       │
                                           │    deliver_webhook_reactive,         │
                                           │    max_concurrent=10                 │
                                           │  )                                   │
                                           │                                      │
                                           │  Parallel HTTP delivery:             │
                                           │  • Max 10 concurrent per priority    │
                                           │  • Async aiohttp requests            │
                                           │  • Emits WebhookDeliveryResult       │
                                           └──────────────┬───────────────────────┘
                                                          │
                                                          ▼
                                           ┌──────────────────────────────────────┐
                                           │       ops.retry(5)                   │
                                           │                                      │
                                           │  If delivery fails:                  │
                                           │  • Retryable error (500, 502, etc)?  │
                                           │    ✓ Retry up to 5 times            │
                                           │  • Non-retryable (401, 404)?         │
                                           │    ✗ Fail immediately                │
                                           └──────────────┬───────────────────────┘
                                                          │
                                                          ▼
                                           ┌──────────────────────────────────────┐
                                           │  ops.catch(handle_delivery_error)    │
                                           │                                      │
                                           │  Error handling:                     │
                                           │  • Max retries exceeded?             │
                                           │    → Dead letter queue               │
                                           │  • Return empty observable           │
                                           │    → Continue processing             │
                                           └──────────────┬───────────────────────┘
                                                          │
                                                          ▼
                                           ┌──────────────────────────────────────┐
                                           │         ops.share()                  │
                                           │                                      │
                                           │  Makes observable HOT:               │
                                           │  • Single execution for all subs     │
                                           │  • Multicast to multiple handlers    │
                                           └──────────────┬───────────────────────┘
                                                          │
                              ┌───────────────────────────┴──────────────────────────┐
                              │                                                      │
                              ▼                                                      ▼
                   ┌──────────────────────┐                            ┌─────────────────────────┐
                   │  on_next handler:    │                            │  Metrics Stream:        │
                   │  _on_delivery_success│                            │  metrics_stream.on_next │
                   │                      │                            │                         │
                   │  • Log success       │                            │  • delivery_success     │
                   │  • Update metrics    │                            │  • duration             │
                   │  • Circuit breaker   │                            │  • endpoint URL         │
                   │    state update      │                            │                         │
                   └──────────────────────┘                            └─────────────────────────┘
    """

    print(flowchart)

    print("\n📊 PIPELINE STATISTICS:")
    print("""
    Input:  1 webhook event
    After group_by: 1 event in priority group
    After flat_map(pairs): N events (one per endpoint)
    After filter: M events (circuit breaker filtering)
    After delivery: M HTTP requests (max_concurrent=10)
    After retry: M results (with up to 5 retries each)
    Output: M WebhookDeliveryResult objects

    Example:
    1 git.push event → 3 configured endpoints
    → 3 circuit breaker checks
    → 2 pass (1 blocked)
    → 2 HTTP requests (parallel)
    → 2 successful deliveries
    → Metrics updated
    """)


def print_metrics_pipeline():
    """
    Flowchart of the metrics collection pipeline
    Based on webhook_manager_reactive.py lines 251-265
    """
    print("\n" + "=" * 100)
    print("METRICS COLLECTION PIPELINE FLOWCHART")
    print("=" * 100 + "\n")

    flowchart = r"""
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   METRICS EVENT STREAM                                          │
│                                   (Hot Observable - Subject)                                    │
│                                                                                                 │
│   Emitted from delivery pipeline:                                                              │
│   • metrics_stream.on_next({'type': 'delivery_success', ...})                                  │
│   • metrics_stream.on_next({'type': 'delivery_failure', ...})                                  │
└──────────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                           │
                                           │  Continuous stream of metrics
                                           │
                                           ▼
                        ┌──────────────────────────────────────────┐
                        │   ops.buffer_with_time(1.0)              │
                        │                                          │
                        │   Batching strategy:                     │
                        │   • Collect metrics for 1 second         │
                        │   • Then emit batch as array             │
                        │                                          │
                        │   Example timeline:                      │
                        │   0.0s: metric1 arrives                  │
                        │   0.3s: metric2 arrives                  │
                        │   0.7s: metric3 arrives                  │
                        │   1.0s: EMIT [metric1, metric2, metric3] │
                        │   1.2s: metric4 arrives                  │
                        │   2.0s: EMIT [metric4]                   │
                        └──────────────────┬───────────────────────┘
                                           │
                                           ▼
                        ┌──────────────────────────────────────────┐
                        │   ops.filter(len(buffer) > 0)            │
                        │                                          │
                        │   Skip empty batches:                    │
                        │   • No metrics in window? Don't emit     │
                        │   • Reduces unnecessary processing       │
                        └──────────────────┬───────────────────────┘
                                           │
                                           ▼
                        ┌──────────────────────────────────────────┐
                        │   ops.do_action(_update_metrics)         │
                        │                                          │
                        │   Update Prometheus counters:            │
                        │   • webhook_deliveries.inc()             │
                        │   • webhook_duration.observe()           │
                        │   • webhook_failures.inc()               │
                        │                                          │
                        │   Batch processing advantage:            │
                        │   • Process 100 metrics in 1 call       │
                        │   • Instead of 100 individual calls      │
                        └──────────────────────────────────────────┘
    """

    print(flowchart)

    print("\n💡 WHY BATCH METRICS?")
    print("""
    Without batching:
    • 1000 webhook deliveries/sec = 1000 metric updates/sec
    • High overhead from function calls
    • Contention on Prometheus counters

    With buffer_with_time(1.0):
    • 1000 webhook deliveries/sec = 1 batch update/sec
    • Process all 1000 metrics in single iteration
    • 1000x reduction in update frequency
    • Lower CPU usage, better throughput
    """)


def print_circuit_breaker_pipeline():
    """
    Flowchart of circuit breaker state monitoring
    Based on webhook_manager_reactive.py lines 267-282
    """
    print("\n" + "=" * 100)
    print("CIRCUIT BREAKER STATE MONITORING PIPELINE")
    print("=" * 100 + "\n")

    flowchart = r"""
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                            CIRCUIT BREAKER STATE STREAM                                         │
│                            (BehaviorSubject - Always has current value)                         │
│                                                                                                 │
│   Emitted on every state change:                                                               │
│   • circuit_breaker_stream.on_next({'url': 'http://api.example.com', 'state': OPEN})          │
└──────────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                           │
                                           │  State change events
                                           │
                                           ▼
                        ┌──────────────────────────────────────────┐
                        │   ops.filter(state is not None)          │
                        │                                          │
                        │   Skip initialization:                   │
                        │   • BehaviorSubject starts with None    │
                        │   • Filter out until real state arrives │
                        └──────────────────┬───────────────────────┘
                                           │
                                           ▼
                        ┌──────────────────────────────────────────┐
                        │   ops.distinct_until_changed()           │
                        │                                          │
                        │   Suppress duplicates:                   │
                        │   • OPEN → OPEN → OPEN                   │
                        │     Only emit first OPEN                 │
                        │                                          │
                        │   • OPEN → CLOSED                        │
                        │     Emit CLOSED (state changed)          │
                        │                                          │
                        │   Why? Prevent metric spam:              │
                        │   • 100 failed requests while OPEN       │
                        │     Should only update metric once       │
                        └──────────────────┬───────────────────────┘
                                           │
                                           ▼
                        ┌──────────────────────────────────────────┐
                        │   ops.do_action(update Prometheus)       │
                        │                                          │
                        │   circuit_breaker_state.labels(          │
                        │       url=state['url']                   │
                        │   ).set(state['state'].value)            │
                        │                                          │
                        │   Grafana dashboard shows:               │
                        │   • Which endpoints have open circuits   │
                        │   • State transition history             │
                        │   • Recovery patterns                    │
                        └──────────────────────────────────────────┘
    """

    print(flowchart)

    print("\n🔄 STATE TRANSITION DIAGRAM:")
    print("""
                ┌─────────────┐
                │   CLOSED    │◄─────────┐
                │  (Normal)   │          │
                └──────┬──────┘          │
                       │                 │
        5 failures     │                 │ half_open_max_attempts
        within window  │                 │ successful requests
                       │                 │
                       ▼                 │
                ┌─────────────┐          │
                │    OPEN     │          │
                │  (Blocking) │          │
                └──────┬──────┘          │
                       │                 │
        timeout_seconds│                 │
        elapsed        │                 │
                       │                 │
                       ▼                 │
                ┌─────────────┐          │
                │  HALF_OPEN  │──────────┘
                │  (Testing)  │
                └─────────────┘
                       │
                       │ More failures
                       ▼
                (Back to OPEN)
    """)


def print_data_flow_summary():
    """
    High-level data flow through entire system
    """
    print("\n" + "=" * 100)
    print("END-TO-END DATA FLOW: Webhook Event → Delivery → Metrics")
    print("=" * 100 + "\n")

    flowchart = r"""
┌─────────────┐
│   SOURCE    │
│  (Trigger)  │
└──────┬──────┘
       │
       │ manager.trigger_event("git.push", {...})
       │
       ▼
┌────────────────────────────────────────────────────────┐
│              WEBHOOK STREAM (Subject)                  │
│                                                        │
│  WebhookPayload {                                      │
│    event_name: "git.push"                              │
│    event_data: {...}                                   │
│    priority: HIGH                                      │
│  }                                                     │
└───────────────────────┬────────────────────────────────┘
                        │
        ┌───────────────┼────────────────┐
        │               │                │
        ▼               ▼                ▼
  ┌─────────┐    ┌─────────┐     ┌──────────┐
  │ URGENT  │    │  HIGH   │     │  NORMAL  │
  │ queue   │    │  queue  │     │  queue   │
  └────┬────┘    └────┬────┘     └────┬─────┘
       │              │                │
       └──────────────┴────────────────┘
                      │
                      │ For each endpoint
                      │
                      ▼
           ┌──────────────────────┐
           │  Circuit Breaker     │
           │  Check               │
           └──────┬───────────────┘
                  │
         ┌────────┴────────┐
         │                 │
    ✓ CLOSED          ✗ OPEN
    HALF_OPEN         (blocked)
         │                 │
         ▼                 ▼
    ┌─────────┐      ┌─────────┐
    │ DELIVER │      │  SKIP   │
    │ (HTTP)  │      │         │
    └────┬────┘      └─────────┘
         │
         │
    ┌────┴─────┐
    │          │
    ▼          ▼
┌────────┐  ┌────────┐
│SUCCESS │  │ ERROR  │
└───┬────┘  └────┬───┘
    │            │
    │            │ retry(5)
    │            │
    │       ┌────┴─────┐
    │       │          │
    │       ▼          ▼
    │   ┌────────┐ ┌──────────┐
    │   │SUCCESS │ │MAX RETRY │
    │   └───┬────┘ └────┬─────┘
    │       │           │
    │       │           ▼
    │       │    ┌─────────────┐
    │       │    │ DEAD LETTER │
    │       │    │   QUEUE     │
    │       │    └─────────────┘
    │       │
    └───────┴──────────┐
                       │
                       ▼
            ┌──────────────────┐
            │  EMIT METRICS    │
            │                  │
            │  • duration      │
            │  • status        │
            │  • endpoint      │
            └────────┬─────────┘
                     │
                     │
            ┌────────┴─────────┐
            │                  │
            ▼                  ▼
    ┌──────────────┐   ┌──────────────┐
    │   METRICS    │   │  CIRCUIT     │
    │   STREAM     │   │  BREAKER     │
    │              │   │  STREAM      │
    └──────┬───────┘   └──────┬───────┘
           │                  │
           ▼                  ▼
    ┌──────────────┐   ┌──────────────┐
    │  PROMETHEUS  │   │  GRAFANA     │
    │  COUNTERS    │   │  DASHBOARD   │
    └──────────────┘   └──────────────┘
    """

    print(flowchart)


def print_operator_reference():
    """
    Quick reference of all operators used
    """
    print("\n" + "=" * 100)
    print("OPERATOR QUICK REFERENCE")
    print("=" * 100 + "\n")

    print("""
╔═══════════════════════════════════════════════════════════════════════════════════════════════╗
║  OPERATOR              │  PURPOSE                                  │  LOCATION IN CODE       ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════╣
║  do_action             │  Side effects (logging, metrics)          │  Line 207-210           ║
║  group_by              │  Split stream by key (priority)           │  Line 215               ║
║  flat_map              │  Transform + flatten (async ops)          │  Line 218, 220, 226     ║
║  filter                │  Conditional filtering (circuit breaker)  │  Line 223, 257          ║
║  retry                 │  Automatic retry on error                 │  Line 233               ║
║  catch                 │  Error boundary (dead letter queue)       │  Line 236               ║
║  share                 │  Make observable hot (multicast)          │  Line 240               ║
║  buffer_with_time      │  Batch events by time window              │  Line 256               ║
║  distinct_until_changed│  Suppress consecutive duplicates          │  Line 272               ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════╝
    """)

    print("\n💡 OPERATOR CHAINING:")
    print("""
    observable.pipe(
        ops.operator1(...),  # Applied first
        ops.operator2(...),  # Then this
        ops.operator3(...)   # Finally this
    )

    Data flows top-to-bottom through the pipeline.
    Each operator transforms the stream and passes to next.
    """)


def print_comparison_table():
    """
    Imperative vs Reactive comparison
    """
    print("\n" + "=" * 100)
    print("IMPERATIVE VS REACTIVE: SIDE-BY-SIDE COMPARISON")
    print("=" * 100 + "\n")

    print("""
╔═══════════════════════════════════════════════════════════════════════════════════════════════╗
║  FEATURE                    │  IMPERATIVE (webhook_manager.py)  │  REACTIVE (reactive.py)   ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════╣
║  Queue Management           │  Manual asyncio.Queue             │  Automatic (streams)      ║
║  Worker Pool                │  Manual task creation             │  Scheduler handles it     ║
║  Priority Handling          │  Manual priority queue            │  ops.group_by(priority)   ║
║  Circuit Breaker Filtering  │  Manual if/else checks            │  ops.filter(check_cb)     ║
║  Parallel Delivery          │  asyncio.gather()                 │  ops.flat_map(max=10)     ║
║  Retry Logic                │  @backoff decorator               │  ops.retry(5)             ║
║  Error Handling             │  try/except blocks                │  ops.catch(handler)       ║
║  Backpressure               │  Manual queue size tracking       │  Automatic                ║
║  Metrics Batching           │  Manual accumulation              │  ops.buffer_with_time(1)  ║
║  Testing                    │  Mock asyncio, complex fixtures   │  Marble diagrams          ║
║  Code Lines (core logic)    │  ~150 lines                       │  ~45 lines (pipeline)     ║
║  Composability              │  Hard to extend                   │  Easy (add operators)     ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════╝
    """)


# ============================================================================
# MAIN EXECUTION
# ============================================================================


def generate_all_flowcharts():
    """Generate all flowcharts and diagrams"""
    print("\n" + "=" * 100)
    print("           COMPREHENSIVE REACTIVE WEBHOOK PIPELINE VISUALIZATION")
    print("=" * 100)

    print_main_delivery_pipeline()
    print_metrics_pipeline()
    print_circuit_breaker_pipeline()
    print_data_flow_summary()
    print_operator_reference()
    print_comparison_table()

    print("\n" + "=" * 100)
    print("✅ ALL FLOWCHARTS GENERATED")
    print("=" * 100)

    print("\n📖 HOW TO READ THESE DIAGRAMS:")
    print("""
    • Boxes represent operators or processing stages
    • Arrows show data flow direction
    • Each stage transforms the stream
    • Multiple arrows show stream splitting (fan-out)
    • Converging arrows show stream merging (fan-in)

    The beauty of reactive programming:
    ALL of this complexity is expressed in ~40 lines of declarative code!
    """)

    print("\n🔍 NEXT STEPS:")
    print("""
    1. Run the code:
       python webhook_manager_reactive.py

    2. Run tests:
       python test_webhook_manager_reactive.py

    3. Explore operators:
       python webhook_advanced_operators.py

    4. Understand hot/cold:
       python webhook_hot_cold_observables.py

    5. View this flowchart:
       python webhook_reactive_flowchart.py
    """)


if __name__ == "__main__":
    generate_all_flowcharts()
