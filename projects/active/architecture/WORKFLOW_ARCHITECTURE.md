# Workflow Architecture Documentation

## Overview

This codebase implements a comprehensive multi-layered workflow architecture designed for enterprise-scale distributed systems. The architecture supports various workflow patterns from simple task orchestration to complex distributed transactions with automatic compensation.

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│         (Business Logic, API Endpoints, UI)                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                 Workflow Orchestration Layer                 │
│  ┌──────────────┐ ┌─────────────┐ ┌───────────────────┐   │
│  │   Workflow   │ │    Agent    │ │   Event Sourcing  │   │
│  │    Engine    │ │ Orchestrator│ │    with Sagas     │   │
│  └──────────────┘ └─────────────┘ └───────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                  Communication & Discovery                   │
│  ┌──────────────┐ ┌─────────────┐ ┌───────────────────┐   │
│  │   Message    │ │   Service   │ │      Redis        │   │
│  │    Queue     │ │  Discovery  │ │     Manager       │   │
│  └──────────────┘ └─────────────┘ └───────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                    Infrastructure Layer                      │
│        (Kubernetes, PostgreSQL, Redis, MQTT/AMQP)           │
└──────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Workflow Engine (`libraries/workflow_engine.py`)

The central workflow orchestration system for task-based workflows.

**Key Features:**
- **Task Dependencies**: Define complex task graphs with dependencies
- **Parallel Execution**: Configurable concurrent task execution
- **Priority Scheduling**: Tasks executed based on priority levels
- **Retry Logic**: Automatic retry with exponential backoff
- **Timeout Management**: Per-task timeout configuration
- **Progress Tracking**: Real-time workflow progress monitoring

**Use Cases:**
- Data processing pipelines
- Multi-step business processes
- Batch job orchestration
- ETL workflows

**Architecture:**
```python
Workflow
  ├── Tasks[]
  │     ├── id: unique identifier
  │     ├── dependencies: [task_ids]
  │     ├── priority: LOW|NORMAL|HIGH|CRITICAL
  │     ├── handler: function/service
  │     └── status: PENDING|RUNNING|COMPLETED|FAILED
  └── Status: CREATED|RUNNING|COMPLETED|FAILED
```

### 2. Agent Orchestrator (`orchestration/agent_orchestrator.py`)

Advanced platform for managing distributed agent systems.

**Key Features:**
- **Dynamic Spawning**: Create agents on-demand
- **Kubernetes Integration**: Native K8s deployment
- **Auto-scaling**: Performance and workload-based scaling
- **Multi-tenancy**: Isolated agent execution environments
- **Health Monitoring**: Continuous health checks with self-healing
- **Resource Management**: CPU/memory limits and requests

**Scaling Strategies:**
- **FIXED**: Maintain constant number of agents
- **AUTO**: Scale based on metrics
- **PERFORMANCE_BASED**: Scale on CPU/memory utilization
- **WORKLOAD_BASED**: Scale on queue length and response time

**Architecture:**
```python
AgentOrchestrator
  ├── AgentSpecs: Template definitions
  ├── AgentInstances: Running agents
  ├── ScalingPolicies: Auto-scaling rules
  └── Workflows: Distributed workflow execution
```

### 3. Event Sourcing & Sagas (`event_sourcing/`)

Implementation of event sourcing pattern with saga support for distributed transactions.

**Key Features:**
- **Event Store**: PostgreSQL-backed persistent event storage
- **Saga Pattern**: Long-running transactions with compensation
- **Optimistic Concurrency**: Version-based conflict resolution
- **Event Replay**: Rebuild state from events
- **Snapshots**: Performance optimization for long streams

**Built-in Sagas:**
- **AgentProvisioningSaga**: Complete agent setup workflow
- **TaskWorkflowSaga**: Multi-step task execution

**Architecture:**
```python
Saga
  ├── Steps[]
  │     ├── command: Forward action
  │     ├── compensation: Rollback action
  │     └── status: Success/Failed
  └── State: STARTED|RUNNING|COMPLETED|COMPENSATING
```

### 4. Message Queue System (`libraries/message_queue.py`)

Asynchronous messaging infrastructure for event-driven workflows.

**Key Features:**
- **Multiple Exchange Types**:
  - DIRECT: Point-to-point messaging
  - FANOUT: Broadcast to all consumers
  - TOPIC: Pattern-based routing
- **Priority Queues**: Message prioritization
- **Dead Letter Queues**: Failed message handling
- **Retry Mechanism**: Automatic retry with limits
- **Durable Queues**: Persistent message storage

**Message Flow:**
```
Publisher → Exchange → Queue → Consumer
             ↓
          Routing Rules
```

### 5. Service Discovery (`libraries/service_discovery.py`)

Dynamic service registry and health monitoring system.

**Key Features:**
- **Auto-registration**: Services register on startup
- **Health Checking**: Periodic health status verification
- **Capability-based Discovery**: Find services by features
- **Status Tracking**: HEALTHY|DEGRADED|UNHEALTHY|OFFLINE
- **Event Callbacks**: React to service state changes

## Workflow Patterns

### 1. Sequential Task Execution
```python
workflow = engine.create_workflow("Sequential Process")
task1 = engine.add_task_to_workflow(workflow.id, "Task 1", "handler1")
task2 = engine.add_task_to_workflow(
    workflow.id, "Task 2", "handler2", 
    dependencies=[task1.id]
)
```

### 2. Parallel Fan-out/Fan-in
```python
workflow = engine.create_workflow("Parallel Process")
task1 = engine.add_task_to_workflow(workflow.id, "Splitter", "split_handler")
parallel_tasks = []
for i in range(5):
    task = engine.add_task_to_workflow(
        workflow.id, f"Worker {i}", "worker_handler",
        dependencies=[task1.id]
    )
    parallel_tasks.append(task)
merger = engine.add_task_to_workflow(
    workflow.id, "Merger", "merge_handler",
    dependencies=[t.id for t in parallel_tasks]
)
```

### 3. Saga with Compensation
```python
saga = AgentProvisioningSaga(
    tenant_id="tenant-123",
    agent_config={
        "type": "processor",
        "permissions": ["read", "write"],
        "initial_task": {"name": "process_data"}
    }
)
await saga_manager.start_saga(saga)
```

### 4. Event-Driven Pipeline
```python
# Publisher
await broker.publish(
    body={"data": "process_this"},
    routing_key="data.raw",
    exchange="processing"
)

# Consumer
broker.subscribe("processed_queue", handle_processed_data)
```

### 5. Service Mesh Communication
```python
# Discover service
services = discovery.discover_services(
    service_type=ServiceType.AGENT,
    status=ServiceStatus.HEALTHY,
    capabilities=["data_processing"]
)

# Use service
for service in services:
    endpoint = service.endpoint.get_url()
    # Make request to endpoint
```

## Best Practices

### 1. Workflow Design
- **Idempotency**: Ensure tasks can be safely retried
- **Timeouts**: Always set reasonable timeouts
- **Error Handling**: Define compensation for critical steps
- **Monitoring**: Add logging and metrics at key points

### 2. Scaling Considerations
- **Resource Limits**: Set appropriate CPU/memory limits
- **Queue Sizing**: Configure queue sizes based on load
- **Concurrency**: Balance parallelism with resource constraints
- **Circuit Breakers**: Implement circuit breakers for external calls

### 3. State Management
- **Event Sourcing**: Use for audit trails and complex state
- **Redis**: Use for fast, temporary state
- **PostgreSQL**: Use for persistent, transactional state
- **Snapshots**: Create snapshots for long event streams

### 4. Security
- **Multi-tenancy**: Isolate workflows by tenant
- **Authentication**: Verify agent/service identity
- **Authorization**: Check permissions before task execution
- **Encryption**: Encrypt sensitive data in messages

## Configuration

### Workflow Engine Configuration
```python
engine = WorkflowEngine(
    max_concurrent_tasks=10  # Parallel execution limit
)
```

### Agent Orchestrator Configuration
```python
orchestrator = AgentOrchestrator({
    "kubernetes_enabled": True,
    "redis_enabled": True,
    "redis_url": "redis://localhost:6379"
})
```

### Message Broker Configuration
```python
broker = MessageBroker()
await broker.declare_queue(
    name="task_queue",
    max_size=1000,
    durable=True,
    dead_letter_queue="dlq"
)
```

## Monitoring & Observability

### Metrics Available
- **Workflow Engine**:
  - `workflows_completed`: Total completed workflows
  - `workflows_failed`: Total failed workflows
  - `tasks_completed`: Total completed tasks
  - `total_execution_time`: Cumulative execution time

- **Agent Orchestrator**:
  - `total_agents`: Current agent count
  - `active_workflows`: Running workflows
  - `scaling_events`: Auto-scaling triggers
  - `message_throughput`: Messages per second

- **Message Broker**:
  - `messages_published`: Total published
  - `messages_consumed`: Total consumed
  - `messages_failed`: Total failures
  - `queue_sizes`: Current queue depths

### Health Endpoints
All major components expose health check endpoints:
- `/health`: Basic health status
- `/ready`: Readiness check
- `/metrics`: Prometheus-compatible metrics

## Troubleshooting Guide

### Common Issues

1. **Workflow Stuck**
   - Check task dependencies for cycles
   - Verify handler availability
   - Check timeout configuration

2. **Agent Not Scaling**
   - Verify scaling policy configuration
   - Check resource availability in Kubernetes
   - Review scaling cooldown periods

3. **Messages Not Processing**
   - Verify queue bindings
   - Check consumer registration
   - Review dead letter queue

4. **Saga Compensation Failing**
   - Check compensation command implementation
   - Verify rollback order
   - Review error handling in compensation

## Performance Optimization

1. **Use Appropriate Concurrency**
   - Set `max_concurrent_tasks` based on resources
   - Use worker pools for CPU-intensive tasks

2. **Implement Caching**
   - Cache frequently accessed data in Redis
   - Use service discovery cache

3. **Optimize Event Streams**
   - Create snapshots for long streams
   - Partition streams by tenant/time

4. **Message Queue Tuning**
   - Use priority queues for critical messages
   - Implement message batching
   - Configure appropriate TTLs

## Integration Examples

### Integrating with MCP Servers
```python
# Register MCP server with discovery
service = Service(
    id="mcp-server-1",
    name="MCP Financial Server",
    type=ServiceType.MCP_SERVER,
    endpoint=ServiceEndpoint(port=8080),
    capabilities=["financial-analysis", "risk-calculation"]
)
discovery.register_service(service)
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: workflow-engine
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: engine
        image: workflow-engine:latest
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## Future Enhancements

1. **Workflow Versioning**: Support multiple workflow versions
2. **Visual Workflow Designer**: GUI for workflow creation
3. **Advanced Routing**: ML-based task routing
4. **Distributed Tracing**: OpenTelemetry integration
5. **Workflow Templates**: Reusable workflow patterns