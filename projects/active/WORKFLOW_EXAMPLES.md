# Workflow Usage Examples

This document provides practical examples of using the various workflow systems in the codebase.

## Table of Contents
1. [Basic Workflow Engine Examples](#basic-workflow-engine-examples)
2. [Agent Orchestration Examples](#agent-orchestration-examples)
3. [Saga Pattern Examples](#saga-pattern-examples)
4. [Message Queue Workflows](#message-queue-workflows)
5. [Service Discovery Workflows](#service-discovery-workflows)
6. [Complete End-to-End Examples](#complete-end-to-end-examples)

## Basic Workflow Engine Examples

### Example 1: Simple Sequential Workflow

```python
import asyncio
from shared.libraries.workflow_engine import (
    WorkflowEngine, 
    PythonFunctionHandler,
    TaskPriority
)

# Initialize engine
engine = WorkflowEngine(max_concurrent_tasks=5)

# Define task handlers
async def fetch_data(source: str):
    print(f"Fetching data from {source}")
    await asyncio.sleep(1)
    return {"data": f"content from {source}"}

async def process_data(data: dict):
    print(f"Processing: {data}")
    await asyncio.sleep(2)
    return {"processed": True, "records": 100}

async def save_results(results: dict):
    print(f"Saving results: {results}")
    await asyncio.sleep(1)
    return {"saved": True}

# Register handlers
engine.register_handler("fetch", PythonFunctionHandler(fetch_data))
engine.register_handler("process", PythonFunctionHandler(process_data))
engine.register_handler("save", PythonFunctionHandler(save_results))

# Create workflow
async def run_data_pipeline():
    workflow = engine.create_workflow(
        name="Data Processing Pipeline",
        description="Fetch, process, and save data"
    )
    
    # Add tasks with dependencies
    fetch_task = engine.add_task_to_workflow(
        workflow.id,
        name="Fetch Data",
        handler="fetch",
        params={"source": "api.example.com"},
        priority=TaskPriority.HIGH
    )
    
    process_task = engine.add_task_to_workflow(
        workflow.id,
        name="Process Data",
        handler="process",
        params={"data": "{{fetch.result}}"},  # Reference previous result
        dependencies=[fetch_task.id]
    )
    
    save_task = engine.add_task_to_workflow(
        workflow.id,
        name="Save Results",
        handler="save",
        params={"results": "{{process.result}}"},
        dependencies=[process_task.id]
    )
    
    # Execute workflow
    success = await engine.execute_workflow(workflow.id)
    
    # Get status
    status = engine.get_workflow_status(workflow.id)
    print(f"Workflow completed: {success}")
    print(f"Status: {status}")

# Run
asyncio.run(run_data_pipeline())
```

### Example 2: Parallel Processing Workflow

```python
import asyncio
from shared.libraries.workflow_engine import WorkflowEngine, PythonFunctionHandler

engine = WorkflowEngine(max_concurrent_tasks=10)

# Handlers for parallel processing
async def split_data(batch_size: int):
    """Split data into batches"""
    total_records = 1000
    batches = []
    for i in range(0, total_records, batch_size):
        batches.append({
            "batch_id": i // batch_size,
            "start": i,
            "end": min(i + batch_size, total_records)
        })
    return {"batches": batches}

async def process_batch(batch: dict):
    """Process individual batch"""
    print(f"Processing batch {batch['batch_id']}: records {batch['start']}-{batch['end']}")
    await asyncio.sleep(1)  # Simulate processing
    return {"batch_id": batch["batch_id"], "processed": batch["end"] - batch["start"]}

async def merge_results(results: list):
    """Merge all batch results"""
    total = sum(r["processed"] for r in results)
    return {"total_processed": total}

# Register handlers
engine.register_handler("split", PythonFunctionHandler(split_data))
engine.register_handler("process_batch", PythonFunctionHandler(process_batch))
engine.register_handler("merge", PythonFunctionHandler(merge_results))

async def run_parallel_workflow():
    workflow = engine.create_workflow(
        name="Parallel Batch Processing",
        description="Process data in parallel batches"
    )
    
    # Split phase
    split_task = engine.add_task_to_workflow(
        workflow.id,
        name="Split Data",
        handler="split",
        params={"batch_size": 100}
    )
    
    # Parallel processing phase
    # In practice, you'd dynamically create these based on split results
    batch_tasks = []
    for i in range(10):  # 10 batches
        batch_task = engine.add_task_to_workflow(
            workflow.id,
            name=f"Process Batch {i}",
            handler="process_batch",
            params={"batch": {"batch_id": i, "start": i*100, "end": (i+1)*100}},
            dependencies=[split_task.id]
        )
        batch_tasks.append(batch_task)
    
    # Merge phase
    merge_task = engine.add_task_to_workflow(
        workflow.id,
        name="Merge Results",
        handler="merge",
        params={"results": "{{batch_results}}"},
        dependencies=[task.id for task in batch_tasks]
    )
    
    # Execute
    await engine.execute_workflow(workflow.id)
    
    # Get statistics
    stats = engine.get_statistics()
    print(f"Workflow Statistics: {stats}")

asyncio.run(run_parallel_workflow())
```

## Agent Orchestration Examples

### Example 3: Dynamic Agent Scaling

```python
import asyncio
from shared.orchestration.agent_orchestrator import (
    AgentOrchestrator,
    AgentSpec,
    ScalingPolicy,
    ScalingStrategy
)

async def setup_auto_scaling_agents():
    # Initialize orchestrator
    orchestrator = AgentOrchestrator({
        "kubernetes_enabled": True,
        "redis_url": "redis://localhost:6379"
    })
    await orchestrator.initialize()
    
    # Define agent specification
    agent_spec = AgentSpec(
        name="data-processor",
        agent_type="processor",
        image="myregistry/data-processor:latest",
        cpu_request="200m",
        cpu_limit="1000m",
        memory_request="256Mi",
        memory_limit="1Gi",
        capabilities=["data_processing", "transformation"],
        ports=[8080],
        health_check_path="/health",
        environment_vars={
            "LOG_LEVEL": "INFO",
            "REDIS_URL": "redis://redis-service:6379"
        }
    )
    
    # Register agent spec
    spec_id = await orchestrator.register_agent_spec(agent_spec)
    
    # Define scaling policy
    scaling_policy = ScalingPolicy(
        agent_type="processor",
        strategy=ScalingStrategy.PERFORMANCE_BASED,
        min_instances=2,
        max_instances=10,
        target_cpu_utilization=0.7,
        target_memory_utilization=0.8,
        scale_up_cooldown=180,  # 3 minutes
        scale_down_cooldown=300,  # 5 minutes
        response_time_threshold=2.0  # seconds
    )
    
    orchestrator.scaling_policies["processor"] = scaling_policy
    
    # Initial spawn
    initial_agents = []
    for i in range(2):
        agent = await orchestrator.spawn_agent(spec_id, tenant_id="tenant-001")
        initial_agents.append(agent)
        print(f"Spawned agent: {agent.id}")
    
    # Monitor and scale
    while True:
        status = orchestrator.get_orchestrator_status()
        print(f"Orchestrator Status: {status}")
        
        # Scaling happens automatically based on metrics
        await asyncio.sleep(60)

asyncio.run(setup_auto_scaling_agents())
```

### Example 4: Distributed Workflow Across Agents

```python
import asyncio
from shared.orchestration.agent_orchestrator import (
    AgentOrchestrator,
    Workflow,
    WorkflowStep
)

async def run_distributed_workflow():
    orchestrator = AgentOrchestrator({
        "kubernetes_enabled": True,
        "redis_enabled": True
    })
    await orchestrator.initialize()
    
    # Create workflow configuration
    workflow_config = {
        "name": "Multi-Agent Data Pipeline",
        "description": "Process data across multiple specialized agents",
        "tenant_id": "tenant-001",
        "max_parallel": 3,
        "timeout": 1800  # 30 minutes
    }
    
    # Create workflow
    workflow = await orchestrator.create_workflow(workflow_config)
    
    # Add workflow steps
    steps = [
        WorkflowStep(
            name="Data Ingestion",
            agent_type="ingester",
            action="ingest_data",
            input_data={"source": "s3://bucket/data.csv"},
            timeout=300
        ),
        WorkflowStep(
            name="Data Validation",
            agent_type="validator",
            action="validate_schema",
            depends_on=["Data Ingestion"],
            timeout=120
        ),
        WorkflowStep(
            name="Data Transformation",
            agent_type="transformer",
            action="transform_data",
            depends_on=["Data Validation"],
            timeout=600
        ),
        WorkflowStep(
            name="Data Enrichment",
            agent_type="enricher",
            action="enrich_data",
            depends_on=["Data Transformation"],
            timeout=300
        ),
        WorkflowStep(
            name="Data Storage",
            agent_type="storage",
            action="store_data",
            depends_on=["Data Enrichment"],
            timeout=180
        )
    ]
    
    workflow.steps = steps
    
    # Execute workflow
    success = await orchestrator.execute_workflow(workflow.id)
    
    # Monitor execution
    while workflow.id in orchestrator.active_workflows:
        status = await orchestrator.get_workflow_status(workflow.id)
        print(f"Workflow Progress: {status}")
        await asyncio.sleep(5)
    
    print(f"Workflow completed: {success}")

asyncio.run(run_distributed_workflow())
```

## Saga Pattern Examples

### Example 5: Agent Provisioning Saga

```python
import asyncio
from shared.event_sourcing.sagas import (
    SagaManager,
    AgentProvisioningSaga
)
from shared.event_sourcing.commands import CommandBus
from shared.event_sourcing.event_store import EventStore
from shared.libraries.database import DatabaseManager

async def provision_agent_with_saga():
    # Initialize components
    db_manager = DatabaseManager("postgresql://localhost/events")
    event_store = EventStore(db_manager)
    command_bus = CommandBus(event_store)
    saga_manager = SagaManager(event_store, command_bus)
    
    # Define agent configuration
    agent_config = {
        "type": "ml_processor",
        "name": "ML Agent 001",
        "description": "Machine learning data processor",
        "configuration": {
            "model": "tensorflow",
            "batch_size": 32,
            "gpu_enabled": True
        },
        "permissions": ["read_data", "write_results", "access_models"],
        "resource_id": "ml-resources",
        "initial_task": {
            "name": "Initialize Model",
            "params": {"model_path": "/models/latest.pb"}
        }
    }
    
    # Create and start saga
    saga = AgentProvisioningSaga(
        tenant_id="tenant-001",
        agent_config=agent_config,
        correlation_id="prov-123"
    )
    
    saga_id = await saga_manager.start_saga(saga)
    print(f"Started provisioning saga: {saga_id}")
    
    # Monitor saga progress
    while True:
        status = await saga_manager.get_saga_status(saga_id)
        if status:
            print(f"Saga Status: {status}")
            
            if status["status"] in ["completed", "compensated", "failed"]:
                break
        
        await asyncio.sleep(2)
    
    # Check final result
    if status["status"] == "completed":
        print(f"Agent provisioned successfully: {saga.context.get('agent_id')}")
    else:
        print(f"Provisioning failed: {status}")

asyncio.run(provision_agent_with_saga())
```

### Example 6: Custom Saga Implementation

```python
import asyncio
from shared.event_sourcing.sagas import Saga, SagaStep, SagaManager
from shared.event_sourcing.commands import Command, CommandResponse

class OrderProcessingSaga(Saga):
    """Saga for processing e-commerce orders"""
    
    def __init__(self, order_data: dict, saga_id=None, correlation_id=None):
        super().__init__(saga_id, correlation_id)
        self.order_data = order_data
        self.context = {"order": order_data}
    
    def get_saga_type(self) -> str:
        return "order_processing"
    
    async def configure_steps(self) -> list:
        # Step 1: Reserve inventory
        reserve_inventory = Command(
            command_type="reserve_inventory",
            payload={
                "items": self.order_data["items"],
                "order_id": self.order_data["id"]
            }
        )
        
        release_inventory = Command(
            command_type="release_inventory",
            payload={"order_id": self.order_data["id"]}
        )
        
        self.add_step(
            command=reserve_inventory,
            compensation_command=release_inventory,
            timeout_seconds=30
        )
        
        # Step 2: Process payment
        process_payment = Command(
            command_type="process_payment",
            payload={
                "amount": self.order_data["total"],
                "payment_method": self.order_data["payment_method"],
                "order_id": self.order_data["id"]
            }
        )
        
        refund_payment = Command(
            command_type="refund_payment",
            payload={"order_id": self.order_data["id"]}
        )
        
        self.add_step(
            command=process_payment,
            compensation_command=refund_payment,
            timeout_seconds=60
        )
        
        # Step 3: Create shipment
        create_shipment = Command(
            command_type="create_shipment",
            payload={
                "order_id": self.order_data["id"],
                "address": self.order_data["shipping_address"],
                "items": self.order_data["items"]
            }
        )
        
        cancel_shipment = Command(
            command_type="cancel_shipment",
            payload={"order_id": self.order_data["id"]}
        )
        
        self.add_step(
            command=create_shipment,
            compensation_command=cancel_shipment,
            timeout_seconds=45
        )
        
        # Step 4: Send confirmation
        send_confirmation = Command(
            command_type="send_confirmation",
            payload={
                "order_id": self.order_data["id"],
                "customer_email": self.order_data["customer_email"]
            }
        )
        
        self.add_step(
            command=send_confirmation,
            timeout_seconds=15
        )
        
        return self.steps
    
    async def handle_step_success(self, step: SagaStep, response: CommandResponse) -> dict:
        context_updates = {}
        
        if "reservation_id" in response.generated_ids:
            context_updates["reservation_id"] = response.generated_ids["reservation_id"]
        
        if "payment_id" in response.generated_ids:
            context_updates["payment_id"] = response.generated_ids["payment_id"]
        
        if "shipment_id" in response.generated_ids:
            context_updates["shipment_id"] = response.generated_ids["shipment_id"]
        
        return context_updates
    
    async def handle_step_failure(self, step: SagaStep, error: str) -> bool:
        # For order processing, any failure should trigger compensation
        print(f"Step failed: {step.command.command_type} - {error}")
        return False
    
    async def handle_compensation_failure(self, step: SagaStep, error: str):
        # Log critical compensation failure
        print(f"CRITICAL: Compensation failed for {step.command.command_type}: {error}")
        # In production, this would trigger alerts

# Usage
async def process_order():
    order = {
        "id": "order-123",
        "customer_email": "customer@example.com",
        "items": [
            {"sku": "PROD-001", "quantity": 2, "price": 29.99},
            {"sku": "PROD-002", "quantity": 1, "price": 49.99}
        ],
        "total": 109.97,
        "payment_method": "credit_card",
        "shipping_address": {
            "street": "123 Main St",
            "city": "Example City",
            "zip": "12345"
        }
    }
    
    saga = OrderProcessingSaga(order)
    saga_id = await saga_manager.start_saga(saga)
    
    # Wait for completion
    # ... monitoring code ...

asyncio.run(process_order())
```

## Message Queue Workflows

### Example 7: Event-Driven Processing Pipeline

```python
import asyncio
from shared.libraries.message_queue import (
    MessageBroker,
    ExchangeType,
    MessagePriority,
    Message
)

async def setup_event_pipeline():
    broker = MessageBroker()
    await broker.start()
    
    # Declare exchanges
    await broker.declare_exchange("events", ExchangeType.TOPIC)
    await broker.declare_exchange("notifications", ExchangeType.FANOUT)
    
    # Declare queues
    await broker.declare_queue("raw_events", max_size=10000)
    await broker.declare_queue("processed_events", max_size=5000)
    await broker.declare_queue("alerts", max_size=1000)
    await broker.declare_queue("audit_log", max_size=50000)
    
    # Set up bindings
    await broker.bind_queue("raw_events", "events", "sensor.*")
    await broker.bind_queue("processed_events", "events", "processed.*")
    await broker.bind_queue("alerts", "events", "*.alert")
    await broker.bind_queue("audit_log", "notifications", "#")
    
    # Event processors
    async def process_sensor_data(message: Message):
        data = message.body
        print(f"Processing sensor data: {data}")
        
        # Process the data
        processed = {
            "original": data,
            "timestamp": message.timestamp.isoformat(),
            "processed_at": asyncio.get_event_loop().time()
        }
        
        # Publish processed event
        await broker.publish(
            body=processed,
            routing_key="processed.sensor",
            exchange="events"
        )
        
        # Check for alerts
        if data.get("value", 0) > 100:
            await broker.publish(
                body={"alert": "High value detected", "data": data},
                routing_key="sensor.alert",
                exchange="events",
                priority=MessagePriority.HIGH
            )
        
        return True
    
    async def handle_alerts(message: Message):
        alert = message.body
        print(f"ALERT: {alert}")
        
        # Send notifications
        await broker.publish(
            body={"type": "alert", "content": alert},
            exchange="notifications"
        )
        
        return True
    
    async def audit_logger(message: Message):
        print(f"Audit: {message.body}")
        # In production, write to persistent storage
        return True
    
    # Subscribe processors
    broker.subscribe("raw_events", process_sensor_data)
    broker.subscribe("alerts", handle_alerts)
    broker.subscribe("audit_log", audit_logger)
    
    # Simulate sensor events
    for i in range(10):
        await broker.publish(
            body={"sensor_id": f"sensor_{i}", "value": i * 15},
            routing_key="sensor.temperature",
            exchange="events"
        )
        await asyncio.sleep(1)
    
    # Get statistics
    stats = broker.get_statistics()
    print(f"Broker Statistics: {stats}")
    
    await asyncio.sleep(5)  # Let processing complete
    await broker.stop()

asyncio.run(setup_event_pipeline())
```

### Example 8: Request-Reply Pattern

```python
import asyncio
import uuid
from shared.libraries.message_queue import MessageBroker, Message

async def request_reply_pattern():
    broker = MessageBroker()
    await broker.start()
    
    # Setup queues
    await broker.declare_queue("requests")
    await broker.declare_queue("responses")
    
    # Response handler
    responses = {}
    response_events = {}
    
    async def handle_response(message: Message):
        correlation_id = message.correlation_id
        if correlation_id in response_events:
            responses[correlation_id] = message.body
            response_events[correlation_id].set()
        return True
    
    # Request processor (simulating a service)
    async def process_request(message: Message):
        request = message.body
        print(f"Processing request: {request}")
        
        # Simulate processing
        await asyncio.sleep(1)
        
        result = {
            "request_id": request.get("id"),
            "result": f"Processed: {request.get('data')}"
        }
        
        # Send response
        if message.reply_to:
            await broker.publish(
                body=result,
                routing_key=message.reply_to,
                correlation_id=message.correlation_id
            )
        
        return True
    
    # Subscribe handlers
    broker.subscribe("requests", process_request)
    broker.subscribe("responses", handle_response)
    
    # Make requests
    async def make_request(data):
        correlation_id = str(uuid.uuid4())
        response_events[correlation_id] = asyncio.Event()
        
        await broker.publish(
            body={"id": correlation_id, "data": data},
            routing_key="requests",
            correlation_id=correlation_id,
            reply_to="responses"
        )
        
        # Wait for response
        await response_events[correlation_id].wait()
        return responses.get(correlation_id)
    
    # Make multiple requests
    tasks = []
    for i in range(5):
        task = asyncio.create_task(make_request(f"data_{i}"))
        tasks.append(task)
    
    results = await asyncio.gather(*tasks)
    for result in results:
        print(f"Received response: {result}")
    
    await broker.stop()

asyncio.run(request_reply_pattern())
```

## Service Discovery Workflows

### Example 9: Dynamic Service Registration and Discovery

```python
import asyncio
from shared.libraries.service_discovery import (
    ServiceDiscovery,
    Service,
    ServiceType,
    ServiceStatus,
    ServiceEndpoint,
    HealthCheck
)

async def service_discovery_workflow():
    discovery = ServiceDiscovery()
    await discovery.start()
    
    # Register multiple services
    services = [
        Service(
            id="api-gateway-1",
            name="API Gateway",
            type=ServiceType.GATEWAY,
            version="2.0.0",
            endpoint=ServiceEndpoint(protocol="https", port=443),
            capabilities=["routing", "authentication", "rate_limiting"],
            health_check=HealthCheck(interval=10)
        ),
        Service(
            id="data-processor-1",
            name="Data Processor",
            type=ServiceType.AGENT,
            version="1.5.0",
            endpoint=ServiceEndpoint(port=8081),
            capabilities=["data_processing", "transformation"],
            health_check=HealthCheck(interval=15)
        ),
        Service(
            id="ml-agent-1",
            name="ML Agent",
            type=ServiceType.AGENT,
            version="1.0.0",
            endpoint=ServiceEndpoint(port=8082),
            capabilities=["inference", "training"],
            health_check=HealthCheck(interval=20)
        ),
        Service(
            id="monitoring-1",
            name="Monitoring Service",
            type=ServiceType.MONITORING,
            version="3.0.0",
            endpoint=ServiceEndpoint(port=9090),
            capabilities=["metrics", "logging", "alerting"],
            health_check=HealthCheck(interval=5)
        )
    ]
    
    for service in services:
        discovery.register_service(service)
        print(f"Registered: {service.name}")
    
    # Discover services by capability
    print("\n--- Discovering Services ---")
    
    # Find all data processing services
    processors = discovery.discover_services(
        capabilities=["data_processing"]
    )
    print(f"Data processors: {[s.name for s in processors]}")
    
    # Find healthy agents
    healthy_agents = discovery.discover_services(
        service_type=ServiceType.AGENT,
        status=ServiceStatus.HEALTHY
    )
    print(f"Healthy agents: {[s.name for s in healthy_agents]}")
    
    # Setup callbacks for service events
    def on_service_registered(service: Service):
        print(f"Event: Service registered - {service.name}")
    
    def on_health_changed(service: Service):
        print(f"Event: Health changed - {service.name} is now {service.status.value}")
    
    discovery.add_callback("service_registered", on_service_registered)
    discovery.add_callback("health_changed", on_health_changed)
    
    # Simulate health checks
    for _ in range(3):
        await asyncio.sleep(5)
        
        # Check health of all services
        for service_id in ["api-gateway-1", "data-processor-1", "ml-agent-1"]:
            status = await discovery.check_health(service_id)
            print(f"Health check - {service_id}: {status.value}")
    
    # Get statistics
    stats = discovery.get_statistics()
    print(f"\nDiscovery Statistics: {stats}")
    
    await discovery.stop()

asyncio.run(service_discovery_workflow())
```

## Complete End-to-End Examples

### Example 10: Complete Data Processing System

```python
import asyncio
from typing import Dict, Any
from shared.libraries.workflow_engine import WorkflowEngine
from shared.orchestration.agent_orchestrator import AgentOrchestrator
from shared.libraries.message_queue import MessageBroker
from shared.libraries.service_discovery import ServiceDiscovery

class DataProcessingSystem:
    """Complete data processing system with all workflow components"""
    
    def __init__(self):
        self.workflow_engine = WorkflowEngine(max_concurrent_tasks=20)
        self.orchestrator = None
        self.message_broker = MessageBroker()
        self.service_discovery = ServiceDiscovery()
        
    async def initialize(self):
        """Initialize all components"""
        # Start message broker
        await self.message_broker.start()
        
        # Start service discovery
        await self.service_discovery.start()
        
        # Initialize orchestrator
        self.orchestrator = AgentOrchestrator({
            "kubernetes_enabled": False,  # For local testing
            "redis_enabled": True
        })
        await self.orchestrator.initialize()
        
        # Setup message queues
        await self._setup_queues()
        
        # Register services
        await self._register_services()
        
        print("System initialized")
    
    async def _setup_queues(self):
        """Setup message queues and exchanges"""
        # Declare exchanges
        await self.message_broker.declare_exchange("data", "topic")
        await self.message_broker.declare_exchange("control", "direct")
        
        # Declare queues
        await self.message_broker.declare_queue("incoming_data")
        await self.message_broker.declare_queue("validated_data")
        await self.message_broker.declare_queue("processed_data")
        await self.message_broker.declare_queue("errors", dead_letter_queue="dlq")
        
        # Bindings
        await self.message_broker.bind_queue("incoming_data", "data", "raw.*")
        await self.message_broker.bind_queue("validated_data", "data", "validated.*")
        await self.message_broker.bind_queue("processed_data", "data", "processed.*")
    
    async def _register_services(self):
        """Register all system services"""
        from shared.libraries.service_discovery import Service, ServiceType, ServiceEndpoint
        
        services = [
            Service(
                id="data-ingester",
                name="Data Ingester",
                type=ServiceType.AGENT,
                endpoint=ServiceEndpoint(port=8001),
                capabilities=["ingestion", "validation"]
            ),
            Service(
                id="data-processor",
                name="Data Processor",
                type=ServiceType.AGENT,
                endpoint=ServiceEndpoint(port=8002),
                capabilities=["processing", "transformation"]
            ),
            Service(
                id="data-storage",
                name="Data Storage",
                type=ServiceType.STORAGE,
                endpoint=ServiceEndpoint(port=8003),
                capabilities=["storage", "retrieval"]
            )
        ]
        
        for service in services:
            self.service_discovery.register_service(service)
    
    async def process_data_batch(self, batch_data: Dict[str, Any]):
        """Process a batch of data through the complete pipeline"""
        
        # Create workflow for this batch
        workflow = self.workflow_engine.create_workflow(
            name=f"Batch Processing - {batch_data['id']}",
            description="Complete data processing pipeline"
        )
        
        # Step 1: Ingest and validate
        async def ingest_data(data: dict):
            # Publish to message queue
            await self.message_broker.publish(
                body=data,
                routing_key="raw.batch",
                exchange="data"
            )
            
            # Simulate validation
            await asyncio.sleep(1)
            
            if data.get("valid", True):
                await self.message_broker.publish(
                    body=data,
                    routing_key="validated.batch",
                    exchange="data"
                )
                return {"status": "validated", "records": len(data.get("records", []))}
            else:
                raise ValueError("Validation failed")
        
        # Step 2: Process data
        async def process_data(validated_data: dict):
            # Find available processor service
            processors = self.service_discovery.discover_services(
                capabilities=["processing"]
            )
            
            if not processors:
                raise Exception("No processing service available")
            
            processor = processors[0]
            print(f"Using processor: {processor.name}")
            
            # Simulate processing
            await asyncio.sleep(2)
            
            result = {
                "processed_records": validated_data["records"],
                "processor_id": processor.id
            }
            
            await self.message_broker.publish(
                body=result,
                routing_key="processed.batch",
                exchange="data"
            )
            
            return result
        
        # Step 3: Store results
        async def store_results(processed_data: dict):
            # Find storage service
            storage_services = self.service_discovery.discover_services(
                capabilities=["storage"]
            )
            
            if not storage_services:
                raise Exception("No storage service available")
            
            storage = storage_services[0]
            print(f"Storing in: {storage.name}")
            
            # Simulate storage
            await asyncio.sleep(1)
            
            return {
                "storage_id": storage.id,
                "location": f"s3://bucket/{batch_data['id']}/processed",
                "records_stored": processed_data["processed_records"]
            }
        
        # Register handlers
        from shared.libraries.workflow_engine import PythonFunctionHandler
        
        self.workflow_engine.register_handler(
            "ingest", 
            PythonFunctionHandler(ingest_data)
        )
        self.workflow_engine.register_handler(
            "process", 
            PythonFunctionHandler(process_data)
        )
        self.workflow_engine.register_handler(
            "store", 
            PythonFunctionHandler(store_results)
        )
        
        # Add tasks to workflow
        ingest_task = self.workflow_engine.add_task_to_workflow(
            workflow.id,
            name="Ingest and Validate",
            handler="ingest",
            params={"data": batch_data}
        )
        
        process_task = self.workflow_engine.add_task_to_workflow(
            workflow.id,
            name="Process Data",
            handler="process",
            params={"validated_data": "{{ingest.result}}"},
            dependencies=[ingest_task.id]
        )
        
        store_task = self.workflow_engine.add_task_to_workflow(
            workflow.id,
            name="Store Results",
            handler="store",
            params={"processed_data": "{{process.result}}"},
            dependencies=[process_task.id]
        )
        
        # Execute workflow
        success = await self.workflow_engine.execute_workflow(workflow.id)
        
        # Get final status
        status = self.workflow_engine.get_workflow_status(workflow.id)
        
        return {
            "success": success,
            "workflow_id": workflow.id,
            "status": status
        }
    
    async def shutdown(self):
        """Shutdown all components"""
        await self.message_broker.stop()
        await self.service_discovery.stop()
        print("System shutdown complete")

# Usage
async def main():
    system = DataProcessingSystem()
    await system.initialize()
    
    # Process multiple batches
    batches = [
        {
            "id": "batch-001",
            "records": 1000,
            "source": "api",
            "valid": True
        },
        {
            "id": "batch-002",
            "records": 500,
            "source": "file",
            "valid": True
        },
        {
            "id": "batch-003",
            "records": 750,
            "source": "stream",
            "valid": True
        }
    ]
    
    # Process batches concurrently
    tasks = []
    for batch in batches:
        task = asyncio.create_task(system.process_data_batch(batch))
        tasks.append(task)
    
    results = await asyncio.gather(*tasks)
    
    print("\n--- Processing Results ---")
    for result in results:
        print(f"Batch {result['workflow_id']}: Success={result['success']}")
    
    # Get system statistics
    print("\n--- System Statistics ---")
    print(f"Workflow Engine: {system.workflow_engine.get_statistics()}")
    print(f"Message Broker: {system.message_broker.get_statistics()}")
    print(f"Service Discovery: {system.service_discovery.get_statistics()}")
    
    await system.shutdown()

asyncio.run(main())
```

## Testing Workflows

### Example 11: Unit Testing Workflows

```python
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from shared.libraries.workflow_engine import WorkflowEngine, Task, TaskStatus

@pytest.mark.asyncio
async def test_workflow_execution():
    """Test basic workflow execution"""
    engine = WorkflowEngine(max_concurrent_tasks=5)
    
    # Mock handler
    mock_handler = AsyncMock()
    mock_handler.execute.return_value = {
        "task_id": "test",
        "status": TaskStatus.COMPLETED,
        "result": {"data": "processed"}
    }
    
    engine.register_handler("test_handler", mock_handler)
    
    # Create workflow
    workflow = engine.create_workflow("Test Workflow")
    
    # Add task
    task = engine.add_task_to_workflow(
        workflow.id,
        name="Test Task",
        handler="test_handler",
        params={"input": "data"}
    )
    
    # Execute
    success = await engine.execute_workflow(workflow.id)
    
    # Assertions
    assert success == True
    assert workflow.status.value == "completed"
    assert mock_handler.execute.called
    
    # Check task result
    completed_task = workflow.get_task(task.id)
    assert completed_task.status == TaskStatus.COMPLETED

@pytest.mark.asyncio  
async def test_workflow_failure_handling():
    """Test workflow failure and retry logic"""
    engine = WorkflowEngine()
    
    # Handler that fails first time
    call_count = 0
    async def failing_handler(task: Task):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise Exception("Simulated failure")
        return {"status": "success"}
    
    from shared.libraries.workflow_engine import PythonFunctionHandler
    engine.register_handler("failing", PythonFunctionHandler(failing_handler))
    
    workflow = engine.create_workflow("Retry Test")
    task = engine.add_task_to_workflow(
        workflow.id,
        name="Retry Task",
        handler="failing",
        max_retries=2
    )
    
    success = await engine.execute_workflow(workflow.id)
    
    assert success == True
    assert call_count == 2  # Failed once, succeeded on retry
```

## Best Practices Summary

1. **Always handle failures gracefully** - Use try/catch blocks and implement proper error handling
2. **Set appropriate timeouts** - Prevent workflows from hanging indefinitely
3. **Use correlation IDs** - Track related events across distributed systems
4. **Implement idempotency** - Ensure operations can be safely retried
5. **Monitor and log** - Add comprehensive logging at key workflow points
6. **Test thoroughly** - Unit test individual handlers and integration test complete workflows
7. **Use the right tool** - Choose the appropriate workflow system for your use case:
   - Simple tasks → Workflow Engine
   - Distributed agents → Agent Orchestrator  
   - Transactions → Saga Pattern
   - Events → Message Queue
   - Service coordination → Service Discovery