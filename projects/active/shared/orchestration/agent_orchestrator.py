"""
Advanced Agent Orchestration Platform

Enterprise-grade agent orchestration with:
- Dynamic agent spawning and lifecycle management
- Agent-to-agent communication protocols
- Distributed workflow orchestration with state management
- Performance-based auto-scaling and load balancing
- Multi-tenant agent isolation and resource management
- Event-driven agent coordination
- Fault tolerance and self-healing capabilities
- Real-time monitoring and health checks
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from uuid import uuid4

import aioredis
import numpy as np
from kubernetes import client, config as k8s_config
from kubernetes.client.rest import ApiException


class AgentStatus(Enum):
    INITIALIZING = "initializing"
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    TERMINATING = "terminating"
    TERMINATED = "terminated"


class WorkflowStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScalingStrategy(Enum):
    FIXED = "fixed"
    AUTO = "auto"
    PERFORMANCE_BASED = "performance_based"
    WORKLOAD_BASED = "workload_based"


class CommunicationProtocol(Enum):
    DIRECT = "direct"
    MESSAGE_QUEUE = "message_queue"
    EVENT_STREAM = "event_stream"
    RPC = "rpc"


@dataclass
class AgentSpec:
    """Agent specification and configuration"""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    agent_type: str = ""
    image: str = ""
    version: str = "1.0.0"

    # Resource requirements
    cpu_request: str = "100m"
    cpu_limit: str = "500m"
    memory_request: str = "128Mi"
    memory_limit: str = "512Mi"

    # Environment configuration
    environment_vars: Dict[str, str] = field(default_factory=dict)
    secrets: List[str] = field(default_factory=list)
    config_maps: List[str] = field(default_factory=list)

    # Networking
    ports: List[int] = field(default_factory=list)
    service_type: str = "ClusterIP"

    # Capabilities
    capabilities: List[str] = field(default_factory=list)
    protocols: List[CommunicationProtocol] = field(default_factory=list)

    # Lifecycle
    startup_timeout: int = 300  # seconds
    health_check_path: str = "/health"
    readiness_check_path: str = "/ready"

    # Tenant isolation
    tenant_id: str = ""
    namespace: str = "default"


@dataclass
class AgentInstance:
    """Running agent instance"""

    id: str = field(default_factory=lambda: str(uuid4()))
    spec_id: str = ""
    status: AgentStatus = AgentStatus.INITIALIZING

    # Runtime information
    pod_name: str = ""
    node_name: str = ""
    ip_address: str = ""
    start_time: datetime = field(default_factory=datetime.utcnow)

    # Performance metrics
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    request_count: int = 0
    error_count: int = 0
    avg_response_time: float = 0.0

    # Health status
    last_health_check: Optional[datetime] = None
    health_status: str = "unknown"
    restart_count: int = 0

    # Communication
    endpoint_url: str = ""
    message_queue: str = ""

    # Metadata
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)


@dataclass
class WorkflowStep:
    """Workflow step definition"""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    agent_type: str = ""
    action: str = ""

    # Input/Output
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_mapping: Dict[str, str] = field(default_factory=dict)

    # Dependencies
    depends_on: List[str] = field(default_factory=list)

    # Execution settings
    timeout: int = 300
    retry_count: int = 3
    retry_delay: int = 10

    # Conditional execution
    condition: Optional[str] = None
    skip_on_error: bool = False


@dataclass
class Workflow:
    """Distributed workflow definition"""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    tenant_id: str = ""

    # Steps and dependencies
    steps: List[WorkflowStep] = field(default_factory=list)

    # Execution settings
    max_parallel: int = 5
    timeout: int = 3600
    retry_policy: Dict[str, Any] = field(default_factory=dict)

    # State management
    status: WorkflowStatus = WorkflowStatus.PENDING
    current_step: Optional[str] = None
    completed_steps: Set[str] = field(default_factory=set)
    failed_steps: Set[str] = field(default_factory=set)

    # Context and variables
    context: Dict[str, Any] = field(default_factory=dict)
    variables: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: str = ""


@dataclass
class ScalingPolicy:
    """Auto-scaling policy configuration"""

    agent_type: str = ""
    strategy: ScalingStrategy = ScalingStrategy.AUTO

    # Scaling parameters
    min_instances: int = 1
    max_instances: int = 10
    target_cpu_utilization: float = 0.7
    target_memory_utilization: float = 0.8
    target_queue_length: int = 10

    # Scaling behavior
    scale_up_cooldown: int = 300  # seconds
    scale_down_cooldown: int = 600
    scale_up_step: int = 2
    scale_down_step: int = 1

    # Performance thresholds
    response_time_threshold: float = 5.0  # seconds
    error_rate_threshold: float = 0.05  # 5%


class AgentOrchestrator:
    """Advanced agent orchestration platform"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

        # Agent management
        self.agent_specs: Dict[str, AgentSpec] = {}
        self.agent_instances: Dict[str, AgentInstance] = {}
        self.agent_pools: Dict[str, List[str]] = {}  # agent_type -> instance_ids

        # Workflow management
        self.workflows: Dict[str, Workflow] = {}
        self.active_workflows: Set[str] = set()
        self.workflow_executions: Dict[str, Dict[str, Any]] = {}

        # Scaling policies
        self.scaling_policies: Dict[str, ScalingPolicy] = {}
        self.scaling_decisions: Dict[str, datetime] = {}

        # Communication
        self.message_handlers: Dict[str, List[Callable]] = {}
        self.agent_connections: Dict[str, Any] = {}

        # Kubernetes integration
        self.k8s_client: Optional[client.CoreV1Api] = None
        self.k8s_apps_client: Optional[client.AppsV1Api] = None

        # Redis for state management
        self.redis_client: Optional[aioredis.Redis] = None

        # Monitoring
        self.metrics: Dict[str, Any] = {
            "total_agents": 0,
            "active_workflows": 0,
            "scaling_events": 0,
            "message_throughput": 0,
        }

        self.logger = logging.getLogger(__name__)

    async def initialize(self):
        """Initialize orchestration platform"""
        try:
            # Initialize Kubernetes client
            if self.config.get("kubernetes_enabled", True):
                await self._init_kubernetes()

            # Initialize Redis for state management
            if self.config.get("redis_enabled", True):
                await self._init_redis()

            # Start background tasks
            asyncio.create_task(self._health_check_loop())
            asyncio.create_task(self._scaling_loop())
            asyncio.create_task(self._workflow_executor_loop())
            asyncio.create_task(self._metrics_collector_loop())

            # Load default scaling policies
            await self._load_default_scaling_policies()

            self.logger.info("Agent orchestrator initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize orchestrator: {e}")
            raise

    async def _init_kubernetes(self):
        """Initialize Kubernetes client"""
        try:
            # Try in-cluster config first, then fallback to local
            try:
                k8s_config.load_incluster_config()
            except Exception:
                k8s_config.load_kube_config()

            self.k8s_client = client.CoreV1Api()
            self.k8s_apps_client = client.AppsV1Api()

            self.logger.info("Kubernetes client initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize Kubernetes client: {e}")
            raise

    async def _init_redis(self):
        """Initialize Redis client"""
        redis_url = self.config.get("redis_url", "redis://localhost:6379")
        self.redis_client = aioredis.from_url(redis_url)

        self.logger.info("Redis client initialized")

    async def register_agent_spec(self, spec: AgentSpec) -> str:
        """Register agent specification"""
        self.agent_specs[spec.id] = spec

        # Initialize agent pool
        if spec.agent_type not in self.agent_pools:
            self.agent_pools[spec.agent_type] = []

        self.logger.info(f"Registered agent spec: {spec.name} ({spec.id})")
        return spec.id

    async def spawn_agent(self, spec_id: str, tenant_id: str = "") -> AgentInstance:
        """Spawn new agent instance"""
        if spec_id not in self.agent_specs:
            raise ValueError(f"Agent spec not found: {spec_id}")

        spec = self.agent_specs[spec_id]

        # Create agent instance
        instance = AgentInstance(
            spec_id=spec_id,
            status=AgentStatus.INITIALIZING,
            start_time=datetime.utcnow(),
        )

        # Apply tenant isolation
        if tenant_id:
            instance.labels["tenant_id"] = tenant_id
            spec.tenant_id = tenant_id

        try:
            # Deploy to Kubernetes
            if self.k8s_client:
                await self._deploy_agent_to_k8s(spec, instance)

            # Register instance
            self.agent_instances[instance.id] = instance
            self.agent_pools[spec.agent_type].append(instance.id)

            # Store state in Redis
            if self.redis_client:
                await self._store_agent_state(instance)

            self.metrics["total_agents"] += 1

            self.logger.info(f"Spawned agent: {spec.name} -> {instance.id}")
            return instance

        except Exception as e:
            self.logger.error(f"Failed to spawn agent: {e}")
            instance.status = AgentStatus.ERROR
            raise

    async def _deploy_agent_to_k8s(self, spec: AgentSpec, instance: AgentInstance):
        """Deploy agent to Kubernetes"""
        # Generate unique names
        deployment_name = f"{spec.name}-{instance.id[:8]}"
        namespace = spec.namespace or "default"

        # Create deployment manifest
        deployment = client.V1Deployment(
            metadata=client.V1ObjectMeta(
                name=deployment_name,
                namespace=namespace,
                labels={
                    "app": spec.name,
                    "agent-type": spec.agent_type,
                    "instance-id": instance.id,
                    "tenant-id": spec.tenant_id,
                },
            ),
            spec=client.V1DeploymentSpec(
                replicas=1,
                selector=client.V1LabelSelector(
                    match_labels={"instance-id": instance.id}
                ),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        labels={
                            "app": spec.name,
                            "agent-type": spec.agent_type,
                            "instance-id": instance.id,
                            "tenant-id": spec.tenant_id,
                        }
                    ),
                    spec=client.V1PodSpec(
                        containers=[
                            client.V1Container(
                                name=spec.name,
                                image=spec.image,
                                resources=client.V1ResourceRequirements(
                                    requests={
                                        "cpu": spec.cpu_request,
                                        "memory": spec.memory_request,
                                    },
                                    limits={
                                        "cpu": spec.cpu_limit,
                                        "memory": spec.memory_limit,
                                    },
                                ),
                                env=[
                                    client.V1EnvVar(name=k, value=v)
                                    for k, v in spec.environment_vars.items()
                                ]
                                + [
                                    client.V1EnvVar(name="AGENT_ID", value=instance.id),
                                    client.V1EnvVar(
                                        name="TENANT_ID", value=spec.tenant_id
                                    ),
                                ],
                                ports=[
                                    client.V1ContainerPort(container_port=port)
                                    for port in spec.ports
                                ],
                                liveness_probe=client.V1Probe(
                                    http_get=client.V1HTTPGetAction(
                                        path=spec.health_check_path,
                                        port=spec.ports[0] if spec.ports else 8080,
                                    ),
                                    initial_delay_seconds=30,
                                    period_seconds=10,
                                ),
                                readiness_probe=client.V1Probe(
                                    http_get=client.V1HTTPGetAction(
                                        path=spec.readiness_check_path,
                                        port=spec.ports[0] if spec.ports else 8080,
                                    ),
                                    initial_delay_seconds=10,
                                    period_seconds=5,
                                ),
                            )
                        ]
                    ),
                ),
            ),
        )

        # Deploy to Kubernetes
        self.k8s_apps_client.create_namespaced_deployment(
            body=deployment, namespace=namespace
        )

        # Create service if ports are specified
        if spec.ports:
            await self._create_agent_service(spec, instance, namespace)

        instance.pod_name = deployment_name

    async def _create_agent_service(
        self, spec: AgentSpec, instance: AgentInstance, namespace: str
    ):
        """Create Kubernetes service for agent"""
        service_name = f"{spec.name}-{instance.id[:8]}-svc"

        service = client.V1Service(
            metadata=client.V1ObjectMeta(
                name=service_name,
                namespace=namespace,
                labels={"app": spec.name, "instance-id": instance.id},
            ),
            spec=client.V1ServiceSpec(
                selector={"instance-id": instance.id},
                ports=[
                    client.V1ServicePort(
                        port=port, target_port=port, name=f"port-{port}"
                    )
                    for port in spec.ports
                ],
                type=spec.service_type,
            ),
        )

        self.k8s_client.create_namespaced_service(body=service, namespace=namespace)

        # Update instance with service endpoint
        if spec.service_type == "LoadBalancer":
            # For LoadBalancer, we'd need to wait for external IP
            instance.endpoint_url = f"http://{service_name}:{spec.ports[0]}"
        else:
            instance.endpoint_url = (
                f"http://{service_name}.{namespace}.svc.cluster.local:{spec.ports[0]}"
            )

    async def terminate_agent(self, instance_id: str) -> bool:
        """Terminate agent instance"""
        if instance_id not in self.agent_instances:
            raise ValueError(f"Agent instance not found: {instance_id}")

        instance = self.agent_instances[instance_id]
        instance.status = AgentStatus.TERMINATING

        try:
            # Remove from Kubernetes
            if self.k8s_client and instance.pod_name:
                spec = self.agent_specs[instance.spec_id]
                namespace = spec.namespace or "default"

                # Delete deployment
                try:
                    self.k8s_apps_client.delete_namespaced_deployment(
                        name=instance.pod_name, namespace=namespace
                    )
                except ApiException as e:
                    if e.status != 404:  # Ignore if already deleted
                        raise

                # Delete service
                service_name = f"{spec.name}-{instance.id[:8]}-svc"
                try:
                    self.k8s_client.delete_namespaced_service(
                        name=service_name, namespace=namespace
                    )
                except ApiException as e:
                    if e.status != 404:  # Ignore if already deleted
                        raise

            # Remove from pools
            spec = self.agent_specs[instance.spec_id]
            if instance.id in self.agent_pools[spec.agent_type]:
                self.agent_pools[spec.agent_type].remove(instance.id)

            # Update status
            instance.status = AgentStatus.TERMINATED

            # Clean up state
            if self.redis_client:
                await self.redis_client.delete(f"agent:{instance_id}")

            self.metrics["total_agents"] -= 1

            self.logger.info(f"Terminated agent: {instance_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to terminate agent {instance_id}: {e}")
            instance.status = AgentStatus.ERROR
            return False

    async def scale_agent_pool(self, agent_type: str, target_count: int) -> List[str]:
        """Scale agent pool to target count"""
        current_instances = self.agent_pools.get(agent_type, [])
        current_count = len(
            [
                i
                for i in current_instances
                if self.agent_instances[i].status
                not in [AgentStatus.TERMINATING, AgentStatus.TERMINATED]
            ]
        )

        if target_count == current_count:
            return current_instances

        # Find matching spec
        matching_specs = [
            spec for spec in self.agent_specs.values() if spec.agent_type == agent_type
        ]

        if not matching_specs:
            raise ValueError(f"No agent spec found for type: {agent_type}")

        spec = matching_specs[0]  # Use first matching spec

        if target_count > current_count:
            # Scale up
            new_instances = []
            for _ in range(target_count - current_count):
                try:
                    instance = await self.spawn_agent(spec.id)
                    new_instances.append(instance.id)
                except Exception as e:
                    self.logger.error(f"Failed to scale up agent {agent_type}: {e}")
                    break

            self.metrics["scaling_events"] += 1
            self.logger.info(
                f"Scaled up {agent_type}: {current_count} -> {current_count + len(new_instances)}"
            )
            return current_instances + new_instances

        else:
            # Scale down
            instances_to_terminate = current_instances[target_count:]

            for instance_id in instances_to_terminate:
                try:
                    await self.terminate_agent(instance_id)
                except Exception as e:
                    self.logger.error(f"Failed to scale down agent {instance_id}: {e}")

            self.metrics["scaling_events"] += 1
            self.logger.info(
                f"Scaled down {agent_type}: {current_count} -> {target_count}"
            )
            return current_instances[:target_count]

    async def _load_default_scaling_policies(self):
        """Load default auto-scaling policies"""
        default_policies = [
            ScalingPolicy(
                agent_type="data_processor",
                strategy=ScalingStrategy.PERFORMANCE_BASED,
                min_instances=2,
                max_instances=20,
                target_cpu_utilization=0.7,
                target_memory_utilization=0.8,
            ),
            ScalingPolicy(
                agent_type="api_agent",
                strategy=ScalingStrategy.WORKLOAD_BASED,
                min_instances=3,
                max_instances=50,
                target_queue_length=15,
                response_time_threshold=2.0,
            ),
            ScalingPolicy(
                agent_type="ml_inference",
                strategy=ScalingStrategy.PERFORMANCE_BASED,
                min_instances=1,
                max_instances=10,
                target_cpu_utilization=0.6,
                scale_up_step=3,  # Batch processing benefits from larger steps
            ),
        ]

        for policy in default_policies:
            self.scaling_policies[policy.agent_type] = policy

    async def create_workflow(self, workflow_config: Dict[str, Any]) -> Workflow:
        """Create new distributed workflow"""
        workflow = Workflow(**workflow_config)
        self.workflows[workflow.id] = workflow

        # Validate workflow steps
        await self._validate_workflow(workflow)

        # Store in Redis for persistence
        if self.redis_client:
            await self.redis_client.set(
                f"workflow:{workflow.id}",
                json.dumps(
                    {
                        "id": workflow.id,
                        "name": workflow.name,
                        "status": workflow.status.value,
                        "steps": [
                            {
                                "id": step.id,
                                "name": step.name,
                                "agent_type": step.agent_type,
                                "action": step.action,
                                "depends_on": step.depends_on,
                            }
                            for step in workflow.steps
                        ],
                        "created_at": workflow.created_at.isoformat(),
                        "tenant_id": workflow.tenant_id,
                    }
                ),
                ex=86400,  # 24 hours
            )

        self.logger.info(f"Created workflow: {workflow.name} ({workflow.id})")
        return workflow

    async def _validate_workflow(self, workflow: Workflow):
        """Validate workflow configuration"""
        step_ids = {step.id for step in workflow.steps}

        # Check for circular dependencies
        for step in workflow.steps:
            for dep in step.depends_on:
                if dep not in step_ids:
                    raise ValueError(f"Step {step.id} depends on unknown step: {dep}")

        # Check for circular dependencies (simple cycle detection)
        visited = set()
        rec_stack = set()

        def has_cycle(step_id: str) -> bool:
            if step_id in rec_stack:
                return True
            if step_id in visited:
                return False

            visited.add(step_id)
            rec_stack.add(step_id)

            step = next((s for s in workflow.steps if s.id == step_id), None)
            if step:
                for dep in step.depends_on:
                    if has_cycle(dep):
                        return True

            rec_stack.remove(step_id)
            return False

        for step in workflow.steps:
            if has_cycle(step.id):
                raise ValueError(
                    f"Circular dependency detected in workflow: {workflow.id}"
                )

    async def execute_workflow(self, workflow_id: str) -> bool:
        """Execute distributed workflow"""
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow not found: {workflow_id}")

        workflow = self.workflows[workflow_id]
        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = datetime.utcnow()

        self.active_workflows.add(workflow_id)
        self.workflow_executions[workflow_id] = {
            "step_results": {},
            "step_status": {},
            "execution_log": [],
        }

        # Store execution state
        if self.redis_client:
            await self.redis_client.set(
                f"workflow_execution:{workflow_id}",
                json.dumps(
                    {
                        "status": workflow.status.value,
                        "started_at": workflow.started_at.isoformat(),
                        "step_results": {},
                        "step_status": {},
                    }
                ),
                ex=86400,
            )

        self.metrics["active_workflows"] += 1

        self.logger.info(f"Started workflow execution: {workflow_id}")
        return True

    async def _workflow_executor_loop(self):
        """Background workflow execution loop"""
        while True:
            try:
                for workflow_id in list(self.active_workflows):
                    await self._process_workflow(workflow_id)

                await asyncio.sleep(5)  # Check every 5 seconds

            except Exception as e:
                self.logger.error(f"Error in workflow executor: {e}")
                await asyncio.sleep(10)

    async def _process_workflow(self, workflow_id: str):
        """Process individual workflow execution"""
        if workflow_id not in self.workflows:
            self.active_workflows.discard(workflow_id)
            return

        workflow = self.workflows[workflow_id]
        execution = self.workflow_executions[workflow_id]

        # Find ready steps (dependencies satisfied)
        ready_steps = []
        for step in workflow.steps:
            if step.id in workflow.completed_steps:
                continue
            if step.id in workflow.failed_steps:
                continue

            # Check if all dependencies are completed
            deps_satisfied = all(
                dep in workflow.completed_steps for dep in step.depends_on
            )

            if deps_satisfied:
                ready_steps.append(step)

        # Execute ready steps (up to max_parallel)
        running_steps = len(
            [
                step_id
                for step_id, status in execution["step_status"].items()
                if status == "running"
            ]
        )

        available_slots = workflow.max_parallel - running_steps
        steps_to_execute = ready_steps[:available_slots]

        for step in steps_to_execute:
            asyncio.create_task(self._execute_workflow_step(workflow_id, step.id))

        # Check if workflow is complete
        if len(workflow.completed_steps) == len(workflow.steps):
            await self._complete_workflow(workflow_id, WorkflowStatus.COMPLETED)
        elif len(workflow.failed_steps) > 0 and not ready_steps:
            await self._complete_workflow(workflow_id, WorkflowStatus.FAILED)

    async def _execute_workflow_step(self, workflow_id: str, step_id: str):
        """Execute individual workflow step"""
        workflow = self.workflows[workflow_id]
        execution = self.workflow_executions[workflow_id]

        step = next((s for s in workflow.steps if s.id == step_id), None)
        if not step:
            return

        execution["step_status"][step_id] = "running"

        try:
            # Find available agent for step
            agent_instance = await self._find_available_agent(
                step.agent_type, workflow.tenant_id
            )

            if not agent_instance:
                # Try to scale up if needed
                await self._handle_no_available_agent(step.agent_type)
                agent_instance = await self._find_available_agent(
                    step.agent_type, workflow.tenant_id
                )

                if not agent_instance:
                    raise Exception(f"No available agent for type: {step.agent_type}")

            # Execute step on agent
            result = await self._send_step_to_agent(
                agent_instance, step, workflow.context
            )

            # Store result
            execution["step_results"][step_id] = result
            execution["step_status"][step_id] = "completed"
            workflow.completed_steps.add(step_id)

            # Update workflow context with step output
            if step.output_mapping:
                for output_key, context_key in step.output_mapping.items():
                    if output_key in result:
                        workflow.context[context_key] = result[output_key]

            execution["execution_log"].append(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "step_id": step_id,
                    "agent_id": agent_instance.id,
                    "status": "completed",
                    "result": result,
                }
            )

            self.logger.info(
                f"Completed workflow step {step_id} on agent {agent_instance.id}"
            )

        except Exception as e:
            execution["step_status"][step_id] = "failed"
            workflow.failed_steps.add(step_id)

            execution["execution_log"].append(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "step_id": step_id,
                    "status": "failed",
                    "error": str(e),
                }
            )

            self.logger.error(f"Failed workflow step {step_id}: {e}")

    async def _find_available_agent(
        self, agent_type: str, tenant_id: str = ""
    ) -> Optional[AgentInstance]:
        """Find available agent instance for task execution"""
        if agent_type not in self.agent_pools:
            return None

        for instance_id in self.agent_pools[agent_type]:
            instance = self.agent_instances.get(instance_id)
            if not instance:
                continue

            if instance.status != AgentStatus.IDLE:
                continue

            # Check tenant isolation
            if tenant_id and instance.labels.get("tenant_id") != tenant_id:
                continue

            # Mark as busy
            instance.status = AgentStatus.BUSY
            return instance

        return None

    async def _handle_no_available_agent(self, agent_type: str):
        """Handle case when no agents are available"""
        # Check if we can scale up
        if agent_type in self.scaling_policies:
            policy = self.scaling_policies[agent_type]
            current_count = len(self.agent_pools.get(agent_type, []))

            if current_count < policy.max_instances:
                # Scale up by one instance
                await self.scale_agent_pool(agent_type, current_count + 1)

    async def _send_step_to_agent(
        self, agent: AgentInstance, step: WorkflowStep, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send workflow step to agent for execution"""
        # Prepare request (would be used in actual HTTP/message queue implementation)
        # request = {
        #     "step_id": step.id,
        #     "action": step.action,
        #     "input_data": step.input_data,
        #     "context": context,
        #     "timeout": step.timeout,
        # }

        # Send to agent (this would be HTTP request, message queue, etc.)
        # For now, simulate execution
        await asyncio.sleep(1)  # Simulate processing time

        # Mark agent as idle again
        agent.status = AgentStatus.IDLE
        agent.request_count += 1

        # Return mock result
        return {
            "status": "success",
            "output": f"Step {step.id} completed by agent {agent.id}",
            "execution_time": 1.0,
        }

    async def _complete_workflow(self, workflow_id: str, status: WorkflowStatus):
        """Complete workflow execution"""
        workflow = self.workflows[workflow_id]
        workflow.status = status
        workflow.completed_at = datetime.utcnow()

        self.active_workflows.discard(workflow_id)
        self.metrics["active_workflows"] -= 1

        # Update Redis state
        if self.redis_client:
            await self.redis_client.set(
                f"workflow_execution:{workflow_id}",
                json.dumps(
                    {
                        "status": status.value,
                        "completed_at": workflow.completed_at.isoformat(),
                        "step_results": self.workflow_executions[workflow_id][
                            "step_results"
                        ],
                        "execution_log": self.workflow_executions[workflow_id][
                            "execution_log"
                        ],
                    }
                ),
                ex=86400,
            )

        self.logger.info(
            f"Completed workflow {workflow_id} with status: {status.value}"
        )

    async def _health_check_loop(self):
        """Background health checking for agents"""
        while True:
            try:
                for instance_id, instance in self.agent_instances.items():
                    if instance.status in [
                        AgentStatus.TERMINATING,
                        AgentStatus.TERMINATED,
                    ]:
                        continue

                    # Perform health check
                    healthy = await self._check_agent_health(instance)

                    if healthy:
                        instance.last_health_check = datetime.utcnow()
                        instance.health_status = "healthy"

                        if instance.status == AgentStatus.ERROR:
                            instance.status = AgentStatus.IDLE  # Recovered
                    else:
                        instance.health_status = "unhealthy"

                        if instance.status != AgentStatus.ERROR:
                            instance.status = AgentStatus.ERROR
                            instance.restart_count += 1

                            # Auto-restart if below threshold
                            if instance.restart_count < 3:
                                await self._restart_agent(instance)

                await asyncio.sleep(30)  # Check every 30 seconds

            except Exception as e:
                self.logger.error(f"Error in health check loop: {e}")
                await asyncio.sleep(60)

    async def _check_agent_health(self, instance: AgentInstance) -> bool:
        """Check individual agent health"""
        try:
            # This would make HTTP request to agent's health endpoint
            # For now, simulate health check
            if instance.endpoint_url:
                # Simulate occasional failures
                import random

                return random.random() > 0.05  # 95% success rate

            return True

        except Exception as e:
            self.logger.error(f"Health check failed for agent {instance.id}: {e}")
            return False

    async def _restart_agent(self, instance: AgentInstance):
        """Restart failed agent"""
        self.logger.info(f"Restarting agent: {instance.id}")

        try:
            # Terminate current instance
            await self.terminate_agent(instance.id)

            # Spawn new instance with same spec
            spec = self.agent_specs[instance.spec_id]
            await self.spawn_agent(spec.id, instance.labels.get("tenant_id", ""))

        except Exception as e:
            self.logger.error(f"Failed to restart agent {instance.id}: {e}")

    async def _scaling_loop(self):
        """Background auto-scaling loop"""
        while True:
            try:
                for agent_type, policy in self.scaling_policies.items():
                    if policy.strategy == ScalingStrategy.FIXED:
                        continue

                    await self._evaluate_scaling_decision(agent_type, policy)

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                self.logger.error(f"Error in scaling loop: {e}")
                await asyncio.sleep(120)

    async def _evaluate_scaling_decision(self, agent_type: str, policy: ScalingPolicy):
        """Evaluate whether to scale agent pool"""
        current_instances = self.agent_pools.get(agent_type, [])
        healthy_count = len(
            [
                i
                for i in current_instances
                if (
                    self.agent_instances[i].status
                    in [AgentStatus.IDLE, AgentStatus.BUSY]
                    and self.agent_instances[i].health_status == "healthy"
                )
            ]
        )

        # Check cooldown periods
        last_decision = self.scaling_decisions.get(agent_type)
        if last_decision:
            time_since_last = (datetime.utcnow() - last_decision).total_seconds()
            if time_since_last < policy.scale_up_cooldown:
                return  # Still in cooldown

        should_scale_up = False
        should_scale_down = False

        if policy.strategy == ScalingStrategy.PERFORMANCE_BASED:
            # Check CPU/Memory utilization
            avg_cpu = (
                np.mean(
                    [
                        self.agent_instances[i].cpu_usage
                        for i in current_instances
                        if self.agent_instances[i].status == AgentStatus.BUSY
                    ]
                )
                if current_instances
                else 0
            )

            avg_memory = (
                np.mean(
                    [
                        self.agent_instances[i].memory_usage
                        for i in current_instances
                        if self.agent_instances[i].status == AgentStatus.BUSY
                    ]
                )
                if current_instances
                else 0
            )

            if (
                avg_cpu > policy.target_cpu_utilization
                or avg_memory > policy.target_memory_utilization
            ):
                should_scale_up = healthy_count < policy.max_instances
            elif (
                avg_cpu < policy.target_cpu_utilization * 0.5
                and avg_memory < policy.target_memory_utilization * 0.5
            ):
                should_scale_down = healthy_count > policy.min_instances

        elif policy.strategy == ScalingStrategy.WORKLOAD_BASED:
            # Check queue length and response times
            busy_count = len(
                [
                    i
                    for i in current_instances
                    if self.agent_instances[i].status == AgentStatus.BUSY
                ]
            )

            if busy_count >= healthy_count:  # All agents busy
                should_scale_up = healthy_count < policy.max_instances
            elif busy_count < healthy_count * 0.3:  # Less than 30% utilization
                should_scale_down = healthy_count > policy.min_instances

        # Execute scaling decision
        if should_scale_up:
            target_count = min(
                healthy_count + policy.scale_up_step, policy.max_instances
            )
            await self.scale_agent_pool(agent_type, target_count)
            self.scaling_decisions[agent_type] = datetime.utcnow()

        elif should_scale_down:
            target_count = max(
                healthy_count - policy.scale_down_step, policy.min_instances
            )
            await self.scale_agent_pool(agent_type, target_count)
            self.scaling_decisions[agent_type] = datetime.utcnow()

    async def _metrics_collector_loop(self):
        """Background metrics collection"""
        while True:
            try:
                # Update metrics
                self.metrics["total_agents"] = len(
                    [
                        i
                        for i in self.agent_instances.values()
                        if i.status not in [AgentStatus.TERMINATED]
                    ]
                )

                self.metrics["active_workflows"] = len(self.active_workflows)

                # Store metrics in Redis for monitoring
                if self.redis_client:
                    await self.redis_client.set(
                        "orchestrator_metrics", json.dumps(self.metrics), ex=300
                    )  # 5 minutes

                await asyncio.sleep(30)  # Collect every 30 seconds

            except Exception as e:
                self.logger.error(f"Error in metrics collection: {e}")
                await asyncio.sleep(60)

    async def _store_agent_state(self, instance: AgentInstance):
        """Store agent state in Redis"""
        if not self.redis_client:
            return

        state = {
            "id": instance.id,
            "status": instance.status.value,
            "pod_name": instance.pod_name,
            "ip_address": instance.ip_address,
            "endpoint_url": instance.endpoint_url,
            "health_status": instance.health_status,
            "last_updated": datetime.utcnow().isoformat(),
        }

        await self.redis_client.set(
            f"agent:{instance.id}", json.dumps(state), ex=3600
        )  # 1 hour

    def get_orchestrator_status(self) -> Dict[str, Any]:
        """Get orchestrator status summary"""
        agent_status_counts = {}
        for status in AgentStatus:
            agent_status_counts[status.value] = len(
                [i for i in self.agent_instances.values() if i.status == status]
            )

        workflow_status_counts = {}
        for status in WorkflowStatus:
            workflow_status_counts[status.value] = len(
                [w for w in self.workflows.values() if w.status == status]
            )

        return {
            "agents": {
                "total": len(self.agent_instances),
                "by_status": agent_status_counts,
                "by_type": {
                    agent_type: len(instances)
                    for agent_type, instances in self.agent_pools.items()
                },
            },
            "workflows": {
                "total": len(self.workflows),
                "active": len(self.active_workflows),
                "by_status": workflow_status_counts,
            },
            "scaling_policies": len(self.scaling_policies),
            "metrics": self.metrics,
        }
