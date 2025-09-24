#!/usr/bin/env python3
"""
Advanced Agent Coordination System
Orchestrates communication and collaboration between multiple specialized agents
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid

# Import communication layer
from redis_communication import RedisCommunicator, RedisConfig, MessageType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AgentType(Enum):
    CONTAINER_OPTIMIZER = "container_optimizer"
    NETWORK_OPTIMIZER = "network_optimizer"
    CAPACITY_PREDICTOR = "capacity_predictor"
    DATABASE_MONITOR = "database_monitor"
    DIRECTOR = "director"
    OBSERVATORY = "observatory"

class TaskPriority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

class TaskStatus(Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class CoordinationStrategy(Enum):
    SEQUENTIAL = "sequential"  # One agent at a time
    PARALLEL = "parallel"     # Multiple agents simultaneously
    PIPELINE = "pipeline"     # Output of one feeds into next
    COLLABORATIVE = "collaborative"  # Agents work together on subtasks

@dataclass
class Agent:
    agent_id: str
    agent_type: AgentType
    capabilities: Set[str]
    current_load: float  # 0-100
    max_capacity: int
    status: str
    last_heartbeat: datetime
    performance_score: float = 100.0
    task_queue_size: int = 0

@dataclass
class CoordinatedTask:
    task_id: str
    task_type: str
    description: str
    priority: TaskPriority
    status: TaskStatus
    created_at: datetime
    assigned_agents: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    strategy: CoordinationStrategy = CoordinationStrategy.SEQUENTIAL
    parameters: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)
    coordination_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WorkflowTemplate:
    name: str
    description: str
    steps: List[Dict[str, Any]]
    coordination_strategy: CoordinationStrategy
    required_capabilities: Set[str]
    estimated_duration_minutes: int

class AdvancedAgentCoordinator:
    """Advanced coordination system for multi-agent collaboration"""

    def __init__(self, redis_config: RedisConfig = None):
        self.coordinator_id = f"advanced-coordinator-{uuid.uuid4().hex[:8]}"
        self.redis_config = redis_config or RedisConfig()
        self.communicator = None
        self.running = False

        # Agent registry and task management
        self.agents: Dict[str, Agent] = {}
        self.tasks: Dict[str, CoordinatedTask] = {}
        self.workflow_templates: Dict[str, WorkflowTemplate] = {}

        # Coordination configuration
        self.coordination_interval = 30  # seconds
        self.heartbeat_timeout = 300  # 5 minutes
        self.max_concurrent_tasks = 50
        self.load_balancing_enabled = True

        # Performance tracking
        self.coordination_metrics = {
            'tasks_completed': 0,
            'tasks_failed': 0,
            'average_task_duration': 0.0,
            'agent_utilization': {},
            'workflow_success_rates': {}
        }

        # Initialize workflow templates
        self.initialize_workflow_templates()

        logger.info("Advanced Agent Coordinator initialized")

    def initialize_workflow_templates(self):
        """Initialize predefined workflow templates"""

        # Infrastructure Health Check Workflow
        self.workflow_templates['infrastructure_health_check'] = WorkflowTemplate(
            name="Infrastructure Health Check",
            description="Comprehensive infrastructure health assessment",
            steps=[
                {
                    'step': 1,
                    'agent_type': AgentType.CONTAINER_OPTIMIZER,
                    'task': 'container_health_check',
                    'timeout_minutes': 5
                },
                {
                    'step': 2,
                    'agent_type': AgentType.NETWORK_OPTIMIZER,
                    'task': 'network_connectivity_test',
                    'timeout_minutes': 3
                },
                {
                    'step': 3,
                    'agent_type': AgentType.DATABASE_MONITOR,
                    'task': 'database_performance_check',
                    'timeout_minutes': 5
                },
                {
                    'step': 4,
                    'agent_type': AgentType.CAPACITY_PREDICTOR,
                    'task': 'capacity_analysis',
                    'timeout_minutes': 10
                }
            ],
            coordination_strategy=CoordinationStrategy.SEQUENTIAL,
            required_capabilities={'monitoring', 'analysis'},
            estimated_duration_minutes=25
        )

        # Performance Optimization Workflow
        self.workflow_templates['performance_optimization'] = WorkflowTemplate(
            name="Performance Optimization",
            description="Comprehensive system performance optimization",
            steps=[
                {
                    'step': 1,
                    'agent_types': [AgentType.CONTAINER_OPTIMIZER, AgentType.NETWORK_OPTIMIZER],
                    'task': 'parallel_optimization',
                    'timeout_minutes': 15
                },
                {
                    'step': 2,
                    'agent_type': AgentType.DATABASE_MONITOR,
                    'task': 'database_optimization',
                    'timeout_minutes': 10,
                    'depends_on': [1]
                },
                {
                    'step': 3,
                    'agent_type': AgentType.CAPACITY_PREDICTOR,
                    'task': 'predict_optimization_impact',
                    'timeout_minutes': 5,
                    'depends_on': [1, 2]
                }
            ],
            coordination_strategy=CoordinationStrategy.PIPELINE,
            required_capabilities={'optimization', 'prediction'},
            estimated_duration_minutes=30
        )

        # Emergency Response Workflow
        self.workflow_templates['emergency_response'] = WorkflowTemplate(
            name="Emergency Response",
            description="Rapid response to critical system issues",
            steps=[
                {
                    'step': 1,
                    'agent_types': [
                        AgentType.CONTAINER_OPTIMIZER,
                        AgentType.NETWORK_OPTIMIZER,
                        AgentType.DATABASE_MONITOR
                    ],
                    'task': 'emergency_diagnostics',
                    'timeout_minutes': 3
                },
                {
                    'step': 2,
                    'agent_type': 'best_available',
                    'task': 'apply_emergency_fixes',
                    'timeout_minutes': 5,
                    'depends_on': [1]
                }
            ],
            coordination_strategy=CoordinationStrategy.COLLABORATIVE,
            required_capabilities={'diagnostics', 'emergency_response'},
            estimated_duration_minutes=10
        )

    async def start(self):
        """Start the advanced agent coordinator"""
        try:
            logger.info("Starting Advanced Agent Coordinator")

            # Initialize Redis communication
            self.communicator = RedisCommunicator(self.redis_config, self.coordinator_id)
            await self.communicator.connect()

            # Subscribe to coordinator channels
            await self.communicator.subscribe_to_channels([
                'coordinator:tasks',
                'coordinator:agents',
                'coordinator:workflows',
                'agent:broadcast'
            ])

            # Register message handlers
            self.communicator.register_handler(MessageType.AGENT_REGISTER, self.handle_agent_registration)
            self.communicator.register_handler(MessageType.AGENT_HEARTBEAT, self.handle_agent_heartbeat)
            self.communicator.register_handler(MessageType.TASK_COMPLETE, self.handle_task_completion)
            self.communicator.register_handler(MessageType.TASK_FAILED, self.handle_task_failure)

            self.running = True

            # Start coordination loops
            asyncio.create_task(self.coordination_loop())
            asyncio.create_task(self.agent_monitoring_loop())
            asyncio.create_task(self.task_scheduling_loop())

            logger.info("Advanced Agent Coordinator started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start Advanced Agent Coordinator: {e}")
            return False

    async def stop(self):
        """Stop the advanced agent coordinator"""
        logger.info("Stopping Advanced Agent Coordinator")
        self.running = False

        if self.communicator:
            await self.communicator.disconnect()

    async def handle_agent_registration(self, message):
        """Handle agent registration messages"""
        payload = message.get('payload', {})
        agent_id = payload.get('agent_id')
        agent_type_str = payload.get('agent_type', '')

        if not agent_id:
            return

        try:
            agent_type = AgentType(agent_type_str) if agent_type_str else AgentType.DIRECTOR
        except ValueError:
            agent_type = AgentType.DIRECTOR

        agent = Agent(
            agent_id=agent_id,
            agent_type=agent_type,
            capabilities=set(payload.get('capabilities', [])),
            current_load=0.0,
            max_capacity=payload.get('max_capacity', 100),
            status='online',
            last_heartbeat=datetime.now(),
            performance_score=100.0
        )

        self.agents[agent_id] = agent
        logger.info(f"Registered agent: {agent_id} ({agent_type.value})")

        # Send welcome message with coordinator capabilities (if communicator available)
        if self.communicator:
            await self.send_coordination_info(agent_id)

    async def handle_agent_heartbeat(self, message):
        """Handle agent heartbeat messages"""
        payload = message.get('payload', {})
        agent_id = payload.get('agent_id')

        if agent_id in self.agents:
            agent = self.agents[agent_id]
            agent.last_heartbeat = datetime.now()
            agent.current_load = payload.get('current_load', agent.current_load)
            agent.task_queue_size = payload.get('task_queue_size', agent.task_queue_size)
            agent.status = payload.get('status', 'online')

            logger.debug(f"Heartbeat from {agent_id}: load={agent.current_load}%")

    async def handle_task_completion(self, message):
        """Handle task completion messages"""
        payload = message.get('payload', {})
        task_id = payload.get('task_id')
        agent_id = payload.get('agent_id')

        if task_id in self.tasks:
            task = self.tasks[task_id]
            task.status = TaskStatus.COMPLETED
            task.results[agent_id] = payload.get('results', {})

            logger.info(f"Task {task_id} completed by {agent_id}")

            # Update coordination metrics
            self.coordination_metrics['tasks_completed'] += 1

            # Check if this completes a workflow
            await self.check_workflow_completion(task)

    async def handle_task_failure(self, message):
        """Handle task failure messages"""
        payload = message.get('payload', {})
        task_id = payload.get('task_id')
        agent_id = payload.get('agent_id')
        error = payload.get('error', 'Unknown error')

        if task_id in self.tasks:
            task = self.tasks[task_id]
            task.status = TaskStatus.FAILED
            task.results[agent_id] = {'error': error}

            logger.warning(f"Task {task_id} failed on {agent_id}: {error}")

            # Update coordination metrics
            self.coordination_metrics['tasks_failed'] += 1

            # Attempt task recovery
            await self.attempt_task_recovery(task, agent_id, error)

    async def coordination_loop(self):
        """Main coordination loop"""
        while self.running:
            try:
                await self.process_pending_tasks()
                await self.optimize_agent_allocation()
                await self.monitor_task_progress()
                await asyncio.sleep(self.coordination_interval)
            except Exception as e:
                logger.error(f"Coordination loop error: {e}")
                await asyncio.sleep(self.coordination_interval)

    async def agent_monitoring_loop(self):
        """Monitor agent health and availability"""
        while self.running:
            try:
                await self.check_agent_health()
                await self.update_agent_performance_scores()
                await asyncio.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Agent monitoring error: {e}")
                await asyncio.sleep(60)

    async def task_scheduling_loop(self):
        """Handle task scheduling and prioritization"""
        while self.running:
            try:
                await self.schedule_priority_tasks()
                await self.balance_agent_workloads()
                await asyncio.sleep(30)  # Schedule every 30 seconds
            except Exception as e:
                logger.error(f"Task scheduling error: {e}")
                await asyncio.sleep(30)

    async def create_coordinated_task(self, task_type: str, description: str,
                                    priority: TaskPriority = TaskPriority.MEDIUM,
                                    strategy: CoordinationStrategy = CoordinationStrategy.SEQUENTIAL,
                                    parameters: Dict[str, Any] = None) -> str:
        """Create a new coordinated task"""

        task_id = f"task-{uuid.uuid4().hex[:8]}"

        task = CoordinatedTask(
            task_id=task_id,
            task_type=task_type,
            description=description,
            priority=priority,
            status=TaskStatus.PENDING,
            created_at=datetime.now(),
            strategy=strategy,
            parameters=parameters or {}
        )

        self.tasks[task_id] = task
        logger.info(f"Created coordinated task: {task_id} ({task_type})")

        return task_id

    async def execute_workflow(self, workflow_name: str, parameters: Dict[str, Any] = None) -> str:
        """Execute a predefined workflow"""

        if workflow_name not in self.workflow_templates:
            raise ValueError(f"Unknown workflow: {workflow_name}")

        template = self.workflow_templates[workflow_name]

        # Create main workflow task
        task_id = await self.create_coordinated_task(
            task_type=f"workflow_{workflow_name}",
            description=template.description,
            priority=TaskPriority.HIGH,
            strategy=template.coordination_strategy,
            parameters=parameters or {}
        )

        # Add workflow metadata
        task = self.tasks[task_id]
        task.coordination_metadata['workflow_template'] = workflow_name
        task.coordination_metadata['steps'] = template.steps
        task.coordination_metadata['current_step'] = 0

        logger.info(f"Started workflow {workflow_name} with task {task_id}")

        return task_id

    async def process_pending_tasks(self):
        """Process pending tasks and assign them to agents"""

        pending_tasks = [
            task for task in self.tasks.values()
            if task.status == TaskStatus.PENDING
        ]

        # Sort by priority and creation time
        pending_tasks.sort(key=lambda t: (
            t.priority.value,
            t.created_at
        ))

        for task in pending_tasks[:10]:  # Process up to 10 tasks per cycle
            await self.assign_task_to_agents(task)

    async def assign_task_to_agents(self, task: CoordinatedTask):
        """Assign a task to appropriate agents based on coordination strategy"""

        if task.strategy == CoordinationStrategy.SEQUENTIAL:
            await self.assign_sequential_task(task)
        elif task.strategy == CoordinationStrategy.PARALLEL:
            await self.assign_parallel_task(task)
        elif task.strategy == CoordinationStrategy.PIPELINE:
            await self.assign_pipeline_task(task)
        elif task.strategy == CoordinationStrategy.COLLABORATIVE:
            await self.assign_collaborative_task(task)

    async def assign_sequential_task(self, task: CoordinatedTask):
        """Assign task for sequential execution"""

        # Find best agent for the task
        best_agent = await self.find_best_agent_for_task(task)

        if best_agent:
            await self.assign_task_to_agent(task, best_agent.agent_id)
            task.status = TaskStatus.ASSIGNED
            logger.info(f"Assigned sequential task {task.task_id} to {best_agent.agent_id}")

    async def assign_parallel_task(self, task: CoordinatedTask):
        """Assign task for parallel execution"""

        # Find multiple suitable agents
        suitable_agents = await self.find_suitable_agents_for_task(task, max_agents=3)

        if suitable_agents:
            for agent in suitable_agents:
                await self.assign_task_to_agent(task, agent.agent_id)

            task.status = TaskStatus.ASSIGNED
            logger.info(f"Assigned parallel task {task.task_id} to {len(suitable_agents)} agents")

    async def assign_pipeline_task(self, task: CoordinatedTask):
        """Assign task for pipeline execution"""

        # For pipeline tasks, start with the first step
        if 'workflow_template' in task.coordination_metadata:
            await self.execute_workflow_step(task, 0)
        else:
            # Simple pipeline - find agent for first stage
            best_agent = await self.find_best_agent_for_task(task)
            if best_agent:
                await self.assign_task_to_agent(task, best_agent.agent_id)
                task.status = TaskStatus.ASSIGNED

    async def assign_collaborative_task(self, task: CoordinatedTask):
        """Assign task for collaborative execution"""

        # Find multiple agents that can collaborate
        collaborative_agents = await self.find_suitable_agents_for_task(task, max_agents=5)

        if len(collaborative_agents) >= 2:
            # Create subtasks for each agent
            for i, agent in enumerate(collaborative_agents):
                subtask_params = task.parameters.copy()
                subtask_params['collaboration_role'] = f"collaborator_{i}"
                subtask_params['collaboration_partners'] = [
                    a.agent_id for a in collaborative_agents if a != agent
                ]

                await self.assign_task_to_agent(task, agent.agent_id, subtask_params)

            task.status = TaskStatus.ASSIGNED
            logger.info(f"Assigned collaborative task {task.task_id} to {len(collaborative_agents)} agents")

    async def find_best_agent_for_task(self, task: CoordinatedTask) -> Optional[Agent]:
        """Find the best agent for a specific task"""

        available_agents = [
            agent for agent in self.agents.values()
            if agent.status == 'online' and agent.current_load < 90
        ]

        if not available_agents:
            return None

        # Score agents based on multiple factors
        scored_agents = []
        for agent in available_agents:
            score = await self.calculate_agent_task_score(agent, task)
            scored_agents.append((score, agent))

        # Return agent with highest score
        scored_agents.sort(key=lambda x: x[0], reverse=True)
        return scored_agents[0][1] if scored_agents else None

    async def find_suitable_agents_for_task(self, task: CoordinatedTask,
                                          max_agents: int = 3) -> List[Agent]:
        """Find multiple suitable agents for a task"""

        available_agents = [
            agent for agent in self.agents.values()
            if agent.status == 'online' and agent.current_load < 80
        ]

        # Score and select top agents
        scored_agents = []
        for agent in available_agents:
            score = await self.calculate_agent_task_score(agent, task)
            if score > 0.5:  # Minimum suitability threshold
                scored_agents.append((score, agent))

        scored_agents.sort(key=lambda x: x[0], reverse=True)
        return [agent for _, agent in scored_agents[:max_agents]]

    async def calculate_agent_task_score(self, agent: Agent, task: CoordinatedTask) -> float:
        """Calculate how suitable an agent is for a specific task"""

        score = 0.0

        # Base score from performance
        score += agent.performance_score / 100.0 * 0.3

        # Load factor (prefer less loaded agents)
        load_factor = max(0, (100 - agent.current_load) / 100.0)
        score += load_factor * 0.4

        # Capability matching
        if hasattr(task, 'required_capabilities'):
            required_caps = task.parameters.get('required_capabilities', set())
            if required_caps:
                capability_match = len(agent.capabilities & required_caps) / len(required_caps)
                score += capability_match * 0.3

        return min(1.0, score)

    async def assign_task_to_agent(self, task: CoordinatedTask, agent_id: str,
                                 custom_parameters: Dict[str, Any] = None):
        """Assign a specific task to a specific agent"""

        if agent_id not in self.agents:
            logger.warning(f"Cannot assign task to unknown agent: {agent_id}")
            return

        # Add agent to task assignment
        if agent_id not in task.assigned_agents:
            task.assigned_agents.append(agent_id)

        # Prepare task parameters
        task_params = task.parameters.copy()
        if custom_parameters:
            task_params.update(custom_parameters)

        task_params['coordination_task_id'] = task.task_id
        task_params['coordination_strategy'] = task.strategy.value

        # Send task assignment message (if communicator available)
        if self.communicator:
            await self.communicator.send_message(
                MessageType.TASK_ASSIGNMENT,
                agent_id,
                {
                    'task_id': task.task_id,
                    'task_type': task.task_type,
                    'description': task.description,
                    'priority': task.priority.value,
                    'parameters': task_params
                }
            )

        # Update agent load
        agent = self.agents[agent_id]
        agent.current_load = min(100, agent.current_load + 20)  # Estimate load increase

        logger.info(f"Assigned task {task.task_id} to agent {agent_id}")

    async def execute_workflow_step(self, task: CoordinatedTask, step_index: int):
        """Execute a specific step in a workflow"""

        steps = task.coordination_metadata.get('steps', [])
        if step_index >= len(steps):
            # Workflow complete
            task.status = TaskStatus.COMPLETED
            logger.info(f"Workflow task {task.task_id} completed")
            return

        step = steps[step_index]
        task.coordination_metadata['current_step'] = step_index

        # Check dependencies
        depends_on = step.get('depends_on', [])
        if depends_on and not await self.check_step_dependencies(task, depends_on):
            logger.info(f"Step {step_index} dependencies not met for task {task.task_id}")
            return

        # Find agents for this step
        if 'agent_type' in step:
            agent_type = step['agent_type']
            suitable_agents = [
                agent for agent in self.agents.values()
                if agent.agent_type.value == agent_type and agent.status == 'online'
            ]
        elif 'agent_types' in step:
            agent_types = step['agent_types']
            suitable_agents = [
                agent for agent in self.agents.values()
                if agent.agent_type in agent_types and agent.status == 'online'
            ]
        else:
            suitable_agents = list(self.agents.values())

        # Assign step to suitable agents
        if suitable_agents:
            step_params = task.parameters.copy()
            step_params['workflow_step'] = step_index
            step_params['step_config'] = step

            for agent in suitable_agents[:2]:  # Max 2 agents per step
                await self.assign_task_to_agent(task, agent.agent_id, step_params)

    async def check_step_dependencies(self, task: CoordinatedTask, depends_on: List[int]) -> bool:
        """Check if workflow step dependencies are satisfied"""

        completed_steps = task.coordination_metadata.get('completed_steps', set())
        return all(step in completed_steps for step in depends_on)

    async def check_workflow_completion(self, task: CoordinatedTask):
        """Check if a workflow task is complete and advance to next step"""

        if 'workflow_template' not in task.coordination_metadata:
            return

        current_step = task.coordination_metadata.get('current_step', 0)
        steps = task.coordination_metadata.get('steps', [])

        # Mark current step as completed
        completed_steps = task.coordination_metadata.get('completed_steps', set())
        completed_steps.add(current_step)
        task.coordination_metadata['completed_steps'] = completed_steps

        # Move to next step
        next_step = current_step + 1
        if next_step < len(steps):
            await self.execute_workflow_step(task, next_step)
        else:
            task.status = TaskStatus.COMPLETED
            logger.info(f"Workflow {task.task_id} completed successfully")

    async def attempt_task_recovery(self, task: CoordinatedTask, failed_agent_id: str, error: str):
        """Attempt to recover from a failed task"""

        logger.info(f"Attempting recovery for failed task {task.task_id}")

        # Remove failed agent from assignment
        if failed_agent_id in task.assigned_agents:
            task.assigned_agents.remove(failed_agent_id)

        # Try to reassign to another agent
        if task.strategy in [CoordinationStrategy.SEQUENTIAL, CoordinationStrategy.PIPELINE]:
            backup_agent = await self.find_best_agent_for_task(task)
            if backup_agent and backup_agent.agent_id != failed_agent_id:
                await self.assign_task_to_agent(task, backup_agent.agent_id)
                task.status = TaskStatus.ASSIGNED
                logger.info(f"Reassigned task {task.task_id} to backup agent {backup_agent.agent_id}")
                return

        # If recovery fails, mark task as failed
        logger.warning(f"Could not recover task {task.task_id}")

    async def check_agent_health(self):
        """Check health of all registered agents"""

        current_time = datetime.now()
        timeout_threshold = current_time - timedelta(seconds=self.heartbeat_timeout)

        for agent_id, agent in list(self.agents.items()):
            if agent.last_heartbeat < timeout_threshold:
                logger.warning(f"Agent {agent_id} appears offline (last heartbeat: {agent.last_heartbeat})")
                agent.status = 'offline'

                # Reassign tasks from offline agent
                await self.handle_agent_offline(agent_id)

    async def handle_agent_offline(self, agent_id: str):
        """Handle an agent going offline"""

        # Find tasks assigned to the offline agent
        affected_tasks = [
            task for task in self.tasks.values()
            if agent_id in task.assigned_agents and task.status in [TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS]
        ]

        for task in affected_tasks:
            await self.attempt_task_recovery(task, agent_id, "Agent offline")

    async def optimize_agent_allocation(self):
        """Optimize allocation of agents to tasks"""

        if not self.load_balancing_enabled:
            return

        # Find overloaded agents
        overloaded_agents = [
            agent for agent in self.agents.values()
            if agent.current_load > 85 and agent.status == 'online'
        ]

        # Find underutilized agents
        underutilized_agents = [
            agent for agent in self.agents.values()
            if agent.current_load < 30 and agent.status == 'online'
        ]

        # Rebalance if possible
        if overloaded_agents and underutilized_agents:
            logger.info(f"Rebalancing load: {len(overloaded_agents)} overloaded, {len(underutilized_agents)} underutilized")
            # Implementation would move tasks from overloaded to underutilized agents

    async def monitor_task_progress(self):
        """Monitor progress of all active tasks"""

        active_tasks = [
            task for task in self.tasks.values()
            if task.status in [TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS]
        ]

        current_time = datetime.now()

        for task in active_tasks:
            # Check for task timeout
            task_age = (current_time - task.created_at).total_seconds() / 60  # minutes

            timeout_threshold = 60  # Default 60 minute timeout
            if 'timeout_minutes' in task.coordination_metadata:
                timeout_threshold = task.coordination_metadata['timeout_minutes']

            if task_age > timeout_threshold:
                logger.warning(f"Task {task.task_id} has exceeded timeout ({timeout_threshold} minutes)")
                task.status = TaskStatus.FAILED
                task.results['timeout'] = f"Task timed out after {task_age:.1f} minutes"

    async def update_agent_performance_scores(self):
        """Update performance scores for all agents"""

        for agent in self.agents.values():
            # This would calculate performance based on task completion rates,
            # response times, error rates, etc.

            # Simplified performance calculation
            if agent.status == 'online':
                agent.performance_score = min(100, agent.performance_score + 1)
            else:
                agent.performance_score = max(0, agent.performance_score - 5)

    async def schedule_priority_tasks(self):
        """Schedule high-priority tasks first"""

        critical_tasks = [
            task for task in self.tasks.values()
            if task.priority in [TaskPriority.CRITICAL, TaskPriority.EMERGENCY]
            and task.status == TaskStatus.PENDING
        ]

        for task in critical_tasks:
            await self.assign_task_to_agents(task)

    async def balance_agent_workloads(self):
        """Balance workloads across agents"""

        if not self.load_balancing_enabled:
            return

        # Calculate average load
        online_agents = [agent for agent in self.agents.values() if agent.status == 'online']
        if not online_agents:
            return

        avg_load = sum(agent.current_load for agent in online_agents) / len(online_agents)

        # Identify imbalanced agents
        high_load_agents = [agent for agent in online_agents if agent.current_load > avg_load + 20]
        low_load_agents = [agent for agent in online_agents if agent.current_load < avg_load - 20]

        if high_load_agents and low_load_agents:
            logger.info(f"Load imbalance detected: avg={avg_load:.1f}%, rebalancing...")

    async def send_coordination_info(self, agent_id: str):
        """Send coordination capabilities and information to an agent"""

        coordination_info = {
            'coordinator_id': self.coordinator_id,
            'available_workflows': list(self.workflow_templates.keys()),
            'coordination_strategies': [strategy.value for strategy in CoordinationStrategy],
            'task_priorities': [priority.value for priority in TaskPriority],
            'coordination_capabilities': [
                'task_orchestration',
                'workflow_execution',
                'load_balancing',
                'failure_recovery',
                'performance_optimization'
            ]
        }

        await self.communicator.send_message(
            MessageType.PROJECT_UPDATE,
            agent_id,
            {
                'update_type': 'coordination_info',
                'coordination_info': coordination_info
            }
        )

    async def get_coordination_status(self) -> Dict[str, Any]:
        """Get comprehensive coordination status"""

        current_time = datetime.now()

        # Agent statistics
        agent_stats = {
            'total_agents': len(self.agents),
            'online_agents': len([a for a in self.agents.values() if a.status == 'online']),
            'offline_agents': len([a for a in self.agents.values() if a.status == 'offline']),
            'agent_types': {}
        }

        for agent in self.agents.values():
            agent_type = agent.agent_type.value
            agent_stats['agent_types'][agent_type] = agent_stats['agent_types'].get(agent_type, 0) + 1

        # Task statistics
        task_stats = {
            'total_tasks': len(self.tasks),
            'by_status': {},
            'by_priority': {}
        }

        for task in self.tasks.values():
            status = task.status.value
            priority = task.priority.value
            task_stats['by_status'][status] = task_stats['by_status'].get(status, 0) + 1
            task_stats['by_priority'][priority] = task_stats['by_priority'].get(priority, 0) + 1

        # Workflow statistics
        workflow_stats = {
            'available_workflows': len(self.workflow_templates),
            'workflow_names': list(self.workflow_templates.keys())
        }

        status = {
            'coordinator_id': self.coordinator_id,
            'status': 'running' if self.running else 'stopped',
            'timestamp': current_time.isoformat(),
            'agent_statistics': agent_stats,
            'task_statistics': task_stats,
            'workflow_statistics': workflow_stats,
            'coordination_metrics': self.coordination_metrics,
            'configuration': {
                'coordination_interval_seconds': self.coordination_interval,
                'heartbeat_timeout_seconds': self.heartbeat_timeout,
                'max_concurrent_tasks': self.max_concurrent_tasks,
                'load_balancing_enabled': self.load_balancing_enabled
            }
        }

        return status

# Test and example usage
async def test_advanced_coordinator():
    """Test the advanced agent coordinator"""

    redis_config = RedisConfig(
        host='localhost',
        port=6380,  # Using catalytic-redis port
        db=0
    )

    coordinator = AdvancedAgentCoordinator(redis_config)

    # Start the coordinator
    started = await coordinator.start()
    if not started:
        print("Failed to start Advanced Agent Coordinator")
        return False

    print("Advanced Agent Coordinator started")

    # Simulate agent registrations
    test_agents = [
        {
            'agent_id': 'container-opt-001',
            'agent_type': 'container_optimizer',
            'capabilities': ['optimization', 'monitoring'],
            'max_capacity': 100
        },
        {
            'agent_id': 'network-opt-001',
            'agent_type': 'network_optimizer',
            'capabilities': ['network', 'optimization'],
            'max_capacity': 100
        },
        {
            'agent_id': 'capacity-pred-001',
            'agent_type': 'capacity_predictor',
            'capabilities': ['prediction', 'analysis'],
            'max_capacity': 100
        }
    ]

    for agent_info in test_agents:
        await coordinator.handle_agent_registration({'payload': agent_info})

    # Create and execute test tasks
    print("Creating coordinated tasks...")

    task1_id = await coordinator.create_coordinated_task(
        'infrastructure_monitoring',
        'Monitor infrastructure health',
        TaskPriority.HIGH,
        CoordinationStrategy.PARALLEL
    )

    task2_id = await coordinator.execute_workflow('infrastructure_health_check')

    # Wait for coordination cycles
    print("Running coordination for 10 seconds...")
    await asyncio.sleep(10)

    # Get coordination status
    try:
        status = await coordinator.get_coordination_status()
        print("Coordination Status:")
        print(f"  - Coordinator ID: {status.get('coordinator_id', 'N/A')}")
        print(f"  - Status: {status.get('status', 'N/A')}")
        print(f"  - Agents registered: {status.get('agent_statistics', {}).get('total_agents', 0)}")
        print(f"  - Online agents: {status.get('agent_statistics', {}).get('online_agents', 0)}")
        print(f"  - Total tasks: {status.get('task_statistics', {}).get('total_tasks', 0)}")
        print(f"  - Available workflows: {status.get('workflow_statistics', {}).get('available_workflows', 0)}")
    except Exception as e:
        print(f"Error getting status: {e}")

    await coordinator.stop()
    print("Advanced Agent Coordinator stopped")
    return True

if __name__ == "__main__":
    asyncio.run(test_advanced_coordinator())