"""
Saga Pattern Implementation for Distributed Transactions

Handles long-running business processes that span multiple aggregates:
- Process managers for complex workflows
- Compensation actions for rollback scenarios
- State persistence and recovery
- Timeout handling and retries
"""

import asyncio
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .commands import Command, CommandBus, CommandResponse, CommandResult
from .event_store import EventMetadata, EventStore, EventType


class SagaStatus(Enum):
    """Saga execution status"""

    STARTED = "started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    TIMEOUT = "timeout"


@dataclass
class SagaStep:
    """Individual step in a saga"""

    step_id: str
    command: Command
    compensation_command: Optional[Command] = None
    timeout_seconds: Optional[int] = None
    max_retries: int = 3
    retry_delay_seconds: int = 5
    executed: bool = False
    succeeded: bool = False
    error_message: Optional[str] = None
    execution_time: Optional[datetime] = None
    retry_count: int = 0


@dataclass
class SagaState:
    """Persistent state of a saga"""

    saga_id: str
    saga_type: str
    status: SagaStatus
    context: Dict[str, Any]
    steps: List[SagaStep]
    current_step_index: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None


class SagaEvent:
    """Events emitted by saga execution"""

    SAGA_STARTED = "saga_started"
    SAGA_STEP_STARTED = "saga_step_started"
    SAGA_STEP_COMPLETED = "saga_step_completed"
    SAGA_STEP_FAILED = "saga_step_failed"
    SAGA_STEP_COMPENSATED = "saga_step_compensated"
    SAGA_COMPLETED = "saga_completed"
    SAGA_FAILED = "saga_failed"
    SAGA_COMPENSATED = "saga_compensated"
    SAGA_TIMEOUT = "saga_timeout"


class Saga(ABC):
    """Base class for saga implementations"""

    def __init__(self, saga_id: str = None, correlation_id: str = None):
        self.saga_id = saga_id or str(uuid.uuid4())
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.status = SagaStatus.STARTED
        self.context: Dict[str, Any] = {}
        self.steps: List[SagaStep] = []
        self.current_step_index = 0
        self.started_at = datetime.utcnow()

    @abstractmethod
    def get_saga_type(self) -> str:
        """Return the type name of this saga"""

    @abstractmethod
    async def configure_steps(self) -> List[SagaStep]:
        """Configure the steps for this saga"""

    @abstractmethod
    async def handle_step_success(
        self, step: SagaStep, response: CommandResponse
    ) -> Dict[str, Any]:
        """Handle successful step execution, return context updates"""

    @abstractmethod
    async def handle_step_failure(self, step: SagaStep, error: str) -> bool:
        """Handle step failure, return True if saga should continue, False to abort"""

    @abstractmethod
    async def handle_compensation_failure(self, step: SagaStep, error: str) -> None:
        """Handle compensation step failure"""

    def add_step(
        self,
        command: Command,
        compensation_command: Command = None,
        timeout_seconds: int = None,
        max_retries: int = 3,
    ) -> SagaStep:
        """Add a step to the saga"""
        step = SagaStep(
            step_id=str(uuid.uuid4()),
            command=command,
            compensation_command=compensation_command,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
        self.steps.append(step)
        return step

    def get_state(self) -> SagaState:
        """Get current saga state"""
        return SagaState(
            saga_id=self.saga_id,
            saga_type=self.get_saga_type(),
            status=self.status,
            context=self.context,
            steps=self.steps,
            current_step_index=self.current_step_index,
            started_at=self.started_at,
            correlation_id=self.correlation_id,
        )


class AgentProvisioningSaga(Saga):
    """Saga for provisioning a new agent with full setup"""

    def __init__(
        self,
        tenant_id: str,
        agent_config: Dict[str, Any],
        saga_id: str = None,
        correlation_id: str = None,
    ):
        super().__init__(saga_id, correlation_id)
        self.tenant_id = tenant_id
        self.agent_config = agent_config
        self.context = {"tenant_id": tenant_id, "agent_config": agent_config}

    def get_saga_type(self) -> str:
        return "agent_provisioning"

    async def configure_steps(self) -> List[SagaStep]:
        from .commands import (
            AssignTaskCommand,
            CreateAgentCommand,
            GrantAccessCommand,
            StartAgentCommand,
        )

        # Step 1: Create agent
        create_cmd = CreateAgentCommand(
            agent_type=self.agent_config["type"],
            configuration=self.agent_config.get("configuration", {}),
            tenant_id=self.tenant_id,
            name=self.agent_config.get("name"),
            description=self.agent_config.get("description"),
            correlation_id=self.correlation_id,
        )

        # Compensation: Delete agent (we'll implement this command)
        # delete_cmd = DeleteAgentCommand(agent_id="to_be_set", correlation_id=self.correlation_id)

        self.add_step(create_cmd, timeout_seconds=30)

        # Step 2: Grant access permissions
        if self.agent_config.get("permissions"):
            grant_cmd = GrantAccessCommand(
                user_id="agent_{{}}",  # Will be filled after agent creation
                resource_id=self.agent_config.get("resource_id", "default"),
                permissions=self.agent_config["permissions"],
                correlation_id=self.correlation_id,
            )
            self.add_step(grant_cmd, timeout_seconds=15)

        # Step 3: Start agent
        start_cmd = StartAgentCommand(
            agent_id="to_be_set",
            correlation_id=self.correlation_id,  # Will be filled after agent creation
        )
        self.add_step(start_cmd, timeout_seconds=30)

        # Step 4: Assign initial task if specified
        if self.agent_config.get("initial_task"):
            task_cmd = AssignTaskCommand(
                agent_id="to_be_set",
                task_definition=self.agent_config["initial_task"],
                priority=1,
                correlation_id=self.correlation_id,
            )
            self.add_step(task_cmd, timeout_seconds=60)

        return self.steps

    async def handle_step_success(
        self, step: SagaStep, response: CommandResponse
    ) -> Dict[str, Any]:
        context_updates = {}

        # Handle agent creation
        if isinstance(step.command, type(step.command)) and hasattr(
            step.command, "agent_type"
        ):
            if "agent_id" in response.generated_ids:
                agent_id = response.generated_ids["agent_id"]
                context_updates["agent_id"] = agent_id

                # Update subsequent steps with agent ID
                for future_step in self.steps[self.current_step_index + 1 :]:
                    if (
                        hasattr(future_step.command, "agent_id")
                        and future_step.command.agent_id == "to_be_set"
                    ):
                        future_step.command.agent_id = agent_id
                    if (
                        hasattr(future_step.command, "user_id")
                        and future_step.command.user_id == "agent_{}"
                    ):
                        future_step.command.user_id = f"agent_{agent_id}"

        return context_updates

    async def handle_step_failure(self, step: SagaStep, error: str) -> bool:
        # For agent provisioning, any failure should trigger compensation
        return False

    async def handle_compensation_failure(self, step: SagaStep, error: str) -> None:
        # Log compensation failure but continue
        print(f"Compensation failed for step {step.step_id}: {error}")


class TaskWorkflowSaga(Saga):
    """Saga for complex multi-step task workflows"""

    def __init__(
        self,
        workflow_definition: Dict[str, Any],
        saga_id: str = None,
        correlation_id: str = None,
    ):
        super().__init__(saga_id, correlation_id)
        self.workflow_definition = workflow_definition
        self.context = {"workflow": workflow_definition}

    def get_saga_type(self) -> str:
        return "task_workflow"

    async def configure_steps(self) -> List[SagaStep]:
        from .commands import AssignTaskCommand

        # Create steps from workflow definition
        for task_def in self.workflow_definition.get("tasks", []):
            cmd = AssignTaskCommand(
                agent_id=task_def["agent_id"],
                task_definition=task_def["definition"],
                priority=task_def.get("priority", 5),
                timeout_seconds=task_def.get("timeout"),
                correlation_id=self.correlation_id,
            )

            self.add_step(cmd, timeout_seconds=task_def.get("timeout", 300))

        return self.steps

    async def handle_step_success(
        self, step: SagaStep, response: CommandResponse
    ) -> Dict[str, Any]:
        context_updates = {}

        if "task_id" in response.generated_ids:
            task_id = response.generated_ids["task_id"]
            context_updates[f"task_{self.current_step_index}_id"] = task_id

        return context_updates

    async def handle_step_failure(self, step: SagaStep, error: str) -> bool:
        # For workflows, we might want to continue with remaining tasks
        # depending on the workflow configuration
        return self.workflow_definition.get("continue_on_failure", False)

    async def handle_compensation_failure(self, step: SagaStep, error: str) -> None:
        print(f"Task workflow compensation failed for step {step.step_id}: {error}")


class SagaManager:
    """
    Manages saga execution, persistence, and recovery
    """

    def __init__(self, event_store: EventStore, command_bus: CommandBus):
        self.event_store = event_store
        self.command_bus = command_bus
        self.running_sagas: Dict[str, Saga] = {}
        self.saga_types: Dict[str, type] = {}
        self.is_running = False
        self._processor_task: Optional[asyncio.Task] = None

    def register_saga_type(self, saga_type: str, saga_class: type):
        """Register a saga type for recovery"""
        self.saga_types[saga_type] = saga_class

    async def start_saga(self, saga: Saga) -> str:
        """Start executing a saga"""
        # Configure steps
        await saga.configure_steps()

        # Persist saga started event
        await self._emit_saga_event(
            saga,
            SagaEvent.SAGA_STARTED,
            {
                "saga_type": saga.get_saga_type(),
                "context": saga.context,
                "total_steps": len(saga.steps),
            },
        )

        # Add to running sagas
        self.running_sagas[saga.saga_id] = saga
        saga.status = SagaStatus.RUNNING

        # Start processing (async)
        asyncio.create_task(self._process_saga(saga))

        return saga.saga_id

    async def _process_saga(self, saga: Saga):
        """Process a saga step by step"""
        try:
            while saga.current_step_index < len(saga.steps):
                step = saga.steps[saga.current_step_index]

                # Execute step
                success = await self._execute_step(saga, step)

                if success:
                    saga.current_step_index += 1
                else:
                    # Step failed, start compensation
                    await self._compensate_saga(saga)
                    break

            # All steps completed successfully
            if saga.current_step_index >= len(saga.steps):
                saga.status = SagaStatus.COMPLETED
                saga.completed_at = datetime.utcnow()

                await self._emit_saga_event(
                    saga,
                    SagaEvent.SAGA_COMPLETED,
                    {
                        "total_steps": len(saga.steps),
                        "duration_seconds": (
                            datetime.utcnow() - saga.started_at
                        ).total_seconds(),
                    },
                )

        except Exception as e:
            saga.status = SagaStatus.FAILED
            saga.error_message = str(e)

            await self._emit_saga_event(
                saga,
                SagaEvent.SAGA_FAILED,
                {"error": str(e), "current_step": saga.current_step_index},
            )

            await self._compensate_saga(saga)

        finally:
            # Remove from running sagas
            if saga.saga_id in self.running_sagas:
                del self.running_sagas[saga.saga_id]

    async def _execute_step(self, saga: Saga, step: SagaStep) -> bool:
        """Execute a single saga step"""
        step.execution_time = datetime.utcnow()

        await self._emit_saga_event(
            saga,
            SagaEvent.SAGA_STEP_STARTED,
            {
                "step_id": step.step_id,
                "command_type": type(step.command).__name__,
                "retry_count": step.retry_count,
            },
        )

        for attempt in range(step.max_retries + 1):
            try:
                # Set timeout if specified
                if step.timeout_seconds:
                    response = await asyncio.wait_for(
                        self.command_bus.execute(step.command),
                        timeout=step.timeout_seconds,
                    )
                else:
                    response = await self.command_bus.execute(step.command)

                if response.result == CommandResult.SUCCESS:
                    step.executed = True
                    step.succeeded = True

                    # Update context
                    context_updates = await saga.handle_step_success(step, response)
                    saga.context.update(context_updates)

                    await self._emit_saga_event(
                        saga,
                        SagaEvent.SAGA_STEP_COMPLETED,
                        {
                            "step_id": step.step_id,
                            "attempt": attempt + 1,
                            "context_updates": context_updates,
                        },
                    )

                    return True

                else:
                    step.error_message = response.error_message

                    if attempt < step.max_retries:
                        step.retry_count += 1
                        await asyncio.sleep(step.retry_delay_seconds)
                    else:
                        step.executed = True
                        step.succeeded = False

                        await self._emit_saga_event(
                            saga,
                            SagaEvent.SAGA_STEP_FAILED,
                            {
                                "step_id": step.step_id,
                                "error": response.error_message,
                                "final_attempt": True,
                            },
                        )

                        # Let saga decide whether to continue
                        should_continue = await saga.handle_step_failure(
                            step, response.error_message
                        )
                        return should_continue

            except asyncio.TimeoutError:
                step.error_message = "Step execution timeout"

                if attempt < step.max_retries:
                    step.retry_count += 1
                    await asyncio.sleep(step.retry_delay_seconds)
                else:
                    step.executed = True
                    step.succeeded = False

                    await self._emit_saga_event(
                        saga,
                        SagaEvent.SAGA_TIMEOUT,
                        {
                            "step_id": step.step_id,
                            "timeout_seconds": step.timeout_seconds,
                        },
                    )

                    should_continue = await saga.handle_step_failure(step, "Timeout")
                    return should_continue

            except Exception as e:
                step.error_message = str(e)

                if attempt < step.max_retries:
                    step.retry_count += 1
                    await asyncio.sleep(step.retry_delay_seconds)
                else:
                    step.executed = True
                    step.succeeded = False

                    await self._emit_saga_event(
                        saga,
                        SagaEvent.SAGA_STEP_FAILED,
                        {
                            "step_id": step.step_id,
                            "error": str(e),
                            "final_attempt": True,
                        },
                    )

                    should_continue = await saga.handle_step_failure(step, str(e))
                    return should_continue

        return False

    async def _compensate_saga(self, saga: Saga):
        """Execute compensation steps in reverse order"""
        saga.status = SagaStatus.COMPENSATING

        # Execute compensation steps in reverse order for completed steps only
        for i in range(saga.current_step_index - 1, -1, -1):
            step = saga.steps[i]

            if step.succeeded and step.compensation_command:
                try:
                    response = await self.command_bus.execute(step.compensation_command)

                    if response.result == CommandResult.SUCCESS:
                        await self._emit_saga_event(
                            saga,
                            SagaEvent.SAGA_STEP_COMPENSATED,
                            {"step_id": step.step_id, "compensation_success": True},
                        )
                    else:
                        await saga.handle_compensation_failure(
                            step, response.error_message
                        )

                        await self._emit_saga_event(
                            saga,
                            SagaEvent.SAGA_STEP_COMPENSATED,
                            {
                                "step_id": step.step_id,
                                "compensation_success": False,
                                "error": response.error_message,
                            },
                        )

                except Exception as e:
                    await saga.handle_compensation_failure(step, str(e))

                    await self._emit_saga_event(
                        saga,
                        SagaEvent.SAGA_STEP_COMPENSATED,
                        {
                            "step_id": step.step_id,
                            "compensation_success": False,
                            "error": str(e),
                        },
                    )

        saga.status = SagaStatus.COMPENSATED
        saga.completed_at = datetime.utcnow()

        await self._emit_saga_event(
            saga,
            SagaEvent.SAGA_COMPENSATED,
            {
                "compensated_steps": sum(1 for s in saga.steps if s.succeeded),
                "duration_seconds": (
                    datetime.utcnow() - saga.started_at
                ).total_seconds(),
            },
        )

    async def _emit_saga_event(self, saga: Saga, event_type: str, data: Dict[str, Any]):
        """Emit saga event to event store"""
        metadata = EventMetadata.create(
            correlation_id=saga.correlation_id,
            user_id=getattr(saga, "user_id", None),
            tenant_id=getattr(saga, "tenant_id", None),
        )

        event_data = {
            "saga_id": saga.saga_id,
            "saga_type": saga.get_saga_type(),
            "status": saga.status.value,
            **data,
        }

        # Create custom event type for saga events
        from .event_store import Event

        event = Event(
            event_type=EventType.SYSTEM_STARTED,  # We'll need to add saga event types
            data=event_data,
            metadata=metadata,
            stream_id=f"saga_{saga.saga_id}",
            stream_version=0,
        )

        try:
            current_version = await self.event_store.get_stream_version(
                f"saga_{saga.saga_id}"
            )
            await self.event_store.append_events(
                f"saga_{saga.saga_id}", [event], current_version
            )
        except Exception as e:
            print(f"Failed to emit saga event: {e}")

    async def get_saga_status(self, saga_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a saga"""
        if saga_id in self.running_sagas:
            saga = self.running_sagas[saga_id]
            return {
                "saga_id": saga_id,
                "status": saga.status.value,
                "current_step": saga.current_step_index,
                "total_steps": len(saga.steps),
                "context": saga.context,
                "started_at": saga.started_at.isoformat(),
                "completed_at": (
                    saga.completed_at.isoformat() if saga.completed_at else None
                ),
            }

        # Check event store for completed saga
        try:
            events = await self.event_store.get_events(f"saga_{saga_id}")
            if events:
                latest_event = events[-1]
                return {
                    "saga_id": saga_id,
                    "status": latest_event.data.get("status", "unknown"),
                    "last_event": latest_event.event_type.value,
                    "timestamp": latest_event.metadata.timestamp.isoformat(),
                }
        except Exception:
            pass

        return None

    def get_running_sagas(self) -> List[Dict[str, Any]]:
        """Get list of currently running sagas"""
        return [
            {
                "saga_id": saga_id,
                "saga_type": saga.get_saga_type(),
                "status": saga.status.value,
                "current_step": saga.current_step_index,
                "total_steps": len(saga.steps),
                "started_at": saga.started_at.isoformat(),
            }
            for saga_id, saga in self.running_sagas.items()
        ]
