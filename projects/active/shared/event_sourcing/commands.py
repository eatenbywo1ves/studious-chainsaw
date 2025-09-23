"""
Command Side of CQRS Implementation

Handles command processing, validation, and event generation:
- Command definitions and validation
- Command bus for routing and execution
- Command handlers that generate events
- Saga coordination for distributed transactions
"""

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type

from .event_store import Event, EventMetadata, EventStore, EventType


class CommandResult(Enum):
    """Command execution result status"""

    SUCCESS = "success"
    VALIDATION_ERROR = "validation_error"
    BUSINESS_ERROR = "business_error"
    SYSTEM_ERROR = "system_error"


@dataclass
class CommandResponse:
    """Response from command execution"""

    result: CommandResult
    events: List[Event] = field(default_factory=list)
    error_message: Optional[str] = None
    correlation_id: Optional[str] = None
    generated_ids: Dict[str, str] = field(default_factory=dict)


class Command(ABC):
    """Base command class with metadata"""

    def __init__(
        self,
        correlation_id: str = None,
        user_id: str = None,
        tenant_id: str = None,
        **kwargs,
    ):
        self.command_id = str(uuid.uuid4())
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.timestamp = datetime.utcnow()

        # Set additional attributes
        for key, value in kwargs.items():
            setattr(self, key, value)

    @abstractmethod
    def validate(self) -> List[str]:
        """Validate command and return list of validation errors"""

    def get_stream_id(self) -> str:
        """Get the stream ID this command will affect"""
        return getattr(
            self, "stream_id", f"{self.__class__.__name__.lower()}_{self.command_id}"
        )


class CommandHandler(ABC):
    """Base command handler"""

    def __init__(self, event_store: EventStore):
        self.event_store = event_store

    @abstractmethod
    async def handle(self, command: Command) -> CommandResponse:
        """Handle the command and return response with events"""

    async def create_events(
        self,
        stream_id: str,
        event_types_and_data: List[tuple],
        metadata_template: EventMetadata,
    ) -> List[Event]:
        """Helper to create events with consistent metadata"""
        events = []
        for event_type, data in event_types_and_data:
            metadata = EventMetadata(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                correlation_id=metadata_template.correlation_id,
                causation_id=metadata_template.event_id,
                user_id=metadata_template.user_id,
                tenant_id=metadata_template.tenant_id,
            )

            event = Event(
                event_type=event_type,
                data=data,
                metadata=metadata,
                stream_id=stream_id,
                stream_version=0,  # Will be set by event store
            )
            events.append(event)

        return events


# Agent Commands


@dataclass
class CreateAgentCommand(Command):
    """Command to create a new agent"""

    agent_type: str
    configuration: Dict[str, Any]
    tenant_id: str
    name: Optional[str] = None
    description: Optional[str] = None

    def validate(self) -> List[str]:
        errors = []
        if not self.agent_type:
            errors.append("agent_type is required")
        if not self.configuration:
            errors.append("configuration is required")
        if not self.tenant_id:
            errors.append("tenant_id is required")
        return errors

    def get_stream_id(self) -> str:
        return f"agent_{getattr(self, 'agent_id', self.command_id)}"


@dataclass
class ConfigureAgentCommand(Command):
    """Command to configure an existing agent"""

    agent_id: str
    configuration: Dict[str, Any]

    def validate(self) -> List[str]:
        errors = []
        if not self.agent_id:
            errors.append("agent_id is required")
        if not self.configuration:
            errors.append("configuration is required")
        return errors

    def get_stream_id(self) -> str:
        return f"agent_{self.agent_id}"


@dataclass
class StartAgentCommand(Command):
    """Command to start an agent"""

    agent_id: str

    def validate(self) -> List[str]:
        return ["agent_id is required"] if not self.agent_id else []

    def get_stream_id(self) -> str:
        return f"agent_{self.agent_id}"


@dataclass
class StopAgentCommand(Command):
    """Command to stop an agent"""

    agent_id: str
    reason: Optional[str] = None
    graceful: bool = True

    def validate(self) -> List[str]:
        return ["agent_id is required"] if not self.agent_id else []

    def get_stream_id(self) -> str:
        return f"agent_{self.agent_id}"


# Task Commands


@dataclass
class AssignTaskCommand(Command):
    """Command to assign task to agent"""

    agent_id: str
    task_definition: Dict[str, Any]
    priority: int = 5
    timeout_seconds: Optional[int] = None

    def validate(self) -> List[str]:
        errors = []
        if not self.agent_id:
            errors.append("agent_id is required")
        if not self.task_definition:
            errors.append("task_definition is required")
        if self.priority < 1 or self.priority > 10:
            errors.append("priority must be between 1 and 10")
        return errors

    def get_stream_id(self) -> str:
        return f"task_{getattr(self, 'task_id', self.command_id)}"


@dataclass
class CompleteTaskCommand(Command):
    """Command to mark task as completed"""

    task_id: str
    agent_id: str
    result: Dict[str, Any]

    def validate(self) -> List[str]:
        errors = []
        if not self.task_id:
            errors.append("task_id is required")
        if not self.agent_id:
            errors.append("agent_id is required")
        return errors

    def get_stream_id(self) -> str:
        return f"task_{self.task_id}"


# Security Commands


@dataclass
class UpdateSecurityPolicyCommand(Command):
    """Command to update security policy"""

    policy_id: str
    policy_data: Dict[str, Any]
    version: str

    def validate(self) -> List[str]:
        errors = []
        if not self.policy_id:
            errors.append("policy_id is required")
        if not self.policy_data:
            errors.append("policy_data is required")
        if not self.version:
            errors.append("version is required")
        return errors

    def get_stream_id(self) -> str:
        return f"security_policy_{self.policy_id}"


@dataclass
class GrantAccessCommand(Command):
    """Command to grant access to resource"""

    user_id: str
    resource_id: str
    permissions: List[str]
    expires_at: Optional[datetime] = None

    def validate(self) -> List[str]:
        errors = []
        if not self.user_id:
            errors.append("user_id is required")
        if not self.resource_id:
            errors.append("resource_id is required")
        if not self.permissions:
            errors.append("permissions is required")
        return errors

    def get_stream_id(self) -> str:
        return f"access_{self.user_id}_{self.resource_id}"


# Command Handlers


class CreateAgentCommandHandler(CommandHandler):
    """Handler for creating new agents"""

    async def handle(self, command: CreateAgentCommand) -> CommandResponse:
        try:
            # Validate command
            errors = command.validate()
            if errors:
                return CommandResponse(
                    result=CommandResult.VALIDATION_ERROR,
                    error_message="; ".join(errors),
                )

            # Generate agent ID
            agent_id = str(uuid.uuid4())
            stream_id = f"agent_{agent_id}"

            # Create metadata
            metadata = EventMetadata.create(
                correlation_id=command.correlation_id,
                user_id=command.user_id,
                tenant_id=command.tenant_id,
            )

            # Create events
            events = await self.create_events(
                stream_id=stream_id,
                event_types_and_data=[
                    (
                        EventType.AGENT_CREATED,
                        {
                            "agent_id": agent_id,
                            "agent_type": command.agent_type,
                            "tenant_id": command.tenant_id,
                            "name": command.name,
                            "description": command.description,
                            "created_by": command.user_id,
                        },
                    ),
                    (
                        EventType.AGENT_CONFIGURED,
                        {"agent_id": agent_id, "configuration": command.configuration},
                    ),
                ],
                metadata_template=metadata,
            )

            # Store events
            await self.event_store.append_events(stream_id, events, expected_version=0)

            return CommandResponse(
                result=CommandResult.SUCCESS,
                events=events,
                correlation_id=command.correlation_id,
                generated_ids={"agent_id": agent_id},
            )

        except Exception as e:
            return CommandResponse(
                result=CommandResult.SYSTEM_ERROR,
                error_message=str(e),
                correlation_id=command.correlation_id,
            )


class StartAgentCommandHandler(CommandHandler):
    """Handler for starting agents"""

    async def handle(self, command: StartAgentCommand) -> CommandResponse:
        try:
            errors = command.validate()
            if errors:
                return CommandResponse(
                    result=CommandResult.VALIDATION_ERROR,
                    error_message="; ".join(errors),
                )

            stream_id = command.get_stream_id()

            # Check if agent exists
            if not await self.event_store.stream_exists(stream_id):
                return CommandResponse(
                    result=CommandResult.BUSINESS_ERROR,
                    error_message=f"Agent {command.agent_id} does not exist",
                )

            # Get current version
            current_version = await self.event_store.get_stream_version(stream_id)

            # Create metadata
            metadata = EventMetadata.create(
                correlation_id=command.correlation_id,
                user_id=command.user_id,
                tenant_id=command.tenant_id,
            )

            # Create event
            events = await self.create_events(
                stream_id=stream_id,
                event_types_and_data=[
                    (
                        EventType.AGENT_STARTED,
                        {
                            "agent_id": command.agent_id,
                            "started_by": command.user_id,
                            "started_at": datetime.utcnow().isoformat(),
                        },
                    )
                ],
                metadata_template=metadata,
            )

            # Store event
            await self.event_store.append_events(
                stream_id, events, expected_version=current_version
            )

            return CommandResponse(
                result=CommandResult.SUCCESS,
                events=events,
                correlation_id=command.correlation_id,
            )

        except Exception as e:
            return CommandResponse(
                result=CommandResult.SYSTEM_ERROR,
                error_message=str(e),
                correlation_id=command.correlation_id,
            )


class AssignTaskCommandHandler(CommandHandler):
    """Handler for assigning tasks"""

    async def handle(self, command: AssignTaskCommand) -> CommandResponse:
        try:
            errors = command.validate()
            if errors:
                return CommandResponse(
                    result=CommandResult.VALIDATION_ERROR,
                    error_message="; ".join(errors),
                )

            # Generate task ID
            task_id = str(uuid.uuid4())
            stream_id = f"task_{task_id}"

            # Create metadata
            metadata = EventMetadata.create(
                correlation_id=command.correlation_id,
                user_id=command.user_id,
                tenant_id=command.tenant_id,
            )

            # Create events
            events = await self.create_events(
                stream_id=stream_id,
                event_types_and_data=[
                    (
                        EventType.TASK_ASSIGNED,
                        {
                            "task_id": task_id,
                            "agent_id": command.agent_id,
                            "task_definition": command.task_definition,
                            "priority": command.priority,
                            "timeout_seconds": command.timeout_seconds,
                            "assigned_by": command.user_id,
                            "assigned_at": datetime.utcnow().isoformat(),
                        },
                    )
                ],
                metadata_template=metadata,
            )

            # Store events
            await self.event_store.append_events(stream_id, events, expected_version=0)

            return CommandResponse(
                result=CommandResult.SUCCESS,
                events=events,
                correlation_id=command.correlation_id,
                generated_ids={"task_id": task_id},
            )

        except Exception as e:
            return CommandResponse(
                result=CommandResult.SYSTEM_ERROR,
                error_message=str(e),
                correlation_id=command.correlation_id,
            )


class CommandBus:
    """
    Command bus for routing commands to handlers
    Supports middleware for cross-cutting concerns
    """

    def __init__(self):
        self._handlers: Dict[Type[Command], CommandHandler] = {}
        self._middleware: List[Callable] = []

    def register_handler(self, command_type: Type[Command], handler: CommandHandler):
        """Register command handler"""
        self._handlers[command_type] = handler

    def add_middleware(self, middleware: Callable):
        """Add middleware for cross-cutting concerns"""
        self._middleware.append(middleware)

    async def execute(self, command: Command) -> CommandResponse:
        """Execute command through registered handler"""
        command_type = type(command)

        if command_type not in self._handlers:
            return CommandResponse(
                result=CommandResult.SYSTEM_ERROR,
                error_message=f"No handler registered for {command_type.__name__}",
            )

        handler = self._handlers[command_type]

        # Apply middleware
        for middleware in self._middleware:
            command = await middleware(command)

        # Execute command
        return await handler.handle(command)

    def get_registered_commands(self) -> List[Type[Command]]:
        """Get list of registered command types"""
        return list(self._handlers.keys())


# Middleware Examples


async def logging_middleware(command: Command) -> Command:
    """Log command execution"""
    print(f"Executing command: {type(command).__name__} (ID: {command.command_id})")
    return command


async def authentication_middleware(command: Command) -> Command:
    """Validate user authentication"""
    if not command.user_id:
        raise ValueError("Command must have authenticated user")
    return command


async def tenant_isolation_middleware(command: Command) -> Command:
    """Ensure tenant isolation"""
    if hasattr(command, "tenant_id") and not command.tenant_id:
        raise ValueError("Command must specify tenant_id")
    return command
