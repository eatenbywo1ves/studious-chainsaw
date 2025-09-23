"""
Integration module for connecting Event Sourcing/CQRS to existing API Gateway

Provides:
- Event sourcing middleware for API Gateway
- Command/Query endpoint adapters
- Projection synchronization
- Migration utilities from existing system
"""

from functools import wraps
from typing import Any, Dict, List

from libraries.database import DatabaseManager

from .commands import (
    AssignTaskCommand,
    CommandBus,
    CommandResult,
    CreateAgentCommand,
    StartAgentCommand,
)
from .event_store import Event, EventMetadata, EventStore, EventType
from .projections import (
    AgentListProjection,
    ProjectionManager,
    SystemMetricsProjection,
    TaskListProjection,
)
from .queries import (
    GetAgentQuery,
    GetSystemStatsQuery,
    GetTaskQuery,
    ListAgentsQuery,
    QueryBus,
    QueryResult,
)
from .sagas import AgentProvisioningSaga, SagaManager, TaskWorkflowSaga


class EventSourcingIntegration:
    """
    Integration service for Event Sourcing/CQRS system
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

        # Core components
        self.event_store = EventStore(db_manager)
        self.command_bus = CommandBus()
        self.query_bus = QueryBus()
        self.projection_manager = ProjectionManager(self.event_store)
        self.saga_manager = SagaManager(self.event_store, self.command_bus)

        # State
        self.initialized = False

    async def initialize(self):
        """Initialize the event sourcing system"""
        if self.initialized:
            return

        # Initialize event store
        await self.event_store.initialize()

        # Register command handlers
        await self._register_command_handlers()

        # Register query handlers
        await self._register_query_handlers()

        # Register projections
        await self._register_projections()

        # Register saga types
        await self._register_saga_types()

        # Start projection updates
        await self.projection_manager.start_continuous_update(interval_seconds=5)

        self.initialized = True

    async def _register_command_handlers(self):
        """Register all command handlers"""
        from .commands import (
            AssignTaskCommandHandler,
            CreateAgentCommandHandler,
            StartAgentCommandHandler,
        )

        self.command_bus.register_handler(
            CreateAgentCommand, CreateAgentCommandHandler(self.event_store)
        )
        self.command_bus.register_handler(
            StartAgentCommand, StartAgentCommandHandler(self.event_store)
        )
        self.command_bus.register_handler(
            AssignTaskCommand, AssignTaskCommandHandler(self.event_store)
        )

    async def _register_query_handlers(self):
        """Register all query handlers"""
        from .queries import (
            GetAgentQueryHandler,
            GetSystemStatsQueryHandler,
            GetTaskQueryHandler,
            ListAgentsQueryHandler,
        )

        self.query_bus.register_handler(
            GetAgentQuery, GetAgentQueryHandler(self.event_store)
        )
        self.query_bus.register_handler(
            ListAgentsQuery, ListAgentsQueryHandler(self.event_store)
        )
        self.query_bus.register_handler(
            GetTaskQuery, GetTaskQueryHandler(self.event_store)
        )
        self.query_bus.register_handler(
            GetSystemStatsQuery, GetSystemStatsQueryHandler(self.event_store)
        )

    async def _register_projections(self):
        """Register all projections"""
        # Agent list projection
        agent_projection = AgentListProjection()
        self.projection_manager.register_projection(agent_projection)

        # Task list projection
        task_projection = TaskListProjection()
        self.projection_manager.register_projection(task_projection)

        # System metrics projection
        metrics_projection = SystemMetricsProjection()
        self.projection_manager.register_projection(metrics_projection)

        # Initial rebuild of projections
        await self.projection_manager.rebuild_all_projections()

    async def _register_saga_types(self):
        """Register saga types for recovery"""
        self.saga_manager.register_saga_type(
            "agent_provisioning", AgentProvisioningSaga
        )
        self.saga_manager.register_saga_type("task_workflow", TaskWorkflowSaga)

    async def shutdown(self):
        """Shutdown the event sourcing system"""
        if not self.initialized:
            return

        await self.projection_manager.stop_continuous_update()
        self.initialized = False

    # Command endpoints
    async def create_agent(
        self, request_data: Dict[str, Any], user_id: str = None, tenant_id: str = None
    ) -> Dict[str, Any]:
        """Create agent through event sourcing"""
        command = CreateAgentCommand(
            agent_type=request_data["agent_type"],
            configuration=request_data["configuration"],
            tenant_id=tenant_id or request_data["tenant_id"],
            name=request_data.get("name"),
            description=request_data.get("description"),
            user_id=user_id,
            tenant_id=tenant_id,
        )

        response = await self.command_bus.execute(command)

        if response.result == CommandResult.SUCCESS:
            return {
                "success": True,
                "agent_id": response.generated_ids.get("agent_id"),
                "correlation_id": response.correlation_id,
                "events_generated": len(response.events),
            }
        else:
            return {
                "success": False,
                "error": response.error_message,
                "correlation_id": response.correlation_id,
            }

    async def start_agent(
        self, agent_id: str, user_id: str = None, tenant_id: str = None
    ) -> Dict[str, Any]:
        """Start agent through event sourcing"""
        command = StartAgentCommand(
            agent_id=agent_id, user_id=user_id, tenant_id=tenant_id
        )

        response = await self.command_bus.execute(command)

        return {
            "success": response.result == CommandResult.SUCCESS,
            "error": (
                response.error_message
                if response.result != CommandResult.SUCCESS
                else None
            ),
            "correlation_id": response.correlation_id,
        }

    async def assign_task(
        self, request_data: Dict[str, Any], user_id: str = None, tenant_id: str = None
    ) -> Dict[str, Any]:
        """Assign task through event sourcing"""
        command = AssignTaskCommand(
            agent_id=request_data["agent_id"],
            task_definition=request_data["task_definition"],
            priority=request_data.get("priority", 5),
            timeout_seconds=request_data.get("timeout_seconds"),
            user_id=user_id,
            tenant_id=tenant_id,
        )

        response = await self.command_bus.execute(command)

        if response.result == CommandResult.SUCCESS:
            return {
                "success": True,
                "task_id": response.generated_ids.get("task_id"),
                "correlation_id": response.correlation_id,
            }
        else:
            return {
                "success": False,
                "error": response.error_message,
                "correlation_id": response.correlation_id,
            }

    async def provision_agent_with_workflow(
        self, request_data: Dict[str, Any], user_id: str = None, tenant_id: str = None
    ) -> Dict[str, Any]:
        """Provision agent using saga pattern"""
        saga = AgentProvisioningSaga(
            tenant_id=tenant_id or request_data["tenant_id"],
            agent_config=request_data["agent_config"],
            correlation_id=request_data.get("correlation_id"),
        )

        saga.user_id = user_id
        saga.tenant_id = tenant_id

        saga_id = await self.saga_manager.start_saga(saga)

        return {
            "success": True,
            "saga_id": saga_id,
            "correlation_id": saga.correlation_id,
            "status": "started",
        }

    # Query endpoints
    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """Get agent details through query side"""
        query = GetAgentQuery(agent_id=agent_id)
        response = await self.query_bus.execute(query)

        if response.result == QueryResult.SUCCESS:
            projection = response.data
            return {
                "success": True,
                "agent": {
                    "agent_id": projection.agent_id,
                    "tenant_id": projection.tenant_id,
                    "agent_type": projection.agent_type,
                    "name": projection.name,
                    "description": projection.description,
                    "status": projection.status,
                    "configuration": projection.configuration,
                    "created_at": (
                        projection.created_at.isoformat()
                        if projection.created_at
                        else None
                    ),
                    "updated_at": (
                        projection.updated_at.isoformat()
                        if projection.updated_at
                        else None
                    ),
                    "version": projection.version,
                },
                "query_time_ms": response.query_time_ms,
            }
        elif response.result == QueryResult.NOT_FOUND:
            return {"success": False, "error": "Agent not found", "agent_id": agent_id}
        else:
            return {"success": False, "error": response.error_message}

    async def list_agents(
        self,
        tenant_id: str = None,
        agent_type: str = None,
        status: str = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        """List agents through query side"""
        query = ListAgentsQuery(
            tenant_id=tenant_id,
            agent_type=agent_type,
            status=status,
            page=page,
            page_size=page_size,
        )

        response = await self.query_bus.execute(query)

        if response.result == QueryResult.SUCCESS:
            agents = []
            for projection in response.data:
                agents.append(
                    {
                        "agent_id": projection.agent_id,
                        "tenant_id": projection.tenant_id,
                        "agent_type": projection.agent_type,
                        "name": projection.name,
                        "status": projection.status,
                        "created_at": (
                            projection.created_at.isoformat()
                            if projection.created_at
                            else None
                        ),
                        "updated_at": (
                            projection.updated_at.isoformat()
                            if projection.updated_at
                            else None
                        ),
                    }
                )

            return {
                "success": True,
                "agents": agents,
                "total_count": response.total_count,
                "page": page,
                "page_size": page_size,
                "query_time_ms": response.query_time_ms,
            }
        else:
            return {"success": False, "error": response.error_message}

    async def get_system_stats(
        self, tenant_id: str = None, time_window: str = "1h"
    ) -> Dict[str, Any]:
        """Get system statistics"""
        query = GetSystemStatsQuery(tenant_id=tenant_id, time_window=time_window)
        response = await self.query_bus.execute(query)

        if response.result == QueryResult.SUCCESS:
            return {
                "success": True,
                "stats": response.data,
                "query_time_ms": response.query_time_ms,
            }
        else:
            return {"success": False, "error": response.error_message}

    async def get_saga_status(self, saga_id: str) -> Dict[str, Any]:
        """Get saga execution status"""
        status = await self.saga_manager.get_saga_status(saga_id)

        if status:
            return {"success": True, "saga": status}
        else:
            return {"success": False, "error": "Saga not found", "saga_id": saga_id}

    # Projection endpoints
    async def get_projection_state(self, projection_name: str) -> Dict[str, Any]:
        """Get current state of a projection"""
        state = await self.projection_manager.get_projection_state(projection_name)

        if state:
            return {"success": True, "projection": projection_name, "state": state}
        else:
            return {
                "success": False,
                "error": f"Projection {projection_name} not found",
            }

    async def rebuild_projection(self, projection_name: str) -> Dict[str, Any]:
        """Rebuild a projection from events"""
        try:
            await self.projection_manager.rebuild_projection(projection_name)
            return {
                "success": True,
                "message": f"Projection {projection_name} rebuilt successfully",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to rebuild projection {projection_name}: {str(e)}",
            }

    async def get_projection_health(self) -> Dict[str, Any]:
        """Get health status of all projections"""
        health = self.projection_manager.get_projection_health()

        return {"success": True, "projections": health, "total_count": len(health)}

    # Event store endpoints
    async def get_event_store_stats(self) -> Dict[str, Any]:
        """Get event store statistics"""
        stats = await self.event_store.get_statistics()

        return {"success": True, "event_store": stats}

    async def get_stream_events(
        self, stream_id: str, from_version: int = 0, to_version: int = None
    ) -> Dict[str, Any]:
        """Get events from a specific stream"""
        try:
            events = await self.event_store.get_events(
                stream_id, from_version, to_version
            )

            event_data = []
            for event in events:
                event_data.append(
                    {
                        "event_type": event.event_type.value,
                        "data": event.data,
                        "metadata": {
                            "event_id": event.metadata.event_id,
                            "timestamp": event.metadata.timestamp.isoformat(),
                            "correlation_id": event.metadata.correlation_id,
                            "user_id": event.metadata.user_id,
                            "tenant_id": event.metadata.tenant_id,
                        },
                        "stream_version": event.stream_version,
                    }
                )

            return {
                "success": True,
                "stream_id": stream_id,
                "events": event_data,
                "count": len(event_data),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


def event_sourcing_middleware(integration: EventSourcingIntegration):
    """
    Middleware decorator for API Gateway endpoints to use event sourcing
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Ensure integration is initialized
            if not integration.initialized:
                await integration.initialize()

            # Execute original function
            return await func(*args, **kwargs)

        return wrapper

    return decorator


class EventSourcingMigration:
    """
    Utilities for migrating from existing system to event sourcing
    """

    def __init__(self, integration: EventSourcingIntegration):
        self.integration = integration

    async def migrate_existing_agents(self, existing_agents: List[Dict[str, Any]]):
        """Migrate existing agents to event sourcing"""
        migrated = []
        errors = []

        for agent_data in existing_agents:
            try:
                # Create agent creation event
                metadata = EventMetadata.create(
                    correlation_id=f"migration_{agent_data['id']}",
                    user_id="system",
                    tenant_id=agent_data.get("tenant_id"),
                )

                create_event = Event(
                    event_type=EventType.AGENT_CREATED,
                    data={
                        "agent_id": agent_data["id"],
                        "tenant_id": agent_data.get("tenant_id"),
                        "agent_type": agent_data.get("type", "unknown"),
                        "name": agent_data.get("name"),
                        "description": agent_data.get("description"),
                        "created_by": "migration",
                    },
                    metadata=metadata,
                    stream_id=f"agent_{agent_data['id']}",
                    stream_version=1,
                )

                events = [create_event]

                # Add configuration event if present
                if agent_data.get("configuration"):
                    config_event = Event(
                        event_type=EventType.AGENT_CONFIGURED,
                        data={
                            "agent_id": agent_data["id"],
                            "configuration": agent_data["configuration"],
                        },
                        metadata=EventMetadata.create(
                            correlation_id=f"migration_{agent_data['id']}",
                            user_id="system",
                            tenant_id=agent_data.get("tenant_id"),
                        ),
                        stream_id=f"agent_{agent_data['id']}",
                        stream_version=2,
                    )
                    events.append(config_event)

                # Add status event if running
                if agent_data.get("status") == "running":
                    status_event = Event(
                        event_type=EventType.AGENT_STARTED,
                        data={"agent_id": agent_data["id"]},
                        metadata=EventMetadata.create(
                            correlation_id=f"migration_{agent_data['id']}",
                            user_id="system",
                            tenant_id=agent_data.get("tenant_id"),
                        ),
                        stream_id=f"agent_{agent_data['id']}",
                        stream_version=len(events) + 1,
                    )
                    events.append(status_event)

                # Append events to store
                await self.integration.event_store.append_events(
                    f"agent_{agent_data['id']}", events, expected_version=0
                )

                migrated.append(agent_data["id"])

            except Exception as e:
                errors.append({"agent_id": agent_data["id"], "error": str(e)})

        return {
            "migrated_count": len(migrated),
            "error_count": len(errors),
            "migrated_agents": migrated,
            "errors": errors,
        }

    async def validate_migration(self) -> Dict[str, Any]:
        """Validate migration by comparing event store data with projections"""
        # Get all agent streams
        agent_streams = await self.integration.event_store.get_all_stream_ids("agent_")

        validation_results = {
            "total_streams": len(agent_streams),
            "valid_streams": 0,
            "invalid_streams": 0,
            "errors": [],
        }

        for stream_id in agent_streams:
            try:
                # Get events
                events = await self.integration.event_store.get_events(stream_id)

                # Build projection
                from .queries import AgentProjection

                projection = AgentProjection.from_events(events)

                # Basic validation
                if projection.agent_id and projection.agent_type:
                    validation_results["valid_streams"] += 1
                else:
                    validation_results["invalid_streams"] += 1
                    validation_results["errors"].append(
                        {"stream_id": stream_id, "error": "Invalid projection data"}
                    )

            except Exception as e:
                validation_results["invalid_streams"] += 1
                validation_results["errors"].append(
                    {"stream_id": stream_id, "error": str(e)}
                )

        return validation_results
