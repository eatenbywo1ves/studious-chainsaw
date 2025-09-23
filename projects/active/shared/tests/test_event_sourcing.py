"""
Comprehensive tests for Event Sourcing and CQRS implementation
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock

from event_sourcing import (
    EventStore,
    Event,
    EventType,
    EventMetadata,
    CommandBus,
    CommandResponse,
    CommandResult,
    QueryBus,
    QueryResult,
    ProjectionManager,
    SagaManager,
)
from event_sourcing.commands import (
    CreateAgentCommand,
    StartAgentCommand,
    CreateAgentCommandHandler,
    StartAgentCommandHandler,
)
from event_sourcing.queries import GetAgentQuery, GetAgentQueryHandler, AgentProjection
from event_sourcing.projections import AgentListProjection
from event_sourcing.sagas import AgentProvisioningSaga
from libraries.database import DatabaseManager


@pytest.fixture
async def mock_db_manager():
    """Mock database manager for testing"""
    db_manager = Mock(spec=DatabaseManager)

    # Mock connection context manager
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[])
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_conn.fetchval = AsyncMock(return_value=0)
    mock_conn.transaction = AsyncMock()
    mock_conn.cursor = AsyncMock()

    # Make cursor async iterable
    async def mock_cursor(*args):
        return []

    mock_conn.cursor.side_effect = mock_cursor

    db_manager.get_connection.return_value.__aenter__.return_value = mock_conn
    db_manager.get_connection.return_value.__aexit__.return_value = None

    return db_manager


@pytest.fixture
async def event_store(mock_db_manager):
    """Event store fixture"""
    store = EventStore(mock_db_manager)
    await store.initialize()
    return store


@pytest.fixture
def sample_metadata():
    """Sample event metadata"""
    return EventMetadata.create(
        correlation_id="test-correlation", user_id="test-user", tenant_id="test-tenant"
    )


class TestEventStore:
    """Test event store functionality"""

    @pytest.mark.asyncio
    async def test_event_creation(self, sample_metadata):
        """Test event creation and serialization"""
        event = Event(
            event_type=EventType.AGENT_CREATED,
            data={"agent_id": "test-agent", "type": "test"},
            metadata=sample_metadata,
            stream_id="agent_test",
            stream_version=1,
        )

        # Test serialization
        event_dict = event.to_dict()
        assert event_dict["event_type"] == "agent_created"
        assert event_dict["data"]["agent_id"] == "test-agent"

        # Test deserialization
        recreated_event = Event.from_dict(event_dict)
        assert recreated_event.event_type == EventType.AGENT_CREATED
        assert recreated_event.data["agent_id"] == "test-agent"

    @pytest.mark.asyncio
    async def test_append_events(self, event_store, sample_metadata):
        """Test appending events to stream"""
        events = [
            Event(
                event_type=EventType.AGENT_CREATED,
                data={"agent_id": "test-agent"},
                metadata=sample_metadata,
                stream_id="agent_test",
                stream_version=1,
            )
        ]

        # Mock successful append
        await event_store.append_events("agent_test", events, expected_version=0)

        # Verify database calls were made
        mock_conn = event_store.db.get_connection.return_value.__aenter__.return_value
        assert mock_conn.execute.called


class TestCommands:
    """Test command side of CQRS"""

    @pytest.mark.asyncio
    async def test_create_agent_command_validation(self):
        """Test command validation"""
        # Valid command
        cmd = CreateAgentCommand(
            agent_type="test-agent",
            configuration={"key": "value"},
            tenant_id="test-tenant",
        )
        errors = cmd.validate()
        assert len(errors) == 0

        # Invalid command
        invalid_cmd = CreateAgentCommand(agent_type="", configuration={}, tenant_id="")
        errors = invalid_cmd.validate()
        assert len(errors) > 0

    @pytest.mark.asyncio
    async def test_command_handler(self, event_store):
        """Test command handler execution"""
        handler = CreateAgentCommandHandler(event_store)

        cmd = CreateAgentCommand(
            agent_type="test-agent",
            configuration={"key": "value"},
            tenant_id="test-tenant",
            correlation_id="test-correlation",
        )

        response = await handler.handle(cmd)
        assert response.result == CommandResult.SUCCESS
        assert len(response.events) == 2  # Created and Configured events
        assert "agent_id" in response.generated_ids

    @pytest.mark.asyncio
    async def test_command_bus(self, event_store):
        """Test command bus routing"""
        bus = CommandBus()
        handler = CreateAgentCommandHandler(event_store)

        bus.register_handler(CreateAgentCommand, handler)

        cmd = CreateAgentCommand(
            agent_type="test-agent",
            configuration={"key": "value"},
            tenant_id="test-tenant",
        )

        response = await bus.execute(cmd)
        assert response.result == CommandResult.SUCCESS


class TestQueries:
    """Test query side of CQRS"""

    @pytest.mark.asyncio
    async def test_agent_projection_from_events(self, sample_metadata):
        """Test building agent projection from events"""
        events = [
            Event(
                event_type=EventType.AGENT_CREATED,
                data={
                    "agent_id": "test-agent",
                    "tenant_id": "test-tenant",
                    "agent_type": "test-type",
                    "name": "Test Agent",
                },
                metadata=sample_metadata,
                stream_id="agent_test",
                stream_version=1,
            ),
            Event(
                event_type=EventType.AGENT_STARTED,
                data={"agent_id": "test-agent"},
                metadata=sample_metadata,
                stream_id="agent_test",
                stream_version=2,
            ),
        ]

        projection = AgentProjection.from_events(events)
        assert projection.agent_id == "test-agent"
        assert projection.status == "running"
        assert projection.version == 2

    @pytest.mark.asyncio
    async def test_query_handler(self, event_store):
        """Test query handler execution"""
        # Mock event store methods
        event_store.stream_exists = AsyncMock(return_value=True)
        event_store.get_events = AsyncMock(
            return_value=[
                Event(
                    event_type=EventType.AGENT_CREATED,
                    data={
                        "agent_id": "test-agent",
                        "tenant_id": "test-tenant",
                        "agent_type": "test-type",
                    },
                    metadata=EventMetadata.create(),
                    stream_id="agent_test",
                    stream_version=1,
                )
            ]
        )

        handler = GetAgentQueryHandler(event_store)
        query = GetAgentQuery(agent_id="test-agent")

        response = await handler.handle(query)
        assert response.result == QueryResult.SUCCESS
        assert response.data.agent_id == "test-agent"

    @pytest.mark.asyncio
    async def test_query_bus_caching(self, event_store):
        """Test query bus caching mechanism"""
        bus = QueryBus()
        handler = GetAgentQueryHandler(event_store)

        # Mock successful response
        event_store.stream_exists = AsyncMock(return_value=True)
        event_store.get_events = AsyncMock(
            return_value=[
                Event(
                    event_type=EventType.AGENT_CREATED,
                    data={
                        "agent_id": "test-agent",
                        "tenant_id": "test-tenant",
                        "agent_type": "test-type",
                    },
                    metadata=EventMetadata.create(),
                    stream_id="agent_test",
                    stream_version=1,
                )
            ]
        )

        bus.register_handler(GetAgentQuery, handler)

        query = GetAgentQuery(agent_id="test-agent")

        # First execution
        response1 = await bus.execute(query)
        assert response1.result == QueryResult.SUCCESS

        # Second execution should use cache
        response2 = await bus.execute(query)
        assert response2.result == QueryResult.SUCCESS

        # Verify cache stats
        stats = bus.get_cache_stats()
        assert stats["cache_size"] == 1


class TestProjections:
    """Test projection management"""

    @pytest.mark.asyncio
    async def test_agent_list_projection(self, sample_metadata):
        """Test agent list projection updates"""
        projection = AgentListProjection()

        # Test agent creation
        create_event = Event(
            event_type=EventType.AGENT_CREATED,
            data={
                "agent_id": "test-agent",
                "tenant_id": "test-tenant",
                "agent_type": "test-type",
                "name": "Test Agent",
            },
            metadata=sample_metadata,
            stream_id="agent_test",
            stream_version=1,
        )

        await projection.handle_event(create_event)

        state = await projection.get_state()
        assert "test-agent" in state["agents"]
        assert state["agents"]["test-agent"]["status"] == "created"

        # Test agent start
        start_event = Event(
            event_type=EventType.AGENT_STARTED,
            data={"agent_id": "test-agent"},
            metadata=sample_metadata,
            stream_id="agent_test",
            stream_version=2,
        )

        await projection.handle_event(start_event)

        state = await projection.get_state()
        assert state["agents"]["test-agent"]["status"] == "running"

    @pytest.mark.asyncio
    async def test_projection_manager(self, event_store):
        """Test projection manager functionality"""
        manager = ProjectionManager(event_store)
        projection = AgentListProjection()

        manager.register_projection(projection)

        # Mock event store replay
        async def mock_replay():
            yield Event(
                event_type=EventType.AGENT_CREATED,
                data={
                    "agent_id": "test-agent",
                    "tenant_id": "test-tenant",
                    "agent_type": "test-type",
                },
                metadata=EventMetadata.create(),
                stream_id="agent_test",
                stream_version=1,
            )

        event_store.replay_events = mock_replay

        # Test projection rebuild
        await manager.rebuild_projection("agent_list")

        state = await manager.get_projection_state("agent_list")
        assert state["total_count"] == 1


class TestSagas:
    """Test saga pattern implementation"""

    @pytest.mark.asyncio
    async def test_agent_provisioning_saga(self):
        """Test agent provisioning saga"""
        saga = AgentProvisioningSaga(
            tenant_id="test-tenant",
            agent_config={
                "type": "test-agent",
                "name": "Test Agent",
                "configuration": {"key": "value"},
            },
        )

        steps = await saga.configure_steps()
        assert len(steps) >= 2  # Create and Start steps

        # Test step success handling
        from event_sourcing.commands import CommandResponse, CommandResult

        response = CommandResponse(
            result=CommandResult.SUCCESS, generated_ids={"agent_id": "new-agent-id"}
        )

        context_updates = await saga.handle_step_success(steps[0], response)
        assert "agent_id" in context_updates

    @pytest.mark.asyncio
    async def test_saga_manager(self, event_store):
        """Test saga manager functionality"""
        command_bus = CommandBus()
        manager = SagaManager(event_store, command_bus)

        # Register saga type
        manager.register_saga_type("agent_provisioning", AgentProvisioningSaga)

        saga = AgentProvisioningSaga(
            tenant_id="test-tenant", agent_config={"type": "test-agent", "name": "Test"}
        )

        # Mock command bus responses
        command_bus.execute = AsyncMock(
            return_value=CommandResponse(
                result=CommandResult.SUCCESS, generated_ids={"agent_id": "new-agent-id"}
            )
        )

        # Start saga
        saga_id = await manager.start_saga(saga)
        assert saga_id == saga.saga_id
        assert saga_id in manager.running_sagas

        # Wait a bit for processing
        await asyncio.sleep(0.1)

        # Check saga status
        status = await manager.get_saga_status(saga_id)
        assert status is not None


class TestIntegration:
    """Integration tests for the complete CQRS system"""

    @pytest.mark.asyncio
    async def test_complete_agent_lifecycle(self, event_store):
        """Test complete agent lifecycle through CQRS"""
        # Setup
        command_bus = CommandBus()
        query_bus = QueryBus()
        projection_manager = ProjectionManager(event_store)

        # Register handlers
        command_bus.register_handler(
            CreateAgentCommand, CreateAgentCommandHandler(event_store)
        )
        command_bus.register_handler(
            StartAgentCommand, StartAgentCommandHandler(event_store)
        )
        query_bus.register_handler(GetAgentQuery, GetAgentQueryHandler(event_store))

        # Register projections
        agent_projection = AgentListProjection()
        projection_manager.register_projection(agent_projection)

        # Mock event store for successful operations
        event_store.append_events = AsyncMock()
        event_store.get_stream_version = AsyncMock(return_value=0)
        event_store.stream_exists = AsyncMock(return_value=True)
        event_store.get_events = AsyncMock()

        # 1. Create agent
        create_cmd = CreateAgentCommand(
            agent_type="test-agent",
            configuration={"key": "value"},
            tenant_id="test-tenant",
            name="Test Agent",
        )

        create_response = await command_bus.execute(create_cmd)
        assert create_response.result == CommandResult.SUCCESS
        agent_id = create_response.generated_ids["agent_id"]

        # 2. Start agent
        start_cmd = StartAgentCommand(agent_id=agent_id)
        start_response = await command_bus.execute(start_cmd)
        assert start_response.result == CommandResult.SUCCESS

        # 3. Update projections with events
        all_events = create_response.events + start_response.events
        for event in all_events:
            if await agent_projection.can_handle(event):
                await agent_projection.handle_event(event)

        # 4. Query agent state
        event_store.get_events.return_value = all_events

        get_query = GetAgentQuery(agent_id=agent_id)
        get_response = await query_bus.execute(get_query)
        assert get_response.result == QueryResult.SUCCESS
        assert get_response.data.agent_id == agent_id
        assert get_response.data.status == "running"


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
