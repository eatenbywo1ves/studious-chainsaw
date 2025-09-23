"""
Event Store Implementation with PostgreSQL Backend

Provides enterprise-grade event storage with:
- ACID transaction guarantees
- Optimistic concurrency control
- Event versioning and metadata
- Stream-based organization
- Snapshot support for performance
"""

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional

import asyncpg

from libraries.database import DatabaseManager


class EventType(Enum):
    """Standard event types for the MCP system"""

    # Agent Lifecycle
    AGENT_CREATED = "agent_created"
    AGENT_CONFIGURED = "agent_configured"
    AGENT_STARTED = "agent_started"
    AGENT_STOPPED = "agent_stopped"
    AGENT_DELETED = "agent_deleted"

    # Task Management
    TASK_ASSIGNED = "task_assigned"
    TASK_STARTED = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_CANCELLED = "task_cancelled"

    # Security Events
    SECURITY_POLICY_UPDATED = "security_policy_updated"
    ACCESS_GRANTED = "access_granted"
    ACCESS_REVOKED = "access_revoked"
    AUTHENTICATION_SUCCEEDED = "authentication_succeeded"
    AUTHENTICATION_FAILED = "authentication_failed"

    # Multi-tenant Events
    TENANT_CREATED = "tenant_created"
    TENANT_CONFIGURED = "tenant_configured"
    TENANT_SUSPENDED = "tenant_suspended"
    BILLING_EVENT = "billing_event"

    # System Events
    SYSTEM_STARTED = "system_started"
    SYSTEM_STOPPED = "system_stopped"
    CONFIGURATION_UPDATED = "configuration_updated"
    HEALTH_CHECK_FAILED = "health_check_failed"


@dataclass
class EventMetadata:
    """Metadata associated with each event"""

    event_id: str
    timestamp: datetime
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    version: str = "1.0"

    @classmethod
    def create(
        cls,
        correlation_id: str = None,
        causation_id: str = None,
        user_id: str = None,
        tenant_id: str = None,
    ) -> "EventMetadata":
        return cls(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            correlation_id=correlation_id,
            causation_id=causation_id,
            user_id=user_id,
            tenant_id=tenant_id,
        )


@dataclass
class Event:
    """Domain event with metadata and payload"""

    event_type: EventType
    data: Dict[str, Any]
    metadata: EventMetadata
    stream_id: str
    stream_version: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization"""
        return {
            "event_type": self.event_type.value,
            "data": self.data,
            "metadata": asdict(self.metadata),
            "stream_id": self.stream_id,
            "stream_version": self.stream_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """Create event from dictionary"""
        metadata_dict = data["metadata"]
        metadata_dict["timestamp"] = datetime.fromisoformat(metadata_dict["timestamp"])

        return cls(
            event_type=EventType(data["event_type"]),
            data=data["data"],
            metadata=EventMetadata(**metadata_dict),
            stream_id=data["stream_id"],
            stream_version=data["stream_version"],
        )


@dataclass
class Snapshot:
    """Event stream snapshot for performance optimization"""

    stream_id: str
    stream_version: int
    data: Dict[str, Any]
    timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stream_id": self.stream_id,
            "stream_version": self.stream_version,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
        }


class ConcurrencyError(Exception):
    """Raised when optimistic concurrency check fails"""


class StreamNotFoundError(Exception):
    """Raised when attempting to access non-existent stream"""


class EventStore:
    """
    PostgreSQL-based event store with CQRS support

    Features:
    - ACID transactions for event appending
    - Optimistic concurrency control
    - Event stream organization
    - Snapshot support
    - Event replay capabilities
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self._initialized = False

    async def initialize(self):
        """Initialize event store schema"""
        if self._initialized:
            return

        await self._create_tables()
        self._initialized = True

    async def _create_tables(self):
        """Create event store tables"""
        async with self.db.get_connection() as conn:
            # Events table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id BIGSERIAL PRIMARY KEY,
                    event_id UUID UNIQUE NOT NULL,
                    stream_id VARCHAR(255) NOT NULL,
                    stream_version INTEGER NOT NULL,
                    event_type VARCHAR(100) NOT NULL,
                    event_data JSONB NOT NULL,
                    metadata JSONB NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    UNIQUE(stream_id, stream_version)
                )
            """
            )

            # Snapshots table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    id BIGSERIAL PRIMARY KEY,
                    stream_id VARCHAR(255) UNIQUE NOT NULL,
                    stream_version INTEGER NOT NULL,
                    snapshot_data JSONB NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """
            )

            # Create indexes for performance
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_stream_id ON events(stream_id)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_tenant ON events((metadata->>'tenant_id'))"
            )

    async def append_events(
        self, stream_id: str, events: List[Event], expected_version: int
    ) -> None:
        """
        Append events to stream with optimistic concurrency control

        Args:
            stream_id: Stream identifier
            events: List of events to append
            expected_version: Expected current version of stream

        Raises:
            ConcurrencyError: If expected version doesn't match current version
        """
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            async with conn.transaction():
                # Check current version
                current_version = await self._get_stream_version(conn, stream_id)

                if current_version != expected_version:
                    raise ConcurrencyError(
                        f"Expected version {expected_version} but current is {current_version}"
                    )

                # Append events
                for i, event in enumerate(events):
                    version = expected_version + i + 1
                    event.stream_version = version

                    await conn.execute(
                        """
                        INSERT INTO events (event_id, stream_id, stream_version,
                                          event_type, event_data, metadata)
                        VALUES ($1, $2, $3, $4, $5, $6)
                    """,
                        event.metadata.event_id,
                        stream_id,
                        version,
                        event.event_type.value,
                        json.dumps(event.data),
                        json.dumps(asdict(event.metadata)),
                    )

    async def get_events(
        self, stream_id: str, from_version: int = 0, to_version: Optional[int] = None
    ) -> List[Event]:
        """
        Get events from stream within version range

        Args:
            stream_id: Stream identifier
            from_version: Starting version (inclusive)
            to_version: Ending version (inclusive), None for all

        Returns:
            List of events in version order
        """
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            if to_version is None:
                query = """
                    SELECT event_type, event_data, metadata, stream_version
                    FROM events
                    WHERE stream_id = $1 AND stream_version > $2
                    ORDER BY stream_version
                """
                rows = await conn.fetch(query, stream_id, from_version)
            else:
                query = """
                    SELECT event_type, event_data, metadata, stream_version
                    FROM events
                    WHERE stream_id = $1 AND stream_version > $2 AND stream_version <= $3
                    ORDER BY stream_version
                """
                rows = await conn.fetch(query, stream_id, from_version, to_version)

            events = []
            for row in rows:
                metadata_dict = row["metadata"]
                metadata_dict["timestamp"] = datetime.fromisoformat(
                    metadata_dict["timestamp"]
                )

                event = Event(
                    event_type=EventType(row["event_type"]),
                    data=row["event_data"],
                    metadata=EventMetadata(**metadata_dict),
                    stream_id=stream_id,
                    stream_version=row["stream_version"],
                )
                events.append(event)

            return events

    async def get_events_by_type(
        self,
        event_types: List[EventType],
        from_timestamp: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[Event]:
        """Get events by type across all streams"""
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            type_values = [et.value for et in event_types]

            if from_timestamp:
                query = """
                    SELECT stream_id, event_type, event_data, metadata, stream_version
                    FROM events
                    WHERE event_type = ANY($1) AND created_at >= $2
                    ORDER BY created_at
                """
                params = [type_values, from_timestamp]
            else:
                query = """
                    SELECT stream_id, event_type, event_data, metadata, stream_version
                    FROM events
                    WHERE event_type = ANY($1)
                    ORDER BY created_at
                """
                params = [type_values]

            if limit:
                query += f" LIMIT {limit}"

            rows = await conn.fetch(query, *params)

            events = []
            for row in rows:
                metadata_dict = row["metadata"]
                metadata_dict["timestamp"] = datetime.fromisoformat(
                    metadata_dict["timestamp"]
                )

                event = Event(
                    event_type=EventType(row["event_type"]),
                    data=row["event_data"],
                    metadata=EventMetadata(**metadata_dict),
                    stream_id=row["stream_id"],
                    stream_version=row["stream_version"],
                )
                events.append(event)

            return events

    async def create_snapshot(
        self, stream_id: str, data: Dict[str, Any], version: int
    ) -> None:
        """Create snapshot for performance optimization"""
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO snapshots (stream_id, stream_version, snapshot_data)
                VALUES ($1, $2, $3)
                ON CONFLICT (stream_id)
                DO UPDATE SET
                    stream_version = EXCLUDED.stream_version,
                    snapshot_data = EXCLUDED.snapshot_data,
                    created_at = NOW()
            """,
                stream_id,
                version,
                json.dumps(data),
            )

    async def get_snapshot(self, stream_id: str) -> Optional[Snapshot]:
        """Get latest snapshot for stream"""
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            row = await conn.fetchrow(
                """
                SELECT stream_version, snapshot_data, created_at
                FROM snapshots
                WHERE stream_id = $1
            """,
                stream_id,
            )

            if row:
                return Snapshot(
                    stream_id=stream_id,
                    stream_version=row["stream_version"],
                    data=row["snapshot_data"],
                    timestamp=row["created_at"],
                )

            return None

    async def stream_exists(self, stream_id: str) -> bool:
        """Check if stream exists"""
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            result = await conn.fetchval(
                """
                SELECT EXISTS(SELECT 1 FROM events WHERE stream_id = $1)
            """,
                stream_id,
            )
            return result

    async def get_stream_version(self, stream_id: str) -> int:
        """Get current version of stream"""
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            return await self._get_stream_version(conn, stream_id)

    async def _get_stream_version(
        self, conn: asyncpg.Connection, stream_id: str
    ) -> int:
        """Internal method to get stream version"""
        version = await conn.fetchval(
            """
            SELECT MAX(stream_version) FROM events WHERE stream_id = $1
        """,
            stream_id,
        )
        return version or 0

    async def get_all_stream_ids(self, prefix: Optional[str] = None) -> List[str]:
        """Get all stream IDs, optionally filtered by prefix"""
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            if prefix:
                rows = await conn.fetch(
                    """
                    SELECT DISTINCT stream_id FROM events
                    WHERE stream_id LIKE $1
                    ORDER BY stream_id
                """,
                    f"{prefix}%",
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT DISTINCT stream_id FROM events
                    ORDER BY stream_id
                """
                )

            return [row["stream_id"] for row in rows]

    async def replay_events(
        self, from_timestamp: Optional[datetime] = None
    ) -> AsyncIterator[Event]:
        """
        Replay all events in chronological order

        Args:
            from_timestamp: Start replay from this timestamp

        Yields:
            Events in chronological order
        """
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            if from_timestamp:
                query = """
                    SELECT stream_id, event_type, event_data, metadata, stream_version
                    FROM events
                    WHERE created_at >= $1
                    ORDER BY created_at, id
                """
                async for row in conn.cursor(query, from_timestamp):
                    yield self._row_to_event(row)
            else:
                query = """
                    SELECT stream_id, event_type, event_data, metadata, stream_version
                    FROM events
                    ORDER BY created_at, id
                """
                async for row in conn.cursor(query):
                    yield self._row_to_event(row)

    def _row_to_event(self, row) -> Event:
        """Convert database row to Event object"""
        metadata_dict = row["metadata"]
        metadata_dict["timestamp"] = datetime.fromisoformat(metadata_dict["timestamp"])

        return Event(
            event_type=EventType(row["event_type"]),
            data=row["event_data"],
            metadata=EventMetadata(**metadata_dict),
            stream_id=row["stream_id"],
            stream_version=row["stream_version"],
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """Get event store statistics"""
        if not self._initialized:
            await self.initialize()

        async with self.db.get_connection() as conn:
            stats = {}

            # Total events
            stats["total_events"] = await conn.fetchval("SELECT COUNT(*) FROM events")

            # Total streams
            stats["total_streams"] = await conn.fetchval(
                "SELECT COUNT(DISTINCT stream_id) FROM events"
            )

            # Events by type
            type_counts = await conn.fetch(
                """
                SELECT event_type, COUNT(*) as count
                FROM events
                GROUP BY event_type
                ORDER BY count DESC
            """
            )
            stats["events_by_type"] = {
                row["event_type"]: row["count"] for row in type_counts
            }

            # Total snapshots
            stats["total_snapshots"] = await conn.fetchval(
                "SELECT COUNT(*) FROM snapshots"
            )

            return stats
