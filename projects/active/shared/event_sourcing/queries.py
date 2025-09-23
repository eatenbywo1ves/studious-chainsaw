"""
Query Side of CQRS Implementation

Handles read operations and projections:
- Query definitions and validation
- Query bus for routing and execution
- Query handlers that read from projections
- Materialized views for optimized reads
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Type

from .event_store import Event, EventStore, EventType


class QueryResult(Enum):
    """Query execution result status"""

    SUCCESS = "success"
    NOT_FOUND = "not_found"
    VALIDATION_ERROR = "validation_error"
    SYSTEM_ERROR = "system_error"


@dataclass
class QueryResponse:
    """Response from query execution"""

    result: QueryResult
    data: Optional[Any] = None
    error_message: Optional[str] = None
    query_time_ms: Optional[float] = None
    total_count: Optional[int] = None


class Query(ABC):
    """Base query class"""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @abstractmethod
    def validate(self) -> List[str]:
        """Validate query parameters"""


class QueryHandler(ABC):
    """Base query handler"""

    def __init__(self, event_store: EventStore):
        self.event_store = event_store

    @abstractmethod
    async def handle(self, query: Query) -> QueryResponse:
        """Handle the query and return response"""


# Agent Queries


@dataclass
class GetAgentQuery(Query):
    """Query to get agent details"""

    agent_id: str

    def validate(self) -> List[str]:
        return ["agent_id is required"] if not self.agent_id else []


@dataclass
class ListAgentsQuery(Query):
    """Query to list agents"""

    tenant_id: Optional[str] = None
    agent_type: Optional[str] = None
    status: Optional[str] = None
    page: int = 1
    page_size: int = 50

    def validate(self) -> List[str]:
        errors = []
        if self.page < 1:
            errors.append("page must be >= 1")
        if self.page_size < 1 or self.page_size > 1000:
            errors.append("page_size must be between 1 and 1000")
        return errors


@dataclass
class GetAgentHistoryQuery(Query):
    """Query to get agent event history"""

    agent_id: str
    from_version: int = 0
    to_version: Optional[int] = None

    def validate(self) -> List[str]:
        errors = []
        if not self.agent_id:
            errors.append("agent_id is required")
        if self.from_version < 0:
            errors.append("from_version must be >= 0")
        return errors


# Task Queries


@dataclass
class GetTaskQuery(Query):
    """Query to get task details"""

    task_id: str

    def validate(self) -> List[str]:
        return ["task_id is required"] if not self.task_id else []


@dataclass
class ListTasksQuery(Query):
    """Query to list tasks"""

    agent_id: Optional[str] = None
    tenant_id: Optional[str] = None
    status: Optional[str] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None
    page: int = 1
    page_size: int = 50

    def validate(self) -> List[str]:
        errors = []
        if self.page < 1:
            errors.append("page must be >= 1")
        if self.page_size < 1 or self.page_size > 1000:
            errors.append("page_size must be between 1 and 1000")
        if self.from_date and self.to_date and self.from_date > self.to_date:
            errors.append("from_date must be before to_date")
        return errors


# Analytics Queries


@dataclass
class GetSystemStatsQuery(Query):
    """Query for system statistics"""

    tenant_id: Optional[str] = None
    time_window: str = "1h"  # 1h, 1d, 1w, 1m

    def validate(self) -> List[str]:
        valid_windows = ["1h", "1d", "1w", "1m"]
        if self.time_window not in valid_windows:
            return [f"time_window must be one of: {', '.join(valid_windows)}"]
        return []


@dataclass
class GetAgentPerformanceQuery(Query):
    """Query for agent performance metrics"""

    agent_id: Optional[str] = None
    tenant_id: Optional[str] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None

    def validate(self) -> List[str]:
        if self.from_date and self.to_date and self.from_date > self.to_date:
            return ["from_date must be before to_date"]
        return []


# Security Queries


@dataclass
class GetUserPermissionsQuery(Query):
    """Query for user permissions"""

    user_id: str
    resource_id: Optional[str] = None

    def validate(self) -> List[str]:
        return ["user_id is required"] if not self.user_id else []


@dataclass
class ListSecurityEventsQuery(Query):
    """Query for security events"""

    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    event_type: Optional[str] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None
    page: int = 1
    page_size: int = 50

    def validate(self) -> List[str]:
        errors = []
        if self.page < 1:
            errors.append("page must be >= 1")
        if self.page_size < 1 or self.page_size > 1000:
            errors.append("page_size must be between 1 and 1000")
        return errors


# Agent Projections and Query Handlers


@dataclass
class AgentProjection:
    """Agent state projection"""

    agent_id: str
    tenant_id: str
    agent_type: str
    name: Optional[str] = None
    description: Optional[str] = None
    status: str = "created"
    configuration: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    version: int = 0

    @classmethod
    def from_events(cls, events: List[Event]) -> "AgentProjection":
        """Build projection from events"""
        if not events:
            raise ValueError("Cannot build projection from empty events")

        projection = None

        for event in events:
            if event.event_type == EventType.AGENT_CREATED:
                data = event.data
                projection = cls(
                    agent_id=data["agent_id"],
                    tenant_id=data["tenant_id"],
                    agent_type=data["agent_type"],
                    name=data.get("name"),
                    description=data.get("description"),
                    created_at=event.metadata.timestamp,
                    created_by=data.get("created_by"),
                    status="created",
                    version=event.stream_version,
                )

            elif projection and event.event_type == EventType.AGENT_CONFIGURED:
                projection.configuration = event.data["configuration"]
                projection.updated_at = event.metadata.timestamp
                projection.version = event.stream_version

            elif projection and event.event_type == EventType.AGENT_STARTED:
                projection.status = "running"
                projection.updated_at = event.metadata.timestamp
                projection.version = event.stream_version

            elif projection and event.event_type == EventType.AGENT_STOPPED:
                projection.status = "stopped"
                projection.updated_at = event.metadata.timestamp
                projection.version = event.stream_version

            elif projection and event.event_type == EventType.AGENT_DELETED:
                projection.status = "deleted"
                projection.updated_at = event.metadata.timestamp
                projection.version = event.stream_version

        if not projection:
            raise ValueError("No AGENT_CREATED event found")

        return projection


@dataclass
class TaskProjection:
    """Task state projection"""

    task_id: str
    agent_id: str
    tenant_id: str
    task_definition: Dict[str, Any]
    status: str = "assigned"
    priority: int = 5
    timeout_seconds: Optional[int] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    assigned_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    assigned_by: Optional[str] = None
    version: int = 0

    @classmethod
    def from_events(cls, events: List[Event]) -> "TaskProjection":
        """Build projection from events"""
        if not events:
            raise ValueError("Cannot build projection from empty events")

        projection = None

        for event in events:
            if event.event_type == EventType.TASK_ASSIGNED:
                data = event.data
                projection = cls(
                    task_id=data["task_id"],
                    agent_id=data["agent_id"],
                    tenant_id=event.metadata.tenant_id,
                    task_definition=data["task_definition"],
                    priority=data["priority"],
                    timeout_seconds=data.get("timeout_seconds"),
                    assigned_at=datetime.fromisoformat(data["assigned_at"]),
                    assigned_by=data.get("assigned_by"),
                    status="assigned",
                    version=event.stream_version,
                )

            elif projection and event.event_type == EventType.TASK_STARTED:
                projection.status = "running"
                projection.started_at = event.metadata.timestamp
                projection.version = event.stream_version

            elif projection and event.event_type == EventType.TASK_COMPLETED:
                projection.status = "completed"
                projection.result = event.data.get("result")
                projection.completed_at = event.metadata.timestamp
                projection.version = event.stream_version

            elif projection and event.event_type == EventType.TASK_FAILED:
                projection.status = "failed"
                projection.error_message = event.data.get("error_message")
                projection.completed_at = event.metadata.timestamp
                projection.version = event.stream_version

            elif projection and event.event_type == EventType.TASK_CANCELLED:
                projection.status = "cancelled"
                projection.completed_at = event.metadata.timestamp
                projection.version = event.stream_version

        if not projection:
            raise ValueError("No TASK_ASSIGNED event found")

        return projection


class GetAgentQueryHandler(QueryHandler):
    """Handler for getting agent details"""

    async def handle(self, query: GetAgentQuery) -> QueryResponse:
        try:
            errors = query.validate()
            if errors:
                return QueryResponse(
                    result=QueryResult.VALIDATION_ERROR, error_message="; ".join(errors)
                )

            stream_id = f"agent_{query.agent_id}"

            # Check if agent exists
            if not await self.event_store.stream_exists(stream_id):
                return QueryResponse(
                    result=QueryResult.NOT_FOUND,
                    error_message=f"Agent {query.agent_id} not found",
                )

            # Get events and build projection
            events = await self.event_store.get_events(stream_id)
            projection = AgentProjection.from_events(events)

            return QueryResponse(result=QueryResult.SUCCESS, data=projection)

        except Exception as e:
            return QueryResponse(result=QueryResult.SYSTEM_ERROR, error_message=str(e))


class ListAgentsQueryHandler(QueryHandler):
    """Handler for listing agents"""

    async def handle(self, query: ListAgentsQuery) -> QueryResponse:
        try:
            errors = query.validate()
            if errors:
                return QueryResponse(
                    result=QueryResult.VALIDATION_ERROR, error_message="; ".join(errors)
                )

            # Get all agent streams
            stream_ids = await self.event_store.get_all_stream_ids("agent_")

            agents = []
            for stream_id in stream_ids:
                try:
                    events = await self.event_store.get_events(stream_id)
                    if events:
                        projection = AgentProjection.from_events(events)

                        # Apply filters
                        if query.tenant_id and projection.tenant_id != query.tenant_id:
                            continue
                        if (
                            query.agent_type
                            and projection.agent_type != query.agent_type
                        ):
                            continue
                        if query.status and projection.status != query.status:
                            continue

                        agents.append(projection)
                except Exception:
                    # Skip invalid agents
                    continue

            # Apply pagination
            start_idx = (query.page - 1) * query.page_size
            end_idx = start_idx + query.page_size
            paginated_agents = agents[start_idx:end_idx]

            return QueryResponse(
                result=QueryResult.SUCCESS,
                data=paginated_agents,
                total_count=len(agents),
            )

        except Exception as e:
            return QueryResponse(result=QueryResult.SYSTEM_ERROR, error_message=str(e))


class GetTaskQueryHandler(QueryHandler):
    """Handler for getting task details"""

    async def handle(self, query: GetTaskQuery) -> QueryResponse:
        try:
            errors = query.validate()
            if errors:
                return QueryResponse(
                    result=QueryResult.VALIDATION_ERROR, error_message="; ".join(errors)
                )

            stream_id = f"task_{query.task_id}"

            # Check if task exists
            if not await self.event_store.stream_exists(stream_id):
                return QueryResponse(
                    result=QueryResult.NOT_FOUND,
                    error_message=f"Task {query.task_id} not found",
                )

            # Get events and build projection
            events = await self.event_store.get_events(stream_id)
            projection = TaskProjection.from_events(events)

            return QueryResponse(result=QueryResult.SUCCESS, data=projection)

        except Exception as e:
            return QueryResponse(result=QueryResult.SYSTEM_ERROR, error_message=str(e))


class GetSystemStatsQueryHandler(QueryHandler):
    """Handler for system statistics"""

    async def handle(self, query: GetSystemStatsQuery) -> QueryResponse:
        try:
            errors = query.validate()
            if errors:
                return QueryResponse(
                    result=QueryResult.VALIDATION_ERROR, error_message="; ".join(errors)
                )

            # Calculate time window
            time_delta_map = {"1h": 3600, "1d": 86400, "1w": 604800, "1m": 2592000}

            seconds = time_delta_map[query.time_window]
            from_time = datetime.utcnow() - timedelta(seconds=seconds)

            # Get recent events
            recent_events = await self.event_store.get_events_by_type(
                [
                    EventType.AGENT_CREATED,
                    EventType.TASK_ASSIGNED,
                    EventType.TASK_COMPLETED,
                ],
                from_timestamp=from_time,
            )

            # Filter by tenant if specified
            if query.tenant_id:
                recent_events = [
                    e for e in recent_events if e.metadata.tenant_id == query.tenant_id
                ]

            # Calculate statistics
            stats = {
                "time_window": query.time_window,
                "agents_created": len(
                    [
                        e
                        for e in recent_events
                        if e.event_type == EventType.AGENT_CREATED
                    ]
                ),
                "tasks_assigned": len(
                    [
                        e
                        for e in recent_events
                        if e.event_type == EventType.TASK_ASSIGNED
                    ]
                ),
                "tasks_completed": len(
                    [
                        e
                        for e in recent_events
                        if e.event_type == EventType.TASK_COMPLETED
                    ]
                ),
                "total_events": len(recent_events),
                "tenant_id": query.tenant_id,
            }

            return QueryResponse(result=QueryResult.SUCCESS, data=stats)

        except Exception as e:
            return QueryResponse(result=QueryResult.SYSTEM_ERROR, error_message=str(e))


class QueryBus:
    """
    Query bus for routing queries to handlers
    Supports caching and performance monitoring
    """

    def __init__(self):
        self._handlers: Dict[Type[Query], QueryHandler] = {}
        self._cache: Dict[str, QueryResponse] = {}
        self._cache_ttl: Dict[str, datetime] = {}

    def register_handler(self, query_type: Type[Query], handler: QueryHandler):
        """Register query handler"""
        self._handlers[query_type] = handler

    async def execute(self, query: Query, use_cache: bool = True) -> QueryResponse:
        """Execute query through registered handler"""
        query_type = type(query)

        if query_type not in self._handlers:
            return QueryResponse(
                result=QueryResult.SYSTEM_ERROR,
                error_message=f"No handler registered for {query_type.__name__}",
            )

        # Check cache
        cache_key = self._get_cache_key(query)
        if use_cache and cache_key in self._cache:
            if datetime.utcnow() < self._cache_ttl[cache_key]:
                return self._cache[cache_key]
            else:
                # Cache expired
                del self._cache[cache_key]
                del self._cache_ttl[cache_key]

        handler = self._handlers[query_type]

        # Execute query with timing
        start_time = datetime.utcnow()
        response = await handler.handle(query)
        end_time = datetime.utcnow()

        # Set query time
        response.query_time_ms = (end_time - start_time).total_seconds() * 1000

        # Cache successful responses
        if use_cache and response.result == QueryResult.SUCCESS:
            self._cache[cache_key] = response
            self._cache_ttl[cache_key] = datetime.utcnow() + timedelta(minutes=5)

        return response

    def _get_cache_key(self, query: Query) -> str:
        """Generate cache key for query"""
        return f"{type(query).__name__}_{hash(str(sorted(query.__dict__.items())))}"

    def clear_cache(self, pattern: Optional[str] = None):
        """Clear cache entries matching pattern"""
        if pattern:
            keys_to_remove = [k for k in self._cache.keys() if pattern in k]
            for key in keys_to_remove:
                del self._cache[key]
                if key in self._cache_ttl:
                    del self._cache_ttl[key]
        else:
            self._cache.clear()
            self._cache_ttl.clear()

    def get_registered_queries(self) -> List[Type[Query]]:
        """Get list of registered query types"""
        return list(self._handlers.keys())

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "cache_size": len(self._cache),
            "cache_keys": list(self._cache.keys()),
            "expired_keys": [
                k for k, ttl in self._cache_ttl.items() if datetime.utcnow() >= ttl
            ],
        }
