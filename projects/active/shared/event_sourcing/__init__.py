"""
Event Sourcing and CQRS Implementation for MCP Agent Architecture

This module provides enterprise-grade event sourcing capabilities including:
- Event Store with PostgreSQL backend
- Command/Query separation (CQRS)
- Event replay and projection rebuilding
- Saga pattern for distributed transactions
- Event versioning and migration
"""

from .commands import Command, CommandBus, CommandHandler
from .event_store import Event, EventMetadata, EventStore
from .projections import Projection, ProjectionManager
from .queries import Query, QueryBus, QueryHandler
from .sagas import Saga, SagaManager

__all__ = [
    "EventStore",
    "Event",
    "EventMetadata",
    "Command",
    "CommandBus",
    "CommandHandler",
    "Query",
    "QueryBus",
    "QueryHandler",
    "Projection",
    "ProjectionManager",
    "Saga",
    "SagaManager",
]
