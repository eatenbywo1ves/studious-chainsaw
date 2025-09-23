"""
Projection Management for Event Sourcing

Handles building and maintaining read models from event streams:
- Projection definitions and rebuilding
- Materialized view management
- Automatic projection updates
- Performance optimization with snapshots
"""

import asyncio
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .event_store import Event, EventStore, EventType


class ProjectionError(Exception):
    """Base exception for projection errors"""


class ProjectionRebuildError(ProjectionError):
    """Raised when projection rebuild fails"""


class Projection(ABC):
    """Base class for event projections"""

    def __init__(self, name: str):
        self.name = name
        self.last_processed_event_id: Optional[str] = None
        self.version = 0
        self.updated_at = datetime.utcnow()

    @abstractmethod
    def get_interested_events(self) -> Set[EventType]:
        """Return set of event types this projection is interested in"""

    @abstractmethod
    async def handle_event(self, event: Event) -> None:
        """Handle a single event to update projection state"""

    @abstractmethod
    async def reset(self) -> None:
        """Reset projection to initial state"""

    @abstractmethod
    async def get_state(self) -> Dict[str, Any]:
        """Get current projection state"""

    async def can_handle(self, event: Event) -> bool:
        """Check if this projection can handle the event"""
        return event.event_type in self.get_interested_events()


@dataclass
class ProjectionCheckpoint:
    """Checkpoint for projection processing"""

    projection_name: str
    last_event_id: str
    last_event_timestamp: datetime
    version: int
    updated_at: datetime


class AgentListProjection(Projection):
    """Projection for agent list view"""

    def __init__(self):
        super().__init__("agent_list")
        self.agents: Dict[str, Dict[str, Any]] = {}

    def get_interested_events(self) -> Set[EventType]:
        return {
            EventType.AGENT_CREATED,
            EventType.AGENT_CONFIGURED,
            EventType.AGENT_STARTED,
            EventType.AGENT_STOPPED,
            EventType.AGENT_DELETED,
        }

    async def handle_event(self, event: Event) -> None:
        agent_id = event.data.get("agent_id")
        if not agent_id:
            return

        if event.event_type == EventType.AGENT_CREATED:
            self.agents[agent_id] = {
                "agent_id": agent_id,
                "tenant_id": event.data.get("tenant_id"),
                "agent_type": event.data.get("agent_type"),
                "name": event.data.get("name"),
                "description": event.data.get("description"),
                "status": "created",
                "configuration": {},
                "created_at": event.metadata.timestamp.isoformat(),
                "updated_at": event.metadata.timestamp.isoformat(),
                "created_by": event.data.get("created_by"),
            }

        elif agent_id in self.agents:
            if event.event_type == EventType.AGENT_CONFIGURED:
                self.agents[agent_id]["configuration"] = event.data.get(
                    "configuration", {}
                )
                self.agents[agent_id][
                    "updated_at"
                ] = event.metadata.timestamp.isoformat()

            elif event.event_type == EventType.AGENT_STARTED:
                self.agents[agent_id]["status"] = "running"
                self.agents[agent_id][
                    "updated_at"
                ] = event.metadata.timestamp.isoformat()

            elif event.event_type == EventType.AGENT_STOPPED:
                self.agents[agent_id]["status"] = "stopped"
                self.agents[agent_id][
                    "updated_at"
                ] = event.metadata.timestamp.isoformat()

            elif event.event_type == EventType.AGENT_DELETED:
                if agent_id in self.agents:
                    del self.agents[agent_id]

        self.last_processed_event_id = event.metadata.event_id
        self.version += 1
        self.updated_at = datetime.utcnow()

    async def reset(self) -> None:
        self.agents.clear()
        self.last_processed_event_id = None
        self.version = 0
        self.updated_at = datetime.utcnow()

    async def get_state(self) -> Dict[str, Any]:
        return {
            "agents": self.agents,
            "total_count": len(self.agents),
            "last_processed_event_id": self.last_processed_event_id,
            "version": self.version,
            "updated_at": self.updated_at.isoformat(),
        }

    def get_agents_by_tenant(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get agents filtered by tenant"""
        return [
            agent
            for agent in self.agents.values()
            if agent.get("tenant_id") == tenant_id
        ]

    def get_agents_by_type(self, agent_type: str) -> List[Dict[str, Any]]:
        """Get agents filtered by type"""
        return [
            agent
            for agent in self.agents.values()
            if agent.get("agent_type") == agent_type
        ]

    def get_agents_by_status(self, status: str) -> List[Dict[str, Any]]:
        """Get agents filtered by status"""
        return [
            agent for agent in self.agents.values() if agent.get("status") == status
        ]


class TaskListProjection(Projection):
    """Projection for task list view"""

    def __init__(self):
        super().__init__("task_list")
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.agent_task_index: Dict[str, List[str]] = defaultdict(list)

    def get_interested_events(self) -> Set[EventType]:
        return {
            EventType.TASK_ASSIGNED,
            EventType.TASK_STARTED,
            EventType.TASK_COMPLETED,
            EventType.TASK_FAILED,
            EventType.TASK_CANCELLED,
        }

    async def handle_event(self, event: Event) -> None:
        task_id = event.data.get("task_id")
        if not task_id:
            return

        if event.event_type == EventType.TASK_ASSIGNED:
            agent_id = event.data.get("agent_id")
            self.tasks[task_id] = {
                "task_id": task_id,
                "agent_id": agent_id,
                "tenant_id": event.metadata.tenant_id,
                "task_definition": event.data.get("task_definition", {}),
                "priority": event.data.get("priority", 5),
                "timeout_seconds": event.data.get("timeout_seconds"),
                "status": "assigned",
                "assigned_at": event.data.get("assigned_at"),
                "assigned_by": event.data.get("assigned_by"),
                "started_at": None,
                "completed_at": None,
                "result": None,
                "error_message": None,
            }

            # Update index
            if agent_id:
                self.agent_task_index[agent_id].append(task_id)

        elif task_id in self.tasks:
            if event.event_type == EventType.TASK_STARTED:
                self.tasks[task_id]["status"] = "running"
                self.tasks[task_id]["started_at"] = event.metadata.timestamp.isoformat()

            elif event.event_type == EventType.TASK_COMPLETED:
                self.tasks[task_id]["status"] = "completed"
                self.tasks[task_id][
                    "completed_at"
                ] = event.metadata.timestamp.isoformat()
                self.tasks[task_id]["result"] = event.data.get("result")

            elif event.event_type == EventType.TASK_FAILED:
                self.tasks[task_id]["status"] = "failed"
                self.tasks[task_id][
                    "completed_at"
                ] = event.metadata.timestamp.isoformat()
                self.tasks[task_id]["error_message"] = event.data.get("error_message")

            elif event.event_type == EventType.TASK_CANCELLED:
                self.tasks[task_id]["status"] = "cancelled"
                self.tasks[task_id][
                    "completed_at"
                ] = event.metadata.timestamp.isoformat()

        self.last_processed_event_id = event.metadata.event_id
        self.version += 1
        self.updated_at = datetime.utcnow()

    async def reset(self) -> None:
        self.tasks.clear()
        self.agent_task_index.clear()
        self.last_processed_event_id = None
        self.version = 0
        self.updated_at = datetime.utcnow()

    async def get_state(self) -> Dict[str, Any]:
        return {
            "tasks": self.tasks,
            "total_count": len(self.tasks),
            "agent_task_index": dict(self.agent_task_index),
            "last_processed_event_id": self.last_processed_event_id,
            "version": self.version,
            "updated_at": self.updated_at.isoformat(),
        }

    def get_tasks_by_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get tasks for specific agent"""
        task_ids = self.agent_task_index.get(agent_id, [])
        return [self.tasks[task_id] for task_id in task_ids if task_id in self.tasks]

    def get_tasks_by_status(self, status: str) -> List[Dict[str, Any]]:
        """Get tasks by status"""
        return [task for task in self.tasks.values() if task.get("status") == status]

    def get_tasks_by_tenant(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get tasks by tenant"""
        return [
            task for task in self.tasks.values() if task.get("tenant_id") == tenant_id
        ]


class SystemMetricsProjection(Projection):
    """Projection for system metrics and statistics"""

    def __init__(self):
        super().__init__("system_metrics")
        self.metrics = {
            "agents": {
                "total_created": 0,
                "total_started": 0,
                "total_stopped": 0,
                "total_deleted": 0,
                "by_type": defaultdict(int),
                "by_tenant": defaultdict(int),
            },
            "tasks": {
                "total_assigned": 0,
                "total_completed": 0,
                "total_failed": 0,
                "total_cancelled": 0,
                "by_agent": defaultdict(int),
                "by_tenant": defaultdict(int),
            },
            "security": {
                "authentication_successes": 0,
                "authentication_failures": 0,
                "access_granted": 0,
                "access_revoked": 0,
                "policy_updates": 0,
            },
        }

    def get_interested_events(self) -> Set[EventType]:
        return {
            EventType.AGENT_CREATED,
            EventType.AGENT_STARTED,
            EventType.AGENT_STOPPED,
            EventType.AGENT_DELETED,
            EventType.TASK_ASSIGNED,
            EventType.TASK_COMPLETED,
            EventType.TASK_FAILED,
            EventType.TASK_CANCELLED,
            EventType.AUTHENTICATION_SUCCEEDED,
            EventType.AUTHENTICATION_FAILED,
            EventType.ACCESS_GRANTED,
            EventType.ACCESS_REVOKED,
            EventType.SECURITY_POLICY_UPDATED,
        }

    async def handle_event(self, event: Event) -> None:
        # Agent metrics
        if event.event_type == EventType.AGENT_CREATED:
            self.metrics["agents"]["total_created"] += 1
            agent_type = event.data.get("agent_type", "unknown")
            tenant_id = event.data.get("tenant_id", "unknown")
            self.metrics["agents"]["by_type"][agent_type] += 1
            self.metrics["agents"]["by_tenant"][tenant_id] += 1

        elif event.event_type == EventType.AGENT_STARTED:
            self.metrics["agents"]["total_started"] += 1

        elif event.event_type == EventType.AGENT_STOPPED:
            self.metrics["agents"]["total_stopped"] += 1

        elif event.event_type == EventType.AGENT_DELETED:
            self.metrics["agents"]["total_deleted"] += 1

        # Task metrics
        elif event.event_type == EventType.TASK_ASSIGNED:
            self.metrics["tasks"]["total_assigned"] += 1
            agent_id = event.data.get("agent_id", "unknown")
            tenant_id = event.metadata.tenant_id or "unknown"
            self.metrics["tasks"]["by_agent"][agent_id] += 1
            self.metrics["tasks"]["by_tenant"][tenant_id] += 1

        elif event.event_type == EventType.TASK_COMPLETED:
            self.metrics["tasks"]["total_completed"] += 1

        elif event.event_type == EventType.TASK_FAILED:
            self.metrics["tasks"]["total_failed"] += 1

        elif event.event_type == EventType.TASK_CANCELLED:
            self.metrics["tasks"]["total_cancelled"] += 1

        # Security metrics
        elif event.event_type == EventType.AUTHENTICATION_SUCCEEDED:
            self.metrics["security"]["authentication_successes"] += 1

        elif event.event_type == EventType.AUTHENTICATION_FAILED:
            self.metrics["security"]["authentication_failures"] += 1

        elif event.event_type == EventType.ACCESS_GRANTED:
            self.metrics["security"]["access_granted"] += 1

        elif event.event_type == EventType.ACCESS_REVOKED:
            self.metrics["security"]["access_revoked"] += 1

        elif event.event_type == EventType.SECURITY_POLICY_UPDATED:
            self.metrics["security"]["policy_updates"] += 1

        self.last_processed_event_id = event.metadata.event_id
        self.version += 1
        self.updated_at = datetime.utcnow()

    async def reset(self) -> None:
        self.metrics = {
            "agents": {
                "total_created": 0,
                "total_started": 0,
                "total_stopped": 0,
                "total_deleted": 0,
                "by_type": defaultdict(int),
                "by_tenant": defaultdict(int),
            },
            "tasks": {
                "total_assigned": 0,
                "total_completed": 0,
                "total_failed": 0,
                "total_cancelled": 0,
                "by_agent": defaultdict(int),
                "by_tenant": defaultdict(int),
            },
            "security": {
                "authentication_successes": 0,
                "authentication_failures": 0,
                "access_granted": 0,
                "access_revoked": 0,
                "policy_updates": 0,
            },
        }
        self.last_processed_event_id = None
        self.version = 0
        self.updated_at = datetime.utcnow()

    async def get_state(self) -> Dict[str, Any]:
        # Convert defaultdicts to regular dicts for serialization
        serializable_metrics = {
            "agents": {
                **self.metrics["agents"],
                "by_type": dict(self.metrics["agents"]["by_type"]),
                "by_tenant": dict(self.metrics["agents"]["by_tenant"]),
            },
            "tasks": {
                **self.metrics["tasks"],
                "by_agent": dict(self.metrics["tasks"]["by_agent"]),
                "by_tenant": dict(self.metrics["tasks"]["by_tenant"]),
            },
            "security": self.metrics["security"],
        }

        return {
            "metrics": serializable_metrics,
            "last_processed_event_id": self.last_processed_event_id,
            "version": self.version,
            "updated_at": self.updated_at.isoformat(),
        }


class ProjectionManager:
    """
    Manages multiple projections and keeps them synchronized with event store
    """

    def __init__(self, event_store: EventStore):
        self.event_store = event_store
        self.projections: Dict[str, Projection] = {}
        self.checkpoints: Dict[str, ProjectionCheckpoint] = {}
        self.is_running = False
        self._update_task: Optional[asyncio.Task] = None

    def register_projection(self, projection: Projection):
        """Register a projection for automatic updates"""
        self.projections[projection.name] = projection

        # Initialize checkpoint if not exists
        if projection.name not in self.checkpoints:
            self.checkpoints[projection.name] = ProjectionCheckpoint(
                projection_name=projection.name,
                last_event_id="",
                last_event_timestamp=datetime.min,
                version=0,
                updated_at=datetime.utcnow(),
            )

    async def rebuild_projection(self, projection_name: str) -> None:
        """Rebuild a projection from all events"""
        if projection_name not in self.projections:
            raise ProjectionRebuildError(f"Projection {projection_name} not found")

        projection = self.projections[projection_name]

        try:
            # Reset projection state
            await projection.reset()

            # Get all relevant events
            interested_events = projection.get_interested_events()

            # Process events in chronological order
            async for event in self.event_store.replay_events():
                if event.event_type in interested_events:
                    await projection.handle_event(event)

            # Update checkpoint
            if projection.last_processed_event_id:
                self.checkpoints[projection_name] = ProjectionCheckpoint(
                    projection_name=projection_name,
                    last_event_id=projection.last_processed_event_id,
                    last_event_timestamp=projection.updated_at,
                    version=projection.version,
                    updated_at=datetime.utcnow(),
                )

        except Exception as e:
            raise ProjectionRebuildError(
                f"Failed to rebuild projection {projection_name}: {str(e)}"
            )

    async def rebuild_all_projections(self) -> None:
        """Rebuild all registered projections"""
        for projection_name in self.projections.keys():
            await self.rebuild_projection(projection_name)

    async def update_projections(self) -> None:
        """Update all projections with new events"""
        if not self.projections:
            return

        # Find the earliest checkpoint
        earliest_timestamp = (
            min(cp.last_event_timestamp for cp in self.checkpoints.values())
            if self.checkpoints
            else datetime.min
        )

        # Get new events since earliest checkpoint
        processed_events = set()

        async for event in self.event_store.replay_events(
            from_timestamp=earliest_timestamp
        ):
            # Skip already processed events
            if event.metadata.event_id in processed_events:
                continue

            # Process event for relevant projections
            for projection_name, projection in self.projections.items():
                checkpoint = self.checkpoints[projection_name]

                # Skip if already processed by this projection
                if event.metadata.event_id == checkpoint.last_event_id:
                    continue

                # Check if projection is interested in this event
                if await projection.can_handle(event):
                    await projection.handle_event(event)

                    # Update checkpoint
                    self.checkpoints[projection_name] = ProjectionCheckpoint(
                        projection_name=projection_name,
                        last_event_id=event.metadata.event_id,
                        last_event_timestamp=event.metadata.timestamp,
                        version=projection.version,
                        updated_at=datetime.utcnow(),
                    )

            processed_events.add(event.metadata.event_id)

    async def start_continuous_update(self, interval_seconds: int = 5):
        """Start continuous projection updates"""
        if self.is_running:
            return

        self.is_running = True

        async def update_loop():
            while self.is_running:
                try:
                    await self.update_projections()
                    await asyncio.sleep(interval_seconds)
                except Exception as e:
                    print(f"Error updating projections: {e}")
                    await asyncio.sleep(interval_seconds)

        self._update_task = asyncio.create_task(update_loop())

    async def stop_continuous_update(self):
        """Stop continuous projection updates"""
        if not self.is_running:
            return

        self.is_running = False

        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass

    def get_projection(self, name: str) -> Optional[Projection]:
        """Get projection by name"""
        return self.projections.get(name)

    async def get_projection_state(self, name: str) -> Optional[Dict[str, Any]]:
        """Get current state of projection"""
        projection = self.get_projection(name)
        if projection:
            return await projection.get_state()
        return None

    def get_projection_checkpoint(self, name: str) -> Optional[ProjectionCheckpoint]:
        """Get checkpoint for projection"""
        return self.checkpoints.get(name)

    async def get_all_projection_states(self) -> Dict[str, Dict[str, Any]]:
        """Get states of all projections"""
        states = {}
        for name, projection in self.projections.items():
            states[name] = await projection.get_state()
        return states

    def get_projection_health(self) -> Dict[str, Dict[str, Any]]:
        """Get health status of all projections"""
        health = {}

        for name, projection in self.projections.items():
            checkpoint = self.checkpoints.get(name)

            health[name] = {
                "name": name,
                "version": projection.version,
                "last_updated": projection.updated_at.isoformat(),
                "last_processed_event_id": projection.last_processed_event_id,
                "checkpoint": (
                    {
                        "last_event_id": (
                            checkpoint.last_event_id if checkpoint else None
                        ),
                        "last_event_timestamp": (
                            checkpoint.last_event_timestamp.isoformat()
                            if checkpoint
                            else None
                        ),
                        "version": checkpoint.version if checkpoint else 0,
                    }
                    if checkpoint
                    else None
                ),
            }

        return health
