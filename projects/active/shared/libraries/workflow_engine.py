"""
Workflow Engine for Director Agent
Provides orchestration, task scheduling, and workflow management capabilities
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import uuid
from abc import ABC, abstractmethod
import traceback


class TaskStatus(Enum):
    """Task execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(Enum):
    """Task priority levels"""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


class WorkflowStatus(Enum):
    """Workflow execution status"""

    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TaskResult:
    """Result of task execution"""

    task_id: str
    status: TaskStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Task:
    """Represents a single task in the workflow"""

    id: str
    name: str
    handler: str  # Handler function name or service endpoint
    params: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: int = 300  # seconds
    retry_count: int = 0
    max_retries: int = 3
    dependencies: List[str] = field(
        default_factory=list
    )  # Task IDs this task depends on
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[TaskResult] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary"""
        data = asdict(self)
        data["priority"] = self.priority.value
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        if self.started_at:
            data["started_at"] = self.started_at.isoformat()
        if self.completed_at:
            data["completed_at"] = self.completed_at.isoformat()
        return data


@dataclass
class Workflow:
    """Represents a workflow containing multiple tasks"""

    id: str
    name: str
    description: str = ""
    tasks: List[Task] = field(default_factory=list)
    status: WorkflowStatus = WorkflowStatus.CREATED
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: int = 3600  # seconds
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_task(self, task: Task):
        """Add task to workflow"""
        self.tasks.append(task)

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        return next((t for t in self.tasks if t.id == task_id), None)

    def get_ready_tasks(self) -> List[Task]:
        """Get tasks that are ready to execute (dependencies satisfied)"""
        ready_tasks = []
        completed_task_ids = {
            t.id for t in self.tasks if t.status == TaskStatus.COMPLETED
        }

        for task in self.tasks:
            if task.status == TaskStatus.PENDING:
                # Check if all dependencies are completed
                if all(dep_id in completed_task_ids for dep_id in task.dependencies):
                    ready_tasks.append(task)

        return ready_tasks

    def to_dict(self) -> Dict[str, Any]:
        """Convert workflow to dictionary"""
        data = asdict(self)
        data["status"] = self.status.value
        data["priority"] = self.priority.value
        data["created_at"] = self.created_at.isoformat()
        if self.started_at:
            data["started_at"] = self.started_at.isoformat()
        if self.completed_at:
            data["completed_at"] = self.completed_at.isoformat()
        data["tasks"] = [task.to_dict() for task in self.tasks]
        return data


class TaskHandler(ABC):
    """Abstract base class for task handlers"""

    @abstractmethod
    async def execute(self, task: Task) -> TaskResult:
        """Execute the task and return result"""


class WorkflowEngine:
    """Core workflow engine for orchestrating tasks"""

    def __init__(self, max_concurrent_tasks: int = 10):
        self.workflows: Dict[str, Workflow] = {}
        self.task_handlers: Dict[str, TaskHandler] = {}
        self.max_concurrent_tasks = max_concurrent_tasks
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.logger = self._setup_logging()
        self.running = False
        self.stats = {
            "workflows_completed": 0,
            "workflows_failed": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "total_execution_time": 0.0,
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger("WorkflowEngine")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "component": "WorkflowEngine", '
                '"level": "%(levelname)s", "message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def register_handler(self, handler_name: str, handler: TaskHandler):
        """Register a task handler"""
        self.task_handlers[handler_name] = handler
        self.logger.info(f"Registered task handler: {handler_name}")

    def create_workflow(self, name: str, description: str = "", **kwargs) -> Workflow:
        """Create a new workflow"""
        workflow_id = str(uuid.uuid4())
        workflow = Workflow(
            id=workflow_id, name=name, description=description, **kwargs
        )
        self.workflows[workflow_id] = workflow
        self.logger.info(f"Created workflow: {name} ({workflow_id})")
        return workflow

    def add_task_to_workflow(
        self,
        workflow_id: str,
        name: str,
        handler: str,
        params: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Optional[Task]:
        """Add task to workflow"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            self.logger.error(f"Workflow not found: {workflow_id}")
            return None

        task_id = f"{workflow_id}:{str(uuid.uuid4())}"
        task = Task(
            id=task_id, name=name, handler=handler, params=params or {}, **kwargs
        )

        workflow.add_task(task)
        self.logger.info(f"Added task '{name}' to workflow {workflow_id}")
        return task

    async def execute_workflow(self, workflow_id: str) -> bool:
        """Execute a workflow"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            self.logger.error(f"Workflow not found: {workflow_id}")
            return False

        self.logger.info(f"Starting workflow execution: {workflow.name}")
        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = datetime.now()

        try:
            # Execute tasks based on dependencies
            while True:
                ready_tasks = workflow.get_ready_tasks()
                if not ready_tasks:
                    # Check if all tasks are completed
                    pending_tasks = [
                        t
                        for t in workflow.tasks
                        if t.status in [TaskStatus.PENDING, TaskStatus.RUNNING]
                    ]
                    if not pending_tasks:
                        break

                    # Wait for running tasks to complete
                    await asyncio.sleep(0.1)
                    continue

                # Execute ready tasks concurrently (up to max_concurrent_tasks)
                available_slots = self.max_concurrent_tasks - len(self.running_tasks)
                tasks_to_execute = ready_tasks[:available_slots]

                execution_tasks = []
                for task in tasks_to_execute:
                    task.status = TaskStatus.RUNNING
                    task.started_at = datetime.now()

                    execution_task = asyncio.create_task(self._execute_task(task))
                    self.running_tasks[task.id] = execution_task
                    execution_tasks.append(execution_task)

                # Wait for at least one task to complete if we have running tasks
                if execution_tasks:
                    done, pending = await asyncio.wait(
                        execution_tasks, return_when=asyncio.FIRST_COMPLETED
                    )

                    for completed_task in done:
                        # Find which task completed
                        for task_id, running_task in list(self.running_tasks.items()):
                            if running_task == completed_task:
                                del self.running_tasks[task_id]
                                break

            # Wait for all remaining tasks to complete
            if self.running_tasks:
                await asyncio.wait(list(self.running_tasks.values()))
                self.running_tasks.clear()

            # Determine workflow result
            failed_tasks = [t for t in workflow.tasks if t.status == TaskStatus.FAILED]
            if failed_tasks:
                workflow.status = WorkflowStatus.FAILED
                self.stats["workflows_failed"] += 1
                self.logger.error(
                    f"Workflow {workflow.name} failed with {len(failed_tasks)} failed tasks"
                )
                return False
            else:
                workflow.status = WorkflowStatus.COMPLETED
                workflow.completed_at = datetime.now()
                self.stats["workflows_completed"] += 1

                execution_time = (
                    workflow.completed_at - workflow.started_at
                ).total_seconds()
                self.stats["total_execution_time"] += execution_time

                self.logger.info(
                    f"Workflow {workflow.name} completed successfully in {execution_time:.2f}s"
                )
                return True

        except Exception as e:
            workflow.status = WorkflowStatus.FAILED
            self.stats["workflows_failed"] += 1
            self.logger.error(f"Workflow {workflow.name} execution error: {e}")
            return False

    async def _execute_task(self, task: Task) -> TaskResult:
        """Execute a single task"""
        start_time = datetime.now()

        try:
            self.logger.info(f"Executing task: {task.name}")

            # Get task handler
            handler = self.task_handlers.get(task.handler)
            if not handler:
                raise Exception(f"Handler not found: {task.handler}")

            # Execute with timeout
            try:
                result = await asyncio.wait_for(
                    handler.execute(task), timeout=task.timeout
                )

                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now()
                task.result = result

                execution_time = (task.completed_at - task.started_at).total_seconds()
                self.stats["tasks_completed"] += 1
                self.logger.info(f"Task {task.name} completed in {execution_time:.2f}s")

                return result

            except asyncio.TimeoutError:
                task.status = TaskStatus.TIMEOUT
                error_msg = f"Task timed out after {task.timeout}s"

                result = TaskResult(
                    task_id=task.id,
                    status=TaskStatus.TIMEOUT,
                    error=error_msg,
                    start_time=start_time,
                    end_time=datetime.now(),
                )

                task.result = result
                self.stats["tasks_failed"] += 1
                self.logger.error(f"Task {task.name} timed out")

                return result

        except Exception as e:
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now()
            error_msg = f"Task execution failed: {str(e)}"

            result = TaskResult(
                task_id=task.id,
                status=TaskStatus.FAILED,
                error=error_msg,
                start_time=start_time,
                end_time=datetime.now(),
                metadata={"traceback": traceback.format_exc()},
            )

            task.result = result
            self.stats["tasks_failed"] += 1
            self.logger.error(f"Task {task.name} failed: {e}")

            # Handle retries
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.PENDING
                self.logger.info(
                    f"Retrying task {task.name} (attempt {task.retry_count + 1})"
                )

            return result

    def cancel_workflow(self, workflow_id: str) -> bool:
        """Cancel a running workflow"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False

        workflow.status = WorkflowStatus.CANCELLED

        # Cancel running tasks
        for task in workflow.tasks:
            if task.status == TaskStatus.RUNNING:
                task.status = TaskStatus.CANCELLED

                if task.id in self.running_tasks:
                    self.running_tasks[task.id].cancel()
                    del self.running_tasks[task.id]

        self.logger.info(f"Cancelled workflow: {workflow.name}")
        return True

    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow status"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return None

        return {
            "workflow": workflow.to_dict(),
            "progress": self._calculate_progress(workflow),
            "running_tasks": len(
                [t for t in workflow.tasks if t.status == TaskStatus.RUNNING]
            ),
        }

    def _calculate_progress(self, workflow: Workflow) -> Dict[str, Any]:
        """Calculate workflow progress"""
        total_tasks = len(workflow.tasks)
        if total_tasks == 0:
            return {"percentage": 0, "completed": 0, "total": 0}

        completed_tasks = len(
            [t for t in workflow.tasks if t.status == TaskStatus.COMPLETED]
        )
        failed_tasks = len([t for t in workflow.tasks if t.status == TaskStatus.FAILED])
        running_tasks = len(
            [t for t in workflow.tasks if t.status == TaskStatus.RUNNING]
        )

        return {
            "percentage": (completed_tasks / total_tasks) * 100,
            "completed": completed_tasks,
            "failed": failed_tasks,
            "running": running_tasks,
            "total": total_tasks,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            **self.stats,
            "active_workflows": len(
                [
                    w
                    for w in self.workflows.values()
                    if w.status == WorkflowStatus.RUNNING
                ]
            ),
            "total_workflows": len(self.workflows),
            "registered_handlers": len(self.task_handlers),
            "current_running_tasks": len(self.running_tasks),
        }

    def cleanup_completed_workflows(self, older_than_hours: int = 24):
        """Clean up old completed workflows"""
        cutoff_time = datetime.now() - timedelta(hours=older_than_hours)
        to_remove = []

        for workflow_id, workflow in self.workflows.items():
            if (
                workflow.status
                in [
                    WorkflowStatus.COMPLETED,
                    WorkflowStatus.FAILED,
                    WorkflowStatus.CANCELLED,
                ]
                and workflow.completed_at
                and workflow.completed_at < cutoff_time
            ):
                to_remove.append(workflow_id)

        for workflow_id in to_remove:
            del self.workflows[workflow_id]

        if to_remove:
            self.logger.info(f"Cleaned up {len(to_remove)} old workflows")


# Built-in task handlers
class PythonFunctionHandler(TaskHandler):
    """Handler for executing Python functions"""

    def __init__(self, function: Callable):
        self.function = function

    async def execute(self, task: Task) -> TaskResult:
        """Execute Python function"""
        start_time = datetime.now()

        try:
            # Execute function with task parameters
            if asyncio.iscoroutinefunction(self.function):
                result = await self.function(**task.params)
            else:
                result = self.function(**task.params)

            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()

            return TaskResult(
                task_id=task.id,
                status=TaskStatus.COMPLETED,
                result=result,
                execution_time=execution_time,
                start_time=start_time,
                end_time=end_time,
            )

        except Exception as e:
            return TaskResult(
                task_id=task.id,
                status=TaskStatus.FAILED,
                error=str(e),
                execution_time=(datetime.now() - start_time).total_seconds(),
                start_time=start_time,
                end_time=datetime.now(),
            )


class HTTPRequestHandler(TaskHandler):
    """Handler for making HTTP requests"""

    def __init__(self):
        import aiohttp

        self.aiohttp = aiohttp

    async def execute(self, task: Task) -> TaskResult:
        """Execute HTTP request"""
        start_time = datetime.now()

        try:
            url = task.params.get("url")
            method = task.params.get("method", "GET")
            headers = task.params.get("headers", {})
            data = task.params.get("data")

            async with self.aiohttp.ClientSession() as session:
                async with session.request(
                    method=method, url=url, headers=headers, json=data
                ) as response:
                    result_data = {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "data": await response.text(),
                    }

                    if response.headers.get("content-type", "").startswith(
                        "application/json"
                    ):
                        try:
                            result_data["json"] = await response.json()
                        except Exception:
                            pass

            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()

            return TaskResult(
                task_id=task.id,
                status=TaskStatus.COMPLETED,
                result=result_data,
                execution_time=execution_time,
                start_time=start_time,
                end_time=end_time,
            )

        except Exception as e:
            return TaskResult(
                task_id=task.id,
                status=TaskStatus.FAILED,
                error=str(e),
                execution_time=(datetime.now() - start_time).total_seconds(),
                start_time=start_time,
                end_time=datetime.now(),
            )


# Singleton instance
_workflow_engine_instance: Optional[WorkflowEngine] = None


def get_workflow_engine() -> WorkflowEngine:
    """Get singleton workflow engine instance"""
    global _workflow_engine_instance
    if _workflow_engine_instance is None:
        _workflow_engine_instance = WorkflowEngine()
    return _workflow_engine_instance
