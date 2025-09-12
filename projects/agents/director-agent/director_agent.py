"""
Director Agent - Central Orchestrator for Multi-Agent Generative AI Video System
"""

import asyncio
import uuid
import json
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import redis
from pydantic import BaseModel
import aiofiles


class ProjectStatus(Enum):
    INITIALIZING = "initializing"
    PLANNING = "planning"
    GENERATING = "generating"
    POST_PROCESSING = "post_processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentType(Enum):
    SCRIPT = "script"
    VISUAL = "visual"
    AUDIO = "audio"
    MOTION = "motion"
    POST_PRODUCTION = "post_production"


class TaskStatus(Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRY = "retry"


@dataclass
class VideoSpecs:
    duration: float
    resolution: tuple = (1920, 1080)
    fps: int = 30
    aspect_ratio: str = "16:9"
    style: str = "realistic"
    quality: str = "high"


@dataclass
class Scene:
    id: str
    description: str
    duration: float
    start_time: float
    visual_prompt: str = ""
    audio_requirements: str = ""
    motion_type: str = "static"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentTask:
    id: str
    agent_type: AgentType
    scene_id: str
    description: str
    input_data: Dict[str, Any]
    output_requirements: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    assigned_agent_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3


class ProjectState(BaseModel):
    id: str
    name: str
    user_prompt: str
    video_specs: VideoSpecs
    scenes: List[Scene]
    tasks: List[AgentTask]
    status: ProjectStatus
    progress: float = 0.0
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = {}


class AgentRegistry:
    """Registry to track available agents and their capabilities"""
    
    def __init__(self):
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.agent_loads: Dict[str, int] = {}
    
    def register_agent(self, agent_id: str, agent_type: AgentType, 
                      capabilities: Dict[str, Any], health_endpoint: str):
        self.agents[agent_id] = {
            'type': agent_type,
            'capabilities': capabilities,
            'health_endpoint': health_endpoint,
            'registered_at': datetime.now(),
            'status': 'available'
        }
        self.agent_loads[agent_id] = 0
    
    def get_best_agent(self, agent_type: AgentType, requirements: Dict[str, Any] = None) -> Optional[str]:
        """Get the best available agent for a task based on load and capabilities"""
        available_agents = [
            agent_id for agent_id, info in self.agents.items() 
            if info['type'] == agent_type and info['status'] == 'available'
        ]
        
        if not available_agents:
            return None
        
        # Simple load balancing - choose agent with lowest current load
        return min(available_agents, key=lambda x: self.agent_loads.get(x, 0))
    
    def update_agent_load(self, agent_id: str, load_change: int):
        if agent_id in self.agent_loads:
            self.agent_loads[agent_id] = max(0, self.agent_loads[agent_id] + load_change)


class DirectorAgent:
    """
    Central orchestrator for the multi-agent generative AI video system.
    Coordinates all other agents and manages the overall workflow.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.logger = logging.getLogger(__name__)
        self.redis_client = redis.from_url(redis_url)
        self.agent_registry = AgentRegistry()
        self.active_projects: Dict[str, ProjectState] = {}
        self.task_queue = asyncio.Queue()
        self.completion_callbacks: Dict[str, List[Callable]] = {}
        
        # Configuration
        self.max_concurrent_tasks = 10
        self.health_check_interval = 30
        
    async def initialize(self):
        """Initialize the Director Agent"""
        self.logger.info("Initializing Director Agent...")
        
        # Start background tasks
        asyncio.create_task(self._task_processor())
        asyncio.create_task(self._health_checker())
        asyncio.create_task(self._progress_monitor())
        
        self.logger.info("Director Agent initialized successfully")
    
    async def create_project(self, user_prompt: str, video_specs: VideoSpecs, 
                           project_name: str = None) -> str:
        """Create a new video generation project"""
        project_id = str(uuid.uuid4())
        
        if not project_name:
            project_name = f"Project_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        project = ProjectState(
            id=project_id,
            name=project_name,
            user_prompt=user_prompt,
            video_specs=video_specs,
            scenes=[],
            tasks=[],
            status=ProjectStatus.INITIALIZING,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        self.active_projects[project_id] = project
        
        # Start the project workflow
        asyncio.create_task(self._execute_project(project_id))
        
        self.logger.info(f"Created new project: {project_id}")
        return project_id
    
    async def _execute_project(self, project_id: str):
        """Main workflow execution for a project"""
        try:
            project = self.active_projects[project_id]
            
            # Phase 1: Planning and Script Generation
            await self._update_project_status(project_id, ProjectStatus.PLANNING)
            await self._generate_script_and_scenes(project_id)
            
            # Phase 2: Content Generation
            await self._update_project_status(project_id, ProjectStatus.GENERATING)
            await self._generate_content(project_id)
            
            # Phase 3: Post-Production
            await self._update_project_status(project_id, ProjectStatus.POST_PROCESSING)
            await self._post_production(project_id)
            
            # Phase 4: Completion
            await self._update_project_status(project_id, ProjectStatus.COMPLETED)
            await self._finalize_project(project_id)
            
        except Exception as e:
            self.logger.error(f"Project {project_id} failed: {str(e)}")
            await self._update_project_status(project_id, ProjectStatus.FAILED)
            await self._handle_project_failure(project_id, str(e))
    
    async def _generate_script_and_scenes(self, project_id: str):
        """Generate script and break down into scenes"""
        project = self.active_projects[project_id]
        
        # Create script generation task
        script_task = AgentTask(
            id=str(uuid.uuid4()),
            agent_type=AgentType.SCRIPT,
            scene_id="global",
            description="Generate script and scene breakdown",
            input_data={
                "user_prompt": project.user_prompt,
                "video_specs": project.video_specs.__dict__,
                "style_preferences": project.metadata.get("style", {})
            },
            output_requirements={
                "script": "Full script text",
                "scenes": "List of scene descriptions with timing",
                "storyboard": "Scene-by-scene visual descriptions"
            }
        )
        
        await self._assign_and_execute_task(script_task)
        
        # Wait for completion and update project with scenes
        await self._wait_for_task_completion(script_task.id)
        result = await self._get_task_result(script_task.id)
        
        # Parse scenes from script agent result
        if result and "scenes" in result:
            scenes = []
            for i, scene_data in enumerate(result["scenes"]):
                scene = Scene(
                    id=f"scene_{i+1}",
                    description=scene_data["description"],
                    duration=scene_data["duration"],
                    start_time=scene_data["start_time"],
                    visual_prompt=scene_data.get("visual_prompt", ""),
                    audio_requirements=scene_data.get("audio_requirements", ""),
                    motion_type=scene_data.get("motion_type", "static")
                )
                scenes.append(scene)
            
            project.scenes = scenes
            project.metadata["script"] = result.get("script", "")
            await self._save_project_state(project_id)
    
    async def _generate_content(self, project_id: str):
        """Generate content for all scenes in parallel"""
        project = self.active_projects[project_id]
        
        # Create tasks for each scene and content type
        tasks = []
        
        for scene in project.scenes:
            # Visual generation task
            visual_task = AgentTask(
                id=str(uuid.uuid4()),
                agent_type=AgentType.VISUAL,
                scene_id=scene.id,
                description=f"Generate visuals for {scene.id}",
                input_data={
                    "scene_description": scene.description,
                    "visual_prompt": scene.visual_prompt,
                    "duration": scene.duration,
                    "video_specs": project.video_specs.__dict__
                },
                output_requirements={
                    "video_file": "Generated video file path",
                    "frames": "Individual frame files",
                    "metadata": "Generation metadata"
                }
            )
            tasks.append(visual_task)
            
            # Audio generation task
            audio_task = AgentTask(
                id=str(uuid.uuid4()),
                agent_type=AgentType.AUDIO,
                scene_id=scene.id,
                description=f"Generate audio for {scene.id}",
                input_data={
                    "scene_description": scene.description,
                    "audio_requirements": scene.audio_requirements,
                    "duration": scene.duration
                },
                output_requirements={
                    "audio_file": "Generated audio file path",
                    "metadata": "Audio metadata"
                }
            )
            tasks.append(audio_task)
            
            # Motion/Animation task if needed
            if scene.motion_type != "static":
                motion_task = AgentTask(
                    id=str(uuid.uuid4()),
                    agent_type=AgentType.MOTION,
                    scene_id=scene.id,
                    description=f"Generate motion for {scene.id}",
                    input_data={
                        "scene_description": scene.description,
                        "motion_type": scene.motion_type,
                        "duration": scene.duration
                    },
                    output_requirements={
                        "motion_data": "Motion/camera data",
                        "keyframes": "Animation keyframes"
                    }
                )
                tasks.append(motion_task)
        
        # Execute all tasks
        for task in tasks:
            await self._assign_and_execute_task(task)
        
        # Wait for all tasks to complete
        await self._wait_for_tasks_completion([task.id for task in tasks])
    
    async def _post_production(self, project_id: str):
        """Final assembly and post-production"""
        project = self.active_projects[project_id]
        
        # Collect all generated assets
        scene_assets = {}
        for scene in project.scenes:
            scene_tasks = [t for t in project.tasks if t.scene_id == scene.id]
            assets = {}
            
            for task in scene_tasks:
                if task.status == TaskStatus.COMPLETED:
                    result = await self._get_task_result(task.id)
                    assets[task.agent_type.value] = result
            
            scene_assets[scene.id] = assets
        
        # Create post-production task
        post_task = AgentTask(
            id=str(uuid.uuid4()),
            agent_type=AgentType.POST_PRODUCTION,
            scene_id="global",
            description="Final video assembly and post-production",
            input_data={
                "scenes": [scene.__dict__ for scene in project.scenes],
                "scene_assets": scene_assets,
                "video_specs": project.video_specs.__dict__,
                "script": project.metadata.get("script", "")
            },
            output_requirements={
                "final_video": "Final assembled video file",
                "preview": "Low-resolution preview",
                "metadata": "Final video metadata"
            }
        )
        
        await self._assign_and_execute_task(post_task)
        await self._wait_for_task_completion(post_task.id)
    
    async def _assign_and_execute_task(self, task: AgentTask):
        """Assign a task to an appropriate agent and execute it"""
        # Find best available agent
        agent_id = self.agent_registry.get_best_agent(task.agent_type)
        
        if not agent_id:
            self.logger.error(f"No available agent for task {task.id} of type {task.agent_type}")
            task.status = TaskStatus.FAILED
            task.error_message = f"No available {task.agent_type.value} agent"
            return
        
        task.assigned_agent_id = agent_id
        task.status = TaskStatus.ASSIGNED
        task.started_at = datetime.now()
        
        # Add task to project
        project_id = None
        for pid, project in self.active_projects.items():
            if any(scene.id == task.scene_id for scene in project.scenes) or task.scene_id == "global":
                project_id = pid
                project.tasks.append(task)
                break
        
        if project_id:
            await self._save_project_state(project_id)
        
        # Send task to agent via message queue
        await self._send_task_to_agent(agent_id, task)
        
        # Update agent load
        self.agent_registry.update_agent_load(agent_id, 1)
        
        self.logger.info(f"Assigned task {task.id} to agent {agent_id}")
    
    async def _send_task_to_agent(self, agent_id: str, task: AgentTask):
        """Send task to specific agent via Redis"""
        task_data = {
            "task_id": task.id,
            "agent_type": task.agent_type.value,
            "description": task.description,
            "input_data": task.input_data,
            "output_requirements": task.output_requirements,
            "callback_endpoint": f"director/task_completed/{task.id}"
        }
        
        queue_name = f"agent_queue_{agent_id}"
        await asyncio.get_event_loop().run_in_executor(
            None, self.redis_client.lpush, queue_name, json.dumps(task_data)
        )
    
    async def _wait_for_task_completion(self, task_id: str, timeout: int = 300):
        """Wait for a specific task to complete"""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).seconds < timeout:
            # Find task in active projects
            task = None
            for project in self.active_projects.values():
                for t in project.tasks:
                    if t.id == task_id:
                        task = t
                        break
                if task:
                    break
            
            if task and task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
                return task.status == TaskStatus.COMPLETED
            
            await asyncio.sleep(1)
        
        self.logger.warning(f"Task {task_id} timed out")
        return False
    
    async def _wait_for_tasks_completion(self, task_ids: List[str], timeout: int = 600):
        """Wait for multiple tasks to complete"""
        completed = set()
        start_time = datetime.now()
        
        while len(completed) < len(task_ids) and (datetime.now() - start_time).seconds < timeout:
            for task_id in task_ids:
                if task_id in completed:
                    continue
                
                # Find task and check status
                task = None
                for project in self.active_projects.values():
                    for t in project.tasks:
                        if t.id == task_id:
                            task = t
                            break
                    if task:
                        break
                
                if task and task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
                    completed.add(task_id)
            
            await asyncio.sleep(2)
        
        return len(completed) == len(task_ids)
    
    async def _get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve task result from Redis"""
        result_key = f"task_result_{task_id}"
        result_data = await asyncio.get_event_loop().run_in_executor(
            None, self.redis_client.get, result_key
        )
        
        if result_data:
            return json.loads(result_data.decode())
        return None
    
    async def task_completed(self, task_id: str, result: Dict[str, Any], success: bool = True):
        """Handle task completion callback from agents"""
        # Find and update task
        for project in self.active_projects.values():
            for task in project.tasks:
                if task.id == task_id:
                    task.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
                    task.completed_at = datetime.now()
                    
                    if not success and "error" in result:
                        task.error_message = result["error"]
                    
                    # Store result
                    if success:
                        result_key = f"task_result_{task_id}"
                        await asyncio.get_event_loop().run_in_executor(
                            None, self.redis_client.setex, result_key, 3600, json.dumps(result)
                        )
                    
                    # Update agent load
                    if task.assigned_agent_id:
                        self.agent_registry.update_agent_load(task.assigned_agent_id, -1)
                    
                    await self._save_project_state(project.id)
                    await self._update_project_progress(project.id)
                    
                    self.logger.info(f"Task {task_id} completed with status: {task.status}")
                    return
        
        self.logger.warning(f"Task {task_id} not found for completion")
    
    async def _update_project_status(self, project_id: str, status: ProjectStatus):
        """Update project status"""
        if project_id in self.active_projects:
            self.active_projects[project_id].status = status
            self.active_projects[project_id].updated_at = datetime.now()
            await self._save_project_state(project_id)
            self.logger.info(f"Project {project_id} status updated to {status.value}")
    
    async def _update_project_progress(self, project_id: str):
        """Calculate and update project progress"""
        project = self.active_projects[project_id]
        
        if not project.tasks:
            project.progress = 0.0
            return
        
        completed_tasks = sum(1 for task in project.tasks if task.status == TaskStatus.COMPLETED)
        total_tasks = len(project.tasks)
        
        project.progress = (completed_tasks / total_tasks) * 100.0
        project.updated_at = datetime.now()
        
        await self._save_project_state(project_id)
    
    async def _save_project_state(self, project_id: str):
        """Save project state to Redis"""
        if project_id in self.active_projects:
            project_data = self.active_projects[project_id].dict()
            state_key = f"project_state_{project_id}"
            
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.setex, state_key, 86400, json.dumps(project_data, default=str)
            )
    
    async def _finalize_project(self, project_id: str):
        """Finalize completed project"""
        project = self.active_projects[project_id]
        
        # Get final video result
        post_tasks = [t for t in project.tasks if t.agent_type == AgentType.POST_PRODUCTION]
        if post_tasks:
            final_result = await self._get_task_result(post_tasks[0].id)
            project.metadata["final_video_path"] = final_result.get("final_video")
            project.metadata["preview_path"] = final_result.get("preview")
        
        project.progress = 100.0
        await self._save_project_state(project_id)
        
        # Execute completion callbacks
        if project_id in self.completion_callbacks:
            for callback in self.completion_callbacks[project_id]:
                try:
                    await callback(project)
                except Exception as e:
                    self.logger.error(f"Completion callback error: {e}")
        
        self.logger.info(f"Project {project_id} finalized successfully")
    
    async def _handle_project_failure(self, project_id: str, error: str):
        """Handle project failure"""
        project = self.active_projects[project_id]
        project.metadata["error"] = error
        await self._save_project_state(project_id)
        
        self.logger.error(f"Project {project_id} failed: {error}")
    
    async def _task_processor(self):
        """Background task processor"""
        while True:
            try:
                # Process task queue and handle retries
                await asyncio.sleep(5)
                
                # Check for failed tasks that need retry
                for project in self.active_projects.values():
                    for task in project.tasks:
                        if (task.status == TaskStatus.FAILED and 
                            task.retry_count < task.max_retries):
                            
                            task.retry_count += 1
                            task.status = TaskStatus.RETRY
                            self.logger.info(f"Retrying task {task.id}, attempt {task.retry_count}")
                            await self._assign_and_execute_task(task)
                
            except Exception as e:
                self.logger.error(f"Task processor error: {e}")
    
    async def _health_checker(self):
        """Background health checker for agents"""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                
                # Check agent health
                for agent_id, agent_info in list(self.agent_registry.agents.items()):
                    try:
                        # Implement health check logic here
                        # For now, just log
                        self.logger.debug(f"Health check for agent {agent_id}")
                    except Exception as e:
                        self.logger.warning(f"Agent {agent_id} health check failed: {e}")
                        agent_info['status'] = 'unhealthy'
                
            except Exception as e:
                self.logger.error(f"Health checker error: {e}")
    
    async def _progress_monitor(self):
        """Background progress monitoring"""
        while True:
            try:
                await asyncio.sleep(10)
                
                for project_id in list(self.active_projects.keys()):
                    await self._update_project_progress(project_id)
                
            except Exception as e:
                self.logger.error(f"Progress monitor error: {e}")
    
    # Public API methods
    
    def get_project_status(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Get current project status"""
        if project_id in self.active_projects:
            project = self.active_projects[project_id]
            return {
                "id": project.id,
                "name": project.name,
                "status": project.status.value,
                "progress": project.progress,
                "created_at": project.created_at,
                "updated_at": project.updated_at,
                "scenes_count": len(project.scenes),
                "tasks_count": len(project.tasks),
                "completed_tasks": sum(1 for t in project.tasks if t.status == TaskStatus.COMPLETED),
                "failed_tasks": sum(1 for t in project.tasks if t.status == TaskStatus.FAILED)
            }
        return None
    
    def list_active_projects(self) -> List[Dict[str, Any]]:
        """List all active projects"""
        return [self.get_project_status(pid) for pid in self.active_projects.keys()]
    
    async def cancel_project(self, project_id: str) -> bool:
        """Cancel an active project"""
        if project_id in self.active_projects:
            await self._update_project_status(project_id, ProjectStatus.CANCELLED)
            
            # Cancel pending tasks
            for task in self.active_projects[project_id].tasks:
                if task.status in [TaskStatus.PENDING, TaskStatus.ASSIGNED, TaskStatus.PROCESSING]:
                    task.status = TaskStatus.FAILED
                    task.error_message = "Project cancelled"
            
            await self._save_project_state(project_id)
            return True
        return False
    
    def add_completion_callback(self, project_id: str, callback: Callable):
        """Add completion callback for project"""
        if project_id not in self.completion_callbacks:
            self.completion_callbacks[project_id] = []
        self.completion_callbacks[project_id].append(callback)


# Usage example
async def main():
    director = DirectorAgent()
    await director.initialize()
    
    # Create a sample project
    video_specs = VideoSpecs(
        duration=30.0,
        resolution=(1920, 1080),
        fps=30,
        style="cinematic"
    )
    
    project_id = await director.create_project(
        user_prompt="Create a short video about a peaceful forest with birds singing",
        video_specs=video_specs,
        project_name="Forest Demo"
    )
    
    print(f"Created project: {project_id}")
    
    # Monitor progress
    while True:
        status = director.get_project_status(project_id)
        if status:
            print(f"Status: {status['status']}, Progress: {status['progress']:.1f}%")
            
            if status['status'] in ['completed', 'failed', 'cancelled']:
                break
        
        await asyncio.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())