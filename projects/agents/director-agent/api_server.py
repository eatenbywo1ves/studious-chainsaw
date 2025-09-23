"""
FastAPI Server for Multi-Agent Video Generation System
Provides REST API endpoints for project submission and monitoring
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import asyncio
import json
import uuid
import logging

from redis_communication import RedisCommunicator, RedisConfig, MessageType
from agent_registry import AgentRegistry
from director_agent import ProjectStatus, AgentType, VideoSpecs, Scene

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Multi-Agent Video Generation API",
    description="API for submitting and monitoring AI video generation projects",
    version="1.0.0"
)

# CORS middleware for web frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic models for API
class SceneModel(BaseModel):
    description: str = Field(..., description="Scene description")
    duration: float = Field(..., gt=0, le=300, description="Duration in seconds")
    visual_prompt: str = Field(..., description="Prompt for visual generation")
    audio_requirements: Optional[str] = None
    motion_type: str = Field(default="static", description="Type of camera motion")
    style: str = Field(default="realistic", description="Visual style")
    mood: Optional[str] = None
    transition_in: Optional[str] = None
    transition_out: Optional[str] = None
    sound_effects: Optional[List[str]] = []
    metadata: Dict[str, Any] = {}

    @validator('motion_type')
    def validate_motion_type(cls, v):
        valid_types = ["static", "pan", "zoom", "rotate", "track", "dolly", "orbit"]
        if v not in valid_types:
            raise ValueError(f"Motion type must be one of: {valid_types}")
        return v

    @validator('style')
    def validate_style(cls, v):
        valid_styles = ["realistic", "animated", "abstract", "cyberpunk",
                       "watercolor", "oil_painting", "sketch", "photographic"]
        if v not in valid_styles:
            raise ValueError(f"Style must be one of: {valid_styles}")
        return v


class VideoProjectModel(BaseModel):
    title: str = Field(..., description="Project title")
    description: Optional[str] = None
    duration: Optional[float] = None
    resolution: List[int] = Field(default=[1920, 1080])
    fps: int = Field(default=30, ge=24, le=120)
    aspect_ratio: str = Field(default="16:9")
    quality: str = Field(default="high")
    scenes: List[SceneModel] = Field(..., min_items=1, max_items=50)
    output_format: str = Field(default="mp4")
    metadata: Dict[str, Any] = {}


class ProjectResponse(BaseModel):
    project_id: str
    status: str
    message: str
    created_at: datetime
    estimated_completion: Optional[datetime] = None


class ProjectStatusResponse(BaseModel):
    project_id: str
    status: str
    progress: float
    completed_scenes: int
    total_scenes: int
    agents_assigned: Dict[str, List[str]]
    created_at: datetime
    updated_at: datetime
    errors: List[str] = []


# Global instances
registry: Optional[AgentRegistry] = None
director_comm: Optional[RedisCommunicator] = None
projects_db: Dict[str, Dict[str, Any]] = {}
websocket_manager = None


class WebSocketManager:
    """Manage WebSocket connections for real-time updates"""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"WebSocket client {client_id} connected")

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"WebSocket client {client_id} disconnected")

    async def send_update(self, client_id: str, message: dict):
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(message)
            except Exception as e:
                logger.error(f"Error sending to {client_id}: {e}")
                self.disconnect(client_id)

    async def broadcast(self, message: dict):
        for client_id in list(self.active_connections.keys()):
            await self.send_update(client_id, message)


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global registry, director_comm, websocket_manager

    logger.info("Starting API server...")

    # Initialize WebSocket manager
    websocket_manager = WebSocketManager()

    # Initialize Redis communication
    director_comm = RedisCommunicator("api_director", "director")
    connected = await director_comm.connect()

    if not connected:
        logger.error("Failed to connect to Redis!")
        raise RuntimeError("Redis connection failed")

    # Initialize agent registry
    registry = AgentRegistry()
    await registry.start()

    # Start background tasks
    asyncio.create_task(monitor_projects())
    asyncio.create_task(director_comm.message_listener())

    logger.info("API server started successfully")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown"""
    if registry:
        await registry.stop()
    if director_comm:
        await director_comm.disconnect()


async def monitor_projects():
    """Background task to monitor project status"""
    while True:
        try:
            # Check for completed tasks
            task_result = await director_comm.redis_client.blpop(
                ["results"], timeout=1
            )

            if task_result:
                _, result_json = task_result
                result = json.loads(result_json)

                # Update project status
                task_id = result.get("task_id")
                for project_id, project in projects_db.items():
                    if task_id in project.get("tasks", []):
                        project["completed_tasks"].append(task_id)

                        # Send WebSocket update
                        await websocket_manager.broadcast({
                            "type": "task_complete",
                            "project_id": project_id,
                            "task_id": task_id,
                            "result": result
                        })

            await asyncio.sleep(0.5)

        except Exception as e:
            logger.error(f"Error in monitor_projects: {e}")
            await asyncio.sleep(5)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Multi-Agent Video Generation API",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "submit_project": "/api/projects/submit",
            "project_status": "/api/projects/{project_id}/status",
            "list_projects": "/api/projects",
            "agent_status": "/api/agents/status",
            "health": "/api/health"
        }
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""

    # Check Redis connection
    redis_healthy = False
    try:
        await director_comm.redis_client.ping()
        redis_healthy = True
    except:
        pass

    # Get agent statistics
    stats = registry.get_registry_stats() if registry else {}

    return {
        "status": "healthy" if redis_healthy else "degraded",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "redis": redis_healthy,
            "registry": registry is not None,
            "agents": {
                "total": stats.get("total_agents", 0),
                "online": stats.get("online_agents", 0)
            }
        }
    }


@app.post("/api/projects/submit", response_model=ProjectResponse)
async def submit_project(
    project: VideoProjectModel,
    background_tasks: BackgroundTasks
):
    """Submit a new video generation project"""

    # Generate project ID
    project_id = str(uuid.uuid4())

    # Store project
    projects_db[project_id] = {
        "id": project_id,
        "title": project.title,
        "status": ProjectStatus.INITIALIZING.value,
        "scenes": [scene.dict() for scene in project.scenes],
        "specs": {
            "resolution": project.resolution,
            "fps": project.fps,
            "quality": project.quality
        },
        "created_at": datetime.now(),
        "updated_at": datetime.now(),
        "tasks": [],
        "completed_tasks": [],
        "errors": []
    }

    # Process project in background
    background_tasks.add_task(process_project, project_id, project)

    # Calculate estimated completion
    total_duration = sum(scene.duration for scene in project.scenes)
    estimated_time = total_duration * 2  # Rough estimate
    estimated_completion = datetime.now() + timedelta(seconds=estimated_time)

    return ProjectResponse(
        project_id=project_id,
        status=ProjectStatus.INITIALIZING.value,
        message="Project submitted successfully",
        created_at=datetime.now(),
        estimated_completion=estimated_completion
    )


async def process_project(project_id: str, project: VideoProjectModel):
    """Process a video project"""

    try:
        # Update status
        projects_db[project_id]["status"] = ProjectStatus.PLANNING.value

        # Send WebSocket update
        await websocket_manager.broadcast({
            "type": "project_status",
            "project_id": project_id,
            "status": ProjectStatus.PLANNING.value
        })

        # Generate tasks for each scene
        tasks = []
        for i, scene in enumerate(project.scenes):
            scene_id = f"{project_id}_scene_{i:03d}"

            # Visual task
            visual_task = {
                "id": f"{scene_id}_visual",
                "project_id": project_id,
                "scene_id": scene_id,
                "type": "visual",
                "data": {
                    "visual_prompt": scene.visual_prompt,
                    "style": scene.style,
                    "resolution": project.resolution,
                    "duration": scene.duration
                }
            }
            tasks.append(visual_task)

            # Audio task
            if scene.audio_requirements or scene.mood:
                audio_task = {
                    "id": f"{scene_id}_audio",
                    "project_id": project_id,
                    "scene_id": scene_id,
                    "type": "audio",
                    "data": {
                        "requirements": scene.audio_requirements,
                        "mood": scene.mood,
                        "duration": scene.duration,
                        "sound_effects": scene.sound_effects
                    }
                }
                tasks.append(audio_task)

            # Motion task
            motion_task = {
                "id": f"{scene_id}_motion",
                "project_id": project_id,
                "scene_id": scene_id,
                "type": "motion",
                "data": {
                    "motion_type": scene.motion_type,
                    "duration": scene.duration,
                    "transition_in": scene.transition_in,
                    "transition_out": scene.transition_out
                }
            }
            tasks.append(motion_task)

        projects_db[project_id]["tasks"] = [t["id"] for t in tasks]

        # Update status to generating
        projects_db[project_id]["status"] = ProjectStatus.GENERATING.value

        # Distribute tasks to agents
        assigned_agents = {}
        for task in tasks:
            agent_type = task["type"]

            # Get best available agent
            agent = registry.get_best_agent(agent_type)

            if agent:
                # Submit task to agent's queue
                await director_comm.submit_task(agent_type, task)

                # Track assignment
                if agent_type not in assigned_agents:
                    assigned_agents[agent_type] = []
                assigned_agents[agent_type].append(agent.id)

                # Send task assignment message
                await director_comm.send_message(
                    agent.id,
                    MessageType.TASK_ASSIGNMENT,
                    task
                )
            else:
                logger.warning(f"No agent available for {agent_type} task")
                projects_db[project_id]["errors"].append(
                    f"No agent available for {agent_type}"
                )

        projects_db[project_id]["agents_assigned"] = assigned_agents
        projects_db[project_id]["updated_at"] = datetime.now()

        # Send WebSocket update
        await websocket_manager.broadcast({
            "type": "tasks_distributed",
            "project_id": project_id,
            "total_tasks": len(tasks),
            "agents_assigned": assigned_agents
        })

    except Exception as e:
        logger.error(f"Error processing project {project_id}: {e}")
        projects_db[project_id]["status"] = ProjectStatus.FAILED.value
        projects_db[project_id]["errors"].append(str(e))


@app.get("/api/projects/{project_id}/status", response_model=ProjectStatusResponse)
async def get_project_status(project_id: str):
    """Get project status"""

    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects_db[project_id]

    total_tasks = len(project["tasks"])
    completed_tasks = len(project["completed_tasks"])
    progress = (completed_tasks / max(total_tasks, 1)) * 100

    return ProjectStatusResponse(
        project_id=project_id,
        status=project["status"],
        progress=progress,
        completed_scenes=completed_tasks // 3,  # Approx scenes
        total_scenes=len(project["scenes"]),
        agents_assigned=project.get("agents_assigned", {}),
        created_at=project["created_at"],
        updated_at=project["updated_at"],
        errors=project["errors"]
    )


@app.get("/api/projects")
async def list_projects(
    status: Optional[str] = None,
    limit: int = 10,
    offset: int = 0
):
    """List all projects with optional filtering"""

    # Filter projects
    filtered_projects = list(projects_db.values())

    if status:
        filtered_projects = [
            p for p in filtered_projects
            if p["status"] == status
        ]

    # Sort by creation date (newest first)
    filtered_projects.sort(key=lambda x: x["created_at"], reverse=True)

    # Paginate
    total = len(filtered_projects)
    projects = filtered_projects[offset:offset + limit]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "projects": [
            {
                "id": p["id"],
                "title": p["title"],
                "status": p["status"],
                "created_at": p["created_at"].isoformat(),
                "updated_at": p["updated_at"].isoformat()
            }
            for p in projects
        ]
    }


@app.get("/api/agents/status")
async def get_agents_status():
    """Get status of all agents"""

    if not registry:
        raise HTTPException(status_code=503, detail="Registry not available")

    stats = registry.get_registry_stats()
    agents = []

    for agent_id, agent_info in registry.agents.items():
        agents.append({
            "id": agent_id,
            "type": agent_info.type,
            "status": agent_info.status.value,
            "capacity": agent_info.capacity,
            "tasks_completed": agent_info.tasks_completed,
            "tasks_failed": agent_info.tasks_failed,
            "average_task_time": agent_info.average_task_time,
            "last_heartbeat": agent_info.last_heartbeat.isoformat()
        })

    return {
        "statistics": stats,
        "agents": agents
    }


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time updates"""

    await websocket_manager.connect(websocket, client_id)

    try:
        # Send initial status
        await websocket.send_json({
            "type": "connected",
            "client_id": client_id,
            "timestamp": datetime.now().isoformat()
        })

        # Keep connection alive
        while True:
            data = await websocket.receive_text()

            # Handle ping/pong
            if data == "ping":
                await websocket.send_text("pong")
            else:
                # Echo back any other messages
                await websocket.send_text(f"Echo: {data}")

    except WebSocketDisconnect:
        websocket_manager.disconnect(client_id)


@app.delete("/api/projects/{project_id}")
async def cancel_project(project_id: str):
    """Cancel a project"""

    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects_db[project_id]

    # Update status
    project["status"] = ProjectStatus.CANCELLED.value
    project["updated_at"] = datetime.now()

    # Broadcast cancellation
    await director_comm.broadcast_message(
        MessageType.PROJECT_UPDATE,
        {
            "project_id": project_id,
            "status": "cancelled"
        }
    )

    return {"message": "Project cancelled", "project_id": project_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )