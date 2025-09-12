# Director Agent - Multi-Agent Generative AI Video System

A comprehensive implementation of the central orchestrator for a multi-agent generative AI video creation system. The Director Agent coordinates script generation, visual content creation, audio synthesis, motion animation, and post-production to produce complete video projects.

## Features

### Core Capabilities
- **Project Orchestration**: Manages complete video generation workflows from prompt to final output
- **Multi-Agent Coordination**: Coordinates specialized agents for different aspects of video creation
- **Quality Control**: Comprehensive validation of visual, audio, and technical quality
- **Error Handling**: Robust retry mechanisms and failure recovery
- **Progress Tracking**: Real-time monitoring of project status and progress
- **Scalable Architecture**: Distributed task processing with Redis message queues

### Agent Types Supported
- **Script Agent**: Generates scripts and scene breakdowns
- **Visual Agent**: Creates video content using AI models
- **Audio Agent**: Synthesizes music, sound effects, and voice
- **Motion Agent**: Handles camera movements and animations  
- **Post-Production Agent**: Assembles final video with effects

### Quality Assurance
- **Visual Quality**: Blur detection, brightness/contrast analysis, resolution validation
- **Audio Quality**: Spectral analysis, clipping detection, dynamic range assessment
- **Consistency Checking**: Cross-scene visual and audio consistency validation
- **Technical Validation**: Format compatibility, synchronization, file integrity
- **Automated Reporting**: Comprehensive quality metrics and recommendations

## Installation

### Prerequisites
- Python 3.8+
- Redis server
- FFmpeg
- CUDA-capable GPU (recommended for video processing)

### Setup
```bash
# Clone or download the implementation files
pip install -r requirements.txt

# Install FFmpeg (Ubuntu/Debian)
sudo apt update
sudo apt install ffmpeg

# Install FFmpeg (macOS)
brew install ffmpeg

# Install FFmpeg (Windows)
# Download from https://ffmpeg.org/download.html

# Start Redis server
redis-server
```

## Usage

### Basic Usage
```python
import asyncio
from director_agent import DirectorAgent, VideoSpecs

async def create_video():
    # Initialize Director Agent
    director = DirectorAgent()
    await director.initialize()
    
    # Define video specifications
    specs = VideoSpecs(
        duration=30.0,
        resolution=(1920, 1080),
        fps=30,
        style="cinematic"
    )
    
    # Create project
    project_id = await director.create_project(
        user_prompt="Create a peaceful forest scene with birds singing",
        video_specs=specs,
        project_name="Forest Demo"
    )
    
    # Monitor progress
    while True:
        status = director.get_project_status(project_id)
        print(f"Status: {status['status']}, Progress: {status['progress']:.1f}%")
        
        if status['status'] in ['completed', 'failed']:
            break
        
        await asyncio.sleep(5)

# Run the example
asyncio.run(create_video())
```

### Command Line Interface
```bash
# Start the Director Agent service
python main.py

# Run with custom configuration
python main.py --config config.json

# Run demo mode
python main.py --demo
```

### Configuration
Create a `config.json` file for custom settings:

```json
{
  "redis": {
    "host": "localhost",
    "port": 6379,
    "db": 0
  },
  "agent": {
    "max_concurrent_tasks": 10,
    "health_check_interval": 30,
    "task_timeout": 300,
    "max_retries": 3
  },
  "quality": {
    "min_visual_quality": 0.7,
    "min_audio_quality": 0.6,
    "min_consistency_score": 0.75,
    "min_overall_score": 0.7
  },
  "storage": {
    "base_path": "./projects",
    "use_s3": false,
    "cleanup_temp_files": true
  },
  "logging": {
    "level": "INFO",
    "file_path": "./logs/director.log"
  }
}
```

## Architecture

### System Components

#### Director Agent (`director_agent.py`)
The central orchestrator that:
- Manages project lifecycle from creation to completion
- Coordinates task distribution across specialized agents
- Handles error recovery and retry logic
- Maintains project state and progress tracking
- Provides API for external integration

#### Quality Controller (`quality_control.py`)
Comprehensive quality assurance system:
- **Visual Analysis**: Blur detection, exposure assessment, resolution validation
- **Audio Analysis**: Spectral quality, clipping detection, dynamic range
- **Consistency Validation**: Cross-scene visual and audio consistency
- **Technical Validation**: Format compatibility, synchronization accuracy
- **Reporting**: Detailed quality metrics and improvement recommendations

#### Configuration System (`config.py`)
Flexible configuration management:
- Environment variable support
- File-based configuration (JSON/YAML)
- Environment-specific presets (development, production, testing)
- Runtime validation and error checking

### Workflow Process

1. **Project Initialization**
   - Parse user prompt and video specifications
   - Create project state and assign unique ID
   - Initialize task queue and monitoring

2. **Script Generation Phase**
   - Send prompt to Script Agent
   - Generate scene-by-scene breakdown
   - Create visual and audio requirements per scene

3. **Content Generation Phase**
   - Distribute visual generation tasks to Visual Agents
   - Assign audio creation tasks to Audio Agents
   - Process motion/animation requirements
   - Execute tasks in parallel for efficiency

4. **Quality Validation Phase**
   - Analyze generated content quality
   - Check cross-scene consistency
   - Validate technical specifications
   - Generate quality report with recommendations

5. **Post-Production Phase**
   - Collect all generated assets
   - Send to Post-Production Agent for final assembly
   - Apply effects, transitions, and color grading
   - Generate final output files

6. **Project Finalization**
   - Store final video and metadata
   - Execute completion callbacks
   - Clean up temporary files
   - Update project status

### Data Flow

```
User Prompt → Director Agent → Script Agent → Scene Breakdown
                    ↓
            Task Distribution
                    ↓
    ┌─ Visual Agent  ┌─ Audio Agent  ┌─ Motion Agent
    ├─ Visual Agent  ├─ Audio Agent  └─ Motion Agent
    └─ Visual Agent  └─ Audio Agent
                    ↓
            Quality Validation
                    ↓
         Post-Production Agent
                    ↓
            Final Video Output
```

### Message Queue Architecture

- **Task Distribution**: Redis-based message queues for agent communication
- **Result Storage**: Temporary storage of intermediate results
- **State Management**: Persistent project state tracking
- **Health Monitoring**: Agent availability and performance tracking

## API Reference

### DirectorAgent Class

#### Core Methods
```python
# Project Management
async def create_project(user_prompt: str, video_specs: VideoSpecs, 
                        project_name: str = None) -> str
async def cancel_project(project_id: str) -> bool
def get_project_status(project_id: str) -> Optional[Dict[str, Any]]
def list_active_projects() -> List[Dict[str, Any]]

# Task Management
async def task_completed(task_id: str, result: Dict[str, Any], success: bool = True)
def add_completion_callback(project_id: str, callback: Callable)

# Agent Registry
def register_agent(agent_id: str, agent_type: AgentType, 
                  capabilities: Dict[str, Any], health_endpoint: str)
```

#### Project Status Response
```python
{
    "id": "project_uuid",
    "name": "Project Name",
    "status": "generating",  # initializing, planning, generating, post_processing, completed, failed, cancelled
    "progress": 65.5,        # Percentage complete
    "created_at": "2024-01-01T00:00:00",
    "updated_at": "2024-01-01T01:30:00",
    "scenes_count": 5,
    "tasks_count": 15,
    "completed_tasks": 10,
    "failed_tasks": 0
}
```

### Quality Control

#### Quality Metrics Response
```python
{
    "visual_quality": 0.85,      # 0.0 - 1.0
    "audio_quality": 0.78,       # 0.0 - 1.0  
    "consistency_score": 0.92,   # 0.0 - 1.0
    "technical_score": 0.95,     # 0.0 - 1.0
    "overall_score": 0.87,       # 0.0 - 1.0
    "issues": [                  # List of identified issues
        "Scene 2: Low visual quality (blur detected)",
        "Scene 4: Audio-video sync offset of 0.8s"
    ],
    "recommendations": [         # Improvement suggestions
        "Consider improving lighting conditions",
        "Adjust audio-video timing synchronization"
    ]
}
```

## Integration with Other Agents

### Agent Communication Protocol
Agents communicate via Redis message queues using standardized message format:

```python
{
    "task_id": "unique_task_id",
    "agent_type": "visual|audio|motion|post_production",
    "description": "Task description",
    "input_data": {
        "scene_description": "...",
        "visual_prompt": "...",
        "duration": 5.0,
        "video_specs": {...}
    },
    "output_requirements": {
        "video_file": "Generated video file path",
        "metadata": "Generation metadata"
    },
    "callback_endpoint": "director/task_completed/task_id"
}
```

### Health Check Protocol
Each agent must implement health check endpoint:
```python
GET /health
Response: {
    "status": "healthy|unhealthy|busy",
    "current_load": 3,
    "max_capacity": 10,
    "capabilities": ["video_generation", "style_transfer"],
    "last_heartbeat": "2024-01-01T12:00:00"
}
```

## Performance Considerations

### Scalability
- **Horizontal Scaling**: Multiple Director Agent instances with shared Redis
- **Load Balancing**: Automatic agent selection based on current load
- **Resource Management**: Configurable concurrent task limits
- **Memory Management**: Efficient handling of large video files

### Optimization Tips
1. **GPU Utilization**: Ensure CUDA is properly configured for video processing
2. **Storage I/O**: Use SSD storage for temporary files and caching
3. **Network**: High-bandwidth connections for distributed agent communication
4. **Memory**: Sufficient RAM for video processing (16GB+ recommended)

### Monitoring
- **Metrics Collection**: Prometheus-compatible metrics endpoint
- **Health Monitoring**: Automated agent health checks
- **Performance Tracking**: Task processing times and queue sizes
- **Error Reporting**: Comprehensive error logging and alerting

## Error Handling

### Retry Mechanisms
- **Automatic Retries**: Configurable retry attempts for failed tasks
- **Exponential Backoff**: Progressive delay between retry attempts
- **Circuit Breaker**: Automatic agent disabling on repeated failures
- **Graceful Degradation**: Fallback strategies for partial failures

### Common Issues and Solutions

#### Agent Connection Issues
```python
# Check Redis connectivity
redis-cli ping

# Verify agent registration
# Check logs for agent heartbeat messages
```

#### Quality Validation Failures
```python
# Review quality report for specific issues
status = director.get_project_status(project_id)
quality_report = status.get('metadata', {}).get('quality_report', {})

# Adjust quality thresholds if needed
config.quality.min_visual_quality = 0.6
```

#### Memory Issues
```python
# Monitor memory usage
import psutil
print(f"Memory usage: {psutil.virtual_memory().percent}%")

# Reduce concurrent tasks if needed
config.agent.max_concurrent_tasks = 5
```

## Development

### Testing
```bash
# Run unit tests
pytest tests/

# Run with coverage
pytest --cov=director_agent tests/

# Integration tests
pytest tests/integration/
```

### Contributing
1. Follow PEP 8 style guidelines
2. Add comprehensive docstrings
3. Include unit tests for new features
4. Update documentation for API changes

### Logging
The system provides comprehensive logging at multiple levels:
- **DEBUG**: Detailed execution information
- **INFO**: General operational messages  
- **WARNING**: Non-critical issues and recommendations
- **ERROR**: Critical errors requiring attention

## License

This implementation is provided as an example for educational and development purposes. Modify and adapt according to your specific requirements and licensing needs.

## Future Enhancements

### Planned Features
- **Web UI**: Browser-based project management interface
- **REST API**: HTTP API for external integration
- **Batch Processing**: Support for multiple project processing
- **Advanced Scheduling**: Priority-based task scheduling
- **Analytics Dashboard**: Real-time performance monitoring
- **Plugin System**: Extensible agent plugin architecture

### Integration Opportunities
- **Cloud Platforms**: AWS, GCP, Azure deployment
- **Container Orchestration**: Kubernetes deployment
- **Monitoring Systems**: Grafana, Prometheus integration
- **Storage Solutions**: S3, GCS, Azure Blob storage
- **Authentication**: OAuth, JWT token support