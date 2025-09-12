#!/usr/bin/env python3
"""
Main application entry point for Director Agent
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from director_agent import DirectorAgent, VideoSpecs, ProjectStatus
from quality_control import integrate_quality_control
from config import DirectorConfig, validate_config


class DirectorService:
    """Main service class for Director Agent"""
    
    def __init__(self, config: DirectorConfig):
        self.config = config
        self.director: Optional[DirectorAgent] = None
        self.running = False
        
        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.logging.level.upper())
        
        # Create formatter
        formatter = logging.Formatter(self.config.logging.format)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        
        # File handler
        log_dir = Path(self.config.logging.file_path).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(self.config.logging.file_path)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)
    
    async def start(self):
        """Start the Director Agent service"""
        try:
            self.logger.info("Starting Director Agent service...")
            
            # Validate configuration
            if not validate_config(self.config):
                self.logger.error("Configuration validation failed")
                return False
            
            # Initialize Director Agent
            self.director = DirectorAgent(self.config.redis.url)
            await self.director.initialize()
            
            # Integrate quality control
            quality_callback = integrate_quality_control(self.director)
            
            # Register signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            self.running = True
            self.logger.info("Director Agent service started successfully")
            
            # Keep the service running
            while self.running:
                await asyncio.sleep(1)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start Director Agent service: {e}")
            return False
    
    async def stop(self):
        """Stop the Director Agent service"""
        self.logger.info("Stopping Director Agent service...")
        self.running = False
        
        if self.director:
            # Cancel all active projects
            for project_id in list(self.director.active_projects.keys()):
                await self.director.cancel_project(project_id)
            
            # Wait for cleanup
            await asyncio.sleep(2)
        
        self.logger.info("Director Agent service stopped")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, initiating shutdown...")
        self.running = False
    
    async def create_sample_project(self):
        """Create a sample project for testing"""
        if not self.director:
            self.logger.error("Director not initialized")
            return None
        
        video_specs = VideoSpecs(
            duration=30.0,
            resolution=(1920, 1080),
            fps=30,
            style="cinematic",
            quality="high"
        )
        
        project_id = await self.director.create_project(
            user_prompt="Create a peaceful nature video showing a serene forest with gentle wind through trees, birds chirping, and soft sunlight filtering through leaves. Include ambient forest sounds and a calm, relaxing atmosphere.",
            video_specs=video_specs,
            project_name="Sample Forest Video"
        )
        
        self.logger.info(f"Created sample project: {project_id}")
        return project_id
    
    def get_project_status(self, project_id: str):
        """Get project status"""
        if self.director:
            return self.director.get_project_status(project_id)
        return None
    
    def list_projects(self):
        """List all active projects"""
        if self.director:
            return self.director.list_active_projects()
        return []


async def main():
    """Main application entry point"""
    
    # Load configuration
    config_file = sys.argv[1] if len(sys.argv) > 1 else None
    config = DirectorConfig(config_file)
    
    # Create and start service
    service = DirectorService(config)
    
    try:
        # Start the service
        success = await service.start()
        if not success:
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
    
    finally:
        # Graceful shutdown
        await service.stop()


async def demo():
    """Demo function to show usage"""
    print("Director Agent Demo")
    print("===================")
    
    # Initialize service
    config = DirectorConfig()
    service = DirectorService(config)
    
    try:
        # Start service
        print("Starting Director Agent...")
        start_task = asyncio.create_task(service.start())
        
        # Wait a moment for startup
        await asyncio.sleep(2)
        
        # Create sample project
        print("Creating sample project...")
        project_id = await service.create_sample_project()
        
        if project_id:
            print(f"Project created: {project_id}")
            
            # Monitor progress
            print("Monitoring project progress...")
            while True:
                status = service.get_project_status(project_id)
                if status:
                    print(f"Status: {status['status']} - Progress: {status['progress']:.1f}%")
                    
                    if status['status'] in ['completed', 'failed', 'cancelled']:
                        print(f"Project finished with status: {status['status']}")
                        break
                else:
                    print("Project not found")
                    break
                
                await asyncio.sleep(5)
        
        # List all projects
        projects = service.list_projects()
        print(f"Total active projects: {len(projects)}")
    
    except KeyboardInterrupt:
        print("\nDemo interrupted")
    
    finally:
        await service.stop()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Director Agent for Multi-Agent Video Generation")
    parser.add_argument("--config", "-c", help="Configuration file path")
    parser.add_argument("--demo", "-d", action="store_true", help="Run demo mode")
    
    args = parser.parse_args()
    
    if args.demo:
        asyncio.run(demo())
    else:
        asyncio.run(main())