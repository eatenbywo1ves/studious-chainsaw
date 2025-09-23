"""
Visual Agent - Handles visual generation for the multi-agent video system
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
import aiohttp
import aiofiles
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VisualStyle(Enum):
    REALISTIC = "realistic"
    ANIMATED = "animated"
    ABSTRACT = "abstract"
    CYBERPUNK = "cyberpunk"
    WATERCOLOR = "watercolor"
    OIL_PAINTING = "oil_painting"
    SKETCH = "sketch"
    PHOTOGRAPHIC = "photographic"


@dataclass
class VisualRequest:
    scene_id: str
    prompt: str
    style: VisualStyle
    resolution: tuple = (1920, 1080)
    aspect_ratio: str = "16:9"
    quality: str = "high"
    metadata: Dict[str, Any] = None


class VisualAgent:
    """Agent responsible for generating visual content for video scenes"""

    def __init__(self, agent_id: str = None, output_dir: str = "./outputs/visuals"):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Configuration for different visual generation APIs
        self.api_config = {
            "stable_diffusion": {
                "url": "http://localhost:7860",  # Local SD WebUI
                "timeout": 60
            },
            "dall_e": {
                "api_key": None,  # Set via environment variable
                "model": "dall-e-3"
            },
            "midjourney": {
                "webhook_url": None
            }
        }

        self.generation_history = []
        self.active_tasks = {}

    async def initialize(self):
        """Initialize the visual agent and check API connectivity"""
        logger.info(f"Initializing Visual Agent {self.agent_id}")

        # Check which APIs are available
        available_apis = await self._check_api_availability()
        logger.info(f"Available visual APIs: {available_apis}")

        return True

    async def _check_api_availability(self) -> List[str]:
        """Check which visual generation APIs are available"""
        available = []

        # Check Stable Diffusion WebUI
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_config['stable_diffusion']['url']}/sdapi/v1/options"
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        available.append("stable_diffusion")
        except:
            logger.debug("Stable Diffusion API not available")

        # Check for API keys for cloud services
        import os
        if os.getenv("OPENAI_API_KEY"):
            available.append("dall_e")
        if os.getenv("MIDJOURNEY_WEBHOOK"):
            available.append("midjourney")

        return available

    async def process_scene(self, scene_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a scene request and generate visual content"""

        request = VisualRequest(
            scene_id=scene_data.get("scene_id"),
            prompt=scene_data.get("visual_prompt"),
            style=VisualStyle(scene_data.get("style", "realistic")),
            resolution=tuple(scene_data.get("resolution", [1920, 1080])),
            aspect_ratio=scene_data.get("aspect_ratio", "16:9"),
            quality=scene_data.get("quality", "high"),
            metadata=scene_data.get("metadata", {})
        )

        logger.info(f"Processing visual for scene {request.scene_id}")

        # Generate the visual
        result = await self._generate_visual(request)

        # Store in history
        self.generation_history.append({
            "scene_id": request.scene_id,
            "timestamp": datetime.now().isoformat(),
            "request": request.__dict__,
            "result": result
        })

        return result

    async def _generate_visual(self, request: VisualRequest) -> Dict[str, Any]:
        """Generate visual content based on the request"""

        task_id = str(uuid.uuid4())
        self.active_tasks[task_id] = {
            "status": "processing",
            "scene_id": request.scene_id,
            "started_at": datetime.now()
        }

        try:
            # Enhanced prompt based on style
            enhanced_prompt = self._enhance_prompt(request.prompt, request.style)

            # For now, simulate generation with a placeholder
            # In production, this would call actual generation APIs
            visual_data = await self._simulate_generation(enhanced_prompt, request)

            # Save the visual output
            output_path = self.output_dir / f"scene_{request.scene_id}_{task_id}.json"
            async with aiofiles.open(output_path, 'w') as f:
                await f.write(json.dumps(visual_data, indent=2))

            self.active_tasks[task_id]["status"] = "completed"

            return {
                "success": True,
                "task_id": task_id,
                "scene_id": request.scene_id,
                "output_path": str(output_path),
                "visual_data": visual_data,
                "generation_time": (datetime.now() - self.active_tasks[task_id]["started_at"]).total_seconds()
            }

        except Exception as e:
            logger.error(f"Error generating visual: {str(e)}")
            self.active_tasks[task_id]["status"] = "failed"

            return {
                "success": False,
                "task_id": task_id,
                "scene_id": request.scene_id,
                "error": str(e)
            }

    def _enhance_prompt(self, base_prompt: str, style: VisualStyle) -> str:
        """Enhance the prompt based on the visual style"""

        style_modifiers = {
            VisualStyle.REALISTIC: "photorealistic, highly detailed, 8k resolution",
            VisualStyle.ANIMATED: "animated style, vibrant colors, cartoon aesthetic",
            VisualStyle.ABSTRACT: "abstract art, geometric shapes, modern art style",
            VisualStyle.CYBERPUNK: "cyberpunk aesthetic, neon lights, futuristic, dark atmosphere",
            VisualStyle.WATERCOLOR: "watercolor painting, soft edges, artistic, flowing colors",
            VisualStyle.OIL_PAINTING: "oil painting, classical art, textured brushstrokes",
            VisualStyle.SKETCH: "pencil sketch, black and white, detailed line art",
            VisualStyle.PHOTOGRAPHIC: "professional photography, perfect lighting, sharp focus"
        }

        modifier = style_modifiers.get(style, "")
        return f"{base_prompt}, {modifier}" if modifier else base_prompt

    async def _simulate_generation(self, prompt: str, request: VisualRequest) -> Dict[str, Any]:
        """Simulate visual generation for testing"""

        # Simulate processing time
        await asyncio.sleep(2)

        return {
            "type": "simulated_visual",
            "prompt": prompt,
            "style": request.style.value,
            "resolution": request.resolution,
            "aspect_ratio": request.aspect_ratio,
            "quality": request.quality,
            "generated_at": datetime.now().isoformat(),
            "placeholder_image": f"placeholder_{request.scene_id}.png",
            "metadata": {
                "seed": 42,
                "steps": 50,
                "cfg_scale": 7.5
            }
        }

    async def generate_batch(self, scenes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate visuals for multiple scenes in parallel"""

        tasks = [self.process_scene(scene) for scene in scenes]
        results = await asyncio.gather(*tasks)

        return results

    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the visual agent"""

        active_count = sum(1 for t in self.active_tasks.values() if t["status"] == "processing")
        completed_count = sum(1 for t in self.active_tasks.values() if t["status"] == "completed")
        failed_count = sum(1 for t in self.active_tasks.values() if t["status"] == "failed")

        return {
            "agent_id": self.agent_id,
            "agent_type": "visual",
            "status": "active" if active_count > 0 else "idle",
            "active_tasks": active_count,
            "completed_tasks": completed_count,
            "failed_tasks": failed_count,
            "total_generations": len(self.generation_history)
        }


async def main():
    """Test the visual agent"""

    agent = VisualAgent()
    await agent.initialize()

    # Test scene
    test_scene = {
        "scene_id": "test_001",
        "visual_prompt": "A futuristic city skyline at sunset",
        "style": "cyberpunk",
        "resolution": [1920, 1080],
        "quality": "high"
    }

    result = await agent.process_scene(test_scene)
    print(f"Visual generation result: {json.dumps(result, indent=2)}")

    # Test batch processing
    batch_scenes = [
        {
            "scene_id": f"batch_{i}",
            "visual_prompt": f"Scene {i}: A beautiful landscape",
            "style": "watercolor"
        }
        for i in range(3)
    ]

    batch_results = await agent.generate_batch(batch_scenes)
    print(f"\nBatch processing completed: {len(batch_results)} scenes")

    # Get status
    status = agent.get_status()
    print(f"\nAgent status: {json.dumps(status, indent=2)}")


if __name__ == "__main__":
    asyncio.run(main())