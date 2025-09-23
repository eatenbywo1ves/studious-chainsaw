"""
Motion Agent - Handles motion, animation, and transitions for the multi-agent video system
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MotionType(Enum):
    STATIC = "static"
    PAN = "pan"
    ZOOM = "zoom"
    ROTATE = "rotate"
    DOLLY = "dolly"
    TRACK = "track"
    CRANE = "crane"
    HANDHELD = "handheld"
    ORBIT = "orbit"
    PARALLAX = "parallax"


class TransitionType(Enum):
    CUT = "cut"
    FADE = "fade"
    DISSOLVE = "dissolve"
    WIPE = "wipe"
    SLIDE = "slide"
    ZOOM_TRANSITION = "zoom_transition"
    MORPH = "morph"
    GLITCH = "glitch"
    BLUR = "blur"
    SPIN = "spin"


class AnimationType(Enum):
    NONE = "none"
    EASE_IN = "ease_in"
    EASE_OUT = "ease_out"
    EASE_IN_OUT = "ease_in_out"
    LINEAR = "linear"
    BOUNCE = "bounce"
    ELASTIC = "elastic"
    BACK = "back"
    CIRCULAR = "circular"
    EXPONENTIAL = "exponential"


@dataclass
class CameraMotion:
    motion_type: MotionType
    duration: float
    start_position: Tuple[float, float, float] = (0, 0, 0)
    end_position: Tuple[float, float, float] = (0, 0, 0)
    start_rotation: Tuple[float, float, float] = (0, 0, 0)
    end_rotation: Tuple[float, float, float] = (0, 0, 0)
    focal_length: float = 50.0
    animation_curve: AnimationType = AnimationType.EASE_IN_OUT
    speed: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SceneTransition:
    transition_type: TransitionType
    duration: float
    from_scene: str
    to_scene: str
    animation_curve: AnimationType = AnimationType.LINEAR
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ObjectAnimation:
    object_id: str
    animation_type: str
    duration: float
    keyframes: List[Dict[str, Any]]
    animation_curve: AnimationType = AnimationType.EASE_IN_OUT
    loop: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class MotionAgent:
    """Agent responsible for handling motion, animation, and transitions"""

    def __init__(self, agent_id: str = None, output_dir: str = "./outputs/motion"):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Motion configuration
        self.motion_config = {
            "default_fps": 30,
            "default_resolution": (1920, 1080),
            "motion_blur": True,
            "stabilization": True,
            "interpolation_quality": "high"
        }

        # Preset motion templates
        self.motion_templates = {
            "dramatic_reveal": self._create_dramatic_reveal_template(),
            "smooth_transition": self._create_smooth_transition_template(),
            "action_sequence": self._create_action_sequence_template(),
            "documentary_style": self._create_documentary_style_template()
        }

        self.generation_history = []
        self.active_tasks = {}
        self.motion_library = {}

    async def initialize(self):
        """Initialize the motion agent"""
        logger.info(f"Initializing Motion Agent {self.agent_id}")

        # Load motion presets
        await self._load_motion_presets()

        # Check available motion processing tools
        available_tools = await self._check_tools_availability()
        logger.info(f"Available motion tools: {available_tools}")

        return True

    async def _check_tools_availability(self) -> List[str]:
        """Check which motion processing tools are available"""
        available = []

        # Check for animation libraries
        try:
            import cv2
            available.append("opencv")
        except ImportError:
            pass

        try:
            import PIL
            available.append("pillow")
        except ImportError:
            pass

        # Simulation always available
        available.append("simulation")

        return available

    async def _load_motion_presets(self):
        """Load preset motion configurations"""
        presets_dir = self.output_dir / "presets"
        if presets_dir.exists():
            for preset_file in presets_dir.glob("*.json"):
                try:
                    with open(preset_file, 'r') as f:
                        preset = json.load(f)
                        self.motion_library[preset['name']] = preset
                except Exception as e:
                    logger.error(f"Error loading preset {preset_file}: {e}")

    def _create_dramatic_reveal_template(self) -> Dict[str, Any]:
        """Create a dramatic reveal motion template"""
        return {
            "name": "dramatic_reveal",
            "camera_motions": [
                {
                    "type": "zoom",
                    "duration": 3,
                    "from": 0.5,
                    "to": 1.0,
                    "curve": "ease_out"
                },
                {
                    "type": "pan",
                    "duration": 2,
                    "direction": "right",
                    "amount": 15,
                    "curve": "ease_in_out"
                }
            ],
            "transitions": ["fade_in", "slow_dissolve"]
        }

    def _create_smooth_transition_template(self) -> Dict[str, Any]:
        """Create a smooth transition template"""
        return {
            "name": "smooth_transition",
            "transitions": [
                {
                    "type": "dissolve",
                    "duration": 1.5,
                    "curve": "ease_in_out"
                }
            ]
        }

    def _create_action_sequence_template(self) -> Dict[str, Any]:
        """Create an action sequence motion template"""
        return {
            "name": "action_sequence",
            "camera_motions": [
                {
                    "type": "handheld",
                    "intensity": 0.7,
                    "duration": "scene"
                },
                {
                    "type": "track",
                    "speed": 2.0,
                    "follow_subject": True
                }
            ],
            "transitions": ["cut", "quick_zoom"]
        }

    def _create_documentary_style_template(self) -> Dict[str, Any]:
        """Create a documentary style template"""
        return {
            "name": "documentary_style",
            "camera_motions": [
                {
                    "type": "slow_zoom",
                    "duration": 5,
                    "amount": 1.2
                },
                {
                    "type": "gentle_pan",
                    "duration": 4,
                    "amount": 10
                }
            ]
        }

    async def process_scene(self, scene_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process motion requirements for a scene"""

        task_id = str(uuid.uuid4())
        self.active_tasks[task_id] = {
            "status": "processing",
            "scene_id": scene_data["scene_id"],
            "started_at": datetime.now()
        }

        try:
            # Parse motion requirements
            camera_motion = await self._plan_camera_motion(scene_data)
            transitions = await self._plan_transitions(scene_data)
            object_animations = await self._plan_object_animations(scene_data)

            # Generate motion data
            motion_data = await self._generate_motion_data(
                camera_motion, transitions, object_animations, scene_data
            )

            # Apply motion effects
            processed_motion = await self._apply_motion_effects(motion_data, scene_data)

            # Generate motion path visualization
            motion_path = await self._generate_motion_path(processed_motion)

            # Save the result
            output_path = await self._save_motion_data(
                processed_motion, scene_data["scene_id"]
            )

            result = {
                "success": True,
                "task_id": task_id,
                "scene_id": scene_data["scene_id"],
                "output_path": str(output_path),
                "motion_summary": {
                    "camera_motions": len(camera_motion),
                    "transitions": len(transitions),
                    "object_animations": len(object_animations),
                    "total_duration": scene_data.get("duration", 10),
                    "motion_path": motion_path
                },
                "generation_time": (
                    datetime.now() - self.active_tasks[task_id]["started_at"]
                ).total_seconds()
            }

            self.active_tasks[task_id]["status"] = "completed"

            # Store in history
            self.generation_history.append({
                "scene_id": scene_data["scene_id"],
                "timestamp": datetime.now().isoformat(),
                "result": result
            })

            return result

        except Exception as e:
            logger.error(f"Error processing motion: {e}")
            self.active_tasks[task_id]["status"] = "failed"
            return {
                "success": False,
                "task_id": task_id,
                "scene_id": scene_data["scene_id"],
                "error": str(e)
            }

    async def _plan_camera_motion(self, scene_data: Dict[str, Any]) -> List[CameraMotion]:
        """Plan camera motions for the scene"""
        motions = []

        # Check for template
        if scene_data.get("motion_template"):
            template = self.motion_templates.get(scene_data["motion_template"])
            if template and "camera_motions" in template:
                for motion_spec in template["camera_motions"]:
                    motion = self._create_camera_motion_from_spec(motion_spec)
                    motions.append(motion)

        # Default motion if none specified
        if not motions:
            motion_type_str = scene_data.get("motion_type", "static")
            motion_type = MotionType[motion_type_str.upper()] if motion_type_str.upper() in MotionType.__members__ else MotionType.STATIC

            motion = CameraMotion(
                motion_type=motion_type,
                duration=scene_data.get("duration", 10),
                speed=scene_data.get("motion_speed", 1.0),
                animation_curve=AnimationType.EASE_IN_OUT
            )
            motions.append(motion)

        return motions

    def _create_camera_motion_from_spec(self, spec: Dict[str, Any]) -> CameraMotion:
        """Create camera motion from specification"""
        motion_type = MotionType[spec.get("type", "static").upper()]
        duration = spec.get("duration", 1.0)

        return CameraMotion(
            motion_type=motion_type,
            duration=duration,
            speed=spec.get("speed", 1.0),
            animation_curve=AnimationType[spec.get("curve", "linear").upper()],
            metadata=spec
        )

    async def _plan_transitions(self, scene_data: Dict[str, Any]) -> List[SceneTransition]:
        """Plan transitions for the scene"""
        transitions = []

        if scene_data.get("transition_in"):
            transition = SceneTransition(
                transition_type=TransitionType[scene_data["transition_in"].upper()],
                duration=scene_data.get("transition_duration", 1.0),
                from_scene="previous",
                to_scene=scene_data["scene_id"]
            )
            transitions.append(transition)

        if scene_data.get("transition_out"):
            transition = SceneTransition(
                transition_type=TransitionType[scene_data["transition_out"].upper()],
                duration=scene_data.get("transition_duration", 1.0),
                from_scene=scene_data["scene_id"],
                to_scene="next"
            )
            transitions.append(transition)

        return transitions

    async def _plan_object_animations(self, scene_data: Dict[str, Any]) -> List[ObjectAnimation]:
        """Plan object animations for the scene"""
        animations = []

        if scene_data.get("object_animations"):
            for obj_anim in scene_data["object_animations"]:
                animation = ObjectAnimation(
                    object_id=obj_anim["object_id"],
                    animation_type=obj_anim["type"],
                    duration=obj_anim.get("duration", 1.0),
                    keyframes=obj_anim.get("keyframes", []),
                    animation_curve=AnimationType[obj_anim.get("curve", "linear").upper()],
                    loop=obj_anim.get("loop", False)
                )
                animations.append(animation)

        return animations

    async def _generate_motion_data(
        self,
        camera_motions: List[CameraMotion],
        transitions: List[SceneTransition],
        object_animations: List[ObjectAnimation],
        scene_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate complete motion data for the scene"""

        # Simulate motion generation
        await asyncio.sleep(1)

        return {
            "scene_id": scene_data["scene_id"],
            "duration": scene_data.get("duration", 10),
            "fps": self.motion_config["default_fps"],
            "camera_data": [self._serialize_camera_motion(m) for m in camera_motions],
            "transitions": [self._serialize_transition(t) for t in transitions],
            "object_animations": [self._serialize_object_animation(a) for a in object_animations],
            "motion_blur": self.motion_config["motion_blur"],
            "stabilization": self.motion_config["stabilization"]
        }

    def _serialize_camera_motion(self, motion: CameraMotion) -> Dict[str, Any]:
        """Serialize camera motion to dictionary"""
        return {
            "type": motion.motion_type.value,
            "duration": motion.duration,
            "start_position": motion.start_position,
            "end_position": motion.end_position,
            "start_rotation": motion.start_rotation,
            "end_rotation": motion.end_rotation,
            "focal_length": motion.focal_length,
            "animation_curve": motion.animation_curve.value,
            "speed": motion.speed
        }

    def _serialize_transition(self, transition: SceneTransition) -> Dict[str, Any]:
        """Serialize transition to dictionary"""
        return {
            "type": transition.transition_type.value,
            "duration": transition.duration,
            "from_scene": transition.from_scene,
            "to_scene": transition.to_scene,
            "animation_curve": transition.animation_curve.value,
            "parameters": transition.parameters
        }

    def _serialize_object_animation(self, animation: ObjectAnimation) -> Dict[str, Any]:
        """Serialize object animation to dictionary"""
        return {
            "object_id": animation.object_id,
            "animation_type": animation.animation_type,
            "duration": animation.duration,
            "keyframes": animation.keyframes,
            "animation_curve": animation.animation_curve.value,
            "loop": animation.loop
        }

    async def _apply_motion_effects(
        self, motion_data: Dict[str, Any], scene_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply motion effects and post-processing"""

        effects_applied = []

        # Apply requested effects
        if scene_data.get("motion_effects"):
            for effect in scene_data["motion_effects"]:
                if effect == "motion_blur":
                    effects_applied.append("motion_blur")
                elif effect == "shake":
                    effects_applied.append("camera_shake")
                elif effect == "stabilize":
                    effects_applied.append("stabilization")
                elif effect == "time_remap":
                    effects_applied.append("time_remapping")

        motion_data["effects_applied"] = effects_applied
        return motion_data

    async def _generate_motion_path(self, motion_data: Dict[str, Any]) -> List[Tuple[float, float]]:
        """Generate a visualization of the motion path"""

        path_points = []
        num_points = 20

        for i in range(num_points):
            t = i / (num_points - 1)
            # Simple curved path for demonstration
            x = t * 100
            y = 50 + 30 * np.sin(2 * np.pi * t)
            path_points.append((x, y))

        return path_points

    async def _save_motion_data(self, motion_data: Dict[str, Any], scene_id: str) -> Path:
        """Save motion data to file"""

        output_file = self.output_dir / f"scene_{scene_id}_motion.json"

        async with asyncio.Lock():
            with open(output_file, 'w') as f:
                json.dump(motion_data, f, indent=2, default=str)

        return output_file

    def get_status(self) -> Dict[str, Any]:
        """Get current status of the motion agent"""

        active_count = sum(1 for t in self.active_tasks.values() if t["status"] == "processing")
        completed_count = sum(1 for t in self.active_tasks.values() if t["status"] == "completed")
        failed_count = sum(1 for t in self.active_tasks.values() if t["status"] == "failed")

        return {
            "agent_id": self.agent_id,
            "agent_type": "motion",
            "status": "active" if active_count > 0 else "idle",
            "active_tasks": active_count,
            "completed_tasks": completed_count,
            "failed_tasks": failed_count,
            "total_generations": len(self.generation_history),
            "available_templates": list(self.motion_templates.keys())
        }


async def main():
    """Test the motion agent"""

    agent = MotionAgent()
    await agent.initialize()

    # Test scene with motion requirements
    test_scene = {
        "scene_id": "test_motion_001",
        "duration": 10,
        "motion_type": "pan",
        "motion_speed": 1.5,
        "motion_template": "dramatic_reveal",
        "transition_in": "fade",
        "transition_out": "dissolve",
        "transition_duration": 1.5,
        "object_animations": [
            {
                "object_id": "title_text",
                "type": "fade_in",
                "duration": 2,
                "keyframes": [
                    {"time": 0, "opacity": 0},
                    {"time": 2, "opacity": 1}
                ],
                "curve": "ease_out"
            }
        ],
        "motion_effects": ["motion_blur", "stabilize"]
    }

    result = await agent.process_scene(test_scene)
    print(f"Motion generation result: {json.dumps(result, indent=2)}")

    # Get status
    status = agent.get_status()
    print(f"\nAgent status: {json.dumps(status, indent=2)}")


if __name__ == "__main__":
    asyncio.run(main())