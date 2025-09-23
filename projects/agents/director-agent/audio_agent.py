"""
Audio Agent - Handles audio generation and processing for the multi-agent video system
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


class AudioType(Enum):
    MUSIC = "music"
    VOICE_OVER = "voice_over"
    SOUND_EFFECTS = "sound_effects"
    AMBIENT = "ambient"
    DIALOGUE = "dialogue"
    FOLEY = "foley"


class AudioMood(Enum):
    HAPPY = "happy"
    SAD = "sad"
    ENERGETIC = "energetic"
    CALM = "calm"
    TENSE = "tense"
    MYSTERIOUS = "mysterious"
    EPIC = "epic"
    ROMANTIC = "romantic"
    COMEDIC = "comedic"
    DRAMATIC = "dramatic"


@dataclass
class AudioRequest:
    scene_id: str
    audio_type: AudioType
    description: str
    duration: float
    mood: Optional[AudioMood] = None
    tempo: Optional[int] = None  # BPM for music
    voice_characteristics: Optional[Dict[str, Any]] = None
    sound_effects: List[str] = field(default_factory=list)
    volume_level: float = 0.8
    fade_in: float = 0.0
    fade_out: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AudioLayer:
    """Represents a single audio layer in the mix"""
    layer_id: str
    audio_type: AudioType
    start_time: float
    duration: float
    volume: float
    effects: List[str] = field(default_factory=list)
    data: Optional[Any] = None


class AudioAgent:
    """Agent responsible for generating and processing audio content"""

    def __init__(self, agent_id: str = None, output_dir: str = "./outputs/audio"):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Audio generation configurations
        self.audio_config = {
            "sample_rate": 44100,
            "bit_depth": 16,
            "channels": 2,  # Stereo
            "format": "wav"
        }

        # API configurations for different audio services
        self.api_config = {
            "elevenlabs": {
                "api_key": None,  # Set via environment
                "voice_models": []
            },
            "mubert": {
                "api_key": None,
                "genres": ["electronic", "ambient", "classical", "rock"]
            },
            "freesound": {
                "api_key": None,
                "max_duration": 30
            }
        }

        self.generation_history = []
        self.active_tasks = {}
        self.audio_library = {}  # Cache for generated audio

    async def initialize(self):
        """Initialize the audio agent"""
        logger.info(f"Initializing Audio Agent {self.agent_id}")

        # Check available audio APIs
        available_apis = await self._check_api_availability()
        logger.info(f"Available audio APIs: {available_apis}")

        # Load any preset audio libraries
        await self._load_audio_presets()

        return True

    async def _check_api_availability(self) -> List[str]:
        """Check which audio generation APIs are available"""
        available = []
        import os

        if os.getenv("ELEVENLABS_API_KEY"):
            available.append("elevenlabs")
        if os.getenv("MUBERT_API_KEY"):
            available.append("mubert")
        if os.getenv("FREESOUND_API_KEY"):
            available.append("freesound")

        # Check for local audio processing tools
        try:
            import soundfile
            available.append("local_processing")
        except ImportError:
            logger.debug("Soundfile not available for local processing")

        return available

    async def _load_audio_presets(self):
        """Load preset audio samples and configurations"""
        presets_dir = self.output_dir / "presets"
        if presets_dir.exists():
            for preset_file in presets_dir.glob("*.json"):
                try:
                    with open(preset_file, 'r') as f:
                        preset = json.load(f)
                        self.audio_library[preset['name']] = preset
                except Exception as e:
                    logger.error(f"Error loading preset {preset_file}: {e}")

    async def process_scene(self, scene_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process audio requirements for a scene"""

        # Parse audio requirements
        audio_requests = self._parse_audio_requirements(scene_data)

        # Generate audio layers
        audio_layers = []
        for request in audio_requests:
            layer = await self._generate_audio_layer(request)
            audio_layers.append(layer)

        # Mix audio layers
        mixed_audio = await self._mix_audio_layers(audio_layers, scene_data.get("duration", 10))

        # Apply post-processing
        processed_audio = await self._apply_audio_effects(mixed_audio, scene_data)

        # Save the result
        output_path = await self._save_audio(processed_audio, scene_data["scene_id"])

        result = {
            "success": True,
            "scene_id": scene_data["scene_id"],
            "audio_layers": len(audio_layers),
            "duration": scene_data.get("duration", 10),
            "output_path": str(output_path),
            "metadata": {
                "sample_rate": self.audio_config["sample_rate"],
                "channels": self.audio_config["channels"],
                "format": self.audio_config["format"]
            }
        }

        # Store in history
        self.generation_history.append({
            "scene_id": scene_data["scene_id"],
            "timestamp": datetime.now().isoformat(),
            "result": result
        })

        return result

    def _parse_audio_requirements(self, scene_data: Dict[str, Any]) -> List[AudioRequest]:
        """Parse scene data to extract audio requirements"""
        requests = []

        # Background music
        if scene_data.get("needs_music", True):
            requests.append(AudioRequest(
                scene_id=scene_data["scene_id"],
                audio_type=AudioType.MUSIC,
                description=scene_data.get("music_description", "Background music"),
                duration=scene_data.get("duration", 10),
                mood=AudioMood(scene_data.get("mood", "calm")),
                tempo=scene_data.get("tempo", 120),
                volume_level=0.6
            ))

        # Voice over / narration
        if scene_data.get("narration"):
            requests.append(AudioRequest(
                scene_id=scene_data["scene_id"],
                audio_type=AudioType.VOICE_OVER,
                description=scene_data["narration"],
                duration=scene_data.get("duration", 10),
                voice_characteristics=scene_data.get("voice", {"gender": "neutral", "age": "adult"}),
                volume_level=1.0
            ))

        # Sound effects
        if scene_data.get("sound_effects"):
            requests.append(AudioRequest(
                scene_id=scene_data["scene_id"],
                audio_type=AudioType.SOUND_EFFECTS,
                description="Scene sound effects",
                duration=scene_data.get("duration", 10),
                sound_effects=scene_data["sound_effects"],
                volume_level=0.7
            ))

        # Ambient sounds
        if scene_data.get("ambient_sound"):
            requests.append(AudioRequest(
                scene_id=scene_data["scene_id"],
                audio_type=AudioType.AMBIENT,
                description=scene_data["ambient_sound"],
                duration=scene_data.get("duration", 10),
                volume_level=0.3,
                fade_in=1.0,
                fade_out=1.0
            ))

        return requests

    async def _generate_audio_layer(self, request: AudioRequest) -> AudioLayer:
        """Generate a single audio layer"""

        task_id = str(uuid.uuid4())
        self.active_tasks[task_id] = {
            "status": "processing",
            "request": request,
            "started_at": datetime.now()
        }

        try:
            # Generate audio based on type
            if request.audio_type == AudioType.MUSIC:
                audio_data = await self._generate_music(request)
            elif request.audio_type == AudioType.VOICE_OVER:
                audio_data = await self._generate_voice(request)
            elif request.audio_type == AudioType.SOUND_EFFECTS:
                audio_data = await self._generate_sound_effects(request)
            elif request.audio_type == AudioType.AMBIENT:
                audio_data = await self._generate_ambient(request)
            else:
                audio_data = await self._generate_generic_audio(request)

            layer = AudioLayer(
                layer_id=task_id,
                audio_type=request.audio_type,
                start_time=0,
                duration=request.duration,
                volume=request.volume_level,
                data=audio_data
            )

            self.active_tasks[task_id]["status"] = "completed"
            return layer

        except Exception as e:
            logger.error(f"Error generating audio layer: {e}")
            self.active_tasks[task_id]["status"] = "failed"
            raise

    async def _generate_music(self, request: AudioRequest) -> Dict[str, Any]:
        """Generate background music"""
        await asyncio.sleep(1)  # Simulate generation

        return {
            "type": "music",
            "mood": request.mood.value if request.mood else "neutral",
            "tempo": request.tempo or 120,
            "duration": request.duration,
            "waveform": self._generate_placeholder_waveform(request.duration)
        }

    async def _generate_voice(self, request: AudioRequest) -> Dict[str, Any]:
        """Generate voice over"""
        await asyncio.sleep(1.5)  # Simulate generation

        return {
            "type": "voice",
            "text": request.description,
            "voice_characteristics": request.voice_characteristics or {},
            "duration": request.duration,
            "waveform": self._generate_placeholder_waveform(request.duration)
        }

    async def _generate_sound_effects(self, request: AudioRequest) -> Dict[str, Any]:
        """Generate sound effects"""
        await asyncio.sleep(0.5)  # Simulate generation

        return {
            "type": "sound_effects",
            "effects": request.sound_effects,
            "duration": request.duration,
            "waveform": self._generate_placeholder_waveform(request.duration)
        }

    async def _generate_ambient(self, request: AudioRequest) -> Dict[str, Any]:
        """Generate ambient sounds"""
        await asyncio.sleep(0.8)  # Simulate generation

        return {
            "type": "ambient",
            "description": request.description,
            "duration": request.duration,
            "fade_in": request.fade_in,
            "fade_out": request.fade_out,
            "waveform": self._generate_placeholder_waveform(request.duration)
        }

    async def _generate_generic_audio(self, request: AudioRequest) -> Dict[str, Any]:
        """Generate generic audio"""
        await asyncio.sleep(0.5)

        return {
            "type": "generic",
            "description": request.description,
            "duration": request.duration,
            "waveform": self._generate_placeholder_waveform(request.duration)
        }

    def _generate_placeholder_waveform(self, duration: float) -> List[float]:
        """Generate placeholder waveform data for testing"""
        samples = int(duration * 100)  # 100 samples per second for visualization
        return [np.sin(2 * np.pi * i / 50) * np.random.random() for i in range(samples)]

    async def _mix_audio_layers(self, layers: List[AudioLayer], total_duration: float) -> Dict[str, Any]:
        """Mix multiple audio layers together"""
        await asyncio.sleep(0.5)  # Simulate mixing

        return {
            "mixed": True,
            "layers_count": len(layers),
            "total_duration": total_duration,
            "layers": [
                {
                    "layer_id": layer.layer_id,
                    "type": layer.audio_type.value,
                    "volume": layer.volume
                }
                for layer in layers
            ]
        }

    async def _apply_audio_effects(self, audio_data: Dict[str, Any], scene_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply post-processing effects to audio"""

        effects_applied = []

        # Apply requested effects
        if scene_data.get("audio_effects"):
            for effect in scene_data["audio_effects"]:
                if effect == "reverb":
                    effects_applied.append("reverb")
                elif effect == "echo":
                    effects_applied.append("echo")
                elif effect == "compression":
                    effects_applied.append("compression")
                elif effect == "eq":
                    effects_applied.append("equalization")

        audio_data["effects_applied"] = effects_applied
        return audio_data

    async def _save_audio(self, audio_data: Dict[str, Any], scene_id: str) -> Path:
        """Save audio data to file"""

        output_file = self.output_dir / f"scene_{scene_id}_audio.json"

        async with asyncio.Lock():
            with open(output_file, 'w') as f:
                json.dump(audio_data, f, indent=2)

        return output_file

    def get_status(self) -> Dict[str, Any]:
        """Get current status of the audio agent"""

        active_count = sum(1 for t in self.active_tasks.values() if t["status"] == "processing")
        completed_count = sum(1 for t in self.active_tasks.values() if t["status"] == "completed")
        failed_count = sum(1 for t in self.active_tasks.values() if t["status"] == "failed")

        return {
            "agent_id": self.agent_id,
            "agent_type": "audio",
            "status": "active" if active_count > 0 else "idle",
            "active_tasks": active_count,
            "completed_tasks": completed_count,
            "failed_tasks": failed_count,
            "total_generations": len(self.generation_history),
            "cached_audio": len(self.audio_library)
        }


async def main():
    """Test the audio agent"""

    agent = AudioAgent()
    await agent.initialize()

    # Test scene with audio requirements
    test_scene = {
        "scene_id": "test_audio_001",
        "duration": 10,
        "needs_music": True,
        "mood": "epic",
        "tempo": 140,
        "narration": "In a world of endless possibilities...",
        "voice": {"gender": "male", "age": "adult", "tone": "dramatic"},
        "sound_effects": ["thunder", "wind", "footsteps"],
        "ambient_sound": "storm atmosphere",
        "audio_effects": ["reverb", "compression"]
    }

    result = await agent.process_scene(test_scene)
    print(f"Audio generation result: {json.dumps(result, indent=2)}")

    # Get status
    status = agent.get_status()
    print(f"\nAgent status: {json.dumps(status, indent=2)}")


if __name__ == "__main__":
    asyncio.run(main())