"""
Quality Control Module for Director Agent
Handles validation, consistency checks, and quality assurance
"""

import cv2
import numpy as np
import librosa
import asyncio
import logging
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import json


class QualityLevel(Enum):
    POOR = "poor"
    ACCEPTABLE = "acceptable"
    GOOD = "good"
    EXCELLENT = "excellent"


class ValidationResult(Enum):
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"


@dataclass
class QualityMetrics:
    visual_quality: float
    audio_quality: float
    consistency_score: float
    technical_score: float
    overall_score: float
    issues: List[str]
    recommendations: List[str]


@dataclass
class ValidationCheck:
    name: str
    result: ValidationResult
    score: float
    message: str
    details: Dict[str, Any] = None


class QualityController:
    """
    Comprehensive quality control system for generated content
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Quality thresholds
        self.min_visual_quality = 0.7
        self.min_audio_quality = 0.6
        self.min_consistency_score = 0.75
        self.min_overall_score = 0.7
        
        # Technical requirements
        self.supported_video_formats = ['.mp4', '.avi', '.mov', '.mkv']
        self.supported_audio_formats = ['.wav', '.mp3', '.aac', '.flac']
        self.max_file_size_mb = 500
        
    async def validate_scene_content(self, scene_id: str, 
                                   visual_path: str = None,
                                   audio_path: str = None,
                                   metadata: Dict[str, Any] = None) -> List[ValidationCheck]:
        """Validate content for a single scene"""
        checks = []
        
        if visual_path:
            visual_checks = await self._validate_visual_content(visual_path, scene_id)
            checks.extend(visual_checks)
        
        if audio_path:
            audio_checks = await self._validate_audio_content(audio_path, scene_id)
            checks.extend(audio_checks)
        
        if visual_path and audio_path:
            sync_checks = await self._validate_audio_video_sync(visual_path, audio_path, scene_id)
            checks.extend(sync_checks)
        
        return checks
    
    async def _validate_visual_content(self, video_path: str, scene_id: str) -> List[ValidationCheck]:
        """Validate visual content quality and technical specs"""
        checks = []
        
        try:
            # Open video file
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                checks.append(ValidationCheck(
                    name=f"video_file_access_{scene_id}",
                    result=ValidationResult.FAIL,
                    score=0.0,
                    message="Cannot open video file",
                    details={"file_path": video_path}
                ))
                return checks
            
            # Get video properties
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            
            # Technical validation
            if fps < 24 or fps > 60:
                checks.append(ValidationCheck(
                    name=f"fps_validation_{scene_id}",
                    result=ValidationResult.WARNING,
                    score=0.6,
                    message=f"Unusual FPS: {fps}. Recommended: 24-60 FPS",
                    details={"actual_fps": fps}
                ))
            else:
                checks.append(ValidationCheck(
                    name=f"fps_validation_{scene_id}",
                    result=ValidationResult.PASS,
                    score=1.0,
                    message=f"FPS validation passed: {fps}",
                    details={"fps": fps}
                ))
            
            # Resolution validation
            if width < 720 or height < 480:
                checks.append(ValidationCheck(
                    name=f"resolution_validation_{scene_id}",
                    result=ValidationResult.WARNING,
                    score=0.5,
                    message=f"Low resolution: {width}x{height}",
                    details={"width": width, "height": height}
                ))
            else:
                checks.append(ValidationCheck(
                    name=f"resolution_validation_{scene_id}",
                    result=ValidationResult.PASS,
                    score=1.0,
                    message=f"Resolution validation passed: {width}x{height}",
                    details={"width": width, "height": height}
                ))
            
            # Sample frames for quality analysis
            frame_indices = np.linspace(0, frame_count-1, min(10, frame_count), dtype=int)
            quality_scores = []
            
            for frame_idx in frame_indices:
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
                ret, frame = cap.read()
                
                if ret:
                    # Calculate frame quality metrics
                    blur_score = self._calculate_blur_score(frame)
                    brightness_score = self._calculate_brightness_score(frame)
                    contrast_score = self._calculate_contrast_score(frame)
                    
                    frame_quality = (blur_score + brightness_score + contrast_score) / 3
                    quality_scores.append(frame_quality)
            
            cap.release()
            
            # Overall visual quality assessment
            avg_quality = np.mean(quality_scores) if quality_scores else 0.0
            
            if avg_quality >= self.min_visual_quality:
                checks.append(ValidationCheck(
                    name=f"visual_quality_{scene_id}",
                    result=ValidationResult.PASS,
                    score=avg_quality,
                    message=f"Visual quality acceptable: {avg_quality:.2f}",
                    details={
                        "average_quality": avg_quality,
                        "frame_scores": quality_scores,
                        "min_threshold": self.min_visual_quality
                    }
                ))
            else:
                checks.append(ValidationCheck(
                    name=f"visual_quality_{scene_id}",
                    result=ValidationResult.FAIL,
                    score=avg_quality,
                    message=f"Visual quality below threshold: {avg_quality:.2f}",
                    details={
                        "average_quality": avg_quality,
                        "frame_scores": quality_scores,
                        "min_threshold": self.min_visual_quality
                    }
                ))
            
        except Exception as e:
            self.logger.error(f"Error validating visual content: {e}")
            checks.append(ValidationCheck(
                name=f"visual_validation_error_{scene_id}",
                result=ValidationResult.FAIL,
                score=0.0,
                message=f"Visual validation error: {str(e)}",
                details={"error": str(e)}
            ))
        
        return checks
    
    async def _validate_audio_content(self, audio_path: str, scene_id: str) -> List[ValidationCheck]:
        """Validate audio content quality and technical specs"""
        checks = []
        
        try:
            # Load audio file
            y, sr = librosa.load(audio_path)
            duration = librosa.duration(y=y, sr=sr)
            
            # Technical validation
            if sr < 22050:
                checks.append(ValidationCheck(
                    name=f"audio_sample_rate_{scene_id}",
                    result=ValidationResult.WARNING,
                    score=0.6,
                    message=f"Low sample rate: {sr} Hz. Recommended: ≥22050 Hz",
                    details={"sample_rate": sr}
                ))
            else:
                checks.append(ValidationCheck(
                    name=f"audio_sample_rate_{scene_id}",
                    result=ValidationResult.PASS,
                    score=1.0,
                    message=f"Sample rate validation passed: {sr} Hz",
                    details={"sample_rate": sr}
                ))
            
            # Audio quality metrics
            rms_energy = librosa.feature.rms(y=y)[0]
            spectral_centroid = librosa.feature.spectral_centroid(y=y, sr=sr)[0]
            zero_crossing_rate = librosa.feature.zero_crossing_rate(y)[0]
            
            # Calculate quality score
            energy_score = min(1.0, np.mean(rms_energy) * 10)  # Normalize energy
            spectral_score = min(1.0, np.mean(spectral_centroid) / 4000)  # Normalize spectral content
            dynamic_score = 1.0 - min(1.0, np.mean(zero_crossing_rate) * 2)  # Less noise = higher score
            
            audio_quality = (energy_score + spectral_score + dynamic_score) / 3
            
            if audio_quality >= self.min_audio_quality:
                checks.append(ValidationCheck(
                    name=f"audio_quality_{scene_id}",
                    result=ValidationResult.PASS,
                    score=audio_quality,
                    message=f"Audio quality acceptable: {audio_quality:.2f}",
                    details={
                        "quality_score": audio_quality,
                        "energy_score": energy_score,
                        "spectral_score": spectral_score,
                        "dynamic_score": dynamic_score,
                        "duration": duration,
                        "min_threshold": self.min_audio_quality
                    }
                ))
            else:
                checks.append(ValidationCheck(
                    name=f"audio_quality_{scene_id}",
                    result=ValidationResult.FAIL,
                    score=audio_quality,
                    message=f"Audio quality below threshold: {audio_quality:.2f}",
                    details={
                        "quality_score": audio_quality,
                        "min_threshold": self.min_audio_quality
                    }
                ))
            
            # Check for clipping
            clipping_ratio = np.sum(np.abs(y) > 0.99) / len(y)
            if clipping_ratio > 0.01:  # More than 1% clipping
                checks.append(ValidationCheck(
                    name=f"audio_clipping_{scene_id}",
                    result=ValidationResult.WARNING,
                    score=1.0 - clipping_ratio,
                    message=f"Audio clipping detected: {clipping_ratio*100:.1f}%",
                    details={"clipping_ratio": clipping_ratio}
                ))
            
        except Exception as e:
            self.logger.error(f"Error validating audio content: {e}")
            checks.append(ValidationCheck(
                name=f"audio_validation_error_{scene_id}",
                result=ValidationResult.FAIL,
                score=0.0,
                message=f"Audio validation error: {str(e)}",
                details={"error": str(e)}
            ))
        
        return checks
    
    async def _validate_audio_video_sync(self, video_path: str, audio_path: str, scene_id: str) -> List[ValidationCheck]:
        """Validate audio-video synchronization"""
        checks = []
        
        try:
            # Get video duration
            cap = cv2.VideoCapture(video_path)
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            video_duration = frame_count / fps if fps > 0 else 0
            cap.release()
            
            # Get audio duration
            y, sr = librosa.load(audio_path)
            audio_duration = librosa.duration(y=y, sr=sr)
            
            # Check duration sync
            duration_diff = abs(video_duration - audio_duration)
            sync_tolerance = 0.5  # 500ms tolerance
            
            if duration_diff <= sync_tolerance:
                checks.append(ValidationCheck(
                    name=f"audio_video_sync_{scene_id}",
                    result=ValidationResult.PASS,
                    score=1.0 - (duration_diff / sync_tolerance) * 0.2,
                    message=f"Audio-video sync acceptable: {duration_diff:.2f}s difference",
                    details={
                        "video_duration": video_duration,
                        "audio_duration": audio_duration,
                        "difference": duration_diff,
                        "tolerance": sync_tolerance
                    }
                ))
            else:
                checks.append(ValidationCheck(
                    name=f"audio_video_sync_{scene_id}",
                    result=ValidationResult.WARNING,
                    score=max(0.0, 1.0 - (duration_diff / video_duration)),
                    message=f"Audio-video sync issue: {duration_diff:.2f}s difference",
                    details={
                        "video_duration": video_duration,
                        "audio_duration": audio_duration,
                        "difference": duration_diff,
                        "tolerance": sync_tolerance
                    }
                ))
            
        except Exception as e:
            self.logger.error(f"Error validating sync: {e}")
            checks.append(ValidationCheck(
                name=f"sync_validation_error_{scene_id}",
                result=ValidationResult.FAIL,
                score=0.0,
                message=f"Sync validation error: {str(e)}",
                details={"error": str(e)}
            ))
        
        return checks
    
    def _calculate_blur_score(self, frame: np.ndarray) -> float:
        """Calculate blur score using Laplacian variance"""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        
        # Normalize to 0-1 range (higher = sharper)
        # Typical blur threshold is around 100-500
        blur_score = min(1.0, laplacian_var / 500)
        return blur_score
    
    def _calculate_brightness_score(self, frame: np.ndarray) -> float:
        """Calculate brightness score"""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        mean_brightness = np.mean(gray) / 255.0
        
        # Penalize over/underexposure
        if 0.3 <= mean_brightness <= 0.7:
            return 1.0
        elif 0.1 <= mean_brightness <= 0.9:
            return 0.8
        else:
            return 0.5
    
    def _calculate_contrast_score(self, frame: np.ndarray) -> float:
        """Calculate contrast score using standard deviation"""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        contrast = np.std(gray) / 255.0
        
        # Normalize contrast score (higher std = better contrast)
        contrast_score = min(1.0, contrast * 4)  # Multiply by 4 for scaling
        return contrast_score
    
    async def validate_project_consistency(self, scenes_data: List[Dict[str, Any]]) -> List[ValidationCheck]:
        """Validate consistency across all scenes in a project"""
        checks = []
        
        if len(scenes_data) < 2:
            return checks
        
        try:
            # Extract visual features from each scene
            visual_features = []
            audio_features = []
            
            for scene in scenes_data:
                if 'visual_path' in scene:
                    features = await self._extract_visual_features(scene['visual_path'])
                    visual_features.append(features)
                
                if 'audio_path' in scene:
                    features = await self._extract_audio_features(scene['audio_path'])
                    audio_features.append(features)
            
            # Check visual consistency
            if visual_features:
                visual_consistency = self._calculate_visual_consistency(visual_features)
                
                if visual_consistency >= self.min_consistency_score:
                    checks.append(ValidationCheck(
                        name="visual_consistency",
                        result=ValidationResult.PASS,
                        score=visual_consistency,
                        message=f"Visual consistency acceptable: {visual_consistency:.2f}",
                        details={"consistency_score": visual_consistency}
                    ))
                else:
                    checks.append(ValidationCheck(
                        name="visual_consistency",
                        result=ValidationResult.WARNING,
                        score=visual_consistency,
                        message=f"Visual consistency below threshold: {visual_consistency:.2f}",
                        details={"consistency_score": visual_consistency}
                    ))
            
            # Check audio consistency
            if audio_features:
                audio_consistency = self._calculate_audio_consistency(audio_features)
                
                if audio_consistency >= self.min_consistency_score:
                    checks.append(ValidationCheck(
                        name="audio_consistency",
                        result=ValidationResult.PASS,
                        score=audio_consistency,
                        message=f"Audio consistency acceptable: {audio_consistency:.2f}",
                        details={"consistency_score": audio_consistency}
                    ))
                else:
                    checks.append(ValidationCheck(
                        name="audio_consistency",
                        result=ValidationResult.WARNING,
                        score=audio_consistency,
                        message=f"Audio consistency below threshold: {audio_consistency:.2f}",
                        details={"consistency_score": audio_consistency}
                    ))
            
        except Exception as e:
            self.logger.error(f"Error validating project consistency: {e}")
            checks.append(ValidationCheck(
                name="consistency_validation_error",
                result=ValidationResult.FAIL,
                score=0.0,
                message=f"Consistency validation error: {str(e)}",
                details={"error": str(e)}
            ))
        
        return checks
    
    async def _extract_visual_features(self, video_path: str) -> Dict[str, Any]:
        """Extract visual features for consistency analysis"""
        try:
            cap = cv2.VideoCapture(video_path)
            features = {
                'color_histogram': [],
                'brightness_values': [],
                'contrast_values': [],
                'dominant_colors': []
            }
            
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            sample_frames = min(5, frame_count)
            
            for i in range(sample_frames):
                cap.set(cv2.CAP_PROP_POS_FRAMES, i * frame_count // sample_frames)
                ret, frame = cap.read()
                
                if ret:
                    # Color histogram
                    hist = cv2.calcHist([frame], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
                    features['color_histogram'].append(hist.flatten())
                    
                    # Brightness and contrast
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    features['brightness_values'].append(np.mean(gray))
                    features['contrast_values'].append(np.std(gray))
            
            cap.release()
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting visual features: {e}")
            return {}
    
    async def _extract_audio_features(self, audio_path: str) -> Dict[str, Any]:
        """Extract audio features for consistency analysis"""
        try:
            y, sr = librosa.load(audio_path)
            
            features = {
                'mfcc': librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13),
                'spectral_centroid': librosa.feature.spectral_centroid(y=y, sr=sr),
                'spectral_rolloff': librosa.feature.spectral_rolloff(y=y, sr=sr),
                'tempo': librosa.beat.tempo(y=y, sr=sr)
            }
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting audio features: {e}")
            return {}
    
    def _calculate_visual_consistency(self, visual_features: List[Dict[str, Any]]) -> float:
        """Calculate visual consistency score between scenes"""
        if len(visual_features) < 2:
            return 1.0
        
        consistency_scores = []
        
        for i in range(len(visual_features) - 1):
            current = visual_features[i]
            next_scene = visual_features[i + 1]
            
            # Compare color histograms
            if 'color_histogram' in current and 'color_histogram' in next_scene:
                hist_similarity = []
                for h1, h2 in zip(current['color_histogram'], next_scene['color_histogram']):
                    correlation = cv2.compareHist(h1.reshape(-1, 1).astype(np.float32), 
                                                h2.reshape(-1, 1).astype(np.float32), 
                                                cv2.HISTCMP_CORREL)
                    hist_similarity.append(max(0, correlation))
                
                consistency_scores.append(np.mean(hist_similarity))
            
            # Compare brightness consistency
            if 'brightness_values' in current and 'brightness_values' in next_scene:
                brightness_diff = abs(np.mean(current['brightness_values']) - 
                                    np.mean(next_scene['brightness_values']))
                brightness_score = max(0, 1.0 - brightness_diff / 255.0)
                consistency_scores.append(brightness_score)
        
        return np.mean(consistency_scores) if consistency_scores else 0.0
    
    def _calculate_audio_consistency(self, audio_features: List[Dict[str, Any]]) -> float:
        """Calculate audio consistency score between scenes"""
        if len(audio_features) < 2:
            return 1.0
        
        consistency_scores = []
        
        for i in range(len(audio_features) - 1):
            current = audio_features[i]
            next_scene = audio_features[i + 1]
            
            # Compare MFCC features
            if 'mfcc' in current and 'mfcc' in next_scene:
                mfcc_similarity = []
                for j in range(min(len(current['mfcc']), len(next_scene['mfcc']))):
                    corr = np.corrcoef(current['mfcc'][j], next_scene['mfcc'][j])[0, 1]
                    if not np.isnan(corr):
                        mfcc_similarity.append(abs(corr))
                
                if mfcc_similarity:
                    consistency_scores.append(np.mean(mfcc_similarity))
        
        return np.mean(consistency_scores) if consistency_scores else 0.0
    
    def generate_quality_report(self, validation_checks: List[ValidationCheck]) -> QualityMetrics:
        """Generate comprehensive quality report"""
        
        visual_checks = [c for c in validation_checks if 'visual' in c.name.lower()]
        audio_checks = [c for c in validation_checks if 'audio' in c.name.lower()]
        consistency_checks = [c for c in validation_checks if 'consistency' in c.name.lower()]
        technical_checks = [c for c in validation_checks if any(term in c.name.lower() 
                           for term in ['fps', 'resolution', 'sample_rate', 'sync'])]
        
        # Calculate category scores
        visual_quality = np.mean([c.score for c in visual_checks]) if visual_checks else 1.0
        audio_quality = np.mean([c.score for c in audio_checks]) if audio_checks else 1.0
        consistency_score = np.mean([c.score for c in consistency_checks]) if consistency_checks else 1.0
        technical_score = np.mean([c.score for c in technical_checks]) if technical_checks else 1.0
        
        # Overall score (weighted average)
        overall_score = (
            visual_quality * 0.3 +
            audio_quality * 0.25 +
            consistency_score * 0.25 +
            technical_score * 0.2
        )
        
        # Collect issues and recommendations
        issues = []
        recommendations = []
        
        for check in validation_checks:
            if check.result == ValidationResult.FAIL:
                issues.append(f"{check.name}: {check.message}")
                
                # Generate recommendations based on check type
                if 'visual_quality' in check.name:
                    recommendations.append("Consider improving lighting, reducing motion blur, or increasing resolution")
                elif 'audio_quality' in check.name:
                    recommendations.append("Consider improving audio recording quality or reducing background noise")
                elif 'sync' in check.name:
                    recommendations.append("Adjust audio-video timing synchronization")
                elif 'consistency' in check.name:
                    recommendations.append("Ensure consistent visual/audio style across scenes")
            
            elif check.result == ValidationResult.WARNING:
                issues.append(f"Warning - {check.name}: {check.message}")
        
        return QualityMetrics(
            visual_quality=visual_quality,
            audio_quality=audio_quality,
            consistency_score=consistency_score,
            technical_score=technical_score,
            overall_score=overall_score,
            issues=issues,
            recommendations=recommendations
        )


# Integration with Director Agent
def integrate_quality_control(director_agent):
    """Integrate quality control into Director Agent workflow"""
    
    quality_controller = QualityController()
    
    async def quality_validation_callback(project_state):
        """Callback to validate project quality before finalization"""
        project_id = project_state.id
        
        try:
            # Collect all scene assets
            scene_validations = []
            
            for scene in project_state.scenes:
                # Find completed tasks for this scene
                scene_tasks = [t for t in project_state.tasks 
                             if t.scene_id == scene.id and t.status.value == "completed"]
                
                visual_path = None
                audio_path = None
                
                for task in scene_tasks:
                    result = await director_agent._get_task_result(task.id)
                    if result:
                        if task.agent_type.value == "visual":
                            visual_path = result.get("video_file")
                        elif task.agent_type.value == "audio":
                            audio_path = result.get("audio_file")
                
                # Validate scene content
                checks = await quality_controller.validate_scene_content(
                    scene.id, visual_path, audio_path
                )
                scene_validations.extend(checks)
            
            # Validate project consistency
            scenes_data = []
            for scene in project_state.scenes:
                scene_data = {"id": scene.id}
                # Add asset paths from completed tasks
                for task in project_state.tasks:
                    if task.scene_id == scene.id and task.status.value == "completed":
                        result = await director_agent._get_task_result(task.id)
                        if result:
                            if task.agent_type.value == "visual":
                                scene_data["visual_path"] = result.get("video_file")
                            elif task.agent_type.value == "audio":
                                scene_data["audio_path"] = result.get("audio_file")
                scenes_data.append(scene_data)
            
            consistency_checks = await quality_controller.validate_project_consistency(scenes_data)
            scene_validations.extend(consistency_checks)
            
            # Generate quality report
            quality_report = quality_controller.generate_quality_report(scene_validations)
            
            # Store quality report in project metadata
            project_state.metadata["quality_report"] = {
                "visual_quality": quality_report.visual_quality,
                "audio_quality": quality_report.audio_quality,
                "consistency_score": quality_report.consistency_score,
                "technical_score": quality_report.technical_score,
                "overall_score": quality_report.overall_score,
                "issues": quality_report.issues,
                "recommendations": quality_report.recommendations,
                "validation_checks": [
                    {
                        "name": check.name,
                        "result": check.result.value,
                        "score": check.score,
                        "message": check.message
                    } for check in scene_validations
                ]
            }
            
            await director_agent._save_project_state(project_id)
            
            # Log quality assessment
            director_agent.logger.info(
                f"Project {project_id} quality assessment: "
                f"Overall Score: {quality_report.overall_score:.2f}, "
                f"Issues: {len(quality_report.issues)}"
            )
            
            # If quality is too low, consider regeneration
            if quality_report.overall_score < quality_controller.min_overall_score:
                director_agent.logger.warning(
                    f"Project {project_id} quality below threshold. "
                    f"Consider regeneration or manual review."
                )
            
        except Exception as e:
            director_agent.logger.error(f"Quality validation error for project {project_id}: {e}")
    
    return quality_validation_callback