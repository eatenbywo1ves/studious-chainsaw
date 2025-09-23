"""
Presentation Layer Sub-Agents
==============================
Agents responsible for visual rendering, layout, animation, and theming
"""

import asyncio
import json
import uuid
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import math
from pathlib import Path

logger = logging.getLogger(__name__)


class LayoutType(Enum):
    """Types of layouts available"""
    GRID = "grid"
    FLEX = "flex"
    ABSOLUTE = "absolute"
    FIXED = "fixed"
    RESPONSIVE = "responsive"
    MASONRY = "masonry"
    CAROUSEL = "carousel"


class AnimationType(Enum):
    """Types of animations available"""
    FADE = "fade"
    SLIDE = "slide"
    SCALE = "scale"
    ROTATE = "rotate"
    BOUNCE = "bounce"
    PULSE = "pulse"
    SHAKE = "shake"
    FLIP = "flip"
    MORPH = "morph"


class ThemeMode(Enum):
    """Theme modes"""
    LIGHT = "light"
    DARK = "dark"
    AUTO = "auto"
    HIGH_CONTRAST = "high_contrast"


@dataclass
class RenderContext:
    """Context for rendering operations"""
    viewport: Tuple[int, int] = (1920, 1080)
    device_type: str = "desktop"
    pixel_density: float = 1.0
    color_depth: int = 24
    supports_animation: bool = True
    supports_webgl: bool = True


class VisualRenderingAgent:
    """
    Sub-agent responsible for visual rendering of UI components
    Generates HTML, CSS, and component structures
    """

    def __init__(self):
        self.agent_id = f"visual_{uuid.uuid4().hex[:8]}"
        self.render_cache = {}
        self.style_sheets = {}
        self.component_library = self._init_component_library()

    async def initialize(self):
        """Initialize the visual rendering agent"""
        # Load style templates
        self.style_sheets = self._load_style_sheets()
        logger.info(f"Visual Rendering Agent initialized: {self.agent_id}")
        return True

    async def render_component(self, request: Any, layout: Dict[str, Any]) -> Dict[str, Any]:
        """
        Render a UI component based on request and layout
        Returns HTML structure with inline styles
        """
        component = {
            'id': f"component_{uuid.uuid4().hex[:8]}",
            'type': request.type.value,
            'html': '',
            'css': {},
            'attributes': {},
            'children': []
        }

        try:
            # Select component template
            template = self.component_library.get(
                request.type.value,
                self.component_library['default']
            )

            # Generate HTML structure
            component['html'] = self._generate_html(template, request)

            # Apply styles
            component['css'] = self._generate_styles(request.style, layout)

            # Add data bindings
            if request.data:
                component['attributes']['data'] = request.data

            # Apply theme
            theme = request.style.get('theme', 'light')
            component['css'].update(self._apply_theme(theme))

            # Generate responsive variants
            if layout.get('responsive'):
                component['responsive'] = self._generate_responsive_styles(component['css'])

            logger.info(f"Rendered component: {component['id']}")

        except Exception as e:
            logger.error(f"Rendering error: {e}")
            component['error'] = str(e)

        return component

    async def update_component(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing component with new styles or content"""
        try:
            # Preserve component ID
            updated = component.copy()

            # Re-apply styles if changed
            if 'style_updates' in component:
                current_css = component.get('css', {})
                new_css = self._merge_styles(current_css, component['style_updates'])
                updated['css'] = new_css

            # Update HTML if content changed
            if 'content_updates' in component:
                updated['html'] = self._update_html(component['html'], component['content_updates'])

            # Mark as updated
            updated['last_updated'] = asyncio.get_event_loop().time()

            return updated

        except Exception as e:
            logger.error(f"Update error: {e}")
            return component

    def _generate_html(self, template: Dict[str, Any], request: Any) -> str:
        """Generate HTML structure from template"""
        tag = template.get('tag', 'div')
        classes = ' '.join(template.get('classes', []))
        attributes = template.get('attributes', {})

        # Build attributes string
        attr_str = ''
        for key, value in attributes.items():
            attr_str += f' {key}="{value}"'

        # Generate content
        content = request.data.get('content', '') if request.data else ''

        # Build HTML
        html = f'<{tag} class="{classes}"{attr_str}>'

        # Add children if template has them
        if 'children' in template:
            for child in template['children']:
                html += f'<div class="{child}">{content}</div>'
        else:
            html += content

        html += f'</{tag}>'

        return html

    def _generate_styles(self, style_config: Dict[str, Any], layout: Dict[str, Any]) -> Dict[str, str]:
        """Generate CSS styles from configuration"""
        styles = {}

        # Apply layout styles
        if layout:
            styles.update({
                'display': layout.get('display', 'block'),
                'position': layout.get('position', 'relative'),
                'width': layout.get('width', 'auto'),
                'height': layout.get('height', 'auto'),
                'margin': layout.get('margin', '0'),
                'padding': layout.get('padding', '0')
            })

        # Apply custom styles
        if style_config:
            # Colors
            if 'color' in style_config:
                styles['color'] = style_config['color']
            if 'background' in style_config:
                styles['background'] = style_config['background']

            # Typography
            if 'fontSize' in style_config:
                styles['font-size'] = style_config['fontSize']
            if 'fontFamily' in style_config:
                styles['font-family'] = style_config['fontFamily']

            # Borders
            if 'border' in style_config:
                styles['border'] = style_config['border']
            if 'borderRadius' in style_config:
                styles['border-radius'] = style_config['borderRadius']

            # Shadows
            if 'boxShadow' in style_config:
                styles['box-shadow'] = style_config['boxShadow']

        return styles

    def _apply_theme(self, theme: str) -> Dict[str, str]:
        """Apply theme-specific styles"""
        themes = {
            'light': {
                'background-color': '#ffffff',
                'color': '#1a1a1a',
                'border-color': '#e0e0e0'
            },
            'dark': {
                'background-color': '#1a1a1a',
                'color': '#ffffff',
                'border-color': '#333333'
            },
            'high_contrast': {
                'background-color': '#000000',
                'color': '#ffffff',
                'border-color': '#ffffff'
            }
        }

        return themes.get(theme, themes['light'])

    def _generate_responsive_styles(self, base_styles: Dict[str, str]) -> Dict[str, Dict[str, str]]:
        """Generate responsive style variants"""
        return {
            'mobile': {**base_styles, 'font-size': '14px', 'padding': '8px'},
            'tablet': {**base_styles, 'font-size': '16px', 'padding': '12px'},
            'desktop': base_styles,
            'wide': {**base_styles, 'font-size': '18px', 'padding': '16px'}
        }

    def _merge_styles(self, current: Dict[str, str], updates: Dict[str, str]) -> Dict[str, str]:
        """Merge style updates with current styles"""
        merged = current.copy()
        merged.update(updates)
        return merged

    def _update_html(self, current_html: str, updates: Dict[str, Any]) -> str:
        """Update HTML content"""
        # Simple content replacement for demonstration
        if 'content' in updates:
            # This would be more sophisticated in production
            return current_html.replace('>{content}<', f">{updates['content']}<")
        return current_html

    def _init_component_library(self) -> Dict[str, Dict[str, Any]]:
        """Initialize component template library"""
        return {
            'button': {
                'tag': 'button',
                'classes': ['btn', 'interactive'],
                'attributes': {'type': 'button'}
            },
            'card': {
                'tag': 'div',
                'classes': ['card', 'elevated'],
                'children': ['card-header', 'card-body', 'card-footer']
            },
            'form': {
                'tag': 'form',
                'classes': ['form', 'vertical'],
                'attributes': {'method': 'post'}
            },
            'chart': {
                'tag': 'div',
                'classes': ['chart-container'],
                'children': ['chart-canvas']
            },
            'default': {
                'tag': 'div',
                'classes': ['component']
            }
        }

    def _load_style_sheets(self) -> Dict[str, str]:
        """Load predefined style sheets"""
        return {
            'base': """
                .component { box-sizing: border-box; }
                .btn { padding: 10px 20px; cursor: pointer; }
                .card { border-radius: 8px; padding: 20px; }
                .elevated { box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            """,
            'animations': """
                @keyframes fade { from { opacity: 0; } to { opacity: 1; } }
                @keyframes slide { from { transform: translateX(-100%); } to { transform: translateX(0); } }
            """
        }


class LayoutAgent:
    """
    Sub-agent responsible for calculating layouts and positioning
    Handles grid systems, flexbox, and responsive design
    """

    def __init__(self):
        self.agent_id = f"layout_{uuid.uuid4().hex[:8]}"
        self.grid_systems = self._init_grid_systems()
        self.breakpoints = self._init_breakpoints()

    async def initialize(self):
        """Initialize the layout agent"""
        logger.info(f"Layout Agent initialized: {self.agent_id}")
        return True

    async def calculate_layout(self, request: Any) -> Dict[str, Any]:
        """
        Calculate optimal layout for a component
        Returns positioning and sizing information
        """
        layout = {
            'type': LayoutType.RESPONSIVE.value,
            'display': 'flex',
            'position': 'relative',
            'dimensions': {},
            'spacing': {},
            'grid': None
        }

        try:
            # Determine layout type
            component_type = request.type.value
            layout_type = self._determine_layout_type(component_type)
            layout['type'] = layout_type.value

            # Calculate dimensions
            layout['dimensions'] = self._calculate_dimensions(request)

            # Calculate spacing
            layout['spacing'] = self._calculate_spacing(request)

            # Setup grid if needed
            if layout_type == LayoutType.GRID:
                layout['grid'] = self._setup_grid(request)
            elif layout_type == LayoutType.FLEX:
                layout['flex'] = self._setup_flex(request)

            # Add responsive properties
            layout['responsive'] = self._calculate_responsive_layout(layout)

            logger.info(f"Calculated layout: {layout['type']}")

        except Exception as e:
            logger.error(f"Layout calculation error: {e}")
            layout['error'] = str(e)

        return layout

    def _determine_layout_type(self, component_type: str) -> LayoutType:
        """Determine the best layout type for a component"""
        layout_map = {
            'dashboard': LayoutType.GRID,
            'form': LayoutType.FLEX,
            'card': LayoutType.FLEX,
            'chart': LayoutType.RESPONSIVE,
            'table': LayoutType.FIXED,
            'navigation': LayoutType.FLEX,
            'modal': LayoutType.ABSOLUTE
        }

        return layout_map.get(component_type, LayoutType.RESPONSIVE)

    def _calculate_dimensions(self, request: Any) -> Dict[str, Any]:
        """Calculate component dimensions"""
        dimensions = {
            'width': '100%',
            'height': 'auto',
            'minWidth': '300px',
            'maxWidth': '1200px',
            'aspectRatio': None
        }

        # Custom dimensions from request
        if request.style and 'dimensions' in request.style:
            dimensions.update(request.style['dimensions'])

        # Component-specific dimensions
        if request.type.value == 'card':
            dimensions['width'] = '350px'
            dimensions['minHeight'] = '200px'
        elif request.type.value == 'modal':
            dimensions['width'] = '600px'
            dimensions['maxHeight'] = '80vh'
        elif request.type.value == 'chart':
            dimensions['aspectRatio'] = '16/9'

        return dimensions

    def _calculate_spacing(self, request: Any) -> Dict[str, str]:
        """Calculate spacing (margin, padding, gap)"""
        spacing = {
            'margin': '0',
            'padding': '16px',
            'gap': '16px'
        }

        # Adjust based on component type
        if request.type.value == 'button':
            spacing['padding'] = '8px 16px'
        elif request.type.value == 'card':
            spacing['padding'] = '20px'
            spacing['margin'] = '10px'
        elif request.type.value == 'dashboard':
            spacing['gap'] = '20px'
            spacing['padding'] = '24px'

        return spacing

    def _setup_grid(self, request: Any) -> Dict[str, Any]:
        """Setup grid layout properties"""
        # Default 12-column grid
        grid = {
            'columns': 12,
            'rows': 'auto',
            'gap': '20px',
            'template': None
        }

        # Dashboard-specific grid
        if request.type.value == 'dashboard':
            grid['template'] = """
                "header header header" 80px
                "sidebar main main" 1fr
                "footer footer footer" 60px
                / 250px 1fr 1fr
            """
        elif request.data and 'columns' in request.data:
            grid['columns'] = request.data['columns']

        return grid

    def _setup_flex(self, request: Any) -> Dict[str, str]:
        """Setup flexbox properties"""
        flex = {
            'direction': 'row',
            'wrap': 'wrap',
            'justify': 'flex-start',
            'align': 'stretch',
            'gap': '16px'
        }

        # Adjust for specific components
        if request.type.value == 'form':
            flex['direction'] = 'column'
            flex['align'] = 'stretch'
        elif request.type.value == 'navigation':
            flex['justify'] = 'space-between'
            flex['align'] = 'center'

        return flex

    def _calculate_responsive_layout(self, base_layout: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Calculate responsive layout variants"""
        responsive = {}

        for breakpoint, min_width in self.breakpoints.items():
            responsive[breakpoint] = self._adapt_layout_for_breakpoint(base_layout, breakpoint)

        return responsive

    def _adapt_layout_for_breakpoint(self, layout: Dict[str, Any], breakpoint: str) -> Dict[str, Any]:
        """Adapt layout for specific breakpoint"""
        adapted = layout.copy()

        if breakpoint == 'mobile':
            # Stack elements vertically on mobile
            if 'flex' in adapted:
                adapted['flex']['direction'] = 'column'
            if 'grid' in adapted:
                adapted['grid']['columns'] = 1
            adapted['dimensions']['width'] = '100%'

        elif breakpoint == 'tablet':
            # Adjust grid for tablet
            if 'grid' in adapted:
                adapted['grid']['columns'] = 6
            adapted['dimensions']['width'] = '90%'

        return adapted

    def _init_grid_systems(self) -> Dict[str, Dict[str, Any]]:
        """Initialize common grid systems"""
        return {
            'bootstrap': {'columns': 12, 'gutter': '15px'},
            'material': {'columns': 12, 'gutter': '16px'},
            'tailwind': {'columns': 12, 'gutter': '0'}
        }

    def _init_breakpoints(self) -> Dict[str, int]:
        """Initialize responsive breakpoints"""
        return {
            'mobile': 320,
            'tablet': 768,
            'desktop': 1024,
            'wide': 1440
        }


class AnimationAgent:
    """
    Sub-agent responsible for adding animations and transitions
    Handles CSS animations, transitions, and interactive effects
    """

    def __init__(self):
        self.agent_id = f"animation_{uuid.uuid4().hex[:8]}"
        self.animation_library = self._init_animation_library()
        self.easing_functions = self._init_easing_functions()

    async def initialize(self):
        """Initialize the animation agent"""
        logger.info(f"Animation Agent initialized: {self.agent_id}")
        return True

    async def add_animations(self, component: Dict[str, Any], style_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add animations to a component
        Returns animation definitions and triggers
        """
        animations = {
            'entrance': None,
            'exit': None,
            'hover': None,
            'active': None,
            'transitions': [],
            'keyframes': {}
        }

        try:
            # Check if animations are enabled
            if not style_config.get('animations', True):
                return animations

            # Determine animation type based on component
            component_type = component.get('type', 'default')

            # Add entrance animation
            animations['entrance'] = self._create_entrance_animation(component_type)

            # Add hover effects
            animations['hover'] = self._create_hover_animation(component_type)

            # Add transitions
            animations['transitions'] = self._create_transitions(component_type)

            # Generate keyframes
            animations['keyframes'] = self._generate_keyframes(animations)

            # Add interaction animations
            if 'interactions' in style_config:
                animations['interactive'] = self._create_interactive_animations(
                    style_config['interactions']
                )

            logger.info(f"Added animations to component: {component.get('id')}")

        except Exception as e:
            logger.error(f"Animation error: {e}")
            animations['error'] = str(e)

        return animations

    def _create_entrance_animation(self, component_type: str) -> Dict[str, Any]:
        """Create entrance animation for component"""
        entrance_map = {
            'card': AnimationType.FADE,
            'modal': AnimationType.SCALE,
            'notification': AnimationType.SLIDE,
            'button': AnimationType.FADE,
            'chart': AnimationType.FADE
        }

        animation_type = entrance_map.get(component_type, AnimationType.FADE)

        return {
            'type': animation_type.value,
            'duration': '0.3s',
            'easing': 'ease-out',
            'delay': '0s',
            'fillMode': 'forwards'
        }

    def _create_hover_animation(self, component_type: str) -> Dict[str, Any]:
        """Create hover animation for component"""
        hover_effects = {
            'button': {
                'transform': 'translateY(-2px)',
                'boxShadow': '0 4px 8px rgba(0,0,0,0.2)'
            },
            'card': {
                'transform': 'translateY(-4px)',
                'boxShadow': '0 8px 16px rgba(0,0,0,0.15)'
            },
            'default': {
                'opacity': '0.9'
            }
        }

        return hover_effects.get(component_type, hover_effects['default'])

    def _create_transitions(self, component_type: str) -> List[str]:
        """Create CSS transitions for component"""
        base_transitions = [
            'all 0.3s ease',
            'transform 0.3s ease',
            'opacity 0.3s ease'
        ]

        # Add component-specific transitions
        if component_type == 'button':
            base_transitions.append('background-color 0.2s ease')
        elif component_type == 'card':
            base_transitions.append('box-shadow 0.3s ease')

        return base_transitions

    def _create_interactive_animations(self, interactions: List[str]) -> Dict[str, Dict[str, Any]]:
        """Create animations for interactive events"""
        interactive = {}

        if 'click' in interactions:
            interactive['click'] = {
                'animation': 'pulse',
                'duration': '0.3s'
            }

        if 'drag' in interactions:
            interactive['drag'] = {
                'cursor': 'grabbing',
                'opacity': '0.8'
            }

        if 'focus' in interactions:
            interactive['focus'] = {
                'outline': '2px solid #4f46e5',
                'outlineOffset': '2px'
            }

        return interactive

    def _generate_keyframes(self, animations: Dict[str, Any]) -> Dict[str, str]:
        """Generate CSS keyframes for animations"""
        keyframes = {}

        # Generate entrance keyframes
        if animations['entrance']:
            anim_type = animations['entrance']['type']
            keyframes[f"{anim_type}In"] = self.animation_library[anim_type]

        # Add standard keyframes
        keyframes.update({
            'pulse': """
                0% { transform: scale(1); }
                50% { transform: scale(1.05); }
                100% { transform: scale(1); }
            """,
            'shake': """
                0%, 100% { transform: translateX(0); }
                25% { transform: translateX(-10px); }
                75% { transform: translateX(10px); }
            """,
            'rotate': """
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            """
        })

        return keyframes

    def _init_animation_library(self) -> Dict[str, str]:
        """Initialize animation keyframe library"""
        return {
            'fade': """
                from { opacity: 0; }
                to { opacity: 1; }
            """,
            'slide': """
                from { transform: translateX(-100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            """,
            'scale': """
                from { transform: scale(0.8); opacity: 0; }
                to { transform: scale(1); opacity: 1; }
            """,
            'rotate': """
                from { transform: rotate(-180deg); opacity: 0; }
                to { transform: rotate(0); opacity: 1; }
            """,
            'bounce': """
                0% { transform: translateY(-100%); opacity: 0; }
                60% { transform: translateY(10%); }
                80% { transform: translateY(-5%); }
                100% { transform: translateY(0); opacity: 1; }
            """
        }

    def _init_easing_functions(self) -> Dict[str, str]:
        """Initialize easing functions"""
        return {
            'linear': 'linear',
            'ease': 'ease',
            'ease-in': 'ease-in',
            'ease-out': 'ease-out',
            'ease-in-out': 'ease-in-out',
            'bounce': 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
            'elastic': 'cubic-bezier(0.68, -0.55, 0.32, 1.55)',
            'back': 'cubic-bezier(0.175, 0.885, 0.32, 1.275)'
        }


class ThemeAgent:
    """
    Sub-agent responsible for theming and color schemes
    Handles dark mode, accessibility themes, and custom themes
    """

    def __init__(self):
        self.agent_id = f"theme_{uuid.uuid4().hex[:8]}"
        self.color_palettes = self._init_color_palettes()
        self.theme_presets = self._init_theme_presets()

    async def initialize(self):
        """Initialize the theme agent"""
        logger.info(f"Theme Agent initialized: {self.agent_id}")
        return True

    async def apply_theme(self, component: Dict[str, Any], theme_config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply theme to component"""
        theme = {
            'mode': theme_config.get('mode', 'light'),
            'colors': {},
            'typography': {},
            'spacing': {},
            'borders': {},
            'shadows': {}
        }

        try:
            # Get theme preset
            preset = self.theme_presets.get(theme['mode'], self.theme_presets['light'])

            # Apply color palette
            theme['colors'] = self._apply_color_palette(preset, theme_config)

            # Apply typography
            theme['typography'] = self._apply_typography(preset, theme_config)

            # Apply spacing system
            theme['spacing'] = self._apply_spacing_system(preset)

            # Apply borders and shadows
            theme['borders'] = preset.get('borders', {})
            theme['shadows'] = preset.get('shadows', {})

            logger.info(f"Applied theme: {theme['mode']}")

        except Exception as e:
            logger.error(f"Theme application error: {e}")
            theme['error'] = str(e)

        return theme

    def _apply_color_palette(self, preset: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, str]:
        """Apply color palette to theme"""
        colors = preset.get('colors', {}).copy()

        # Override with custom colors if provided
        if 'colors' in config:
            colors.update(config['colors'])

        return colors

    def _apply_typography(self, preset: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply typography settings"""
        typography = {
            'fontFamily': preset.get('fontFamily', 'system-ui'),
            'fontSize': {
                'xs': '12px',
                'sm': '14px',
                'md': '16px',
                'lg': '18px',
                'xl': '24px',
                'xxl': '32px'
            },
            'fontWeight': {
                'light': 300,
                'normal': 400,
                'medium': 500,
                'bold': 700
            },
            'lineHeight': {
                'tight': 1.25,
                'normal': 1.5,
                'relaxed': 1.75
            }
        }

        # Override with custom typography if provided
        if 'typography' in config:
            typography.update(config['typography'])

        return typography

    def _apply_spacing_system(self, preset: Dict[str, Any]) -> Dict[str, str]:
        """Apply spacing system"""
        base = 4  # Base unit in px
        return {
            'xs': f'{base}px',
            'sm': f'{base * 2}px',
            'md': f'{base * 4}px',
            'lg': f'{base * 6}px',
            'xl': f'{base * 8}px',
            'xxl': f'{base * 12}px'
        }

    def _init_color_palettes(self) -> Dict[str, Dict[str, str]]:
        """Initialize color palettes"""
        return {
            'default': {
                'primary': '#4f46e5',
                'secondary': '#06b6d4',
                'success': '#10b981',
                'warning': '#f59e0b',
                'error': '#ef4444',
                'info': '#3b82f6'
            },
            'pastel': {
                'primary': '#a78bfa',
                'secondary': '#67e8f9',
                'success': '#86efac',
                'warning': '#fcd34d',
                'error': '#fca5a5',
                'info': '#93c5fd'
            }
        }

    def _init_theme_presets(self) -> Dict[str, Dict[str, Any]]:
        """Initialize theme presets"""
        return {
            'light': {
                'colors': {
                    'background': '#ffffff',
                    'surface': '#f9fafb',
                    'text': '#1f2937',
                    'textSecondary': '#6b7280',
                    'border': '#e5e7eb',
                    **self.color_palettes['default']
                },
                'fontFamily': '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
                'shadows': {
                    'sm': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
                    'md': '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                    'lg': '0 10px 15px -3px rgba(0, 0, 0, 0.1)'
                },
                'borders': {
                    'width': '1px',
                    'style': 'solid',
                    'radius': {
                        'sm': '4px',
                        'md': '8px',
                        'lg': '12px',
                        'full': '9999px'
                    }
                }
            },
            'dark': {
                'colors': {
                    'background': '#0f172a',
                    'surface': '#1e293b',
                    'text': '#f1f5f9',
                    'textSecondary': '#94a3b8',
                    'border': '#334155',
                    **self.color_palettes['default']
                },
                'fontFamily': '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
                'shadows': {
                    'sm': '0 1px 2px 0 rgba(0, 0, 0, 0.25)',
                    'md': '0 4px 6px -1px rgba(0, 0, 0, 0.3)',
                    'lg': '0 10px 15px -3px rgba(0, 0, 0, 0.4)'
                },
                'borders': {
                    'width': '1px',
                    'style': 'solid',
                    'radius': {
                        'sm': '4px',
                        'md': '8px',
                        'lg': '12px',
                        'full': '9999px'
                    }
                }
            }
        }


# Example usage
async def test_presentation_agents():
    """Test the presentation layer agents"""

    # Initialize agents
    visual_agent = VisualRenderingAgent()
    await visual_agent.initialize()

    layout_agent = LayoutAgent()
    await layout_agent.initialize()

    animation_agent = AnimationAgent()
    await animation_agent.initialize()

    theme_agent = ThemeAgent()
    await theme_agent.initialize()

    # Create a mock request
    from ui_agent_core import UIRequest, UIComponentType
    request = UIRequest(
        type=UIComponentType.CARD,
        data={'content': 'Test Card Content', 'title': 'Demo Card'},
        style={
            'theme': 'dark',
            'animations': True,
            'dimensions': {'width': '400px'}
        }
    )

    # Calculate layout
    layout = await layout_agent.calculate_layout(request)
    print(f"Layout calculated: {layout['type']}")

    # Render component
    component = await visual_agent.render_component(request, layout)
    print(f"Component rendered: {component['id']}")

    # Add animations
    animations = await animation_agent.add_animations(component, request.style)
    print(f"Animations added: {list(animations.keys())}")

    # Apply theme
    theme = await theme_agent.apply_theme(component, {'mode': 'dark'})
    print(f"Theme applied: {theme['mode']}")

    return {
        'layout': layout,
        'component': component,
        'animations': animations,
        'theme': theme
    }


if __name__ == "__main__":
    asyncio.run(test_presentation_agents())