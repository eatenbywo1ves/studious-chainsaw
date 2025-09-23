"""
Interaction Layer Sub-Agents
=============================
Agents responsible for handling user interactions, feedback, and accessibility
"""

import asyncio
import json
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class GestureType(Enum):
    """Types of gestures that can be recognized"""
    TAP = "tap"
    DOUBLE_TAP = "double_tap"
    LONG_PRESS = "long_press"
    SWIPE_LEFT = "swipe_left"
    SWIPE_RIGHT = "swipe_right"
    SWIPE_UP = "swipe_up"
    SWIPE_DOWN = "swipe_down"
    PINCH = "pinch"
    SPREAD = "spread"
    ROTATE = "rotate"


class FeedbackType(Enum):
    """Types of feedback that can be provided"""
    VISUAL = "visual"
    AUDIO = "audio"
    HAPTIC = "haptic"
    TOAST = "toast"
    MODAL = "modal"
    INLINE = "inline"
    TOOLTIP = "tooltip"


class ValidationStatus(Enum):
    """Validation status for form inputs"""
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"
    PENDING = "pending"


@dataclass
class InteractionEvent:
    """Represents an interaction event"""
    type: str
    target: str
    coordinates: Optional[Tuple[int, int]] = None
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    user_agent: Optional[str] = None
    modifiers: List[str] = field(default_factory=list)  # shift, ctrl, alt, meta


@dataclass
class FeedbackResponse:
    """Represents a feedback response"""
    type: FeedbackType
    message: str
    severity: str = "info"  # info, success, warning, error
    duration: int = 3000  # milliseconds
    position: str = "top-right"
    actions: List[Dict[str, Any]] = field(default_factory=list)


class InputHandlerAgent:
    """
    Sub-agent responsible for handling user input events
    Manages clicks, keyboard input, gestures, and voice commands
    """

    def __init__(self):
        self.agent_id = f"input_{uuid.uuid4().hex[:8]}"
        self.event_handlers = {}
        self.gesture_recognizer = GestureRecognizer()
        self.shortcut_manager = ShortcutManager()
        self.debounce_timers = {}

    async def initialize(self):
        """Initialize the input handler agent"""
        # Setup default event handlers
        self._setup_default_handlers()
        logger.info(f"Input Handler Agent initialized: {self.agent_id}")
        return True

    async def setup_interactions(self, interaction_types: List[str],
                                component: Dict[str, Any]) -> Dict[str, Any]:
        """
        Setup interaction handlers for a component
        Returns interaction configuration
        """
        interactions = {
            'handlers': {},
            'gestures': [],
            'shortcuts': [],
            'voice_commands': []
        }

        try:
            for interaction in interaction_types:
                if interaction == 'click':
                    interactions['handlers']['onClick'] = self._create_click_handler(component)
                elif interaction == 'hover':
                    interactions['handlers']['onMouseEnter'] = self._create_hover_handler(component)
                    interactions['handlers']['onMouseLeave'] = self._create_hover_exit_handler(component)
                elif interaction == 'input':
                    interactions['handlers']['onChange'] = self._create_input_handler(component)
                    interactions['handlers']['onInput'] = self._create_debounced_handler(component)
                elif interaction == 'drag':
                    interactions['handlers']['onDragStart'] = self._create_drag_handler(component)
                    interactions['handlers']['onDragEnd'] = self._create_drag_end_handler(component)
                elif interaction == 'focus':
                    interactions['handlers']['onFocus'] = self._create_focus_handler(component)
                    interactions['handlers']['onBlur'] = self._create_blur_handler(component)
                elif interaction == 'keypress':
                    interactions['handlers']['onKeyDown'] = self._create_keypress_handler(component)
                elif interaction == 'gesture':
                    interactions['gestures'] = await self._setup_gestures(component)
                elif interaction == 'voice':
                    interactions['voice_commands'] = await self._setup_voice_commands(component)

            # Add keyboard shortcuts if applicable
            if component.get('type') in ['form', 'modal', 'dashboard']:
                interactions['shortcuts'] = self._setup_shortcuts(component)

            logger.info(f"Setup {len(interactions['handlers'])} interaction handlers")

        except Exception as e:
            logger.error(f"Interaction setup error: {e}")
            interactions['error'] = str(e)

        return interactions

    async def process_event(self, event: Any) -> Dict[str, Any]:
        """
        Process an interaction event
        Returns event result and any required actions
        """
        result = {
            'event_id': event.id,
            'processed': False,
            'actions': [],
            'requires_feedback': False,
            'requires_rerender': False
        }

        try:
            # Identify event type
            event_type = event.type.value if hasattr(event.type, 'value') else event.type

            # Check for gesture
            if event_type in ['touchstart', 'touchmove', 'touchend']:
                gesture = await self.gesture_recognizer.recognize(event)
                if gesture:
                    result['gesture'] = gesture
                    result['actions'].append({'type': 'gesture', 'gesture': gesture})

            # Check for keyboard shortcut
            if event_type == 'keypress' and event.data.get('key'):
                shortcut = self.shortcut_manager.check_shortcut(event)
                if shortcut:
                    result['shortcut'] = shortcut
                    result['actions'].append({'type': 'shortcut', 'action': shortcut})

            # Process standard events
            handler = self.event_handlers.get(event_type)
            if handler:
                handler_result = await handler(event)
                result.update(handler_result)

            # Determine if feedback is needed
            result['requires_feedback'] = self._should_provide_feedback(event_type, result)

            # Determine if re-render is needed
            result['requires_rerender'] = self._should_rerender(event_type, result)

            result['processed'] = True
            logger.info(f"Processed event: {event_type}")

        except Exception as e:
            logger.error(f"Event processing error: {e}")
            result['error'] = str(e)

        return result

    def _create_click_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create click event handler"""
        return {
            'type': 'click',
            'handler': 'handleClick',
            'preventDefault': True,
            'stopPropagation': False,
            'data': {'component_id': component.get('id')}
        }

    def _create_hover_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create hover event handler"""
        return {
            'type': 'mouseenter',
            'handler': 'handleHover',
            'data': {'component_id': component.get('id'), 'hover': True}
        }

    def _create_hover_exit_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create hover exit handler"""
        return {
            'type': 'mouseleave',
            'handler': 'handleHoverExit',
            'data': {'component_id': component.get('id'), 'hover': False}
        }

    def _create_input_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create input change handler"""
        return {
            'type': 'change',
            'handler': 'handleInputChange',
            'validation': True,
            'data': {'component_id': component.get('id')}
        }

    def _create_debounced_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create debounced input handler"""
        return {
            'type': 'input',
            'handler': 'handleInputDebounced',
            'debounce': 300,  # milliseconds
            'data': {'component_id': component.get('id')}
        }

    def _create_drag_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create drag start handler"""
        return {
            'type': 'dragstart',
            'handler': 'handleDragStart',
            'data': {'component_id': component.get('id'), 'draggable': True}
        }

    def _create_drag_end_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create drag end handler"""
        return {
            'type': 'dragend',
            'handler': 'handleDragEnd',
            'data': {'component_id': component.get('id')}
        }

    def _create_focus_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create focus handler"""
        return {
            'type': 'focus',
            'handler': 'handleFocus',
            'data': {'component_id': component.get('id'), 'focused': True}
        }

    def _create_blur_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create blur handler"""
        return {
            'type': 'blur',
            'handler': 'handleBlur',
            'validation': True,
            'data': {'component_id': component.get('id'), 'focused': False}
        }

    def _create_keypress_handler(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Create keypress handler"""
        return {
            'type': 'keydown',
            'handler': 'handleKeyPress',
            'data': {'component_id': component.get('id')}
        }

    async def _setup_gestures(self, component: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Setup gesture recognition for component"""
        gestures = []

        # Common gestures for different component types
        if component.get('type') == 'card':
            gestures.extend([
                {'type': 'swipe_left', 'action': 'dismiss'},
                {'type': 'swipe_right', 'action': 'archive'},
                {'type': 'long_press', 'action': 'options'}
            ])
        elif component.get('type') == 'image':
            gestures.extend([
                {'type': 'pinch', 'action': 'zoom_out'},
                {'type': 'spread', 'action': 'zoom_in'},
                {'type': 'double_tap', 'action': 'toggle_zoom'}
            ])

        return gestures

    async def _setup_voice_commands(self, component: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Setup voice commands for component"""
        commands = []

        # Common voice commands
        commands.extend([
            {'command': 'click', 'action': 'click'},
            {'command': 'select', 'action': 'focus'},
            {'command': 'close', 'action': 'close'},
            {'command': 'submit', 'action': 'submit'}
        ])

        return commands

    def _setup_shortcuts(self, component: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Setup keyboard shortcuts for component"""
        shortcuts = []

        if component.get('type') == 'form':
            shortcuts.extend([
                {'keys': 'Ctrl+Enter', 'action': 'submit'},
                {'keys': 'Escape', 'action': 'cancel'}
            ])
        elif component.get('type') == 'modal':
            shortcuts.extend([
                {'keys': 'Escape', 'action': 'close'},
                {'keys': 'Enter', 'action': 'confirm'}
            ])
        elif component.get('type') == 'dashboard':
            shortcuts.extend([
                {'keys': 'Ctrl+R', 'action': 'refresh'},
                {'keys': 'Ctrl+F', 'action': 'search'},
                {'keys': 'Ctrl+,', 'action': 'settings'}
            ])

        return shortcuts

    def _setup_default_handlers(self):
        """Setup default event handlers"""
        self.event_handlers = {
            'click': self._handle_click,
            'dblclick': self._handle_double_click,
            'mouseenter': self._handle_mouse_enter,
            'mouseleave': self._handle_mouse_leave,
            'keydown': self._handle_key_down,
            'input': self._handle_input,
            'change': self._handle_change,
            'submit': self._handle_submit
        }

    async def _handle_click(self, event: InteractionEvent) -> Dict[str, Any]:
        """Handle click event"""
        return {
            'action': 'click',
            'target': event.target,
            'timestamp': event.timestamp.isoformat()
        }

    async def _handle_double_click(self, event: InteractionEvent) -> Dict[str, Any]:
        """Handle double click event"""
        return {
            'action': 'double_click',
            'target': event.target,
            'timestamp': event.timestamp.isoformat()
        }

    async def _handle_mouse_enter(self, event: InteractionEvent) -> Dict[str, Any]:
        """Handle mouse enter event"""
        return {
            'action': 'hover_start',
            'target': event.target,
            'timestamp': event.timestamp.isoformat()
        }

    async def _handle_mouse_leave(self, event: InteractionEvent) -> Dict[str, Any]:
        """Handle mouse leave event"""
        return {
            'action': 'hover_end',
            'target': event.target,
            'timestamp': event.timestamp.isoformat()
        }

    async def _handle_key_down(self, event: InteractionEvent) -> Dict[str, Any]:
        """Handle key down event"""
        return {
            'action': 'keypress',
            'key': event.data.get('key'),
            'target': event.target,
            'modifiers': event.modifiers,
            'timestamp': event.timestamp.isoformat()
        }

    async def _handle_input(self, event: InteractionEvent) -> Dict[str, Any]:
        """Handle input event"""
        return {
            'action': 'input',
            'value': event.data.get('value'),
            'target': event.target,
            'timestamp': event.timestamp.isoformat()
        }

    async def _handle_change(self, event: InteractionEvent) -> Dict[str, Any]:
        """Handle change event"""
        return {
            'action': 'change',
            'value': event.data.get('value'),
            'target': event.target,
            'timestamp': event.timestamp.isoformat()
        }

    async def _handle_submit(self, event: InteractionEvent) -> Dict[str, Any]:
        """Handle submit event"""
        return {
            'action': 'submit',
            'data': event.data,
            'target': event.target,
            'timestamp': event.timestamp.isoformat()
        }

    def _should_provide_feedback(self, event_type: str, result: Dict[str, Any]) -> bool:
        """Determine if feedback should be provided"""
        # Provide feedback for certain events
        feedback_events = ['submit', 'click', 'change', 'error']
        return event_type in feedback_events or 'error' in result

    def _should_rerender(self, event_type: str, result: Dict[str, Any]) -> bool:
        """Determine if component should be re-rendered"""
        # Re-render for state-changing events
        rerender_events = ['change', 'submit', 'toggle']
        return event_type in rerender_events or result.get('state_changed', False)


class FeedbackAgent:
    """
    Sub-agent responsible for providing user feedback
    Handles visual, audio, and haptic feedback
    """

    def __init__(self):
        self.agent_id = f"feedback_{uuid.uuid4().hex[:8]}"
        self.feedback_queue = asyncio.Queue()
        self.feedback_templates = self._init_feedback_templates()

    async def initialize(self):
        """Initialize the feedback agent"""
        # Start feedback processing loop
        asyncio.create_task(self._process_feedback_queue())
        logger.info(f"Feedback Agent initialized: {self.agent_id}")
        return True

    async def generate_feedback(self, event: Any, event_result: Dict[str, Any]) -> FeedbackResponse:
        """
        Generate appropriate feedback for an event
        Returns feedback response configuration
        """
        # Determine feedback type based on event and result
        if 'error' in event_result:
            return self._create_error_feedback(event_result['error'])
        elif event_result.get('action') == 'submit':
            return self._create_success_feedback("Form submitted successfully")
        elif event_result.get('action') == 'click':
            return self._create_click_feedback()
        elif event_result.get('validation') == ValidationStatus.INVALID:
            return self._create_validation_feedback(event_result)
        else:
            return self._create_info_feedback("Action completed")

    def _create_error_feedback(self, error_message: str) -> FeedbackResponse:
        """Create error feedback"""
        return FeedbackResponse(
            type=FeedbackType.TOAST,
            message=error_message,
            severity="error",
            duration=5000,
            position="top-right",
            actions=[
                {'label': 'Dismiss', 'action': 'dismiss'},
                {'label': 'Details', 'action': 'show_details'}
            ]
        )

    def _create_success_feedback(self, message: str) -> FeedbackResponse:
        """Create success feedback"""
        return FeedbackResponse(
            type=FeedbackType.TOAST,
            message=message,
            severity="success",
            duration=3000,
            position="top-right"
        )

    def _create_click_feedback(self) -> FeedbackResponse:
        """Create click feedback (visual ripple effect)"""
        return FeedbackResponse(
            type=FeedbackType.VISUAL,
            message="",
            severity="info",
            duration=300
        )

    def _create_validation_feedback(self, validation_result: Dict[str, Any]) -> FeedbackResponse:
        """Create validation feedback"""
        errors = validation_result.get('errors', [])
        message = "Please fix the following errors: " + ", ".join(errors)

        return FeedbackResponse(
            type=FeedbackType.INLINE,
            message=message,
            severity="warning",
            duration=0  # Persistent until fixed
        )

    def _create_info_feedback(self, message: str) -> FeedbackResponse:
        """Create info feedback"""
        return FeedbackResponse(
            type=FeedbackType.TOOLTIP,
            message=message,
            severity="info",
            duration=2000
        )

    async def _process_feedback_queue(self):
        """Process queued feedback items"""
        while True:
            try:
                feedback = await self.feedback_queue.get()
                await self._render_feedback(feedback)
            except Exception as e:
                logger.error(f"Feedback processing error: {e}")
            await asyncio.sleep(0.1)

    async def _render_feedback(self, feedback: FeedbackResponse):
        """Render feedback (would integrate with UI in production)"""
        logger.info(f"Rendering feedback: {feedback.type.value} - {feedback.message}")

    def _init_feedback_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize feedback templates"""
        return {
            'toast': {
                'component': 'Toast',
                'animation': 'slide-in',
                'dismiss': 'auto'
            },
            'modal': {
                'component': 'Modal',
                'animation': 'fade-in',
                'dismiss': 'manual'
            },
            'inline': {
                'component': 'InlineMessage',
                'animation': 'fade-in',
                'dismiss': 'on-fix'
            }
        }


class AccessibilityAgent:
    """
    Sub-agent responsible for ensuring accessibility
    Handles ARIA attributes, keyboard navigation, and screen reader support
    """

    def __init__(self):
        self.agent_id = f"accessibility_{uuid.uuid4().hex[:8]}"
        self.wcag_guidelines = self._init_wcag_guidelines()

    async def initialize(self):
        """Initialize the accessibility agent"""
        logger.info(f"Accessibility Agent initialized: {self.agent_id}")
        return True

    async def apply_accessibility(self, component: Dict[str, Any],
                                 accessibility_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply accessibility features to component
        Returns accessibility attributes and enhancements
        """
        accessibility = {
            'aria': {},
            'keyboard': {},
            'screen_reader': {},
            'focus': {},
            'contrast': {}
        }

        try:
            # Apply ARIA attributes
            accessibility['aria'] = self._apply_aria_attributes(component, accessibility_config)

            # Setup keyboard navigation
            accessibility['keyboard'] = self._setup_keyboard_navigation(component)

            # Add screen reader support
            accessibility['screen_reader'] = self._add_screen_reader_support(component)

            # Ensure focus management
            accessibility['focus'] = self._setup_focus_management(component)

            # Check and fix contrast ratios
            accessibility['contrast'] = await self._ensure_contrast_compliance(component)

            logger.info(f"Applied accessibility features to component")

        except Exception as e:
            logger.error(f"Accessibility error: {e}")
            accessibility['error'] = str(e)

        return accessibility

    def _apply_aria_attributes(self, component: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, str]:
        """Apply ARIA attributes to component"""
        aria = {}

        component_type = component.get('type')

        # Basic ARIA attributes
        aria['role'] = self._get_aria_role(component_type)

        # Labels and descriptions
        if config.get('aria_labels'):
            aria['aria-label'] = config.get('label', f"{component_type} component")
            aria['aria-describedby'] = f"{component.get('id')}_description"

        # State attributes
        if component_type == 'button':
            aria['aria-pressed'] = 'false'
        elif component_type == 'form':
            aria['aria-invalid'] = 'false'
            aria['aria-required'] = 'true'
        elif component_type == 'modal':
            aria['aria-modal'] = 'true'
            aria['aria-hidden'] = 'false'
        elif component_type == 'navigation':
            aria['aria-label'] = 'Main navigation'

        # Live regions for dynamic content
        if component.get('dynamic'):
            aria['aria-live'] = 'polite'
            aria['aria-atomic'] = 'true'

        return aria

    def _setup_keyboard_navigation(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Setup keyboard navigation for component"""
        keyboard = {
            'tabindex': '0',
            'navigation': [],
            'shortcuts': []
        }

        component_type = component.get('type')

        if component_type in ['button', 'link', 'input']:
            keyboard['tabindex'] = '0'
        elif component_type == 'modal':
            keyboard['trap_focus'] = True
            keyboard['escape_closes'] = True
        elif component_type == 'form':
            keyboard['navigation'] = ['Tab', 'Shift+Tab']
            keyboard['shortcuts'] = ['Enter to submit', 'Escape to cancel']
        elif component_type == 'table':
            keyboard['navigation'] = ['Arrow keys to navigate cells']

        return keyboard

    def _add_screen_reader_support(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Add screen reader support"""
        screen_reader = {
            'announcements': [],
            'descriptions': [],
            'landmarks': []
        }

        component_type = component.get('type')

        # Add announcements for interactive elements
        if component_type == 'button':
            screen_reader['announcements'].append('Button, press Enter to activate')
        elif component_type == 'form':
            screen_reader['announcements'].append('Form, navigate with Tab key')
            screen_reader['landmarks'].append('form')
        elif component_type == 'navigation':
            screen_reader['landmarks'].append('navigation')

        # Add descriptions for complex elements
        if component.get('complex'):
            screen_reader['descriptions'].append(
                f"Complex {component_type} with multiple interactive elements"
            )

        return screen_reader

    def _setup_focus_management(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Setup focus management"""
        focus = {
            'visible': True,
            'style': 'outline: 2px solid #4f46e5; outline-offset: 2px;',
            'trap': False,
            'initial': None
        }

        component_type = component.get('type')

        if component_type == 'modal':
            focus['trap'] = True
            focus['initial'] = 'first_interactive'
        elif component_type == 'form':
            focus['initial'] = 'first_input'

        return focus

    async def _ensure_contrast_compliance(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure color contrast meets WCAG guidelines"""
        contrast = {
            'ratio': 0,
            'compliant': False,
            'adjustments': []
        }

        # Get colors from component
        bg_color = component.get('css', {}).get('background-color', '#ffffff')
        text_color = component.get('css', {}).get('color', '#000000')

        # Calculate contrast ratio (simplified)
        ratio = self._calculate_contrast_ratio(bg_color, text_color)
        contrast['ratio'] = ratio

        # WCAG AA requires 4.5:1 for normal text, 3:1 for large text
        required_ratio = 4.5
        contrast['compliant'] = ratio >= required_ratio

        if not contrast['compliant']:
            # Suggest adjustments
            contrast['adjustments'] = [
                {'property': 'color', 'value': self._adjust_color_for_contrast(text_color, bg_color)},
                {'property': 'font-weight', 'value': 'bold'}  # Bold text has lower contrast requirements
            ]

        return contrast

    def _calculate_contrast_ratio(self, bg_color: str, text_color: str) -> float:
        """Calculate contrast ratio between two colors"""
        # Simplified calculation (would use proper luminance calculation in production)
        return 4.5  # Placeholder

    def _adjust_color_for_contrast(self, color: str, background: str) -> str:
        """Adjust color to meet contrast requirements"""
        # Simplified adjustment (would use proper color adjustment in production)
        return '#1a1a1a' if background == '#ffffff' else '#ffffff'

    def _get_aria_role(self, component_type: str) -> str:
        """Get appropriate ARIA role for component type"""
        role_map = {
            'button': 'button',
            'link': 'link',
            'form': 'form',
            'navigation': 'navigation',
            'modal': 'dialog',
            'alert': 'alert',
            'table': 'table',
            'list': 'list',
            'tab': 'tab'
        }

        return role_map.get(component_type, 'region')

    def _init_wcag_guidelines(self) -> Dict[str, Any]:
        """Initialize WCAG guidelines reference"""
        return {
            'contrast': {
                'normal_text': 4.5,
                'large_text': 3.0,
                'ui_components': 3.0
            },
            'target_size': {
                'minimum': '44px',
                'recommended': '48px'
            },
            'focus': {
                'visible': True,
                'keyboard_accessible': True
            }
        }


class GestureRecognizer:
    """Helper class for gesture recognition"""

    def __init__(self):
        self.touch_history = []
        self.gesture_threshold = 50  # pixels

    async def recognize(self, event: InteractionEvent) -> Optional[GestureType]:
        """Recognize gesture from touch events"""
        # Add event to history
        self.touch_history.append(event)

        # Keep only recent events
        if len(self.touch_history) > 10:
            self.touch_history.pop(0)

        # Simple gesture recognition (would be more sophisticated in production)
        if event.type == 'touchend' and len(self.touch_history) >= 2:
            start = self.touch_history[0]
            end = self.touch_history[-1]

            if start.coordinates and end.coordinates:
                dx = end.coordinates[0] - start.coordinates[0]
                dy = end.coordinates[1] - start.coordinates[1]

                if abs(dx) > self.gesture_threshold:
                    return GestureType.SWIPE_LEFT if dx < 0 else GestureType.SWIPE_RIGHT
                elif abs(dy) > self.gesture_threshold:
                    return GestureType.SWIPE_UP if dy < 0 else GestureType.SWIPE_DOWN

        return None


class ShortcutManager:
    """Helper class for keyboard shortcut management"""

    def __init__(self):
        self.shortcuts = {
            'Ctrl+S': 'save',
            'Ctrl+Z': 'undo',
            'Ctrl+Y': 'redo',
            'Ctrl+C': 'copy',
            'Ctrl+V': 'paste',
            'Ctrl+X': 'cut',
            'Ctrl+A': 'select_all',
            'Escape': 'cancel',
            'Enter': 'submit'
        }

    def check_shortcut(self, event: InteractionEvent) -> Optional[str]:
        """Check if event matches a keyboard shortcut"""
        key = event.data.get('key', '')
        modifiers = event.modifiers

        # Build shortcut string
        shortcut = ''
        if 'ctrl' in modifiers:
            shortcut += 'Ctrl+'
        if 'shift' in modifiers:
            shortcut += 'Shift+'
        if 'alt' in modifiers:
            shortcut += 'Alt+'
        shortcut += key

        return self.shortcuts.get(shortcut)


# Example usage
async def test_interaction_agents():
    """Test the interaction layer agents"""

    # Initialize agents
    input_agent = InputHandlerAgent()
    await input_agent.initialize()

    feedback_agent = FeedbackAgent()
    await feedback_agent.initialize()

    accessibility_agent = AccessibilityAgent()
    await accessibility_agent.initialize()

    # Create a test component
    component = {
        'id': 'test_button',
        'type': 'button',
        'content': 'Click Me'
    }

    # Setup interactions
    interactions = await input_agent.setup_interactions(['click', 'hover', 'keypress'], component)
    print(f"Setup interactions: {list(interactions['handlers'].keys())}")

    # Apply accessibility
    accessibility = await accessibility_agent.apply_accessibility(
        component,
        {'aria_labels': True, 'keyboard_nav': True}
    )
    print(f"Applied accessibility: {list(accessibility['aria'].keys())}")

    # Simulate click event
    click_event = InteractionEvent(
        type='click',
        target='test_button',
        coordinates=(100, 100)
    )

    event_result = await input_agent.process_event(click_event)
    print(f"Event processed: {event_result['action']}")

    # Generate feedback
    feedback = await feedback_agent.generate_feedback(click_event, event_result)
    print(f"Feedback generated: {feedback.type.value} - {feedback.message}")

    return {
        'interactions': interactions,
        'accessibility': accessibility,
        'event_result': event_result,
        'feedback': feedback
    }


if __name__ == "__main__":
    asyncio.run(test_interaction_agents())