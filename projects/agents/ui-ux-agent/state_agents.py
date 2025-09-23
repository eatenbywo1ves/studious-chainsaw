"""
State Management Sub-Agents
============================
Agents responsible for form handling, session management, and state persistence
"""

import asyncio
import json
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime, timedelta
import hashlib
import re

logger = logging.getLogger(__name__)


class FormFieldType(Enum):
    """Types of form fields"""
    TEXT = "text"
    EMAIL = "email"
    PASSWORD = "password"
    NUMBER = "number"
    DATE = "date"
    SELECT = "select"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    TEXTAREA = "textarea"
    FILE = "file"
    HIDDEN = "hidden"


class ValidationRule(Enum):
    """Types of validation rules"""
    REQUIRED = "required"
    EMAIL = "email"
    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"
    PATTERN = "pattern"
    MIN_VALUE = "min_value"
    MAX_VALUE = "max_value"
    CUSTOM = "custom"


class SessionStatus(Enum):
    """Session status states"""
    ACTIVE = "active"
    IDLE = "idle"
    EXPIRED = "expired"
    LOCKED = "locked"


@dataclass
class FormField:
    """Represents a form field"""
    name: str
    type: FormFieldType
    label: str
    value: Any = None
    placeholder: Optional[str] = None
    required: bool = False
    validation_rules: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    disabled: bool = False
    options: Optional[List[Dict[str, str]]] = None  # For select, radio


@dataclass
class FormState:
    """Represents the state of a form"""
    id: str
    fields: Dict[str, FormField]
    values: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    touched: Dict[str, bool] = field(default_factory=dict)
    submitted: bool = False
    valid: bool = False
    dirty: bool = False
    submitting: bool = False


@dataclass
class UserSession:
    """Represents a user session"""
    id: str
    user_id: Optional[str]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    data: Dict[str, Any] = field(default_factory=dict)
    preferences: Dict[str, Any] = field(default_factory=dict)
    status: SessionStatus = SessionStatus.ACTIVE


class FormAgent:
    """
    Sub-agent responsible for form handling and validation
    Manages form state, validation, and submission
    """

    def __init__(self):
        self.agent_id = f"form_{uuid.uuid4().hex[:8]}"
        self.forms: Dict[str, FormState] = {}
        self.validators = self._init_validators()
        self.field_templates = self._init_field_templates()

    async def initialize(self):
        """Initialize the form agent"""
        logger.info(f"Form Agent initialized: {self.agent_id}")
        return True

    async def create_form(self, form_config: Dict[str, Any]) -> FormState:
        """
        Create a new form with validation rules
        Returns form state object
        """
        form_id = f"form_{uuid.uuid4().hex[:8]}"

        # Create form fields
        fields = {}
        for field_config in form_config.get('fields', []):
            field = self._create_form_field(field_config)
            fields[field.name] = field

        # Create form state
        form_state = FormState(
            id=form_id,
            fields=fields
        )

        # Store form
        self.forms[form_id] = form_state

        logger.info(f"Created form {form_id} with {len(fields)} fields")

        return form_state

    async def validate_field(self, form_id: str, field_name: str, value: Any) -> Dict[str, Any]:
        """
        Validate a single form field
        Returns validation result
        """
        result = {
            'valid': True,
            'error': None,
            'warnings': []
        }

        try:
            form = self.forms.get(form_id)
            if not form:
                raise ValueError(f"Form {form_id} not found")

            field = form.fields.get(field_name)
            if not field:
                raise ValueError(f"Field {field_name} not found")

            # Update field value
            form.values[field_name] = value
            form.touched[field_name] = True
            form.dirty = True

            # Run validation rules
            for rule in field.validation_rules:
                validation_result = await self._validate_rule(value, rule, field)
                if not validation_result['valid']:
                    result['valid'] = False
                    result['error'] = validation_result['error']
                    form.errors[field_name] = validation_result['error']
                    break

            # Clear error if valid
            if result['valid'] and field_name in form.errors:
                del form.errors[field_name]

            # Update form validity
            form.valid = len(form.errors) == 0

        except Exception as e:
            logger.error(f"Field validation error: {e}")
            result['valid'] = False
            result['error'] = str(e)

        return result

    async def validate_form(self, form_id: str) -> Dict[str, Any]:
        """
        Validate entire form
        Returns validation result with all errors
        """
        result = {
            'valid': True,
            'errors': {},
            'warnings': []
        }

        try:
            form = self.forms.get(form_id)
            if not form:
                raise ValueError(f"Form {form_id} not found")

            # Validate each field
            for field_name, field in form.fields.items():
                value = form.values.get(field_name)
                field_result = await self.validate_field(form_id, field_name, value)

                if not field_result['valid']:
                    result['valid'] = False
                    result['errors'][field_name] = field_result['error']

            form.valid = result['valid']

        except Exception as e:
            logger.error(f"Form validation error: {e}")
            result['valid'] = False
            result['errors']['_form'] = str(e)

        return result

    async def submit_form(self, form_id: str) -> Dict[str, Any]:
        """
        Submit a form after validation
        Returns submission result
        """
        result = {
            'success': False,
            'data': None,
            'errors': {}
        }

        try:
            form = self.forms.get(form_id)
            if not form:
                raise ValueError(f"Form {form_id} not found")

            form.submitting = True

            # Validate form
            validation = await self.validate_form(form_id)

            if validation['valid']:
                # Process submission
                result['data'] = form.values.copy()
                result['success'] = True
                form.submitted = True

                logger.info(f"Form {form_id} submitted successfully")
            else:
                result['errors'] = validation['errors']
                logger.warning(f"Form {form_id} submission failed validation")

            form.submitting = False

        except Exception as e:
            logger.error(f"Form submission error: {e}")
            result['errors']['_form'] = str(e)

        return result

    async def reset_form(self, form_id: str):
        """Reset form to initial state"""
        form = self.forms.get(form_id)
        if form:
            form.values.clear()
            form.errors.clear()
            form.touched.clear()
            form.submitted = False
            form.valid = False
            form.dirty = False
            logger.info(f"Form {form_id} reset")

    def _create_form_field(self, config: Dict[str, Any]) -> FormField:
        """Create a form field from configuration"""
        field_type = FormFieldType(config.get('type', 'text'))

        # Get template if available
        template = self.field_templates.get(field_type, {})

        # Create field
        field = FormField(
            name=config['name'],
            type=field_type,
            label=config.get('label', config['name']),
            placeholder=config.get('placeholder'),
            required=config.get('required', False),
            disabled=config.get('disabled', False),
            options=config.get('options')
        )

        # Add validation rules
        validation_rules = []

        if field.required:
            validation_rules.append({
                'type': ValidationRule.REQUIRED,
                'message': f"{field.label} is required"
            })

        if field_type == FormFieldType.EMAIL:
            validation_rules.append({
                'type': ValidationRule.EMAIL,
                'message': "Please enter a valid email address"
            })

        # Add custom validation rules
        if 'validation' in config:
            for rule in config['validation']:
                validation_rules.append(rule)

        field.validation_rules = validation_rules

        return field

    async def _validate_rule(self, value: Any, rule: Dict[str, Any], field: FormField) -> Dict[str, Any]:
        """Validate a value against a rule"""
        rule_type = rule.get('type')

        if isinstance(rule_type, str):
            rule_type = ValidationRule(rule_type)

        validator = self.validators.get(rule_type)
        if validator:
            return await validator(value, rule, field)

        return {'valid': True}

    def _init_validators(self) -> Dict[ValidationRule, Callable]:
        """Initialize validation functions"""
        return {
            ValidationRule.REQUIRED: self._validate_required,
            ValidationRule.EMAIL: self._validate_email,
            ValidationRule.MIN_LENGTH: self._validate_min_length,
            ValidationRule.MAX_LENGTH: self._validate_max_length,
            ValidationRule.PATTERN: self._validate_pattern,
            ValidationRule.MIN_VALUE: self._validate_min_value,
            ValidationRule.MAX_VALUE: self._validate_max_value
        }

    async def _validate_required(self, value: Any, rule: Dict[str, Any], field: FormField) -> Dict[str, Any]:
        """Validate required field"""
        is_valid = value is not None and value != '' and value != []

        return {
            'valid': is_valid,
            'error': rule.get('message', f"{field.label} is required") if not is_valid else None
        }

    async def _validate_email(self, value: Any, rule: Dict[str, Any], field: FormField) -> Dict[str, Any]:
        """Validate email format"""
        if not value:
            return {'valid': True}  # Empty is valid (use required for that)

        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        is_valid = bool(re.match(email_pattern, str(value)))

        return {
            'valid': is_valid,
            'error': rule.get('message', "Invalid email format") if not is_valid else None
        }

    async def _validate_min_length(self, value: Any, rule: Dict[str, Any], field: FormField) -> Dict[str, Any]:
        """Validate minimum length"""
        min_length = rule.get('value', 0)
        is_valid = len(str(value)) >= min_length if value else True

        return {
            'valid': is_valid,
            'error': rule.get('message', f"Minimum {min_length} characters required") if not is_valid else None
        }

    async def _validate_max_length(self, value: Any, rule: Dict[str, Any], field: FormField) -> Dict[str, Any]:
        """Validate maximum length"""
        max_length = rule.get('value', float('inf'))
        is_valid = len(str(value)) <= max_length if value else True

        return {
            'valid': is_valid,
            'error': rule.get('message', f"Maximum {max_length} characters allowed") if not is_valid else None
        }

    async def _validate_pattern(self, value: Any, rule: Dict[str, Any], field: FormField) -> Dict[str, Any]:
        """Validate against regex pattern"""
        pattern = rule.get('value', '.*')
        is_valid = bool(re.match(pattern, str(value))) if value else True

        return {
            'valid': is_valid,
            'error': rule.get('message', "Invalid format") if not is_valid else None
        }

    async def _validate_min_value(self, value: Any, rule: Dict[str, Any], field: FormField) -> Dict[str, Any]:
        """Validate minimum numeric value"""
        min_value = rule.get('value', float('-inf'))
        is_valid = float(value) >= min_value if value else True

        return {
            'valid': is_valid,
            'error': rule.get('message', f"Minimum value is {min_value}") if not is_valid else None
        }

    async def _validate_max_value(self, value: Any, rule: Dict[str, Any], field: FormField) -> Dict[str, Any]:
        """Validate maximum numeric value"""
        max_value = rule.get('value', float('inf'))
        is_valid = float(value) <= max_value if value else True

        return {
            'valid': is_valid,
            'error': rule.get('message', f"Maximum value is {max_value}") if not is_valid else None
        }

    def _init_field_templates(self) -> Dict[FormFieldType, Dict[str, Any]]:
        """Initialize field templates"""
        return {
            FormFieldType.EMAIL: {
                'autocomplete': 'email',
                'inputmode': 'email'
            },
            FormFieldType.PASSWORD: {
                'autocomplete': 'current-password',
                'minlength': 8
            },
            FormFieldType.NUMBER: {
                'inputmode': 'numeric'
            },
            FormFieldType.DATE: {
                'min': '1900-01-01',
                'max': '2100-12-31'
            }
        }


class SessionAgent:
    """
    Sub-agent responsible for session management
    Handles user sessions, preferences, and state persistence
    """

    def __init__(self):
        self.agent_id = f"session_{uuid.uuid4().hex[:8]}"
        self.sessions: Dict[str, UserSession] = {}
        self.session_timeout = timedelta(hours=24)
        self.idle_timeout = timedelta(minutes=30)
        self.storage_backend = None  # Could be Redis, database, etc.

    async def initialize(self):
        """Initialize the session agent"""
        # Start session cleanup task
        asyncio.create_task(self._cleanup_sessions())
        logger.info(f"Session Agent initialized: {self.agent_id}")
        return True

    async def create_session(self, user_id: Optional[str] = None,
                           data: Optional[Dict[str, Any]] = None) -> UserSession:
        """
        Create a new user session
        Returns session object
        """
        session_id = self._generate_session_id()
        now = datetime.now()

        session = UserSession(
            id=session_id,
            user_id=user_id,
            created_at=now,
            last_activity=now,
            expires_at=now + self.session_timeout,
            data=data or {},
            status=SessionStatus.ACTIVE
        )

        self.sessions[session_id] = session

        # Persist to storage
        await self._persist_session(session)

        logger.info(f"Created session {session_id} for user {user_id}")

        return session

    async def get_session(self, session_id: str) -> Optional[UserSession]:
        """Get a session by ID"""
        session = self.sessions.get(session_id)

        if not session:
            # Try to load from storage
            session = await self._load_session(session_id)
            if session:
                self.sessions[session_id] = session

        if session:
            # Check if expired
            if datetime.now() > session.expires_at:
                session.status = SessionStatus.EXPIRED
                logger.info(f"Session {session_id} has expired")
                return None

            # Check if idle
            if datetime.now() - session.last_activity > self.idle_timeout:
                session.status = SessionStatus.IDLE

        return session

    async def update_session(self, session_id: str, event: Any, event_result: Dict[str, Any]):
        """Update session with event data"""
        session = await self.get_session(session_id)

        if session and session.status == SessionStatus.ACTIVE:
            # Update last activity
            session.last_activity = datetime.now()

            # Store event in session
            if 'events' not in session.data:
                session.data['events'] = []

            session.data['events'].append({
                'timestamp': datetime.now().isoformat(),
                'type': event.type.value if hasattr(event.type, 'value') else event.type,
                'target': event.target if hasattr(event, 'target') else None,
                'result': event_result.get('action')
            })

            # Keep only last 100 events
            if len(session.data['events']) > 100:
                session.data['events'] = session.data['events'][-100:]

            # Persist changes
            await self._persist_session(session)

            logger.info(f"Updated session {session_id}")

    async def update_preferences(self, session_id: str, preferences: Dict[str, Any]):
        """Update user preferences in session"""
        session = await self.get_session(session_id)

        if session:
            session.preferences.update(preferences)
            await self._persist_session(session)
            logger.info(f"Updated preferences for session {session_id}")

    async def destroy_session(self, session_id: str):
        """Destroy a session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            await self._remove_from_storage(session_id)
            logger.info(f"Destroyed session {session_id}")

    async def extend_session(self, session_id: str, duration: timedelta = None):
        """Extend session expiration"""
        session = await self.get_session(session_id)

        if session:
            extension = duration or self.session_timeout
            session.expires_at = datetime.now() + extension
            session.status = SessionStatus.ACTIVE
            await self._persist_session(session)
            logger.info(f"Extended session {session_id} by {extension}")

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        random_data = f"{uuid.uuid4()}{datetime.now().isoformat()}"
        return hashlib.sha256(random_data.encode()).hexdigest()[:32]

    async def _persist_session(self, session: UserSession):
        """Persist session to storage backend"""
        # In production, this would save to Redis, database, etc.
        # For now, just keep in memory
        pass

    async def _load_session(self, session_id: str) -> Optional[UserSession]:
        """Load session from storage backend"""
        # In production, this would load from Redis, database, etc.
        return None

    async def _remove_from_storage(self, session_id: str):
        """Remove session from storage backend"""
        # In production, this would remove from Redis, database, etc.
        pass

    async def _cleanup_sessions(self):
        """Background task to cleanup expired sessions"""
        while True:
            try:
                now = datetime.now()
                expired_sessions = []

                for session_id, session in self.sessions.items():
                    if now > session.expires_at:
                        expired_sessions.append(session_id)

                for session_id in expired_sessions:
                    await self.destroy_session(session_id)
                    logger.info(f"Cleaned up expired session {session_id}")

            except Exception as e:
                logger.error(f"Session cleanup error: {e}")

            await asyncio.sleep(300)  # Cleanup every 5 minutes


class CacheAgent:
    """
    Sub-agent responsible for caching UI components and data
    Improves performance by caching frequently accessed items
    """

    def __init__(self):
        self.agent_id = f"cache_{uuid.uuid4().hex[:8]}"
        self.component_cache: Dict[str, Dict[str, Any]] = {}
        self.data_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(minutes=15)
        self.max_cache_size = 1000

    async def initialize(self):
        """Initialize the cache agent"""
        # Start cache cleanup task
        asyncio.create_task(self._cleanup_cache())
        logger.info(f"Cache Agent initialized: {self.agent_id}")
        return True

    async def cache_component(self, component_id: str, component: Dict[str, Any],
                            ttl: Optional[timedelta] = None):
        """Cache a UI component"""
        expiry = datetime.now() + (ttl or self.cache_ttl)

        self.component_cache[component_id] = {
            'data': component,
            'expiry': expiry,
            'hits': 0
        }

        # Evict if cache is full
        if len(self.component_cache) > self.max_cache_size:
            await self._evict_lru()

        logger.debug(f"Cached component {component_id}")

    async def get_cached_component(self, component_id: str) -> Optional[Dict[str, Any]]:
        """Get a cached component"""
        cached = self.component_cache.get(component_id)

        if cached:
            # Check if expired
            if datetime.now() > cached['expiry']:
                del self.component_cache[component_id]
                return None

            # Update hit count
            cached['hits'] += 1
            return cached['data']

        return None

    async def cache_data(self, key: str, data: Any, ttl: Optional[timedelta] = None):
        """Cache arbitrary data"""
        expiry = datetime.now() + (ttl or self.cache_ttl)

        self.data_cache[key] = {
            'data': data,
            'expiry': expiry,
            'hits': 0
        }

        logger.debug(f"Cached data with key {key}")

    async def get_cached_data(self, key: str) -> Optional[Any]:
        """Get cached data"""
        cached = self.data_cache.get(key)

        if cached:
            if datetime.now() > cached['expiry']:
                del self.data_cache[key]
                return None

            cached['hits'] += 1
            return cached['data']

        return None

    async def invalidate_cache(self, pattern: Optional[str] = None):
        """Invalidate cache entries matching pattern"""
        if pattern:
            # Invalidate matching entries
            to_remove = [k for k in self.component_cache.keys() if pattern in k]
            for key in to_remove:
                del self.component_cache[key]

            to_remove = [k for k in self.data_cache.keys() if pattern in k]
            for key in to_remove:
                del self.data_cache[key]

            logger.info(f"Invalidated cache entries matching {pattern}")
        else:
            # Clear all cache
            self.component_cache.clear()
            self.data_cache.clear()
            logger.info("Cleared all cache")

    async def _evict_lru(self):
        """Evict least recently used cache entry"""
        # Find LRU component
        if self.component_cache:
            lru_key = min(self.component_cache.keys(),
                         key=lambda k: self.component_cache[k]['hits'])
            del self.component_cache[lru_key]
            logger.debug(f"Evicted LRU component {lru_key}")

    async def _cleanup_cache(self):
        """Background task to cleanup expired cache entries"""
        while True:
            try:
                now = datetime.now()

                # Cleanup component cache
                expired = [k for k, v in self.component_cache.items()
                          if now > v['expiry']]
                for key in expired:
                    del self.component_cache[key]

                # Cleanup data cache
                expired = [k for k, v in self.data_cache.items()
                          if now > v['expiry']]
                for key in expired:
                    del self.data_cache[key]

                if expired:
                    logger.debug(f"Cleaned up {len(expired)} expired cache entries")

            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")

            await asyncio.sleep(60)  # Cleanup every minute

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'component_cache_size': len(self.component_cache),
            'data_cache_size': len(self.data_cache),
            'total_hits': sum(v['hits'] for v in self.component_cache.values()) +
                         sum(v['hits'] for v in self.data_cache.values()),
            'max_size': self.max_cache_size
        }


# Example usage
async def test_state_agents():
    """Test the state management agents"""

    # Initialize agents
    form_agent = FormAgent()
    await form_agent.initialize()

    session_agent = SessionAgent()
    await session_agent.initialize()

    cache_agent = CacheAgent()
    await cache_agent.initialize()

    # Create a form
    form_config = {
        'fields': [
            {
                'name': 'email',
                'type': 'email',
                'label': 'Email Address',
                'required': True
            },
            {
                'name': 'password',
                'type': 'password',
                'label': 'Password',
                'required': True,
                'validation': [
                    {'type': 'min_length', 'value': 8, 'message': 'Password must be at least 8 characters'}
                ]
            },
            {
                'name': 'remember',
                'type': 'checkbox',
                'label': 'Remember me'
            }
        ]
    }

    form = await form_agent.create_form(form_config)
    print(f"Created form: {form.id}")

    # Validate fields
    validation = await form_agent.validate_field(form.id, 'email', 'user@example.com')
    print(f"Email validation: {validation['valid']}")

    validation = await form_agent.validate_field(form.id, 'password', 'short')
    print(f"Password validation: {validation['valid']} - {validation.get('error')}")

    # Create a session
    session = await session_agent.create_session(user_id='user123')
    print(f"Created session: {session.id}")

    # Cache a component
    await cache_agent.cache_component('comp_123', {'type': 'card', 'data': 'test'})
    cached = await cache_agent.get_cached_component('comp_123')
    print(f"Cached component retrieved: {cached is not None}")

    # Get cache stats
    stats = cache_agent.get_cache_stats()
    print(f"Cache stats: {stats}")

    return {
        'form': form,
        'session': session,
        'cache_stats': stats
    }


if __name__ == "__main__":
    asyncio.run(test_state_agents())