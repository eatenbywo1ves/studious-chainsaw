"""
Advanced Shorthand Auto-Response System
Intelligent text expansion, templates, and context-aware responses
"""

import re
import json
import sqlite3
import datetime
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
import difflib
import time
from collections import defaultdict, Counter
import threading
import queue


class ResponseCategory(Enum):
    """Categories for organizing responses"""
    GREETING = "greeting"
    ACKNOWLEDGMENT = "acknowledgment"
    TECHNICAL = "technical"
    SUPPORT = "support"
    EMAIL = "email"
    CODE = "code"
    NETWORK = "network"
    SECURITY = "security"
    MEETING = "meeting"
    PROJECT = "project"
    CUSTOMER = "customer"
    EMERGENCY = "emergency"
    SOCIAL = "social"
    DOCUMENTATION = "documentation"
    CUSTOM = "custom"


class TriggerType(Enum):
    """Types of triggers for responses"""
    EXACT = "exact"              # Exact match
    PREFIX = "prefix"            # Starts with
    SUFFIX = "suffix"            # Ends with
    CONTAINS = "contains"        # Contains substring
    REGEX = "regex"              # Regular expression
    FUZZY = "fuzzy"              # Fuzzy matching
    CONTEXTUAL = "contextual"    # Based on context
    SMART = "smart"              # AI-based matching


@dataclass
class ShorthandRule:
    """Represents a shorthand expansion rule"""
    trigger: str
    expansion: str
    category: ResponseCategory
    trigger_type: TriggerType
    priority: int = 5
    case_sensitive: bool = False
    enabled: bool = True
    usage_count: int = 0
    last_used: Optional[datetime.datetime] = None
    variables: Dict[str, str] = field(default_factory=dict)
    conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponseTemplate:
    """Template for generating responses"""
    template_id: str
    name: str
    category: ResponseCategory
    template: str
    variables: List[str]
    examples: List[str]
    tags: List[str]
    usage_count: int = 0
    effectiveness_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponseContext:
    """Context information for response selection"""
    input_text: str
    sender: Optional[str] = None
    recipient: Optional[str] = None
    channel: Optional[str] = None  # email, chat, sms, etc.
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    history: List[str] = field(default_factory=list)
    sentiment: Optional[str] = None
    urgency: int = 0  # 0-10 scale
    metadata: Dict[str, Any] = field(default_factory=dict)


class ShorthandEngine:
    """Core engine for shorthand expansion and response generation"""
    
    def __init__(self, 
                 config_file: str = "shorthand_config.json",
                 db_file: str = "shorthand_responses.db",
                 learning_enabled: bool = True):
        """
        Initialize the shorthand engine
        
        Args:
            config_file: Path to configuration file
            db_file: Path to SQLite database
            learning_enabled: Enable machine learning features
        """
        self.config_file = config_file
        self.db_file = db_file
        self.learning_enabled = learning_enabled
        
        # Rule storage
        self.rules: Dict[str, ShorthandRule] = {}
        self.templates: Dict[str, ResponseTemplate] = {}
        self.category_rules: Dict[ResponseCategory, List[str]] = defaultdict(list)
        
        # Performance tracking
        self.response_times: List[float] = []
        self.cache: Dict[str, str] = {}
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Initialize database
        self._init_database()
        
        # Load configuration
        self.load_config()
        
        # Initialize default rules
        self._init_default_rules()

    def _init_database(self):
        """Initialize SQLite database for persistence"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shorthand_rules (
                trigger TEXT PRIMARY KEY,
                expansion TEXT,
                category TEXT,
                trigger_type TEXT,
                priority INTEGER,
                case_sensitive INTEGER,
                enabled INTEGER,
                usage_count INTEGER,
                last_used TIMESTAMP,
                variables TEXT,
                conditions TEXT,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS templates (
                template_id TEXT PRIMARY KEY,
                name TEXT,
                category TEXT,
                template TEXT,
                variables TEXT,
                examples TEXT,
                tags TEXT,
                usage_count INTEGER,
                effectiveness_score REAL,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS response_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                input_text TEXT,
                trigger_matched TEXT,
                response_generated TEXT,
                context TEXT,
                response_time REAL,
                user_feedback INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS learning_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                pattern TEXT,
                response TEXT,
                effectiveness REAL,
                context TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def _init_default_rules(self):
        """Initialize default shorthand rules"""
        default_rules = [
            # Greetings
            ShorthandRule("gm", "Good morning", ResponseCategory.GREETING, TriggerType.EXACT),
            ShorthandRule("gn", "Good night", ResponseCategory.GREETING, TriggerType.EXACT),
            ShorthandRule("ty", "Thank you", ResponseCategory.ACKNOWLEDGMENT, TriggerType.EXACT),
            ShorthandRule("yw", "You're welcome", ResponseCategory.ACKNOWLEDGMENT, TriggerType.EXACT),
            ShorthandRule("np", "No problem", ResponseCategory.ACKNOWLEDGMENT, TriggerType.EXACT),
            
            # Technical
            ShorthandRule("brb", "Be right back", ResponseCategory.SOCIAL, TriggerType.EXACT),
            ShorthandRule("afk", "Away from keyboard", ResponseCategory.SOCIAL, TriggerType.EXACT),
            ShorthandRule("imo", "In my opinion", ResponseCategory.SOCIAL, TriggerType.EXACT),
            ShorthandRule("fyi", "For your information", ResponseCategory.EMAIL, TriggerType.EXACT),
            ShorthandRule("asap", "As soon as possible", ResponseCategory.EMAIL, TriggerType.EXACT),
            ShorthandRule("eod", "End of day", ResponseCategory.EMAIL, TriggerType.EXACT),
            ShorthandRule("eta", "Estimated time of arrival", ResponseCategory.PROJECT, TriggerType.EXACT),
            
            # Support responses
            ShorthandRule("htb", "Happy to help! Is there anything else you need?", 
                         ResponseCategory.SUPPORT, TriggerType.EXACT),
            ShorthandRule("chk", "I'll check on that and get back to you shortly.", 
                         ResponseCategory.SUPPORT, TriggerType.EXACT),
            ShorthandRule("esc", "I'm escalating this issue to the senior team for immediate attention.", 
                         ResponseCategory.SUPPORT, TriggerType.EXACT),
            
            # Code snippets
            ShorthandRule("pydef", "def function_name(parameters):\n    '''Docstring'''\n    pass", 
                         ResponseCategory.CODE, TriggerType.EXACT),
            ShorthandRule("pyclass", "class ClassName:\n    def __init__(self):\n        pass", 
                         ResponseCategory.CODE, TriggerType.EXACT),
            ShorthandRule("tryex", "try:\n    # code\nexcept Exception as e:\n    print(f'Error: {e}')", 
                         ResponseCategory.CODE, TriggerType.EXACT),
            
            # Network/Security
            ShorthandRule("netstat", "netstat -tuln | grep LISTEN", 
                         ResponseCategory.NETWORK, TriggerType.EXACT),
            ShorthandRule("pingtest", "ping -c 4 google.com", 
                         ResponseCategory.NETWORK, TriggerType.EXACT),
            ShorthandRule("sshgen", "ssh-keygen -t rsa -b 4096 -C 'email@example.com'", 
                         ResponseCategory.SECURITY, TriggerType.EXACT),
            
            # Email templates
            ShorthandRule("emailgreet", "Dear {name},\n\nI hope this email finds you well.", 
                         ResponseCategory.EMAIL, TriggerType.EXACT),
            ShorthandRule("emailclose", "Best regards,\n{sender_name}", 
                         ResponseCategory.EMAIL, TriggerType.EXACT),
            ShorthandRule("followup", "I wanted to follow up on our previous conversation regarding {topic}.", 
                         ResponseCategory.EMAIL, TriggerType.EXACT),
            
            # Meeting
            ShorthandRule("mtg15", "I have another meeting in 15 minutes, so we'll need to wrap up soon.", 
                         ResponseCategory.MEETING, TriggerType.EXACT),
            ShorthandRule("mtgagenda", "Let's review today's agenda:\n1. {item1}\n2. {item2}\n3. {item3}", 
                         ResponseCategory.MEETING, TriggerType.EXACT),
            
            # Emergency
            ShorthandRule("911sec", "[SECURITY ALERT] Potential security breach detected. Initiating incident response protocol.", 
                         ResponseCategory.EMERGENCY, TriggerType.EXACT, priority=10),
            ShorthandRule("911down", "[CRITICAL] Service is down. Investigating immediately.", 
                         ResponseCategory.EMERGENCY, TriggerType.EXACT, priority=10),
        ]
        
        for rule in default_rules:
            self.add_rule(rule)

    def add_rule(self, rule: ShorthandRule) -> bool:
        """Add a new shorthand rule"""
        try:
            self.rules[rule.trigger] = rule
            self.category_rules[rule.category].append(rule.trigger)
            self._save_rule_to_db(rule)
            return True
        except Exception as e:
            print(f"Error adding rule: {e}")
            return False

    def remove_rule(self, trigger: str) -> bool:
        """Remove a shorthand rule"""
        if trigger in self.rules:
            rule = self.rules[trigger]
            del self.rules[trigger]
            self.category_rules[rule.category].remove(trigger)
            self._delete_rule_from_db(trigger)
            return True
        return False

    def expand(self, text: str, context: Optional[ResponseContext] = None) -> str:
        """
        Expand shorthand text to full response
        
        Args:
            text: Input text containing shorthands
            context: Optional context for intelligent expansion
        
        Returns:
            Expanded text
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = hashlib.md5(text.encode()).hexdigest()
        if cache_key in self.cache:
            self.cache_hits += 1
            return self.cache[cache_key]
        
        self.cache_misses += 1
        
        # Process text
        result = text
        matches_found = []
        
        # Sort rules by priority
        sorted_rules = sorted(self.rules.values(), 
                            key=lambda x: x.priority, 
                            reverse=True)
        
        for rule in sorted_rules:
            if not rule.enabled:
                continue
            
            if self._matches_trigger(result, rule, context):
                expansion = self._apply_expansion(rule, context)
                result = self._replace_trigger(result, rule, expansion)
                matches_found.append(rule.trigger)
                
                # Update usage statistics
                rule.usage_count += 1
                rule.last_used = datetime.datetime.now()
                self._update_rule_stats(rule)
        
        # Cache result
        self.cache[cache_key] = result
        
        # Record response time
        response_time = time.time() - start_time
        self.response_times.append(response_time)
        
        # Save to history
        if matches_found:
            self._save_to_history(text, matches_found, result, context, response_time)
        
        return result

    def _matches_trigger(self, text: str, rule: ShorthandRule, 
                        context: Optional[ResponseContext]) -> bool:
        """Check if text matches the trigger rule"""
        trigger = rule.trigger
        if not rule.case_sensitive:
            text = text.lower()
            trigger = trigger.lower()
        
        if rule.trigger_type == TriggerType.EXACT:
            # Word boundary matching
            pattern = r'\b' + re.escape(trigger) + r'\b'
            return bool(re.search(pattern, text))
        
        elif rule.trigger_type == TriggerType.PREFIX:
            words = text.split()
            return any(word.startswith(trigger) for word in words)
        
        elif rule.trigger_type == TriggerType.SUFFIX:
            words = text.split()
            return any(word.endswith(trigger) for word in words)
        
        elif rule.trigger_type == TriggerType.CONTAINS:
            return trigger in text
        
        elif rule.trigger_type == TriggerType.REGEX:
            try:
                return bool(re.search(trigger, text))
            except:
                return False
        
        elif rule.trigger_type == TriggerType.FUZZY:
            # Fuzzy matching with threshold
            words = text.split()
            for word in words:
                ratio = difflib.SequenceMatcher(None, word, trigger).ratio()
                if ratio > 0.8:  # 80% similarity threshold
                    return True
            return False
        
        elif rule.trigger_type == TriggerType.CONTEXTUAL:
            # Context-based matching
            if context:
                return self._evaluate_context(rule, context)
            return False
        
        elif rule.trigger_type == TriggerType.SMART:
            # Smart matching using multiple strategies
            return (self._matches_trigger(text, ShorthandRule(trigger, "", 
                                                             rule.category, 
                                                             TriggerType.EXACT), context) or
                   self._matches_trigger(text, ShorthandRule(trigger, "", 
                                                            rule.category, 
                                                            TriggerType.FUZZY), context))
        
        return False

    def _evaluate_context(self, rule: ShorthandRule, context: ResponseContext) -> bool:
        """Evaluate contextual conditions"""
        if not rule.conditions:
            return True
        
        for condition, value in rule.conditions.items():
            if condition == "urgency_min" and context.urgency < value:
                return False
            elif condition == "channel" and context.channel != value:
                return False
            elif condition == "sentiment" and context.sentiment != value:
                return False
            elif condition == "time_range":
                current_hour = datetime.datetime.now().hour
                start, end = value
                if not (start <= current_hour < end):
                    return False
        
        return True

    def _apply_expansion(self, rule: ShorthandRule, 
                        context: Optional[ResponseContext]) -> str:
        """Apply variable substitution to expansion"""
        expansion = rule.expansion
        
        # Substitute rule variables
        for var, value in rule.variables.items():
            expansion = expansion.replace(f"{{{var}}}", value)
        
        # Substitute context variables
        if context and context.metadata:
            for var, value in context.metadata.items():
                expansion = expansion.replace(f"{{{var}}}", str(value))
        
        # Add timestamp variables
        now = datetime.datetime.now()
        expansion = expansion.replace("{date}", now.strftime("%Y-%m-%d"))
        expansion = expansion.replace("{time}", now.strftime("%H:%M:%S"))
        expansion = expansion.replace("{datetime}", now.strftime("%Y-%m-%d %H:%M:%S"))
        
        return expansion

    def _replace_trigger(self, text: str, rule: ShorthandRule, expansion: str) -> str:
        """Replace trigger with expansion in text"""
        trigger = rule.trigger
        if not rule.case_sensitive:
            # Case-insensitive replacement
            pattern = re.compile(re.escape(trigger), re.IGNORECASE)
            return pattern.sub(expansion, text)
        else:
            # Case-sensitive replacement
            return text.replace(trigger, expansion)

    def suggest_responses(self, context: ResponseContext, 
                         num_suggestions: int = 5) -> List[Tuple[str, float]]:
        """
        Suggest appropriate responses based on context
        
        Args:
            context: Current conversation context
            num_suggestions: Number of suggestions to return
        
        Returns:
            List of (response, confidence_score) tuples
        """
        suggestions = []
        
        # Analyze input for keywords and patterns
        keywords = self._extract_keywords(context.input_text)
        sentiment = self._analyze_sentiment(context.input_text)
        context.sentiment = sentiment
        
        # Score each template
        for template_id, template in self.templates.items():
            score = self._score_template(template, context, keywords)
            if score > 0:
                suggestions.append((template, score))
        
        # Sort by score and return top suggestions
        suggestions.sort(key=lambda x: x[1], reverse=True)
        
        # Format suggestions
        formatted = []
        for template, score in suggestions[:num_suggestions]:
            response = self._format_template(template, context)
            formatted.append((response, score))
        
        return formatted

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract keywords from text"""
        # Simple keyword extraction
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 
                     'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were'}
        words = text.lower().split()
        keywords = [w for w in words if w not in stop_words and len(w) > 2]
        return keywords

    def _analyze_sentiment(self, text: str) -> str:
        """Simple sentiment analysis"""
        positive_words = {'good', 'great', 'excellent', 'happy', 'thanks', 
                         'appreciate', 'wonderful', 'perfect', 'awesome'}
        negative_words = {'bad', 'terrible', 'awful', 'angry', 'upset', 
                         'disappointed', 'frustrated', 'problem', 'issue', 'error'}
        urgent_words = {'urgent', 'asap', 'immediately', 'critical', 'emergency'}
        
        text_lower = text.lower()
        
        if any(word in text_lower for word in urgent_words):
            return "urgent"
        elif any(word in text_lower for word in negative_words):
            return "negative"
        elif any(word in text_lower for word in positive_words):
            return "positive"
        else:
            return "neutral"

    def _score_template(self, template: ResponseTemplate, 
                       context: ResponseContext, 
                       keywords: List[str]) -> float:
        """Score a template based on context match"""
        score = 0.0
        
        # Category match
        if context.metadata.get("category") == template.category:
            score += 0.3
        
        # Keyword match
        template_keywords = template.tags + template.name.lower().split()
        matching_keywords = set(keywords) & set(template_keywords)
        if matching_keywords:
            score += 0.2 * len(matching_keywords)
        
        # Effectiveness score
        score += template.effectiveness_score * 0.2
        
        # Usage frequency (popular templates)
        if template.usage_count > 0:
            score += min(0.1, template.usage_count / 100)
        
        # Sentiment match
        if context.sentiment == "urgent" and "urgent" in template.tags:
            score += 0.3
        elif context.sentiment == "negative" and "support" in template.tags:
            score += 0.2
        
        return min(1.0, score)  # Cap at 1.0

    def _format_template(self, template: ResponseTemplate, 
                        context: ResponseContext) -> str:
        """Format template with context variables"""
        response = template.template
        
        # Replace variables
        for var in template.variables:
            value = context.metadata.get(var, f"[{var}]")
            response = response.replace(f"{{{var}}}", str(value))
        
        return response

    def create_template(self, 
                       name: str,
                       template: str,
                       category: ResponseCategory,
                       variables: List[str] = None,
                       tags: List[str] = None) -> ResponseTemplate:
        """Create a new response template"""
        template_id = hashlib.md5(f"{name}{template}".encode()).hexdigest()[:8]
        
        template_obj = ResponseTemplate(
            template_id=template_id,
            name=name,
            category=category,
            template=template,
            variables=variables or [],
            examples=[],
            tags=tags or [],
            usage_count=0,
            effectiveness_score=0.5
        )
        
        self.templates[template_id] = template_obj
        self._save_template_to_db(template_obj)
        
        return template_obj

    def learn_from_feedback(self, response: str, feedback: int):
        """
        Learn from user feedback on responses
        
        Args:
            response: The generated response
            feedback: Rating (1-5, where 5 is best)
        """
        if not self.learning_enabled:
            return
        
        # Update effectiveness scores
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Find which template/rule was used
        cursor.execute('''
            SELECT trigger_matched FROM response_history 
            WHERE response_generated = ? 
            ORDER BY timestamp DESC LIMIT 1
        ''', (response,))
        
        result = cursor.fetchone()
        if result:
            triggers = json.loads(result[0])
            for trigger in triggers:
                if trigger in self.rules:
                    rule = self.rules[trigger]
                    # Update effectiveness based on feedback
                    old_score = rule.metadata.get("effectiveness", 0.5)
                    new_score = (old_score * 0.8) + (feedback / 5.0 * 0.2)
                    rule.metadata["effectiveness"] = new_score
                    self._update_rule_stats(rule)
        
        # Save learning data
        cursor.execute('''
            INSERT INTO learning_data (timestamp, pattern, response, effectiveness, context)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.datetime.now(), "", response, feedback / 5.0, ""))
        
        conn.commit()
        conn.close()

    def export_rules(self, filename: str = "shorthand_rules.json"):
        """Export all rules to JSON file"""
        export_data = {
            "rules": [asdict(rule) for rule in self.rules.values()],
            "templates": [asdict(template) for template in self.templates.values()],
            "statistics": {
                "total_rules": len(self.rules),
                "total_templates": len(self.templates),
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "avg_response_time": sum(self.response_times) / len(self.response_times) 
                                    if self.response_times else 0
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        return filename

    def import_rules(self, filename: str):
        """Import rules from JSON file"""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        # Import rules
        for rule_data in data.get("rules", []):
            rule = ShorthandRule(
                trigger=rule_data["trigger"],
                expansion=rule_data["expansion"],
                category=ResponseCategory(rule_data["category"]),
                trigger_type=TriggerType(rule_data["trigger_type"]),
                priority=rule_data.get("priority", 5),
                case_sensitive=rule_data.get("case_sensitive", False),
                enabled=rule_data.get("enabled", True),
                variables=rule_data.get("variables", {}),
                conditions=rule_data.get("conditions", {}),
                metadata=rule_data.get("metadata", {})
            )
            self.add_rule(rule)
        
        # Import templates
        for template_data in data.get("templates", []):
            template = ResponseTemplate(
                template_id=template_data["template_id"],
                name=template_data["name"],
                category=ResponseCategory(template_data["category"]),
                template=template_data["template"],
                variables=template_data.get("variables", []),
                examples=template_data.get("examples", []),
                tags=template_data.get("tags", []),
                usage_count=template_data.get("usage_count", 0),
                effectiveness_score=template_data.get("effectiveness_score", 0.5),
                metadata=template_data.get("metadata", {})
            )
            self.templates[template.template_id] = template
            self._save_template_to_db(template)

    def get_statistics(self) -> Dict[str, Any]:
        """Get usage statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get top used rules
        cursor.execute('''
            SELECT trigger, usage_count FROM shorthand_rules 
            ORDER BY usage_count DESC LIMIT 10
        ''')
        top_rules = cursor.fetchall()
        
        # Get response time statistics
        cursor.execute('''
            SELECT AVG(response_time), MIN(response_time), MAX(response_time) 
            FROM response_history
        ''')
        time_stats = cursor.fetchone()
        
        conn.close()
        
        return {
            "total_rules": len(self.rules),
            "total_templates": len(self.templates),
            "categories": dict(Counter(r.category.value for r in self.rules.values())),
            "top_rules": top_rules,
            "cache_performance": {
                "hits": self.cache_hits,
                "misses": self.cache_misses,
                "hit_rate": self.cache_hits / max(1, self.cache_hits + self.cache_misses)
            },
            "response_times": {
                "average": time_stats[0] if time_stats[0] else 0,
                "min": time_stats[1] if time_stats[1] else 0,
                "max": time_stats[2] if time_stats[2] else 0
            }
        }

    def _save_rule_to_db(self, rule: ShorthandRule):
        """Save rule to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO shorthand_rules 
            (trigger, expansion, category, trigger_type, priority, case_sensitive,
             enabled, usage_count, last_used, variables, conditions, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule.trigger,
            rule.expansion,
            rule.category.value,
            rule.trigger_type.value,
            rule.priority,
            int(rule.case_sensitive),
            int(rule.enabled),
            rule.usage_count,
            rule.last_used,
            json.dumps(rule.variables),
            json.dumps(rule.conditions),
            json.dumps(rule.metadata)
        ))
        
        conn.commit()
        conn.close()

    def _save_template_to_db(self, template: ResponseTemplate):
        """Save template to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO templates 
            (template_id, name, category, template, variables, examples,
             tags, usage_count, effectiveness_score, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            template.template_id,
            template.name,
            template.category.value,
            template.template,
            json.dumps(template.variables),
            json.dumps(template.examples),
            json.dumps(template.tags),
            template.usage_count,
            template.effectiveness_score,
            json.dumps(template.metadata)
        ))
        
        conn.commit()
        conn.close()

    def _update_rule_stats(self, rule: ShorthandRule):
        """Update rule statistics in database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE shorthand_rules 
            SET usage_count = ?, last_used = ?, metadata = ?
            WHERE trigger = ?
        ''', (rule.usage_count, rule.last_used, 
              json.dumps(rule.metadata), rule.trigger))
        
        conn.commit()
        conn.close()

    def _save_to_history(self, input_text: str, triggers: List[str], 
                        response: str, context: Optional[ResponseContext], 
                        response_time: float):
        """Save expansion to history"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO response_history 
            (timestamp, input_text, trigger_matched, response_generated, 
             context, response_time, user_feedback)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now(),
            input_text,
            json.dumps(triggers),
            response,
            json.dumps(asdict(context)) if context else "{}",
            response_time,
            0
        ))
        
        conn.commit()
        conn.close()

    def _delete_rule_from_db(self, trigger: str):
        """Delete rule from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM shorthand_rules WHERE trigger = ?", (trigger,))
        conn.commit()
        conn.close()

    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                # Apply configuration settings
                self.learning_enabled = config.get("learning_enabled", True)
                # Load any custom rules from config
                for rule_data in config.get("custom_rules", []):
                    self.add_rule(ShorthandRule(**rule_data))


class AutoResponder:
    """Automated response system using shorthand engine"""
    
    def __init__(self, engine: ShorthandEngine):
        self.engine = engine
        self.response_queue = queue.Queue()
        self.is_running = False
    
    def generate_response(self, 
                         input_text: str,
                         context: Optional[ResponseContext] = None) -> str:
        """Generate an appropriate response"""
        # First try to expand any shorthand
        expanded = self.engine.expand(input_text, context)
        
        # If no expansion occurred, suggest responses
        if expanded == input_text:
            if not context:
                context = ResponseContext(input_text=input_text)
            
            suggestions = self.engine.suggest_responses(context, num_suggestions=1)
            if suggestions:
                return suggestions[0][0]
        
        return expanded
    
    def batch_process(self, messages: List[str]) -> List[str]:
        """Process multiple messages in batch"""
        responses = []
        for message in messages:
            context = ResponseContext(input_text=message)
            response = self.generate_response(message, context)
            responses.append(response)
        return responses


# Convenience functions
def quick_expand(text: str) -> str:
    """Quick function to expand shorthand text"""
    engine = ShorthandEngine()
    return engine.expand(text)


def create_custom_rule(trigger: str, expansion: str, category: str = "CUSTOM"):
    """Create a custom shorthand rule"""
    engine = ShorthandEngine()
    rule = ShorthandRule(
        trigger=trigger,
        expansion=expansion,
        category=ResponseCategory[category.upper()],
        trigger_type=TriggerType.EXACT
    )
    engine.add_rule(rule)
    return rule


# Example usage and testing
if __name__ == "__main__":
    print("="*60)
    print("SHORTHAND AUTO-RESPONSE SYSTEM")
    print("="*60)
    
    # Initialize engine
    engine = ShorthandEngine()
    responder = AutoResponder(engine)
    
    # Test basic expansions
    print("\n[1] Testing Basic Expansions:")
    test_texts = [
        "gm everyone!",
        "ty for your help",
        "Please respond asap",
        "Meeting at eod",
        "brb in 5 minutes"
    ]
    
    for text in test_texts:
        expanded = engine.expand(text)
        print(f"  '{text}' -> '{expanded}'")
    
    # Test custom rules
    print("\n[2] Adding Custom Rules:")
    engine.add_rule(ShorthandRule(
        "sig",
        "\n\nBest regards,\nJohn Doe\nSenior Developer\nTech Corp",
        ResponseCategory.EMAIL,
        TriggerType.EXACT
    ))
    
    engine.add_rule(ShorthandRule(
        "sqlq",
        "SELECT * FROM table_name WHERE condition;",
        ResponseCategory.CODE,
        TriggerType.EXACT
    ))
    
    test = "Please check the database. sqlq sig"
    expanded = engine.expand(test)
    print(f"  '{test}'")
    print(f"  Expanded to:\n{expanded}")
    
    # Test context-aware suggestions
    print("\n[3] Testing Context-Aware Suggestions:")
    contexts = [
        ResponseContext(input_text="The server is down!", urgency=9),
        ResponseContext(input_text="Can you help me with this?", sentiment="positive"),
        ResponseContext(input_text="Great job on the project!", sentiment="positive")
    ]
    
    # Create some templates
    engine.create_template(
        "urgent_response",
        "I'm investigating this issue immediately. I'll update you within {time_frame}.",
        ResponseCategory.EMERGENCY,
        variables=["time_frame"],
        tags=["urgent", "incident"]
    )
    
    engine.create_template(
        "help_response",
        "I'd be happy to help! Can you provide more details about {topic}?",
        ResponseCategory.SUPPORT,
        variables=["topic"],
        tags=["help", "support"]
    )
    
    for context in contexts:
        context.metadata = {"time_frame": "15 minutes", "topic": "the issue"}
        suggestions = engine.suggest_responses(context, num_suggestions=1)
        if suggestions:
            print(f"\n  Input: '{context.input_text}'")
            print(f"  Suggested: '{suggestions[0][0]}'")
            print(f"  Confidence: {suggestions[0][1]:.2f}")
    
    # Test statistics
    print("\n[4] Usage Statistics:")
    stats = engine.get_statistics()
    print(f"  Total rules: {stats['total_rules']}")
    print(f"  Total templates: {stats['total_templates']}")
    print(f"  Categories: {stats['categories']}")
    print(f"  Cache hit rate: {stats['cache_performance']['hit_rate']:.2%}")
    
    # Export rules
    print("\n[5] Exporting Rules:")
    export_file = engine.export_rules("my_shorthand_rules.json")
    print(f"  Rules exported to: {export_file}")
    
    print("\n" + "="*60)
    print("System ready for use!")
    print("="*60)