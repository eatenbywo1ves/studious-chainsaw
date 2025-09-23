"""
Enhanced Role-Based Access Control (RBAC) System

Enterprise-grade RBAC with:
- Fine-grained permissions and roles
- Resource-based access control
- Dynamic policy evaluation
- Attribute-based access control (ABAC)
- Role inheritance and delegation
- Audit trails for access decisions
"""

import fnmatch
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class PermissionType(Enum):
    """Permission types"""

    ALLOW = "allow"
    DENY = "deny"


class ResourceType(Enum):
    """Resource types in the system"""

    AGENT = "agent"
    TASK = "task"
    TENANT = "tenant"
    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    SYSTEM = "system"
    API_ENDPOINT = "api_endpoint"
    DATA = "data"


class Action(Enum):
    """Standard actions"""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    MANAGE = "manage"
    VIEW = "view"
    EDIT = "edit"
    APPROVE = "approve"
    ASSIGN = "assign"
    CONFIGURE = "configure"


@dataclass
class Permission:
    """Individual permission definition"""

    permission_id: str
    name: str
    description: str
    resource_type: ResourceType
    action: Action
    conditions: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def matches_request(self, resource_type: ResourceType, action: Action) -> bool:
        """Check if permission matches the requested access"""
        return self.resource_type == resource_type and self.action == action

    def to_dict(self) -> Dict[str, Any]:
        return {
            "permission_id": self.permission_id,
            "name": self.name,
            "description": self.description,
            "resource_type": self.resource_type.value,
            "action": self.action.value,
            "conditions": self.conditions,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class Role:
    """Role definition with permissions"""

    role_id: str
    name: str
    description: str
    permissions: Set[str] = field(default_factory=set)
    parent_roles: Set[str] = field(default_factory=set)
    is_system_role: bool = False
    tenant_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def add_permission(self, permission_id: str):
        """Add permission to role"""
        self.permissions.add(permission_id)
        self.updated_at = datetime.utcnow()

    def remove_permission(self, permission_id: str):
        """Remove permission from role"""
        self.permissions.discard(permission_id)
        self.updated_at = datetime.utcnow()

    def add_parent_role(self, parent_role_id: str):
        """Add parent role for inheritance"""
        self.parent_roles.add(parent_role_id)
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role_id": self.role_id,
            "name": self.name,
            "description": self.description,
            "permissions": list(self.permissions),
            "parent_roles": list(self.parent_roles),
            "is_system_role": self.is_system_role,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class AccessPolicy:
    """Access control policy"""

    policy_id: str
    name: str
    description: str
    resource_pattern: str  # e.g., "agent:*", "task:tenant-123:*"
    action_patterns: List[str]  # e.g., ["read", "update"]
    effect: PermissionType = PermissionType.ALLOW
    conditions: List[str] = field(default_factory=list)
    priority: int = 100
    tenant_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def matches_resource(self, resource_id: str) -> bool:
        """Check if policy applies to resource"""
        return fnmatch.fnmatch(resource_id, self.resource_pattern)

    def matches_action(self, action: str) -> bool:
        """Check if policy applies to action"""
        return any(fnmatch.fnmatch(action, pattern) for pattern in self.action_patterns)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "resource_pattern": self.resource_pattern,
            "action_patterns": self.action_patterns,
            "effect": self.effect.value,
            "conditions": self.conditions,
            "priority": self.priority,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class UserRole:
    """User role assignment"""

    assignment_id: str
    user_id: str
    role_id: str
    tenant_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    assigned_by: Optional[str] = None
    assigned_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and datetime.utcnow() > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "user_id": self.user_id,
            "role_id": self.role_id,
            "tenant_id": self.tenant_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "assigned_by": self.assigned_by,
            "assigned_at": self.assigned_at.isoformat(),
        }


@dataclass
class AccessRequest:
    """Access request for policy evaluation"""

    user_id: str
    resource_type: ResourceType
    resource_id: str
    action: Action
    tenant_id: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AccessDecision:
    """Result of access control evaluation"""

    allowed: bool
    reason: str
    matched_policies: List[str] = field(default_factory=list)
    matched_permissions: List[str] = field(default_factory=list)
    evaluation_time_ms: float = 0
    context: Dict[str, Any] = field(default_factory=dict)


class ConditionEvaluator:
    """Evaluates policy conditions"""

    def __init__(self):
        self.functions = {
            "time_between": self._time_between,
            "day_of_week": self._day_of_week,
            "ip_in_range": self._ip_in_range,
            "attribute_equals": self._attribute_equals,
            "attribute_in": self._attribute_in,
            "resource_owner": self._resource_owner,
            "tenant_member": self._tenant_member,
        }

    def evaluate(self, conditions: List[str], context: Dict[str, Any]) -> bool:
        """Evaluate all conditions (AND logic)"""
        if not conditions:
            return True

        for condition in conditions:
            if not self._evaluate_single_condition(condition, context):
                return False

        return True

    def _evaluate_single_condition(
        self, condition: str, context: Dict[str, Any]
    ) -> bool:
        """Evaluate a single condition"""
        try:
            # Parse condition: function(arg1, arg2, ...)
            if "(" not in condition:
                return True

            func_name = condition.split("(")[0]
            args_str = condition.split("(")[1].rstrip(")")
            args = [arg.strip().strip("\"'") for arg in args_str.split(",")]

            if func_name in self.functions:
                return self.functions[func_name](args, context)

            return True  # Unknown condition defaults to true
        except Exception:
            return False  # Invalid condition defaults to false

    def _time_between(self, args: List[str], context: Dict[str, Any]) -> bool:
        """Check if current time is between start and end times"""
        if len(args) < 2:
            return False

        start_time = args[0]  # Format: "09:00"
        end_time = args[1]  # Format: "17:00"

        now = datetime.now().time()
        start = datetime.strptime(start_time, "%H:%M").time()
        end = datetime.strptime(end_time, "%H:%M").time()

        if start <= end:
            return start <= now <= end
        else:  # Spans midnight
            return now >= start or now <= end

    def _day_of_week(self, args: List[str], context: Dict[str, Any]) -> bool:
        """Check if current day is in allowed days"""
        if not args:
            return False

        allowed_days = [day.lower() for day in args]
        current_day = datetime.now().strftime("%A").lower()

        return current_day in allowed_days

    def _ip_in_range(self, args: List[str], context: Dict[str, Any]) -> bool:
        """Check if client IP is in allowed range"""
        if not args or "client_ip" not in context:
            return False

        # Simplified IP range check
        allowed_range = args[0]
        client_ip = context["client_ip"]

        # This would need proper CIDR implementation
        return client_ip.startswith(allowed_range.split("/")[0])

    def _attribute_equals(self, args: List[str], context: Dict[str, Any]) -> bool:
        """Check if attribute equals value"""
        if len(args) < 2:
            return False

        attribute_name = args[0]
        expected_value = args[1]

        return context.get(attribute_name) == expected_value

    def _attribute_in(self, args: List[str], context: Dict[str, Any]) -> bool:
        """Check if attribute value is in list"""
        if len(args) < 2:
            return False

        attribute_name = args[0]
        allowed_values = args[1:]

        return context.get(attribute_name) in allowed_values

    def _resource_owner(self, args: List[str], context: Dict[str, Any]) -> bool:
        """Check if user is resource owner"""
        user_id = context.get("user_id")
        resource_owner = context.get("resource_owner")

        return user_id == resource_owner

    def _tenant_member(self, args: List[str], context: Dict[str, Any]) -> bool:
        """Check if user is member of tenant"""
        user_tenant = context.get("user_tenant_id")
        resource_tenant = context.get("resource_tenant_id")

        return user_tenant == resource_tenant


class RBACManager:
    """
    Complete RBAC management system with fine-grained access control
    """

    def __init__(self):
        # Storage (in production, use database)
        self.permissions: Dict[str, Permission] = {}
        self.roles: Dict[str, Role] = {}
        self.policies: Dict[str, AccessPolicy] = {}
        self.user_roles: Dict[str, List[UserRole]] = {}  # user_id -> roles

        # Caches
        self.role_permission_cache: Dict[str, Set[str]] = {}
        self.user_permission_cache: Dict[str, Set[str]] = {}

        # Components
        self.condition_evaluator = ConditionEvaluator()

        # Initialize system permissions and roles
        self._initialize_system_rbac()

    def _initialize_system_rbac(self):
        """Initialize system permissions and roles"""
        # System permissions
        system_permissions = [
            (
                "system_admin",
                "System Administration",
                ResourceType.SYSTEM,
                Action.MANAGE,
            ),
            ("user_create", "Create Users", ResourceType.USER, Action.CREATE),
            ("user_read", "Read Users", ResourceType.USER, Action.READ),
            ("user_update", "Update Users", ResourceType.USER, Action.UPDATE),
            ("user_delete", "Delete Users", ResourceType.USER, Action.DELETE),
            ("agent_create", "Create Agents", ResourceType.AGENT, Action.CREATE),
            ("agent_read", "Read Agents", ResourceType.AGENT, Action.READ),
            ("agent_update", "Update Agents", ResourceType.AGENT, Action.UPDATE),
            ("agent_delete", "Delete Agents", ResourceType.AGENT, Action.DELETE),
            ("agent_execute", "Execute Agents", ResourceType.AGENT, Action.EXECUTE),
            ("task_create", "Create Tasks", ResourceType.TASK, Action.CREATE),
            ("task_read", "Read Tasks", ResourceType.TASK, Action.READ),
            ("task_update", "Update Tasks", ResourceType.TASK, Action.UPDATE),
            ("task_delete", "Delete Tasks", ResourceType.TASK, Action.DELETE),
            ("task_assign", "Assign Tasks", ResourceType.TASK, Action.ASSIGN),
        ]

        for perm_id, name, resource_type, action in system_permissions:
            permission = Permission(
                permission_id=perm_id,
                name=name,
                description=f"{name} permission",
                resource_type=resource_type,
                action=action,
            )
            self.permissions[perm_id] = permission

        # System roles
        # Super Admin
        super_admin = Role(
            role_id="super_admin",
            name="Super Administrator",
            description="Full system access",
            is_system_role=True,
        )
        for perm_id in self.permissions.keys():
            super_admin.add_permission(perm_id)
        self.roles["super_admin"] = super_admin

        # Tenant Admin
        tenant_admin = Role(
            role_id="tenant_admin",
            name="Tenant Administrator",
            description="Full tenant access",
            is_system_role=True,
        )
        tenant_perms = [
            "user_create",
            "user_read",
            "user_update",
            "user_delete",
            "agent_create",
            "agent_read",
            "agent_update",
            "agent_delete",
            "agent_execute",
            "task_create",
            "task_read",
            "task_update",
            "task_delete",
            "task_assign",
        ]
        for perm_id in tenant_perms:
            tenant_admin.add_permission(perm_id)
        self.roles["tenant_admin"] = tenant_admin

        # Agent Operator
        agent_operator = Role(
            role_id="agent_operator",
            name="Agent Operator",
            description="Operate agents and tasks",
            is_system_role=True,
        )
        operator_perms = [
            "agent_read",
            "agent_execute",
            "task_create",
            "task_read",
            "task_assign",
        ]
        for perm_id in operator_perms:
            agent_operator.add_permission(perm_id)
        self.roles["agent_operator"] = agent_operator

        # Viewer
        viewer = Role(
            role_id="viewer",
            name="Viewer",
            description="Read-only access",
            is_system_role=True,
        )
        viewer_perms = ["user_read", "agent_read", "task_read"]
        for perm_id in viewer_perms:
            viewer.add_permission(perm_id)
        self.roles["viewer"] = viewer

    # Permission Management
    async def create_permission(
        self,
        name: str,
        description: str,
        resource_type: ResourceType,
        action: Action,
        conditions: List[str] = None,
    ) -> Permission:
        """Create new permission"""
        permission_id = str(uuid.uuid4())

        permission = Permission(
            permission_id=permission_id,
            name=name,
            description=description,
            resource_type=resource_type,
            action=action,
            conditions=conditions or [],
        )

        self.permissions[permission_id] = permission
        self._invalidate_caches()

        return permission

    def get_permission(self, permission_id: str) -> Optional[Permission]:
        """Get permission by ID"""
        return self.permissions.get(permission_id)

    def list_permissions(
        self, resource_type: Optional[ResourceType] = None
    ) -> List[Permission]:
        """List all permissions, optionally filtered by resource type"""
        permissions = list(self.permissions.values())

        if resource_type:
            permissions = [p for p in permissions if p.resource_type == resource_type]

        return permissions

    # Role Management
    async def create_role(
        self, name: str, description: str, tenant_id: Optional[str] = None
    ) -> Role:
        """Create new role"""
        role_id = str(uuid.uuid4())

        role = Role(
            role_id=role_id, name=name, description=description, tenant_id=tenant_id
        )

        self.roles[role_id] = role
        self._invalidate_caches()

        return role

    def get_role(self, role_id: str) -> Optional[Role]:
        """Get role by ID"""
        return self.roles.get(role_id)

    def list_roles(self, tenant_id: Optional[str] = None) -> List[Role]:
        """List all roles, optionally filtered by tenant"""
        roles = list(self.roles.values())

        if tenant_id is not None:
            roles = [r for r in roles if r.tenant_id == tenant_id or r.is_system_role]

        return roles

    async def add_permission_to_role(self, role_id: str, permission_id: str) -> bool:
        """Add permission to role"""
        role = self.get_role(role_id)
        permission = self.get_permission(permission_id)

        if not role or not permission:
            return False

        role.add_permission(permission_id)
        self._invalidate_role_cache(role_id)

        return True

    async def remove_permission_from_role(
        self, role_id: str, permission_id: str
    ) -> bool:
        """Remove permission from role"""
        role = self.get_role(role_id)

        if not role:
            return False

        role.remove_permission(permission_id)
        self._invalidate_role_cache(role_id)

        return True

    # User Role Assignment
    async def assign_role_to_user(
        self,
        user_id: str,
        role_id: str,
        tenant_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        assigned_by: Optional[str] = None,
    ) -> bool:
        """Assign role to user"""
        role = self.get_role(role_id)
        if not role:
            return False

        assignment_id = str(uuid.uuid4())
        user_role = UserRole(
            assignment_id=assignment_id,
            user_id=user_id,
            role_id=role_id,
            tenant_id=tenant_id,
            expires_at=expires_at,
            assigned_by=assigned_by,
        )

        if user_id not in self.user_roles:
            self.user_roles[user_id] = []

        self.user_roles[user_id].append(user_role)
        self._invalidate_user_cache(user_id)

        return True

    async def remove_role_from_user(
        self, user_id: str, role_id: str, tenant_id: Optional[str] = None
    ) -> bool:
        """Remove role from user"""
        if user_id not in self.user_roles:
            return False

        user_role_assignments = self.user_roles[user_id]

        # Find matching assignment
        for i, assignment in enumerate(user_role_assignments):
            if assignment.role_id == role_id and (
                tenant_id is None or assignment.tenant_id == tenant_id
            ):
                del user_role_assignments[i]
                self._invalidate_user_cache(user_id)
                return True

        return False

    def get_user_roles(
        self, user_id: str, tenant_id: Optional[str] = None
    ) -> List[UserRole]:
        """Get all roles assigned to user"""
        if user_id not in self.user_roles:
            return []

        assignments = self.user_roles[user_id]

        # Filter by tenant and remove expired assignments
        valid_assignments = []
        for assignment in assignments:
            if assignment.is_expired:
                continue

            if tenant_id is not None and assignment.tenant_id != tenant_id:
                # Allow system roles across tenants
                role = self.get_role(assignment.role_id)
                if not role or not role.is_system_role:
                    continue

            valid_assignments.append(assignment)

        return valid_assignments

    # Policy Management
    async def create_policy(
        self,
        name: str,
        description: str,
        resource_pattern: str,
        action_patterns: List[str],
        effect: PermissionType = PermissionType.ALLOW,
        conditions: List[str] = None,
        priority: int = 100,
        tenant_id: Optional[str] = None,
    ) -> AccessPolicy:
        """Create access policy"""
        policy_id = str(uuid.uuid4())

        policy = AccessPolicy(
            policy_id=policy_id,
            name=name,
            description=description,
            resource_pattern=resource_pattern,
            action_patterns=action_patterns,
            effect=effect,
            conditions=conditions or [],
            priority=priority,
            tenant_id=tenant_id,
        )

        self.policies[policy_id] = policy
        return policy

    def get_policy(self, policy_id: str) -> Optional[AccessPolicy]:
        """Get policy by ID"""
        return self.policies.get(policy_id)

    def list_policies(self, tenant_id: Optional[str] = None) -> List[AccessPolicy]:
        """List all policies"""
        policies = list(self.policies.values())

        if tenant_id is not None:
            policies = [
                p for p in policies if p.tenant_id == tenant_id or p.tenant_id is None
            ]

        # Sort by priority (higher priority first)
        return sorted(policies, key=lambda p: p.priority, reverse=True)

    # Access Control
    async def check_access(
        self,
        user_id: str,
        resource_type: ResourceType,
        resource_id: str,
        action: Action,
        tenant_id: Optional[str] = None,
        context: Dict[str, Any] = None,
    ) -> AccessDecision:
        """Check if user has access to resource"""
        start_time = datetime.utcnow()

        request = AccessRequest(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            tenant_id=tenant_id,
            context=context or {},
        )

        # Add user context
        request.context.update(
            {
                "user_id": user_id,
                "resource_tenant_id": tenant_id,
                "timestamp": start_time.isoformat(),
            }
        )

        decision = await self._evaluate_access(request)

        # Calculate evaluation time
        end_time = datetime.utcnow()
        decision.evaluation_time_ms = (end_time - start_time).total_seconds() * 1000

        return decision

    async def _evaluate_access(self, request: AccessRequest) -> AccessDecision:
        """Evaluate access request"""
        matched_policies = []
        matched_permissions = []

        # 1. Check explicit policies first
        policies = self.list_policies(request.tenant_id)
        for policy in policies:
            if policy.matches_resource(request.resource_id) and policy.matches_action(
                request.action.value
            ):

                # Check conditions
                if self.condition_evaluator.evaluate(
                    policy.conditions, request.context
                ):
                    matched_policies.append(policy.policy_id)

                    if policy.effect == PermissionType.DENY:
                        return AccessDecision(
                            allowed=False,
                            reason=f"Explicitly denied by policy: {policy.name}",
                            matched_policies=matched_policies,
                        )
                    elif policy.effect == PermissionType.ALLOW:
                        return AccessDecision(
                            allowed=True,
                            reason=f"Explicitly allowed by policy: {policy.name}",
                            matched_policies=matched_policies,
                        )

        # 2. Check role-based permissions
        user_permissions = self._get_user_permissions(
            request.user_id, request.tenant_id
        )

        for perm_id in user_permissions:
            permission = self.get_permission(perm_id)
            if permission and permission.matches_request(
                request.resource_type, request.action
            ):
                matched_permissions.append(perm_id)

                # Check permission conditions
                if self.condition_evaluator.evaluate(
                    permission.conditions, request.context
                ):
                    return AccessDecision(
                        allowed=True,
                        reason=f"Allowed by permission: {permission.name}",
                        matched_permissions=matched_permissions,
                    )

        # 3. Default deny
        return AccessDecision(
            allowed=False,
            reason="No matching permissions or policies found",
            matched_policies=matched_policies,
            matched_permissions=matched_permissions,
        )

    def _get_user_permissions(
        self, user_id: str, tenant_id: Optional[str] = None
    ) -> Set[str]:
        """Get all permissions for user (with caching)"""
        cache_key = f"{user_id}:{tenant_id}"

        if cache_key in self.user_permission_cache:
            return self.user_permission_cache[cache_key]

        permissions = set()
        user_role_assignments = self.get_user_roles(user_id, tenant_id)

        for assignment in user_role_assignments:
            role_permissions = self._get_role_permissions(assignment.role_id)
            permissions.update(role_permissions)

        self.user_permission_cache[cache_key] = permissions
        return permissions

    def _get_role_permissions(self, role_id: str) -> Set[str]:
        """Get all permissions for role including inherited (with caching)"""
        if role_id in self.role_permission_cache:
            return self.role_permission_cache[role_id]

        permissions = set()
        visited = set()

        def collect_permissions(current_role_id: str):
            if current_role_id in visited:
                return  # Prevent infinite recursion

            visited.add(current_role_id)
            role = self.get_role(current_role_id)

            if role:
                permissions.update(role.permissions)

                # Collect permissions from parent roles
                for parent_role_id in role.parent_roles:
                    collect_permissions(parent_role_id)

        collect_permissions(role_id)

        self.role_permission_cache[role_id] = permissions
        return permissions

    def _invalidate_caches(self):
        """Invalidate all caches"""
        self.role_permission_cache.clear()
        self.user_permission_cache.clear()

    def _invalidate_role_cache(self, role_id: str):
        """Invalidate caches related to specific role"""
        if role_id in self.role_permission_cache:
            del self.role_permission_cache[role_id]

        # Also invalidate user caches that might be affected
        self.user_permission_cache.clear()

    def _invalidate_user_cache(self, user_id: str):
        """Invalidate caches related to specific user"""
        keys_to_remove = [
            key
            for key in self.user_permission_cache.keys()
            if key.startswith(f"{user_id}:")
        ]

        for key in keys_to_remove:
            del self.user_permission_cache[key]

    # Utility methods
    async def bulk_check_access(
        self, requests: List[Tuple[str, ResourceType, str, Action, Optional[str]]]
    ) -> List[AccessDecision]:
        """Check access for multiple requests efficiently"""
        decisions = []

        for user_id, resource_type, resource_id, action, tenant_id in requests:
            decision = await self.check_access(
                user_id, resource_type, resource_id, action, tenant_id
            )
            decisions.append(decision)

        return decisions

    def get_user_accessible_resources(
        self,
        user_id: str,
        resource_type: ResourceType,
        action: Action,
        tenant_id: Optional[str] = None,
    ) -> List[str]:
        """Get list of resource IDs user can access (simplified implementation)"""
        # This would typically query the database for resources and check each one
        # For now, return empty list as this requires resource enumeration
        return []

    def get_rbac_stats(self) -> Dict[str, Any]:
        """Get RBAC system statistics"""
        total_users_with_roles = len(self.user_roles)
        total_role_assignments = sum(
            len(assignments) for assignments in self.user_roles.values()
        )

        return {
            "total_permissions": len(self.permissions),
            "total_roles": len(self.roles),
            "total_policies": len(self.policies),
            "total_users_with_roles": total_users_with_roles,
            "total_role_assignments": total_role_assignments,
            "cache_stats": {
                "role_permission_cache_size": len(self.role_permission_cache),
                "user_permission_cache_size": len(self.user_permission_cache),
            },
        }

    async def audit_user_access(
        self, user_id: str, tenant_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate audit report for user access"""
        user_roles = self.get_user_roles(user_id, tenant_id)
        user_permissions = self._get_user_permissions(user_id, tenant_id)

        return {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "roles": [assignment.to_dict() for assignment in user_roles],
            "effective_permissions": [
                self.get_permission(perm_id).to_dict()
                for perm_id in user_permissions
                if perm_id in self.permissions
            ],
            "audit_timestamp": datetime.utcnow().isoformat(),
        }
