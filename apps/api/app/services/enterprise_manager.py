"""Enterprise features for multi-tenancy, RBAC, audit logging, and SLA tracking."""

from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from app.models.enterprise import (
    AuditLog,
    ExternalIntegration,
    FeatureFlag,
    Permission,
    Role,
    SLAMetric,
    SLAPolicy,
    SLAReport,
    Tenant,
    TenantUsage,
    User,
)


class TenantManager:
    """Manages multi-tenant operations."""

    _tenants: dict[str, Tenant] = {}
    _users: dict[str, User] = {}

    @staticmethod
    def create_tenant(
        name: str,
        owner_id: str,
        subscription_tier: str = "pro",
        max_users: int = 10,
        max_traces_per_month: int = 100000,
    ) -> Tenant:
        """Create a new tenant.

        Args:
            name: Tenant organization name
            owner_id: User ID of tenant owner
            subscription_tier: "free", "pro", "enterprise"
            max_users: Maximum users allowed
            max_traces_per_month: Trace processing limit

        Returns:
            Created Tenant
        """
        tenant_id = f"tenant_{uuid4().hex[:12]}"

        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            owner_id=owner_id,
            subscription_tier=subscription_tier,
            max_users=max_users,
            max_traces_per_month=max_traces_per_month,
            features_enabled=_get_tier_features(subscription_tier),
            status="active",
            created_at=datetime.utcnow().isoformat(),
        )

        TenantManager._tenants[tenant_id] = tenant
        return tenant

    @staticmethod
    def get_tenant(tenant_id: str) -> Tenant | None:
        """Get tenant by ID."""
        return TenantManager._tenants.get(tenant_id)

    @staticmethod
    def list_tenants() -> list[Tenant]:
        """List all tenants."""
        return list(TenantManager._tenants.values())

    @staticmethod
    def update_tenant_status(tenant_id: str, status: str) -> Tenant | None:
        """Update tenant status."""
        tenant = TenantManager._tenants.get(tenant_id)
        if tenant:
            tenant.status = status
        return tenant

    @staticmethod
    def add_user_to_tenant(
        tenant_id: str, username: str, email: str, roles: list[str] | None = None
    ) -> User | None:
        """Add user to tenant."""
        tenant = TenantManager._tenants.get(tenant_id)
        if not tenant:
            return None

        user_id = f"user_{uuid4().hex[:12]}"
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            tenant_id=tenant_id,
            roles=roles or ["viewer"],
            created_at=datetime.utcnow().isoformat(),
        )

        TenantManager._users[user_id] = user
        return user

    @staticmethod
    def get_tenant_users(tenant_id: str) -> list[User]:
        """Get all users in a tenant."""
        return [u for u in TenantManager._users.values() if u.tenant_id == tenant_id]

    @staticmethod
    def get_user(user_id: str) -> User | None:
        """Get user by ID."""
        return TenantManager._users.get(user_id)

    @staticmethod
    def update_user_roles(user_id: str, roles: list[str]) -> User | None:
        """Update user roles."""
        user = TenantManager._users.get(user_id)
        if user:
            user.roles = roles
        return user

    @staticmethod
    def clear_all() -> None:
        """Clear all tenants and users (for testing)."""
        TenantManager._tenants.clear()
        TenantManager._users.clear()


class RBACManager:
    """Manages role-based access control."""

    _roles: dict[str, Role] = {}
    _permissions: dict[str, Permission] = {}

    # Define default permissions (keyed by permission_id)
    _default_permissions = {
        "perm_read_traces": Permission(
            permission_id="perm_read_traces",
            name="read_traces",
            resource="traces",
            action="read",
            description="Read trace data",
        ),
        "perm_create_rules": Permission(
            permission_id="perm_create_rules",
            name="create_rules",
            resource="rules",
            action="create",
            description="Create alert rules",
        ),
        "perm_modify_rules": Permission(
            permission_id="perm_modify_rules",
            name="modify_rules",
            resource="rules",
            action="update",
            description="Modify alert rules",
        ),
        "perm_manage_users": Permission(
            permission_id="perm_manage_users",
            name="manage_users",
            resource="users",
            action="update",
            description="Manage tenant users",
        ),
        "perm_view_dashboards": Permission(
            permission_id="perm_view_dashboards",
            name="view_dashboards",
            resource="dashboards",
            action="read",
            description="View dashboards",
        ),
        "perm_admin_access": Permission(
            permission_id="perm_admin_access",
            name="admin_access",
            resource="*",
            action="*",
            description="Full administrative access",
        ),
    }

    @staticmethod
    def initialize_default_permissions() -> None:
        """Initialize default permissions."""
        for perm_id, perm in RBACManager._default_permissions.items():
            RBACManager._permissions[perm_id] = perm

    @staticmethod
    def create_role(
        name: str, permissions: list[str], tenant_id: str | None = None, description: str | None = None
    ) -> Role:
        """Create a new role.

        Args:
            name: Role name
            permissions: List of permission IDs
            tenant_id: Tenant ID (None = global role)
            description: Role description

        Returns:
            Created Role
        """
        role_id = f"role_{uuid4().hex[:12]}"

        role = Role(
            role_id=role_id,
            name=name,
            permissions=permissions,
            tenant_id=tenant_id,
            description=description,
            created_at=datetime.utcnow().isoformat(),
            created_by="system",
        )

        RBACManager._roles[role_id] = role
        return role

    @staticmethod
    def get_role(role_id: str) -> Role | None:
        """Get role by ID."""
        return RBACManager._roles.get(role_id)

    @staticmethod
    def list_roles(tenant_id: str | None = None) -> list[Role]:
        """List roles (global or tenant-specific)."""
        roles = RBACManager._roles.values()
        if tenant_id:
            return [r for r in roles if r.tenant_id == tenant_id or r.tenant_id is None]
        return list(roles)

    @staticmethod
    def get_user_permissions(user_id: str) -> list[Permission]:
        """Get all permissions for a user based on roles."""
        user = TenantManager.get_user(user_id)
        if not user:
            return []

        permissions = set()
        for role_id in user.roles:
            role = RBACManager.get_role(role_id)
            if role:
                for perm_id in role.permissions:
                    perm = RBACManager._permissions.get(perm_id)
                    if perm:
                        permissions.add(perm_id)

        return [RBACManager._permissions[pid] for pid in permissions]

    @staticmethod
    def has_permission(user_id: str, permission_id: str) -> bool:
        """Check if user has permission."""
        permissions = RBACManager.get_user_permissions(user_id)
        return any(p.permission_id == permission_id for p in permissions)

    @staticmethod
    def has_resource_action(user_id: str, resource: str, action: str) -> bool:
        """Check if user can perform action on resource."""
        permissions = RBACManager.get_user_permissions(user_id)
        return any(
            (p.resource == resource or p.resource == "*")
            and (p.action == action or p.action == "*")
            for p in permissions
        )

    @staticmethod
    def clear_all() -> None:
        """Clear all roles and permissions."""
        RBACManager._roles.clear()
        RBACManager._permissions.clear()


class AuditLogger:
    """Manages audit trail logging."""

    _logs: list[AuditLog] = []

    @staticmethod
    def log_action(
        tenant_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        changes: dict[str, Any] | None = None,
        user_id: str | None = None,
        ip_address: str | None = None,
        success: bool = True,
        error_message: str | None = None,
    ) -> AuditLog:
        """Log an action to audit trail.

        Args:
            tenant_id: Tenant ID
            action: Action performed (e.g., "create_rule", "modify_user")
            resource_type: Type of resource affected
            resource_id: ID of resource affected
            changes: Dictionary of changes {field: {old: value, new: value}}
            user_id: User ID performing action
            ip_address: Client IP address
            success: Whether action succeeded
            error_message: Error message if failed

        Returns:
            Created AuditLog entry
        """
        audit_id = f"audit_{uuid4().hex[:12]}"

        log = AuditLog(
            audit_id=audit_id,
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            changes=changes or {},
            ip_address=ip_address,
            success=success,
            error_message=error_message,
            timestamp=datetime.utcnow().isoformat(),
        )

        AuditLogger._logs.append(log)
        return log

    @staticmethod
    def get_logs(tenant_id: str, limit: int = 100) -> list[AuditLog]:
        """Get audit logs for a tenant."""
        logs = [l for l in AuditLogger._logs if l.tenant_id == tenant_id]
        return sorted(logs, key=lambda l: l.timestamp, reverse=True)[:limit]

    @staticmethod
    def get_user_logs(tenant_id: str, user_id: str, limit: int = 50) -> list[AuditLog]:
        """Get audit logs for a specific user."""
        logs = [
            l
            for l in AuditLogger._logs
            if l.tenant_id == tenant_id and l.user_id == user_id
        ]
        return sorted(logs, key=lambda l: l.timestamp, reverse=True)[:limit]

    @staticmethod
    def get_resource_logs(
        tenant_id: str, resource_type: str, resource_id: str
    ) -> list[AuditLog]:
        """Get audit logs for a specific resource."""
        return [
            l
            for l in AuditLogger._logs
            if l.tenant_id == tenant_id
            and l.resource_type == resource_type
            and l.resource_id == resource_id
        ]

    @staticmethod
    def clear_all() -> None:
        """Clear all audit logs."""
        AuditLogger._logs.clear()


class SLATracker:
    """Tracks SLA compliance and violations."""

    _policies: dict[str, SLAPolicy] = {}
    _metrics: list[SLAMetric] = []

    @staticmethod
    def create_sla_policy(
        tenant_id: str,
        name: str,
        metric_name: str,
        metric_type: str,
        threshold_value: float,
        threshold_operator: str,
        measurement_window: int = 60,
        severity_level: str = "warning",
    ) -> SLAPolicy:
        """Create SLA policy."""
        policy_id = f"sla_{uuid4().hex[:12]}"

        policy = SLAPolicy(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name=name,
            metric_name=metric_name,
            metric_type=metric_type,
            threshold_value=threshold_value,
            threshold_operator=threshold_operator,
            measurement_window=measurement_window,
            severity_level=severity_level,
            created_at=datetime.utcnow().isoformat(),
            created_by="system",
        )

        SLATracker._policies[policy_id] = policy
        return policy

    @staticmethod
    def get_sla_policy(policy_id: str) -> SLAPolicy | None:
        """Get SLA policy."""
        return SLATracker._policies.get(policy_id)

    @staticmethod
    def list_sla_policies(tenant_id: str) -> list[SLAPolicy]:
        """List SLA policies for tenant."""
        return [p for p in SLATracker._policies.values() if p.tenant_id == tenant_id]

    @staticmethod
    def record_sla_metric(
        policy_id: str, metric_value: float
    ) -> tuple[SLAMetric, bool]:
        """Record SLA metric and check compliance.

        Args:
            policy_id: SLA policy ID
            metric_value: Measured metric value

        Returns:
            Tuple of (SLAMetric, is_compliant)
        """
        policy = SLATracker._policies.get(policy_id)
        if not policy:
            return None, False

        # Check compliance
        compliant = _check_compliance(
            metric_value, policy.threshold_value, policy.threshold_operator
        )

        metric = SLAMetric(
            metric_id=f"metric_{uuid4().hex[:12]}",
            policy_id=policy_id,
            tenant_id=policy.tenant_id,
            measurement_period="hourly",
            start_time=datetime.utcnow().isoformat(),
            end_time=(datetime.utcnow() + timedelta(hours=1)).isoformat(),
            metric_value=metric_value,
            threshold_value=policy.threshold_value,
            compliant=compliant,
            breach_count=0 if compliant else 1,
            total_measurements=1,
            compliance_percentage=100.0 if compliant else 0.0,
            severity=None if compliant else policy.severity_level,
            timestamp=datetime.utcnow().isoformat(),
        )

        SLATracker._metrics.append(metric)
        return metric, compliant

    @staticmethod
    def generate_sla_report(
        tenant_id: str, start_date: str, end_date: str
    ) -> SLAReport | None:
        """Generate SLA compliance report."""
        policies = SLATracker.list_sla_policies(tenant_id)
        if not policies:
            return None

        metrics = [
            m
            for m in SLATracker._metrics
            if m.tenant_id == tenant_id
            and m.start_time >= start_date
            and m.end_time <= end_date
        ]

        compliant_count = sum(1 for m in metrics if m.compliant)
        breaches = [m for m in metrics if not m.compliant]

        compliance_pct = (
            (compliant_count / len(metrics) * 100) if metrics else 100.0
        )

        return SLAReport(
            report_id=f"report_{uuid4().hex[:12]}",
            tenant_id=tenant_id,
            start_date=start_date,
            end_date=end_date,
            total_policies=len(policies),
            compliant_policies=compliant_count,
            non_compliant_policies=len(policies) - compliant_count,
            compliance_percentage=compliance_pct,
            breaches=breaches[:10],
            summary=f"{compliance_pct:.1f}% SLA compliance",
            generated_at=datetime.utcnow().isoformat(),
            generated_by="system",
        )

    @staticmethod
    def clear_all() -> None:
        """Clear all SLA data."""
        SLATracker._policies.clear()
        SLATracker._metrics.clear()


class IntegrationManager:
    """Manages external system integrations."""

    _integrations: dict[str, ExternalIntegration] = {}
    _feature_flags: dict[str, FeatureFlag] = {}
    _usage: list[TenantUsage] = []

    @staticmethod
    def create_integration(
        tenant_id: str,
        name: str,
        integration_type: str,
        config: dict[str, Any],
        api_key: str | None = None,
    ) -> ExternalIntegration:
        """Create external integration."""
        integration_id = f"integ_{uuid4().hex[:12]}"

        integration = ExternalIntegration(
            integration_id=integration_id,
            tenant_id=tenant_id,
            name=name,
            integration_type=integration_type,
            status="disconnected",
            config=config,
            api_key=api_key,
            enabled=True,
            created_at=datetime.utcnow().isoformat(),
            created_by="system",
        )

        IntegrationManager._integrations[integration_id] = integration
        return integration

    @staticmethod
    def get_integration(integration_id: str) -> ExternalIntegration | None:
        """Get integration."""
        return IntegrationManager._integrations.get(integration_id)

    @staticmethod
    def list_integrations(tenant_id: str) -> list[ExternalIntegration]:
        """List integrations for tenant."""
        return [
            i for i in IntegrationManager._integrations.values()
            if i.tenant_id == tenant_id
        ]

    @staticmethod
    def update_integration_status(
        integration_id: str, status: str, error: str | None = None
    ) -> ExternalIntegration | None:
        """Update integration status."""
        integration = IntegrationManager._integrations.get(integration_id)
        if integration:
            integration.status = status
            if error:
                integration.last_error = error
            if status == "connected":
                integration.last_sync = datetime.utcnow().isoformat()
        return integration

    @staticmethod
    def create_feature_flag(
        feature_name: str, enabled: bool, tenant_id: str | None = None
    ) -> FeatureFlag:
        """Create feature flag."""
        flag_id = f"flag_{uuid4().hex[:12]}"

        flag = FeatureFlag(
            flag_id=flag_id,
            tenant_id=tenant_id,
            feature_name=feature_name,
            enabled=enabled,
            rollout_percentage=100.0 if enabled else 0.0,
            owner="system",
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
        )

        IntegrationManager._feature_flags[flag_id] = flag
        return flag

    @staticmethod
    def is_feature_enabled(feature_name: str, tenant_id: str | None = None) -> bool:
        """Check if feature is enabled."""
        flags = [
            f
            for f in IntegrationManager._feature_flags.values()
            if f.feature_name == feature_name
            and (f.tenant_id == tenant_id or f.tenant_id is None)
        ]

        if not flags:
            return False

        # Tenant-specific flag takes precedence
        tenant_flag = next((f for f in flags if f.tenant_id == tenant_id), None)
        if tenant_flag:
            return tenant_flag.enabled

        # Fall back to global flag
        global_flag = next((f for f in flags if f.tenant_id is None), None)
        return global_flag.enabled if global_flag else False

    @staticmethod
    def record_usage(tenant_id: str, **kwargs) -> TenantUsage:
        """Record tenant resource usage."""
        usage = TenantUsage(
            usage_id=f"usage_{uuid4().hex[:12]}",
            tenant_id=tenant_id,
            measurement_period=datetime.utcnow().isoformat()[:10],
            traces_processed=kwargs.get("traces_processed", 0),
            api_calls=kwargs.get("api_calls", 0),
            storage_gb=kwargs.get("storage_gb", 0.0),
            dashboard_views=kwargs.get("dashboard_views", 0),
            alerts_triggered=kwargs.get("alerts_triggered", 0),
            rules_evaluated=kwargs.get("rules_evaluated", 0),
            limit_traces_per_month=kwargs.get("limit_traces_per_month", 100000),
            limit_api_calls_per_day=kwargs.get("limit_api_calls_per_day", 10000),
            limit_storage_gb=kwargs.get("limit_storage_gb", 100),
            usage_percentage=kwargs.get("usage_percentage", 0.0),
            timestamp=datetime.utcnow().isoformat(),
        )

        IntegrationManager._usage.append(usage)
        return usage

    @staticmethod
    def get_usage(tenant_id: str) -> TenantUsage | None:
        """Get latest usage for tenant."""
        usage_list = [u for u in IntegrationManager._usage if u.tenant_id == tenant_id]
        return usage_list[-1] if usage_list else None

    @staticmethod
    def clear_all() -> None:
        """Clear all integration data."""
        IntegrationManager._integrations.clear()
        IntegrationManager._feature_flags.clear()
        IntegrationManager._usage.clear()


def _get_tier_features(tier: str) -> list[str]:
    """Get enabled features for subscription tier."""
    features = {
        "free": ["basic_analytics", "limited_rules"],
        "pro": ["advanced_analytics", "unlimited_rules", "integrations"],
        "enterprise": [
            "advanced_analytics",
            "unlimited_rules",
            "integrations",
            "sla_tracking",
            "audit_logging",
            "custom_integrations",
        ],
    }
    return features.get(tier, [])


def _check_compliance(value: float, threshold: float, operator: str) -> bool:
    """Check if value complies with threshold."""
    if operator == ">":
        return value > threshold
    elif operator == "<":
        return value < threshold
    elif operator == ">=":
        return value >= threshold
    elif operator == "<=":
        return value <= threshold
    elif operator == "==":
        return value == threshold
    return False
