"""Data models for enterprise features."""

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class Role(BaseModel):
    """RBAC role definition."""

    role_id: str
    name: str  # "admin", "analyst", "operator", "viewer"
    description: str | None = None
    permissions: list[str] = Field(default_factory=list)  # Permission IDs
    tenant_id: str | None = None  # None = global role
    created_at: str  # ISO timestamp
    created_by: str  # User ID


class Permission(BaseModel):
    """RBAC permission definition."""

    permission_id: str
    name: str  # "read_traces", "modify_rules", "manage_users"
    resource: str  # "traces", "rules", "users", "dashboards"
    action: str  # "read", "create", "update", "delete"
    description: str | None = None


class User(BaseModel):
    """User account with roles."""

    user_id: str
    username: str
    email: str
    roles: list[str] = Field(default_factory=list)  # Role IDs
    tenant_id: str
    is_active: bool = True
    last_login: str | None = None  # ISO timestamp
    created_at: str  # ISO timestamp
    metadata: dict[str, Any] = Field(default_factory=dict)


class Tenant(BaseModel):
    """Multi-tenant organization."""

    tenant_id: str
    name: str
    description: str | None = None
    owner_id: str  # User ID of owner
    subscription_tier: str  # "free", "pro", "enterprise"
    max_users: int
    max_traces_per_month: int
    features_enabled: list[str] = Field(default_factory=list)
    status: str  # "active", "suspended", "inactive"
    created_at: str  # ISO timestamp
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditLog(BaseModel):
    """Audit trail entry."""

    audit_id: str
    tenant_id: str
    user_id: str | None  # None for system operations
    action: str  # "create_rule", "modify_config", "delete_user", etc.
    resource_type: str  # "rule", "user", "tenant", "integration"
    resource_id: str
    changes: dict[str, Any]  # {field: {old: value, new: value}}
    ip_address: str | None = None
    success: bool
    error_message: str | None = None
    timestamp: str  # ISO timestamp
    metadata: dict[str, Any] = Field(default_factory=dict)


class SLAPolicy(BaseModel):
    """SLA policy definition."""

    policy_id: str
    tenant_id: str
    name: str
    description: str | None = None
    metric_name: str  # "registration_success_rate", "completion_rate"
    metric_type: str  # "success_rate", "latency", "availability"
    threshold_value: float
    threshold_operator: str  # ">", "<", "=="
    measurement_window: int  # Minutes
    severity_level: str  # "critical", "warning", "info"
    alert_on_breach: bool = True
    enabled: bool = True
    created_at: str  # ISO timestamp
    created_by: str  # User ID
    metadata: dict[str, Any] = Field(default_factory=dict)


class SLAMetric(BaseModel):
    """SLA compliance tracking."""

    metric_id: str
    policy_id: str
    tenant_id: str
    measurement_period: str  # "hourly", "daily", "weekly", "monthly"
    start_time: str  # ISO timestamp
    end_time: str  # ISO timestamp
    metric_value: float
    threshold_value: float
    compliant: bool
    breach_count: int
    total_measurements: int
    compliance_percentage: float  # 0-100
    severity: str | None = None  # If breached
    timestamp: str  # ISO timestamp


class SLAReport(BaseModel):
    """SLA compliance report."""

    report_id: str
    tenant_id: str
    start_date: str  # ISO date
    end_date: str  # ISO date
    total_policies: int
    compliant_policies: int
    non_compliant_policies: int
    compliance_percentage: float  # 0-100
    breaches: list[SLAMetric] = Field(default_factory=list)
    summary: str
    generated_at: str  # ISO timestamp
    generated_by: str  # User ID


class ExternalIntegration(BaseModel):
    """External system integration configuration."""

    integration_id: str
    tenant_id: str
    name: str
    integration_type: str  # "kafka", "elasticsearch", "splunk", "datadog"
    status: str  # "connected", "disconnected", "error"
    config: dict[str, Any]  # Connection details (host, port, etc.)
    api_key: str | None = None  # Encrypted
    enabled: bool = True
    retry_count: int = 0
    last_sync: str | None = None  # ISO timestamp
    last_error: str | None = None
    created_at: str  # ISO timestamp
    created_by: str  # User ID
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationEvent(BaseModel):
    """Event sent to external integration."""

    event_id: str
    integration_id: str
    tenant_id: str
    event_type: str  # "trace_analyzed", "insight_generated", "alert_triggered"
    source: str  # "dashboard", "api", "rules_engine"
    payload: dict[str, Any]
    status: str  # "pending", "sent", "failed", "retry"
    retry_attempts: int = 0
    max_retries: int = 3
    created_at: str  # ISO timestamp
    sent_at: str | None = None  # ISO timestamp
    error_message: str | None = None


class FeatureFlag(BaseModel):
    """Feature flag for tenant-specific features."""

    flag_id: str
    tenant_id: str | None  # None = global flag
    feature_name: str
    description: str | None = None
    enabled: bool
    rollout_percentage: float  # 0-100 for gradual rollout
    owner: str  # Team/user responsible
    created_at: str  # ISO timestamp
    updated_at: str  # ISO timestamp
    metadata: dict[str, Any] = Field(default_factory=dict)


class TenantUsage(BaseModel):
    """Tenant resource usage tracking."""

    usage_id: str
    tenant_id: str
    measurement_period: str  # ISO date or datetime
    traces_processed: int
    api_calls: int
    storage_gb: float
    dashboard_views: int
    alerts_triggered: int
    rules_evaluated: int
    limit_traces_per_month: int
    limit_api_calls_per_day: int
    limit_storage_gb: int
    usage_percentage: float  # 0-100 for primary resource
    timestamp: str  # ISO timestamp
