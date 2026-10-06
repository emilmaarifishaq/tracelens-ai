"""Tests for Phase 6: Enterprise features (multi-tenancy, RBAC, audit logging, SLA tracking, integrations)."""

from datetime import datetime, timedelta
import pytest

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
from app.services.enterprise_manager import (
    AuditLogger,
    IntegrationManager,
    RBACManager,
    SLATracker,
    TenantManager,
)


class TestTenantManager:
    """Tests for TenantManager."""

    def setup_method(self):
        """Clear all data before each test."""
        TenantManager.clear_all()

    def test_create_tenant_pro(self):
        """Test creating a pro tenant."""
        tenant = TenantManager.create_tenant(
            name="Acme Corp",
            owner_id="user_123",
            subscription_tier="pro",
            max_users=20,
            max_traces_per_month=500000,
        )

        assert tenant.name == "Acme Corp"
        assert tenant.owner_id == "user_123"
        assert tenant.subscription_tier == "pro"
        assert tenant.max_users == 20
        assert tenant.status == "active"
        assert "advanced_analytics" in tenant.features_enabled
        assert "unlimited_rules" in tenant.features_enabled
        assert tenant.tenant_id.startswith("tenant_")

    def test_create_tenant_enterprise(self):
        """Test creating enterprise tenant with all features."""
        tenant = TenantManager.create_tenant(
            name="Enterprise Ltd",
            owner_id="user_456",
            subscription_tier="enterprise",
            max_users=100,
        )

        assert tenant.subscription_tier == "enterprise"
        assert "sla_tracking" in tenant.features_enabled
        assert "audit_logging" in tenant.features_enabled
        assert "custom_integrations" in tenant.features_enabled

    def test_create_tenant_free(self):
        """Test creating free tenant with limited features."""
        tenant = TenantManager.create_tenant(
            name="Startup",
            owner_id="user_789",
            subscription_tier="free",
            max_users=5,
        )

        assert tenant.subscription_tier == "free"
        assert "basic_analytics" in tenant.features_enabled
        assert "limited_rules" in tenant.features_enabled
        assert "sla_tracking" not in tenant.features_enabled

    def test_get_tenant(self):
        """Test retrieving tenant by ID."""
        created = TenantManager.create_tenant("Test Org", "owner_1")
        retrieved = TenantManager.get_tenant(created.tenant_id)

        assert retrieved is not None
        assert retrieved.tenant_id == created.tenant_id
        assert retrieved.name == "Test Org"

    def test_get_nonexistent_tenant(self):
        """Test retrieving nonexistent tenant returns None."""
        result = TenantManager.get_tenant("invalid_id")
        assert result is None

    def test_list_tenants(self):
        """Test listing all tenants."""
        tenant1 = TenantManager.create_tenant("Org 1", "owner_1")
        tenant2 = TenantManager.create_tenant("Org 2", "owner_2")
        tenant3 = TenantManager.create_tenant("Org 3", "owner_3")

        tenants = TenantManager.list_tenants()
        assert len(tenants) == 3
        tenant_ids = [t.tenant_id for t in tenants]
        assert tenant1.tenant_id in tenant_ids
        assert tenant2.tenant_id in tenant_ids
        assert tenant3.tenant_id in tenant_ids

    def test_update_tenant_status(self):
        """Test updating tenant status."""
        tenant = TenantManager.create_tenant("Org", "owner_1")
        updated = TenantManager.update_tenant_status(tenant.tenant_id, "suspended")

        assert updated.status == "suspended"
        assert TenantManager.get_tenant(tenant.tenant_id).status == "suspended"

    def test_add_user_to_tenant(self):
        """Test adding user to tenant."""
        tenant = TenantManager.create_tenant("Org", "owner_1")
        user = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "john_doe", "john@example.com"
        )

        assert user is not None
        assert user.username == "john_doe"
        assert user.email == "john@example.com"
        assert user.tenant_id == tenant.tenant_id
        assert user.user_id.startswith("user_")

    def test_add_user_with_roles(self):
        """Test adding user with specific roles."""
        tenant = TenantManager.create_tenant("Org", "owner_1")
        roles = ["role_admin", "role_analyst"]
        user = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "admin_user", "admin@example.com", roles=roles
        )

        assert user.roles == roles

    def test_add_user_to_nonexistent_tenant(self):
        """Test adding user to nonexistent tenant returns None."""
        result = TenantManager.add_user_to_tenant(
            "invalid_tenant", "user", "user@example.com"
        )
        assert result is None

    def test_get_tenant_users(self):
        """Test retrieving all users in tenant."""
        tenant = TenantManager.create_tenant("Org", "owner_1")
        user1 = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "user1", "user1@example.com"
        )
        user2 = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "user2", "user2@example.com"
        )

        users = TenantManager.get_tenant_users(tenant.tenant_id)
        assert len(users) == 2
        user_ids = [u.user_id for u in users]
        assert user1.user_id in user_ids
        assert user2.user_id in user_ids

    def test_get_user(self):
        """Test retrieving user by ID."""
        tenant = TenantManager.create_tenant("Org", "owner_1")
        user = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "user1", "user1@example.com"
        )

        retrieved = TenantManager.get_user(user.user_id)
        assert retrieved is not None
        assert retrieved.username == "user1"

    def test_update_user_roles(self):
        """Test updating user roles."""
        tenant = TenantManager.create_tenant("Org", "owner_1")
        user = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "user1", "user1@example.com", roles=["viewer"]
        )

        new_roles = ["admin", "analyst"]
        updated = TenantManager.update_user_roles(user.user_id, new_roles)

        assert updated.roles == new_roles
        assert TenantManager.get_user(user.user_id).roles == new_roles


class TestRBACManager:
    """Tests for RBACManager."""

    def setup_method(self):
        """Clear and initialize RBAC data."""
        RBACManager.clear_all()
        RBACManager.initialize_default_permissions()

    def test_initialize_default_permissions(self):
        """Test default permissions are initialized."""
        perms = RBACManager._permissions
        assert "perm_read_traces" in perms
        assert "perm_create_rules" in perms
        assert "perm_modify_rules" in perms
        assert "perm_manage_users" in perms
        assert "perm_view_dashboards" in perms
        assert "perm_admin_access" in perms

    def test_create_role(self):
        """Test creating a role."""
        role = RBACManager.create_role(
            name="analyst",
            permissions=["perm_read_traces", "perm_view_dashboards"],
        )

        assert role.name == "analyst"
        assert "perm_read_traces" in role.permissions
        assert role.tenant_id is None  # Global role

    def test_create_tenant_specific_role(self):
        """Test creating tenant-specific role."""
        role = RBACManager.create_role(
            name="custom_role",
            permissions=["perm_read_traces"],
            tenant_id="tenant_123",
            description="Custom tenant role",
        )

        assert role.tenant_id == "tenant_123"
        assert role.description == "Custom tenant role"

    def test_get_role(self):
        """Test retrieving role by ID."""
        created = RBACManager.create_role(
            "operator", ["perm_read_traces", "perm_create_rules"]
        )
        retrieved = RBACManager.get_role(created.role_id)

        assert retrieved is not None
        assert retrieved.name == "operator"

    def test_list_roles_global(self):
        """Test listing global roles."""
        RBACManager.create_role("admin", ["perm_admin_access"])
        RBACManager.create_role("viewer", ["perm_read_traces"])

        roles = RBACManager.list_roles()
        assert len(roles) >= 2

    def test_list_roles_tenant_specific(self):
        """Test listing roles for specific tenant."""
        RBACManager.create_role("global_role", ["perm_read_traces"])
        RBACManager.create_role(
            "tenant_role", ["perm_read_traces"], tenant_id="tenant_456"
        )

        tenant_roles = RBACManager.list_roles(tenant_id="tenant_456")
        # Should include both global and tenant-specific roles
        assert any(r.name == "tenant_role" for r in tenant_roles)

    def test_get_user_permissions(self):
        """Test retrieving user permissions based on roles."""
        TenantManager.clear_all()
        tenant = TenantManager.create_tenant("Org", "owner_1")
        user = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "user1", "user1@example.com"
        )

        role = RBACManager.create_role(
            "analyst", ["perm_read_traces", "perm_view_dashboards"]
        )
        TenantManager.update_user_roles(user.user_id, [role.role_id])

        permissions = RBACManager.get_user_permissions(user.user_id)
        perm_ids = [p.permission_id for p in permissions]
        assert "perm_read_traces" in perm_ids
        assert "perm_view_dashboards" in perm_ids

    def test_has_permission(self):
        """Test checking if user has specific permission."""
        TenantManager.clear_all()
        tenant = TenantManager.create_tenant("Org", "owner_1")
        user = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "user1", "user1@example.com"
        )

        role = RBACManager.create_role("analyst", ["perm_read_traces"])
        TenantManager.update_user_roles(user.user_id, [role.role_id])

        assert RBACManager.has_permission(user.user_id, "perm_read_traces")
        assert not RBACManager.has_permission(user.user_id, "perm_admin_access")

    def test_has_resource_action(self):
        """Test checking resource action permissions."""
        TenantManager.clear_all()
        tenant = TenantManager.create_tenant("Org", "owner_1")
        user = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "user1", "user1@example.com"
        )

        role = RBACManager.create_role("analyst", ["perm_read_traces"])
        TenantManager.update_user_roles(user.user_id, [role.role_id])

        assert RBACManager.has_resource_action(user.user_id, "traces", "read")
        assert not RBACManager.has_resource_action(user.user_id, "rules", "update")

    def test_wildcard_admin_permission(self):
        """Test admin permission with wildcard resource and action."""
        TenantManager.clear_all()
        tenant = TenantManager.create_tenant("Org", "owner_1")
        user = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "admin", "admin@example.com"
        )

        role = RBACManager.create_role("admin", ["perm_admin_access"])
        TenantManager.update_user_roles(user.user_id, [role.role_id])

        assert RBACManager.has_resource_action(user.user_id, "traces", "read")
        assert RBACManager.has_resource_action(user.user_id, "users", "update")
        assert RBACManager.has_resource_action(user.user_id, "rules", "delete")


class TestAuditLogger:
    """Tests for AuditLogger."""

    def setup_method(self):
        """Clear audit logs before each test."""
        AuditLogger.clear_all()

    def test_log_action_success(self):
        """Test logging successful action."""
        log = AuditLogger.log_action(
            tenant_id="tenant_1",
            action="create_rule",
            resource_type="rule",
            resource_id="rule_123",
            user_id="user_1",
            ip_address="192.168.1.1",
            changes={"name": {"old": None, "new": "Alert Rule"}},
            success=True,
        )

        assert log.action == "create_rule"
        assert log.success is True
        assert log.error_message is None

    def test_log_action_failure(self):
        """Test logging failed action."""
        log = AuditLogger.log_action(
            tenant_id="tenant_1",
            action="create_rule",
            resource_type="rule",
            resource_id="rule_123",
            user_id="user_1",
            success=False,
            error_message="Insufficient permissions",
        )

        assert log.success is False
        assert log.error_message == "Insufficient permissions"

    def test_log_system_action(self):
        """Test logging system action (no user_id)."""
        log = AuditLogger.log_action(
            tenant_id="tenant_1",
            action="auto_scale",
            resource_type="tenant",
            resource_id="tenant_1",
            user_id=None,
        )

        assert log.user_id is None
        assert log.action == "auto_scale"

    def test_get_logs(self):
        """Test retrieving audit logs for tenant."""
        AuditLogger.log_action(
            "tenant_1", "create_rule", "rule", "rule_1", user_id="user_1"
        )
        AuditLogger.log_action(
            "tenant_1", "modify_rule", "rule", "rule_1", user_id="user_2"
        )
        AuditLogger.log_action(
            "tenant_2", "create_rule", "rule", "rule_2", user_id="user_3"
        )

        logs = AuditLogger.get_logs("tenant_1")
        assert len(logs) == 2
        assert all(l.tenant_id == "tenant_1" for l in logs)

    def test_get_user_logs(self):
        """Test retrieving audit logs for specific user."""
        AuditLogger.log_action(
            "tenant_1", "create_rule", "rule", "rule_1", user_id="user_1"
        )
        AuditLogger.log_action(
            "tenant_1", "modify_rule", "rule", "rule_1", user_id="user_2"
        )
        AuditLogger.log_action(
            "tenant_1", "delete_rule", "rule", "rule_2", user_id="user_1"
        )

        logs = AuditLogger.get_user_logs("tenant_1", "user_1")
        assert len(logs) == 2
        assert all(l.user_id == "user_1" for l in logs)

    def test_get_resource_logs(self):
        """Test retrieving audit logs for specific resource."""
        AuditLogger.log_action(
            "tenant_1", "create_rule", "rule", "rule_1", user_id="user_1"
        )
        AuditLogger.log_action(
            "tenant_1", "modify_rule", "rule", "rule_1", user_id="user_2"
        )
        AuditLogger.log_action(
            "tenant_1", "modify_rule", "rule", "rule_2", user_id="user_2"
        )

        logs = AuditLogger.get_resource_logs("tenant_1", "rule", "rule_1")
        assert len(logs) == 2
        assert all(l.resource_id == "rule_1" for l in logs)

    def test_audit_log_ordering(self):
        """Test logs are ordered by timestamp descending."""
        log1 = AuditLogger.log_action(
            "tenant_1", "action_1", "resource", "res_1"
        )
        log2 = AuditLogger.log_action(
            "tenant_1", "action_2", "resource", "res_2"
        )
        log3 = AuditLogger.log_action(
            "tenant_1", "action_3", "resource", "res_3"
        )

        logs = AuditLogger.get_logs("tenant_1")
        assert logs[0].action == "action_3"
        assert logs[1].action == "action_2"
        assert logs[2].action == "action_1"


class TestSLATracker:
    """Tests for SLATracker."""

    def setup_method(self):
        """Clear SLA data before each test."""
        SLATracker.clear_all()

    def test_create_sla_policy_availability(self):
        """Test creating SLA policy for availability metric."""
        policy = SLATracker.create_sla_policy(
            tenant_id="tenant_1",
            name="Service Availability",
            metric_name="availability",
            metric_type="availability",
            threshold_value=99.9,
            threshold_operator=">=",
        )

        assert policy.name == "Service Availability"
        assert policy.metric_name == "availability"
        assert policy.threshold_value == 99.9
        assert policy.threshold_operator == ">="

    def test_create_sla_policy_latency(self):
        """Test creating SLA policy for latency metric."""
        policy = SLATracker.create_sla_policy(
            tenant_id="tenant_1",
            name="Response Latency",
            metric_name="response_time",
            metric_type="latency",
            threshold_value=500.0,
            threshold_operator="<",
            measurement_window=60,
        )

        assert policy.threshold_value == 500.0
        assert policy.measurement_window == 60

    def test_get_sla_policy(self):
        """Test retrieving SLA policy."""
        created = SLATracker.create_sla_policy(
            "tenant_1",
            "Availability",
            "availability",
            "availability",
            99.9,
            ">=",
        )
        retrieved = SLATracker.get_sla_policy(created.policy_id)

        assert retrieved is not None
        assert retrieved.name == "Availability"

    def test_list_sla_policies(self):
        """Test listing SLA policies for tenant."""
        SLATracker.create_sla_policy(
            "tenant_1", "Policy 1", "metric_1", "availability", 99.9, ">="
        )
        SLATracker.create_sla_policy(
            "tenant_1", "Policy 2", "metric_2", "latency", 500.0, "<"
        )
        SLATracker.create_sla_policy(
            "tenant_2", "Policy 3", "metric_3", "availability", 99.5, ">="
        )

        policies = SLATracker.list_sla_policies("tenant_1")
        assert len(policies) == 2

    def test_record_sla_metric_compliant(self):
        """Test recording compliant SLA metric."""
        policy = SLATracker.create_sla_policy(
            "tenant_1", "Availability", "availability", "availability", 99.0, ">="
        )
        metric, compliant = SLATracker.record_sla_metric(policy.policy_id, 99.5)

        assert compliant is True
        assert metric.compliant is True
        assert metric.breach_count == 0
        assert metric.compliance_percentage == 100.0

    def test_record_sla_metric_breach(self):
        """Test recording SLA metric breach."""
        policy = SLATracker.create_sla_policy(
            "tenant_1", "Availability", "availability", "availability", 99.0, ">="
        )
        metric, compliant = SLATracker.record_sla_metric(policy.policy_id, 98.5)

        assert compliant is False
        assert metric.compliant is False
        assert metric.breach_count == 1
        assert metric.compliance_percentage == 0.0
        assert metric.severity == "warning"

    def test_record_sla_metric_with_different_operators(self):
        """Test SLA compliance with different operators."""
        # Test <
        policy_less = SLATracker.create_sla_policy(
            "tenant_1", "Latency", "latency", "latency", 500.0, "<"
        )
        _, compliant_less = SLATracker.record_sla_metric(policy_less.policy_id, 400.0)
        assert compliant_less is True

        _, not_compliant_less = SLATracker.record_sla_metric(
            policy_less.policy_id, 600.0
        )
        assert not_compliant_less is False

    def test_generate_sla_report(self):
        """Test generating SLA compliance report."""
        policy = SLATracker.create_sla_policy(
            "tenant_1", "Availability", "availability", "availability", 99.0, ">="
        )

        # Record metrics
        SLATracker.record_sla_metric(policy.policy_id, 99.5)
        SLATracker.record_sla_metric(policy.policy_id, 99.2)
        SLATracker.record_sla_metric(policy.policy_id, 98.5)

        # Generate report
        today = datetime.utcnow().date().isoformat()
        tomorrow = (datetime.utcnow().date() + timedelta(days=1)).isoformat()
        report = SLATracker.generate_sla_report("tenant_1", today, tomorrow)

        assert report is not None
        assert report.tenant_id == "tenant_1"
        assert report.total_policies >= 1

    def test_generate_sla_report_no_policies(self):
        """Test generating report with no policies returns None."""
        today = datetime.utcnow().date().isoformat()
        tomorrow = (datetime.utcnow().date() + timedelta(days=1)).isoformat()
        report = SLATracker.generate_sla_report("tenant_1", today, tomorrow)

        assert report is None


class TestIntegrationManager:
    """Tests for IntegrationManager."""

    def setup_method(self):
        """Clear integration data before each test."""
        IntegrationManager.clear_all()

    def test_create_kafka_integration(self):
        """Test creating Kafka integration."""
        integration = IntegrationManager.create_integration(
            tenant_id="tenant_1",
            name="Kafka Cluster",
            integration_type="kafka",
            config={"bootstrap_servers": "localhost:9092"},
            api_key="kafka_key_123",
        )

        assert integration.name == "Kafka Cluster"
        assert integration.integration_type == "kafka"
        assert integration.status == "disconnected"
        assert integration.enabled is True

    def test_create_elasticsearch_integration(self):
        """Test creating Elasticsearch integration."""
        integration = IntegrationManager.create_integration(
            tenant_id="tenant_1",
            name="ELK Stack",
            integration_type="elasticsearch",
            config={"host": "elastic.example.com", "port": 9200},
        )

        assert integration.integration_type == "elasticsearch"

    def test_create_splunk_integration(self):
        """Test creating Splunk integration."""
        integration = IntegrationManager.create_integration(
            tenant_id="tenant_1",
            name="Splunk",
            integration_type="splunk",
            config={"hec_url": "https://splunk.example.com:8088"},
            api_key="splunk_hec_token",
        )

        assert integration.integration_type == "splunk"

    def test_get_integration(self):
        """Test retrieving integration by ID."""
        created = IntegrationManager.create_integration(
            "tenant_1", "Kafka", "kafka", {"server": "localhost"}
        )
        retrieved = IntegrationManager.get_integration(created.integration_id)

        assert retrieved is not None
        assert retrieved.name == "Kafka"

    def test_list_integrations(self):
        """Test listing integrations for tenant."""
        IntegrationManager.create_integration(
            "tenant_1", "Kafka", "kafka", {"server": "localhost"}
        )
        IntegrationManager.create_integration(
            "tenant_1", "Elasticsearch", "elasticsearch", {"host": "elastic"}
        )
        IntegrationManager.create_integration(
            "tenant_2", "Splunk", "splunk", {"url": "splunk"}
        )

        integrations = IntegrationManager.list_integrations("tenant_1")
        assert len(integrations) == 2

    def test_update_integration_status_connected(self):
        """Test updating integration to connected status."""
        integration = IntegrationManager.create_integration(
            "tenant_1", "Kafka", "kafka", {"server": "localhost"}
        )

        updated = IntegrationManager.update_integration_status(
            integration.integration_id, "connected"
        )

        assert updated.status == "connected"
        assert updated.last_sync is not None

    def test_update_integration_status_error(self):
        """Test updating integration with error status."""
        integration = IntegrationManager.create_integration(
            "tenant_1", "Kafka", "kafka", {"server": "localhost"}
        )

        updated = IntegrationManager.update_integration_status(
            integration.integration_id,
            "error",
            error="Connection timeout",
        )

        assert updated.status == "error"
        assert updated.last_error == "Connection timeout"

    def test_create_feature_flag_enabled(self):
        """Test creating enabled feature flag."""
        flag = IntegrationManager.create_feature_flag(
            feature_name="advanced_ml_models", enabled=True
        )

        assert flag.feature_name == "advanced_ml_models"
        assert flag.enabled is True
        assert flag.rollout_percentage == 100.0
        assert flag.tenant_id is None  # Global flag

    def test_create_feature_flag_disabled(self):
        """Test creating disabled feature flag."""
        flag = IntegrationManager.create_feature_flag(
            feature_name="beta_feature", enabled=False
        )

        assert flag.enabled is False
        assert flag.rollout_percentage == 0.0

    def test_create_tenant_specific_feature_flag(self):
        """Test creating tenant-specific feature flag."""
        flag = IntegrationManager.create_feature_flag(
            feature_name="custom_rules",
            enabled=True,
            tenant_id="tenant_1",
        )

        assert flag.tenant_id == "tenant_1"

    def test_is_feature_enabled_global(self):
        """Test checking global feature flag."""
        IntegrationManager.create_feature_flag(
            "ml_features", enabled=True
        )

        enabled = IntegrationManager.is_feature_enabled("ml_features")
        assert enabled is True

    def test_is_feature_enabled_disabled(self):
        """Test disabled feature returns False."""
        IntegrationManager.create_feature_flag("beta_feature", enabled=False)

        enabled = IntegrationManager.is_feature_enabled("beta_feature")
        assert enabled is False

    def test_is_feature_enabled_tenant_override(self):
        """Test tenant-specific flag overrides global."""
        # Global: enabled
        IntegrationManager.create_feature_flag("feature", enabled=True)
        # Tenant override: disabled
        IntegrationManager.create_feature_flag(
            "feature", enabled=False, tenant_id="tenant_1"
        )

        global_enabled = IntegrationManager.is_feature_enabled("feature")
        tenant_enabled = IntegrationManager.is_feature_enabled(
            "feature", tenant_id="tenant_1"
        )

        assert global_enabled is True
        assert tenant_enabled is False

    def test_record_usage(self):
        """Test recording tenant usage."""
        usage = IntegrationManager.record_usage(
            tenant_id="tenant_1",
            traces_processed=15000,
            api_calls=5000,
            storage_gb=25.5,
            dashboard_views=120,
            alerts_triggered=8,
            rules_evaluated=500,
        )

        assert usage.tenant_id == "tenant_1"
        assert usage.traces_processed == 15000
        assert usage.api_calls == 5000
        assert usage.storage_gb == 25.5

    def test_record_usage_with_limits(self):
        """Test recording usage with custom limits."""
        usage = IntegrationManager.record_usage(
            tenant_id="tenant_1",
            traces_processed=10000,
            limit_traces_per_month=50000,
            limit_api_calls_per_day=5000,
        )

        assert usage.limit_traces_per_month == 50000
        assert usage.limit_api_calls_per_day == 5000

    def test_get_usage(self):
        """Test retrieving latest usage for tenant."""
        IntegrationManager.record_usage(
            "tenant_1",
            traces_processed=1000,
        )
        IntegrationManager.record_usage(
            "tenant_1",
            traces_processed=2000,
        )

        latest = IntegrationManager.get_usage("tenant_1")
        assert latest is not None
        assert latest.traces_processed == 2000

    def test_get_usage_nonexistent_tenant(self):
        """Test getting usage for tenant with no records."""
        usage = IntegrationManager.get_usage("nonexistent_tenant")
        assert usage is None


class TestEnterpriseIntegration:
    """Integration tests across multiple enterprise services."""

    def setup_method(self):
        """Clear all data."""
        TenantManager.clear_all()
        RBACManager.clear_all()
        AuditLogger.clear_all()
        SLATracker.clear_all()
        IntegrationManager.clear_all()
        RBACManager.initialize_default_permissions()

    def test_complete_tenant_onboarding_flow(self):
        """Test complete tenant onboarding with users, roles, and audit."""
        # Create tenant
        tenant = TenantManager.create_tenant(
            "NewCorp", "owner_1", "enterprise"
        )

        # Add users
        user1 = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "admin_user", "admin@newcorp.com"
        )
        user2 = TenantManager.add_user_to_tenant(
            tenant.tenant_id, "analyst", "analyst@newcorp.com"
        )

        # Create roles
        admin_role = RBACManager.create_role(
            "admin", ["perm_admin_access"], tenant_id=tenant.tenant_id
        )
        analyst_role = RBACManager.create_role(
            "analyst",
            ["perm_read_traces", "perm_view_dashboards"],
            tenant_id=tenant.tenant_id,
        )

        # Assign roles
        TenantManager.update_user_roles(user1.user_id, [admin_role.role_id])
        TenantManager.update_user_roles(user2.user_id, [analyst_role.role_id])

        # Log actions
        AuditLogger.log_action(
            tenant.tenant_id,
            "create_tenant",
            "tenant",
            tenant.tenant_id,
            user_id="owner_1",
            changes={"status": {"old": None, "new": "active"}},
        )

        # Verify setup
        users = TenantManager.get_tenant_users(tenant.tenant_id)
        assert len(users) == 2

        admin_perms = RBACManager.get_user_permissions(user1.user_id)
        assert any(p.name == "admin_access" for p in admin_perms)

        analyst_perms = RBACManager.get_user_permissions(user2.user_id)
        assert any(p.name == "read_traces" for p in analyst_perms)

        logs = AuditLogger.get_logs(tenant.tenant_id)
        assert len(logs) >= 1

    def test_sla_and_integration_setup(self):
        """Test SLA policies with external integration."""
        # Create tenant
        tenant = TenantManager.create_tenant("SLA Corp", "owner_1")

        # Create SLA policies
        availability_policy = SLATracker.create_sla_policy(
            tenant.tenant_id,
            "Service Availability",
            "availability",
            "availability",
            99.9,
            ">=",
        )

        # Create integrations
        kafka = IntegrationManager.create_integration(
            tenant.tenant_id,
            "Kafka",
            "kafka",
            {"server": "localhost"},
        )

        # Record metrics and update integration
        metric, compliant = SLATracker.record_sla_metric(
            availability_policy.policy_id, 99.95
        )
        assert compliant is True

        updated_kafka = IntegrationManager.update_integration_status(
            kafka.integration_id, "connected"
        )
        assert updated_kafka.status == "connected"

        # Log action
        AuditLogger.log_action(
            tenant.tenant_id,
            "create_sla_policy",
            "sla_policy",
            availability_policy.policy_id,
            user_id="owner_1",
        )

        logs = AuditLogger.get_logs(tenant.tenant_id)
        assert len(logs) >= 1
