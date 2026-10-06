"""
Unit tests for NGAP/NAS-5GS cause classification.
Verifies that all causes are properly classified into business categories
and match the spec (TS 38.413, TS 24.501).
"""
import pytest
from pathlib import Path
import yaml


def load_causes(filename: str) -> dict:
    """Load cause classification YAML."""
    path = Path(__file__).resolve().parents[1] / "app" / "knowledge" / filename
    with path.open() as f:
        return yaml.safe_load(f) or {}


class TestNGAPCauses:
    """Test NGAP cause classification (TS 38.413)."""

    @pytest.fixture
    def ngap_causes(self):
        return load_causes("ngap_causes.yaml")

    def test_radionetwork_causes_exist(self, ngap_causes):
        """Verify radioNetwork category exists and has expected causes."""
        assert "radioNetwork" in ngap_causes
        radionet = ngap_causes["radioNetwork"]
        # Key causes per spec
        assert 20 in radionet  # user-inactivity
        assert 21 in radionet  # radio-connection-with-ue-lost
        assert 24 in radionet  # failure-in-radio-interface-procedure

    def test_cause_20_is_normal(self, ngap_causes):
        """Cause 20 (user-inactivity) must be NORMAL, not an issue."""
        cause_20 = ngap_causes["radioNetwork"][20]
        assert cause_20["name"] == "user-inactivity"
        assert cause_20["class"] == "NORMAL"

    def test_cause_21_is_abnormal_radio(self, ngap_causes):
        """Cause 21 (radio-connection-with-ue-lost) must be ABNORMAL_RADIO."""
        cause_21 = ngap_causes["radioNetwork"][21]
        assert cause_21["name"] == "radio-connection-with-ue-lost"
        assert cause_21["class"] == "ABNORMAL_RADIO"

    def test_cause_24_is_abnormal_radio(self, ngap_causes):
        """Cause 24 (failure-in-radio-interface-procedure) must be ABNORMAL_RADIO."""
        cause_24 = ngap_causes["radioNetwork"][24]
        assert cause_24["name"] == "failure-in-radio-interface-procedure"
        assert cause_24["class"] == "ABNORMAL_RADIO"

    def test_mobility_normal_causes(self, ngap_causes):
        """Handover-related causes should be MOBILITY_NORMAL."""
        radionet = ngap_causes["radioNetwork"]
        mobility_causes = [2, 16, 17, 18, 19, 31, 32, 33, 36, 41, 44]
        for cause_code in mobility_causes:
            if cause_code in radionet:
                assert radionet[cause_code]["class"] == "MOBILITY_NORMAL", \
                    f"Cause {cause_code} should be MOBILITY_NORMAL"

    def test_ho_failure_causes(self, ngap_causes):
        """HO-related failures should be HO_FAILURE."""
        radionet = ngap_causes["radioNetwork"]
        ho_failure_causes = [1, 5, 6, 7, 8, 9, 10, 12, 13]
        for cause_code in ho_failure_causes:
            if cause_code in radionet:
                assert radionet[cause_code]["class"] == "HO_FAILURE", \
                    f"Cause {cause_code} should be HO_FAILURE"

    def test_all_causes_have_name(self, ngap_causes):
        """Every cause must have a name field."""
        for category, causes in ngap_causes.items():
            for code, definition in causes.items():
                assert "name" in definition, \
                    f"{category} cause {code} missing 'name' field"
                assert isinstance(definition["name"], str), \
                    f"{category} cause {code} name must be string"

    def test_all_causes_have_class(self, ngap_causes):
        """Every cause must have a class field (except rare cases)."""
        valid_classes = {
            "NORMAL", "MOBILITY_NORMAL", "ABNORMAL_RADIO", "ABNORMAL_RESOURCE",
            "ABNORMAL_TRANSPORT", "ABNORMAL_PROTOCOL", "ABNORMAL_CONFIG",
            "HO_FAILURE", "ADMIN", "REVIEW"
        }
        for category, causes in ngap_causes.items():
            for code, definition in causes.items():
                assert "class" in definition, \
                    f"{category} cause {code} missing 'class' field"
                assert definition["class"] in valid_classes, \
                    f"{category} cause {code} has invalid class '{definition['class']}'"

    def test_transport_causes(self, ngap_causes):
        """Transport causes should be ABNORMAL_TRANSPORT."""
        transport = ngap_causes.get("transport", {})
        for code, definition in transport.items():
            assert definition["class"] == "ABNORMAL_TRANSPORT", \
                f"Transport cause {code} should be ABNORMAL_TRANSPORT"

    def test_nas_causes(self, ngap_causes):
        """NAS causes: normal-release and deregister should be NORMAL."""
        nas = ngap_causes.get("nas", {})
        if 0 in nas:
            assert nas[0]["class"] == "NORMAL"
        if 2 in nas:
            assert nas[2]["class"] == "NORMAL"

    def test_protocol_causes(self, ngap_causes):
        """Protocol causes should be ABNORMAL_PROTOCOL."""
        protocol = ngap_causes.get("protocol", {})
        for code, definition in protocol.items():
            assert definition["class"] == "ABNORMAL_PROTOCOL", \
                f"Protocol cause {code} should be ABNORMAL_PROTOCOL"

    def test_misc_causes(self, ngap_causes):
        """Misc cause 3 (om-intervention) should be ADMIN."""
        misc = ngap_causes.get("misc", {})
        if 3 in misc:
            assert misc[3]["class"] == "ADMIN"


class TestNAS5GSCauses:
    """Test NAS-5GS cause classification (TS 24.501)."""

    @pytest.fixture
    def nas_5gs_causes(self):
        return load_causes("nas_5gs_causes.yaml")

    def test_5gmm_causes_exist(self, nas_5gs_causes):
        """Verify 5GMM cause category exists."""
        assert "5gmm_causes" in nas_5gs_causes
        gmm = nas_5gs_causes["5gmm_causes"]
        # Key causes
        assert 1 in gmm   # Illegal UE
        assert 20 in gmm  # MAC failure
        assert 111 in gmm # Protocol error, unspecified

    def test_5gsm_causes_exist(self, nas_5gs_causes):
        """Verify 5GSM cause category exists."""
        assert "5gsm_causes" in nas_5gs_causes
        gsm = nas_5gs_causes["5gsm_causes"]
        assert 26 in gsm  # Insufficient resources

    def test_5gmm_cause_1_is_subscription_policy(self, nas_5gs_causes):
        """Cause 1 (Illegal UE) is SUBSCRIPTION_POLICY."""
        cause = nas_5gs_causes["5gmm_causes"][1]
        assert cause["sub_class"] == "SUBSCRIPTION_POLICY"

    def test_5gmm_cause_20_is_security_auth(self, nas_5gs_causes):
        """Cause 20 (MAC failure) is SECURITY_AUTH."""
        cause = nas_5gs_causes["5gmm_causes"][20]
        assert cause["sub_class"] == "SECURITY_AUTH"

    def test_5gmm_cause_22_is_congestion(self, nas_5gs_causes):
        """Cause 22 (Congestion) is CONGESTION_RESOURCE."""
        cause = nas_5gs_causes["5gmm_causes"][22]
        assert cause["sub_class"] == "CONGESTION_RESOURCE"

    def test_5gmm_cause_111_is_protocol(self, nas_5gs_causes):
        """Cause 111 (Protocol error, unspecified) is PROTOCOL."""
        cause = nas_5gs_causes["5gmm_causes"][111]
        assert cause["sub_class"] == "PROTOCOL"

    def test_5gsm_normal_causes(self, nas_5gs_causes):
        """Causes 36 (Regular deactivation) and 39 (Reactivation) are NORMAL."""
        gsm = nas_5gs_causes["5gsm_causes"]
        assert gsm[36]["class"] == "NORMAL"
        assert gsm[39]["class"] == "NORMAL"

    def test_5gsm_congestion_causes(self, nas_5gs_causes):
        """Cause 26 should be CONGESTION_RESOURCE."""
        assert nas_5gs_causes["5gsm_causes"][26]["class"] == "CONGESTION_RESOURCE"

    def test_5gmm_all_have_name_and_subclass(self, nas_5gs_causes):
        """All 5GMM causes must have name and sub_class."""
        gmm = nas_5gs_causes["5gmm_causes"]
        for code, definition in gmm.items():
            assert "name" in definition
            assert "sub_class" in definition

    def test_5gsm_all_have_name_and_class(self, nas_5gs_causes):
        """All 5GSM causes must have name and class."""
        gsm = nas_5gs_causes["5gsm_causes"]
        for code, definition in gsm.items():
            assert "name" in definition
            assert "class" in definition

    def test_valid_5gmm_subclasses(self, nas_5gs_causes):
        """5GMM sub-classes must be from spec section 4.1."""
        valid_classes = {
            "SUBSCRIPTION_POLICY", "IDENTITY_STATE", "SECURITY_AUTH",
            "CONGESTION_RESOURCE", "ROUTING_CONFIG", "PROTOCOL"
        }
        gmm = nas_5gs_causes["5gmm_causes"]
        for code, definition in gmm.items():
            assert definition["sub_class"] in valid_classes, \
                f"5GMM cause {code} has invalid sub_class"

    def test_valid_5gsm_classes(self, nas_5gs_causes):
        """5GSM classes must align with spec section 4.2."""
        valid_classes = {
            "NORMAL", "SUBSCRIPTION_POLICY", "CONGESTION_RESOURCE", "PROTOCOL"
        }
        gsm = nas_5gs_causes["5gsm_causes"]
        for code, definition in gsm.items():
            assert definition["class"] in valid_classes, \
                f"5GSM cause {code} has invalid class"


class TestNASEPSCauses:
    """Test NAS-EPS cause classification (TS 24.301)."""

    @pytest.fixture
    def nas_eps_causes(self):
        return load_causes("nas_eps_causes.yaml")

    def test_eps_causes_exist(self, nas_eps_causes):
        """Verify EPS cause category exists."""
        assert "causes" in nas_eps_causes
        causes = nas_eps_causes["causes"]
        assert 15 in causes  # MAC failure
        assert 32 in causes  # Protocol error

    def test_eps_normal_causes(self, nas_eps_causes):
        """Causes 101 (Regular deactivation) should be NORMAL."""
        causes = nas_eps_causes["causes"]
        if 101 in causes:
            assert causes[101]["class"] == "NORMAL"

    def test_eps_all_have_name_and_class(self, nas_eps_causes):
        """All EPS causes must have name and class."""
        causes = nas_eps_causes["causes"]
        for code, definition in causes.items():
            assert "name" in definition
            assert "class" in definition


class TestCauseLoadability:
    """Test that cause files can be loaded by the actual knowledge system."""

    def test_ngap_loads_via_knowledge(self):
        """Verify NGAP causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        ngap = load_yaml("ngap_causes.yaml")
        assert isinstance(ngap, dict)
        assert "radioNetwork" in ngap
        assert len(ngap["radioNetwork"]) > 40

    def test_nas_5gs_loads_via_knowledge(self):
        """Verify NAS-5GS causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        nas_5gs = load_yaml("nas_5gs_causes.yaml")
        assert isinstance(nas_5gs, dict)
        assert "5gmm_causes" in nas_5gs
        assert "5gsm_causes" in nas_5gs

    def test_nas_eps_loads_via_knowledge(self):
        """Verify NAS-EPS causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        nas_eps = load_yaml("nas_eps_causes.yaml")
        assert isinstance(nas_eps, dict)
        assert "causes" in nas_eps
