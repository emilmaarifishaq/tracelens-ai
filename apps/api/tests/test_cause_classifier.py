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


class TestGTPCauses:
    """Test GTP cause classification (GTPv2-C and GTPv1-C)."""

    @pytest.fixture
    def gtp_causes(self):
        return load_causes("gtp_causes.yaml")

    def test_gtp_categories_exist(self, gtp_causes):
        """Verify GTPv2-C and GTPv1-C categories exist."""
        assert "gtpv2_c" in gtp_causes
        assert "gtpv1_c" in gtp_causes

    def test_gtp_causes_have_class(self, gtp_causes):
        """All GTP causes must have class field."""
        valid_classes = {
            "NORMAL", "ABNORMAL_RESOURCE", "ABNORMAL_PROTOCOL",
            "ABNORMAL_TRANSPORT", "ABNORMAL_CONFIG", "REVIEW"
        }
        for category in ["gtpv2_c", "gtpv1_c"]:
            if category in gtp_causes:
                for code, definition in gtp_causes[category].items():
                    assert "class" in definition
                    assert definition["class"] in valid_classes


class TestPFCPCauses:
    """Test PFCP cause classification (N4 interface)."""

    @pytest.fixture
    def pfcp_causes(self):
        return load_causes("pfcp_causes.yaml")

    def test_pfcp_category_exists(self, pfcp_causes):
        """Verify PFCP category exists."""
        assert "pfcp" in pfcp_causes

    def test_pfcp_causes_have_class(self, pfcp_causes):
        """All PFCP causes must have class field."""
        valid_classes = {
            "NORMAL", "ABNORMAL_RESOURCE", "ABNORMAL_PROTOCOL",
            "ABNORMAL_TRANSPORT", "ABNORMAL_CONFIG"
        }
        pfcp = pfcp_causes["pfcp"]
        for code, definition in pfcp.items():
            assert "class" in definition
            assert definition["class"] in valid_classes


class TestDiameterCauses:
    """Test Diameter result code classification."""

    @pytest.fixture
    def diameter_causes(self):
        return load_causes("diameter_causes.yaml")

    def test_diameter_category_exists(self, diameter_causes):
        """Verify Diameter category exists."""
        assert "diameter" in diameter_causes

    def test_diameter_causes_have_class(self, diameter_causes):
        """All Diameter codes must have class field."""
        valid_classes = {
            "NORMAL", "ABNORMAL_CONFIG", "ABNORMAL_RESOURCE", "ABNORMAL_PROTOCOL",
            "ABNORMAL_TRANSPORT"
        }
        diameter = diameter_causes["diameter"]
        for code, definition in diameter.items():
            assert "class" in definition
            assert definition["class"] in valid_classes


class TestDNSCauses:
    """Test DNS response code classification."""

    @pytest.fixture
    def dns_causes(self):
        return load_causes("dns_causes.yaml")

    def test_dns_category_exists(self, dns_causes):
        """Verify DNS category exists."""
        assert "dns" in dns_causes

    def test_dns_causes_have_class(self, dns_causes):
        """All DNS codes must have class field."""
        valid_classes = {
            "NORMAL", "ABNORMAL_PROTOCOL", "ABNORMAL_CONFIG", "ABNORMAL_RESOURCE"
        }
        dns = dns_causes["dns"]
        for code, definition in dns.items():
            assert "class" in definition
            assert definition["class"] in valid_classes


class TestHTTPCauses:
    """Test HTTP status code classification (SBI)."""

    @pytest.fixture
    def http_causes(self):
        return load_causes("http_causes.yaml")

    def test_http_category_exists(self, http_causes):
        """Verify HTTP category exists."""
        assert "http" in http_causes

    def test_http_2xx_status(self, http_causes):
        """2xx codes should be NORMAL."""
        http = http_causes["http"]
        if "2xx" in http:
            assert http["2xx"]["class"] == "NORMAL"

    def test_http_causes_have_class(self, http_causes):
        """All HTTP codes must have class field."""
        valid_classes = {
            "NORMAL", "ABNORMAL_PROTOCOL", "ABNORMAL_CONFIG",
            "ABNORMAL_RESOURCE", "ABNORMAL_TRANSPORT"
        }
        http = http_causes["http"]
        for code, definition in http.items():
            assert "class" in definition
            assert definition["class"] in valid_classes


class TestSIPCauses:
    """Test SIP response code classification (IMS)."""

    @pytest.fixture
    def sip_causes(self):
        return load_causes("sip_causes.yaml")

    def test_sip_category_exists(self, sip_causes):
        """Verify SIP category exists."""
        assert "sip" in sip_causes

    def test_sip_1xx_provisional(self, sip_causes):
        """1xx provisional codes should be NORMAL."""
        sip = sip_causes["sip"]
        if 100 in sip:
            assert sip[100]["class"] == "NORMAL"
        if 180 in sip:
            assert sip[180]["class"] == "NORMAL"

    def test_sip_2xx_success(self, sip_causes):
        """2xx success codes should be NORMAL."""
        sip = sip_causes["sip"]
        if 200 in sip:
            assert sip[200]["class"] == "NORMAL"

    def test_sip_causes_have_class(self, sip_causes):
        """All SIP codes must have class field."""
        valid_classes = {
            "NORMAL", "ABNORMAL_PROTOCOL", "ABNORMAL_CONFIG",
            "ABNORMAL_RESOURCE", "ABNORMAL_TRANSPORT"
        }
        sip = sip_causes["sip"]
        for code, definition in sip.items():
            assert "class" in definition
            assert definition["class"] in valid_classes


class TestRADIUSCauses:
    """Test RADIUS code classification."""

    @pytest.fixture
    def radius_causes(self):
        return load_causes("radius_causes.yaml")

    def test_radius_category_exists(self, radius_causes):
        """Verify RADIUS category exists."""
        assert "radius" in radius_causes

    def test_radius_normal_codes(self, radius_causes):
        """Common RADIUS codes should be NORMAL."""
        radius = radius_causes["radius"]
        if 1 in radius:  # Access-Request
            assert radius[1]["class"] == "NORMAL"
        if 2 in radius:  # Access-Accept
            assert radius[2]["class"] == "NORMAL"

    def test_radius_causes_have_class(self, radius_causes):
        """All RADIUS codes must have class field."""
        valid_classes = {
            "NORMAL", "ABNORMAL_CONFIG", "ABNORMAL_RESOURCE"
        }
        radius = radius_causes["radius"]
        for code, definition in radius.items():
            assert "class" in definition
            assert definition["class"] in valid_classes


class TestTLSCauses:
    """Test TLS alert code classification."""

    @pytest.fixture
    def tls_causes(self):
        return load_causes("tls_causes.yaml")

    def test_tls_category_exists(self, tls_causes):
        """Verify TLS category exists."""
        assert "tls" in tls_causes

    def test_tls_close_notify(self, tls_causes):
        """Code 0 (Close Notify) should be NORMAL."""
        tls = tls_causes["tls"]
        if 0 in tls:
            assert tls[0]["class"] == "NORMAL"

    def test_tls_causes_have_class(self, tls_causes):
        """All TLS codes must have class field."""
        valid_classes = {
            "NORMAL", "ABNORMAL_PROTOCOL", "ABNORMAL_CONFIG", "ABNORMAL_RESOURCE"
        }
        tls = tls_causes["tls"]
        for code, definition in tls.items():
            assert "class" in definition
            assert definition["class"] in valid_classes


class TestTCPCauses:
    """Test TCP condition classification."""

    @pytest.fixture
    def tcp_causes(self):
        return load_causes("tcp_causes.yaml")

    def test_tcp_category_exists(self, tcp_causes):
        """Verify TCP category exists."""
        assert "tcp" in tcp_causes

    def test_tcp_anomalies(self, tcp_causes):
        """TCP conditions should be ABNORMAL_TRANSPORT."""
        tcp = tcp_causes["tcp"]
        anomaly_types = ["RST", "retransmission", "duplicate", "out-of-order"]
        for anomaly in anomaly_types:
            if anomaly in tcp:
                assert tcp[anomaly]["class"] == "ABNORMAL_TRANSPORT"

    def test_tcp_causes_have_class(self, tcp_causes):
        """All TCP conditions must have class field."""
        valid_classes = {"ABNORMAL_TRANSPORT"}
        tcp = tcp_causes["tcp"]
        for condition, definition in tcp.items():
            assert "class" in definition
            assert definition["class"] in valid_classes


class TestMQTTCauses:
    """Test MQTT reason code classification."""

    @pytest.fixture
    def mqtt_causes(self):
        return load_causes("mqtt_causes.yaml")

    def test_mqtt_category_exists(self, mqtt_causes):
        """Verify MQTT category exists."""
        assert "mqtt" in mqtt_causes

    def test_mqtt_success(self, mqtt_causes):
        """Code 0 (Success) should be NORMAL."""
        mqtt = mqtt_causes["mqtt"]
        if 0 in mqtt:
            assert mqtt[0]["class"] == "NORMAL"

    def test_mqtt_causes_have_class(self, mqtt_causes):
        """All MQTT codes must have class field."""
        valid_classes = {
            "NORMAL", "ABNORMAL_RESOURCE", "ABNORMAL_PROTOCOL",
            "ABNORMAL_CONFIG", "ABNORMAL_TRANSPORT", "ADMIN"
        }
        mqtt = mqtt_causes["mqtt"]
        for code, definition in mqtt.items():
            assert "class" in definition
            assert definition["class"] in valid_classes


class TestPhase1bIntegration:
    """Test that all Phase 1b protocol files can be loaded by the knowledge system."""

    def test_gtp_loads_via_knowledge(self):
        """Verify GTP causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        gtp = load_yaml("gtp_causes.yaml")
        assert isinstance(gtp, dict)
        assert "gtpv2_c" in gtp
        assert "gtpv1_c" in gtp

    def test_pfcp_loads_via_knowledge(self):
        """Verify PFCP causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        pfcp = load_yaml("pfcp_causes.yaml")
        assert isinstance(pfcp, dict)
        assert "pfcp" in pfcp

    def test_diameter_loads_via_knowledge(self):
        """Verify Diameter causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        diameter = load_yaml("diameter_causes.yaml")
        assert isinstance(diameter, dict)
        assert "diameter" in diameter

    def test_dns_loads_via_knowledge(self):
        """Verify DNS causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        dns = load_yaml("dns_causes.yaml")
        assert isinstance(dns, dict)
        assert "dns" in dns

    def test_http_loads_via_knowledge(self):
        """Verify HTTP causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        http = load_yaml("http_causes.yaml")
        assert isinstance(http, dict)
        assert "http" in http

    def test_sip_loads_via_knowledge(self):
        """Verify SIP causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        sip = load_yaml("sip_causes.yaml")
        assert isinstance(sip, dict)
        assert "sip" in sip

    def test_radius_loads_via_knowledge(self):
        """Verify RADIUS causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        radius = load_yaml("radius_causes.yaml")
        assert isinstance(radius, dict)
        assert "radius" in radius

    def test_tls_loads_via_knowledge(self):
        """Verify TLS causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        tls = load_yaml("tls_causes.yaml")
        assert isinstance(tls, dict)
        assert "tls" in tls

    def test_tcp_loads_via_knowledge(self):
        """Verify TCP causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        tcp = load_yaml("tcp_causes.yaml")
        assert isinstance(tcp, dict)
        assert "tcp" in tcp

    def test_mqtt_loads_via_knowledge(self):
        """Verify MQTT causes can be loaded by knowledge.py."""
        from app.services.knowledge import load_yaml
        mqtt = load_yaml("mqtt_causes.yaml")
        assert isinstance(mqtt, dict)
        assert "mqtt" in mqtt
