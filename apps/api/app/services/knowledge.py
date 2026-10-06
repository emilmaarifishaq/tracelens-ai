from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "knowledge"


@lru_cache(maxsize=1)
def load_error_codes() -> dict[str, dict[str, dict[str, Any]]]:
    return load_yaml("error_codes.yaml")


@lru_cache(maxsize=1)
def load_procedure_rules() -> list[dict[str, Any]]:
    data = load_yaml("procedure_rules.yaml")
    return data.get("procedure_groups", [])


@lru_cache(maxsize=1)
def load_ngap_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load NGAP cause classification (TS 38.413)."""
    return load_yaml("ngap_causes.yaml")


@lru_cache(maxsize=1)
def load_nas_5gs_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load NAS-5GS cause classification (TS 24.501)."""
    return load_yaml("nas_5gs_causes.yaml")


@lru_cache(maxsize=1)
def load_nas_eps_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load NAS-EPS cause classification (TS 24.301)."""
    return load_yaml("nas_eps_causes.yaml")


@lru_cache(maxsize=1)
def load_gtp_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load GTP cause classification (GTPv2-C and GTPv1-C)."""
    return load_yaml("gtp_causes.yaml")


@lru_cache(maxsize=1)
def load_pfcp_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load PFCP cause classification (N4 interface)."""
    return load_yaml("pfcp_causes.yaml")


@lru_cache(maxsize=1)
def load_diameter_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load Diameter result code classification."""
    return load_yaml("diameter_causes.yaml")


@lru_cache(maxsize=1)
def load_dns_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load DNS response code classification."""
    return load_yaml("dns_causes.yaml")


@lru_cache(maxsize=1)
def load_http_causes() -> dict[str, dict[str, dict[str, Any]]]:
    """Load HTTP status code classification (SBI)."""
    return load_yaml("http_causes.yaml")


@lru_cache(maxsize=1)
def load_sip_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load SIP response code classification (IMS)."""
    return load_yaml("sip_causes.yaml")


@lru_cache(maxsize=1)
def load_radius_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load RADIUS code classification."""
    return load_yaml("radius_causes.yaml")


@lru_cache(maxsize=1)
def load_tls_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load TLS alert code classification."""
    return load_yaml("tls_causes.yaml")


@lru_cache(maxsize=1)
def load_tcp_causes() -> dict[str, dict[str, dict[str, Any]]]:
    """Load TCP condition classification."""
    return load_yaml("tcp_causes.yaml")


@lru_cache(maxsize=1)
def load_mqtt_causes() -> dict[str, dict[int, dict[str, Any]]]:
    """Load MQTT reason code classification."""
    return load_yaml("mqtt_causes.yaml")


def load_yaml(filename: str) -> dict[str, Any]:
    path = KNOWLEDGE_DIR / filename
    with path.open() as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Knowledge file {filename} must contain a mapping")
    return data
