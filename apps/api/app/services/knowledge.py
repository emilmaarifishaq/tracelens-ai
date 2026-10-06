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


def load_yaml(filename: str) -> dict[str, Any]:
    path = KNOWLEDGE_DIR / filename
    with path.open() as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Knowledge file {filename} must contain a mapping")
    return data
