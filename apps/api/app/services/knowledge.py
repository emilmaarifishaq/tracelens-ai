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


def load_yaml(filename: str) -> dict[str, Any]:
    path = KNOWLEDGE_DIR / filename
    with path.open() as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Knowledge file {filename} must contain a mapping")
    return data
