import json
from typing import Any

import yaml
from fastapi import UploadFile


EndpointMapping = dict[str, dict[str, str]]


async def parse_endpoint_mapping(file: UploadFile | None) -> EndpointMapping:
    if file is None:
        return {}

    content = await file.read()
    if not content:
        return {}

    text = content.decode("utf-8", errors="ignore")
    data = _load_mapping_document(text)
    mapping: EndpointMapping = {}

    if isinstance(data, dict):
        _parse_manual_mapping(data, mapping)
        _parse_kubernetes_mapping(data, mapping)

    return mapping


def _load_mapping_document(text: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {}


def _parse_manual_mapping(data: dict, mapping: EndpointMapping) -> None:
    nodes = data.get("nodes") or data.get("endpoints") or data.get("mapping")
    if isinstance(nodes, dict):
        for address, value in nodes.items():
            if isinstance(value, str):
                mapping[str(address)] = {"label": value, "source": "manual"}
            elif isinstance(value, dict):
                label = str(value.get("label") or value.get("name") or address)
                namespace = str(value.get("namespace") or "")
                mapping[str(address)] = {"label": label, "namespace": namespace, "source": "manual"}

    if isinstance(nodes, list):
        for item in nodes:
            if not isinstance(item, dict):
                continue
            address = item.get("ip") or item.get("address")
            if not address:
                continue
            mapping[str(address)] = {
                "label": str(item.get("label") or item.get("name") or address),
                "namespace": str(item.get("namespace") or ""),
                "source": "manual",
            }


def _parse_kubernetes_mapping(data: dict, mapping: EndpointMapping) -> None:
    items = data.get("items")
    if not isinstance(items, list):
        return

    for item in items:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") or {}
        status = item.get("status") or {}
        annotations = metadata.get("annotations") or {}
        pod_name = str(metadata.get("name") or "pod")
        namespace = str(metadata.get("namespace") or "default")

        addresses = []
        pod_ip = status.get("podIP")
        if isinstance(pod_ip, str):
            addresses.append(pod_ip)

        pod_ips = status.get("podIPs")
        if isinstance(pod_ips, list):
            for item_ip in pod_ips:
                if isinstance(item_ip, dict) and isinstance(item_ip.get("ip"), str):
                    addresses.append(item_ip["ip"])

        network_status = annotations.get("k8s.v1.cni.cncf.io/network-status")
        addresses.extend(_parse_multus_addresses(network_status))

        for address in sorted(set(addresses)):
            mapping[address] = {
                "label": pod_name,
                "namespace": namespace,
                "source": "kubernetes",
            }


def _parse_multus_addresses(value: object) -> list[str]:
    if not isinstance(value, str):
        return []

    try:
        networks = json.loads(value)
    except json.JSONDecodeError:
        return []

    addresses = []
    if isinstance(networks, list):
        for network in networks:
            if not isinstance(network, dict):
                continue
            ips = network.get("ips")
            if isinstance(ips, list):
                addresses.extend(str(ip) for ip in ips)

    return addresses
