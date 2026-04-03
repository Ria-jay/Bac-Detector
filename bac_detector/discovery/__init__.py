"""
Discovery module — endpoint ingestion from OpenAPI specs and endpoint lists.

Public API:
    run_discovery(config)           -> EndpointInventory
    parse_openapi(source, base)     -> list[Endpoint]
    parse_endpoint_list(path, base) -> list[Endpoint]
    build_inventory(batches)        -> EndpointInventory
    EndpointInventory
"""

from bac_detector.discovery.endpoint_list import (
    parse_endpoint_list,
    parse_endpoint_list_text,
)
from bac_detector.discovery.inventory import EndpointInventory, build_inventory
from bac_detector.discovery.openapi_parser import parse_openapi
from bac_detector.discovery.runner import run_discovery

__all__ = [
    "EndpointInventory",
    "build_inventory",
    "parse_endpoint_list",
    "parse_endpoint_list_text",
    "parse_openapi",
    "run_discovery",
]
