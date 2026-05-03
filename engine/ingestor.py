"""
Loads resource inventory from mock JSON or Azure Resource Graph.
AZURE_MODE=false -> reads data/mock_resources.json
AZURE_MODE=true  -> queries Azure Resource Graph (read-only)
"""

import json
import logging
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

MOCK_DATA_PATH = Path(__file__).parent.parent / "data" / "mock_resources.json"


def load_resources() -> list[dict]:
    """Load Azure resource inventory from mock data or live Azure."""
    azure_mode = os.getenv("AZURE_MODE", "false").lower() == "true"

    if azure_mode:
        return _load_from_azure()
    else:
        return _load_from_mock()


def _load_from_mock() -> list[dict]:
    """Load resources from local mock JSON file."""
    if not MOCK_DATA_PATH.exists():
        raise FileNotFoundError(f"Mock data file not found: {MOCK_DATA_PATH}")

    with open(MOCK_DATA_PATH, "r", encoding="utf-8") as f:
        resources = json.load(f)

    if not isinstance(resources, list) or len(resources) == 0:
        raise ValueError("Mock data must be a non-empty list of resource objects")

    logger.info("Loaded %d resources from mock data (AZURE_MODE=false)", len(resources))
    return resources


def _load_from_azure() -> list[dict]:
    """Load resources from Azure Resource Graph (read-only)."""
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        raise EnvironmentError(
            "AZURE_SUBSCRIPTION_ID must be set when AZURE_MODE=true"
        )

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resource import ResourceManagementClient
    except ImportError as exc:
        raise ImportError(
            "azure-identity and azure-mgmt-resource are required for Azure mode. "
            "Run: pip install -r requirements.txt"
        ) from exc

    credential = DefaultAzureCredential()
    client = ResourceManagementClient(credential, subscription_id)

    resources = []
    # Read-only: only list_* calls
    for item in client.resources.list():
        resource_dict = {
            "id": item.id,
            "name": item.name,
            "type": item.type,
            "location": item.location,
            "tags": dict(item.tags) if item.tags else {},
            "criticality": _infer_criticality(item.tags),
            "properties": {},
        }
        resources.append(resource_dict)

    if not resources:
        raise ValueError("No resources returned from Azure subscription")

    logger.info(
        "Loaded %d resources from Azure subscription %s (AZURE_MODE=true)",
        len(resources),
        subscription_id,
    )
    return resources


def _infer_criticality(tags: dict | None) -> str:
    """Infer criticality from resource tags, default to 'medium'."""
    if not tags:
        return "medium"
    env = (tags.get("environment") or tags.get("env") or "").lower()
    mapping = {"production": "high", "prod": "high", "staging": "medium", "dev": "low", "development": "low"}
    return mapping.get(env, "medium")
