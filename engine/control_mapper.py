"""
Maps each resource against each applicable CIS control.
Returns a list of ControlResult objects:
  - resource_id, resource_name, resource_type
  - control_id, control_title, severity
  - status: "PASS" | "FAIL" | "PARTIAL" | "NOT_APPLICABLE"
  - evidence: dict of actual vs expected values
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

CONTROLS_PATH = Path(__file__).parent.parent / "frameworks" / "cis_azure_benchmark.json"


@dataclass
class ControlResult:
    resource_id: str
    resource_name: str
    resource_type: str
    control_id: str
    control_title: str
    section: str
    severity: str
    likelihood: int
    impact: int
    status: str  # PASS | FAIL | PARTIAL | NOT_APPLICABLE
    evidence: dict = field(default_factory=dict)
    remediation_template: str = ""


def load_controls() -> list[dict]:
    """Load CIS benchmark controls from JSON file."""
    with open(CONTROLS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _get_nested_value(obj: dict, dotted_path: str):
    """Traverse a dict using dot-notation path. Returns None if any key is missing."""
    keys = dotted_path.split(".")
    current = obj
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _evaluate_control(resource: dict, control: dict) -> ControlResult:
    """Evaluate a single resource against a single control."""
    check_property = control.get("check_property", "")
    expected_value = control.get("expected_value")

    actual_value = _get_nested_value(resource, check_property)

    if actual_value is None:
        status = "NOT_APPLICABLE"
    elif actual_value == expected_value:
        status = "PASS"
    elif isinstance(expected_value, bool) and isinstance(actual_value, bool):
        status = "FAIL"
    elif isinstance(expected_value, str) and isinstance(actual_value, str):
        if actual_value.lower() == expected_value.lower():
            status = "PASS"
        else:
            status = "FAIL"
    else:
        status = "FAIL"

    evidence = {
        "property": check_property,
        "expected": expected_value,
        "actual": actual_value,
    }

    return ControlResult(
        resource_id=resource.get("id", ""),
        resource_name=resource.get("name", ""),
        resource_type=resource.get("type", ""),
        control_id=control.get("id", ""),
        control_title=control.get("title", ""),
        section=control.get("section", ""),
        severity=control.get("severity", "medium"),
        likelihood=control.get("likelihood", 2),
        impact=control.get("impact", 2),
        status=status,
        evidence=evidence,
        remediation_template=control.get("remediation_template", ""),
    )


def map_controls(resources: list[dict]) -> list[ControlResult]:
    """Map all resources against all applicable CIS controls."""
    controls = load_controls()
    results: list[ControlResult] = []

    for control in controls:
        applicable_types = control.get("resource_types", [])
        matched_resources = [
            r for r in resources if r.get("type", "") in applicable_types
        ]

        if not matched_resources:
            logger.debug(
                "Control %s: no resources of types %s found",
                control.get("id"),
                applicable_types,
            )
            continue

        for resource in matched_resources:
            result = _evaluate_control(resource, control)
            results.append(result)

    pass_count = sum(1 for r in results if r.status == "PASS")
    fail_count = sum(1 for r in results if r.status == "FAIL")
    na_count = sum(1 for r in results if r.status == "NOT_APPLICABLE")
    logger.info(
        "Control mapping complete: %d results (%d PASS, %d FAIL, %d N/A)",
        len(results),
        pass_count,
        fail_count,
        na_count,
    )
    return results
