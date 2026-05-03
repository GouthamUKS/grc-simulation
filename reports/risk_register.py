"""Produces output/risk_register.csv from scored findings and remediation actions."""

import csv
import logging
from pathlib import Path

from engine.remediation import RemediationAction
from engine.risk_scorer import RiskFinding

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).parent.parent / "output"
RISK_REGISTER_PATH = OUTPUT_DIR / "risk_register.csv"

COLUMNS = [
    "finding_id",
    "resource_name",
    "resource_type",
    "control_id",
    "control_title",
    "severity",
    "status",
    "likelihood",
    "impact",
    "asset_criticality",
    "final_score",
    "risk_band",
    "remediation_priority",
    "effort_estimate",
    "owner_suggestion",
]


def write_risk_register(
    findings: list[RiskFinding],
    actions: list[RemediationAction],
) -> Path:
    """Write risk_register.csv and return the output path."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Build lookup: finding_ref -> action
    action_map = {a.finding_ref: a for a in actions}

    rows = []
    for idx, finding in enumerate(findings, start=1):
        finding_id = f"FINDING-{idx:04d}"
        ref = f"{finding.control_id}::{finding.resource_id}"
        action = action_map.get(ref)

        rows.append({
            "finding_id": finding_id,
            "resource_name": finding.resource_name,
            "resource_type": finding.resource_type,
            "control_id": finding.control_id,
            "control_title": finding.control_title,
            "severity": finding.severity,
            "status": finding.status,
            "likelihood": finding.likelihood,
            "impact": finding.impact,
            "asset_criticality": finding.resource_criticality,
            "final_score": finding.final_score,
            "risk_band": finding.risk_band,
            "remediation_priority": action.priority if action else idx,
            "effort_estimate": action.effort_estimate if action else "Medium",
            "owner_suggestion": action.owner_suggestion if action else "Cloud Infrastructure Team",
        })

    with open(RISK_REGISTER_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    logger.info("Risk register written to %s (%d findings)", RISK_REGISTER_PATH, len(rows))
    return RISK_REGISTER_PATH
