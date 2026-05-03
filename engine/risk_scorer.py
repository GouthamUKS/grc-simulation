"""
Scores each FAIL/PARTIAL ControlResult using:
  raw_score = likelihood x impact
  asset_weight = { "critical": 1.5, "high": 1.2, "medium": 1.0, "low": 0.7 }
  final_score = raw_score x asset_weight
  risk_band = "CRITICAL" (>=15) | "HIGH" (>=10) | "MEDIUM" (>=5) | "LOW" (<5)
"""

import logging
from dataclasses import dataclass

from engine.control_mapper import ControlResult

logger = logging.getLogger(__name__)

ASSET_WEIGHTS: dict[str, float] = {
    "critical": 1.5,
    "high": 1.2,
    "medium": 1.0,
    "low": 0.7,
}


def _risk_band(score: float) -> str:
    if score >= 15:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    else:
        return "LOW"


@dataclass
class RiskFinding:
    resource_id: str
    resource_name: str
    resource_type: str
    resource_criticality: str
    control_id: str
    control_title: str
    section: str
    severity: str
    status: str
    likelihood: int
    impact: int
    raw_score: float
    asset_weight: float
    final_score: float
    risk_band: str
    evidence: dict
    remediation_template: str


def score_findings(
    control_results: list[ControlResult],
    resources: list[dict],
) -> list[RiskFinding]:
    """Score FAIL/PARTIAL control results and return sorted RiskFinding list."""
    resource_map = {r.get("id", ""): r for r in resources}

    findings: list[RiskFinding] = []

    for result in control_results:
        if result.status not in ("FAIL", "PARTIAL"):
            continue

        resource = resource_map.get(result.resource_id, {})
        criticality = resource.get("criticality", "medium").lower()
        weight = ASSET_WEIGHTS.get(criticality, 1.0)

        raw_score = float(result.likelihood * result.impact)
        final_score = round(raw_score * weight, 2)

        findings.append(
            RiskFinding(
                resource_id=result.resource_id,
                resource_name=result.resource_name,
                resource_type=result.resource_type,
                resource_criticality=criticality,
                control_id=result.control_id,
                control_title=result.control_title,
                section=result.section,
                severity=result.severity,
                status=result.status,
                likelihood=result.likelihood,
                impact=result.impact,
                raw_score=raw_score,
                asset_weight=weight,
                final_score=final_score,
                risk_band=_risk_band(final_score),
                evidence=result.evidence,
                remediation_template=result.remediation_template,
            )
        )

    findings.sort(key=lambda f: f.final_score, reverse=True)
    logger.info("Scored %d FAIL/PARTIAL findings", len(findings))
    return findings
