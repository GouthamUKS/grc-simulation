"""Produces output/summary.json consumed by the dashboard."""

import json
import logging
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from engine.control_mapper import ControlResult
from engine.gap_analyser import ExposureGap
from engine.risk_scorer import RiskFinding

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).parent.parent / "output"
SUMMARY_PATH = OUTPUT_DIR / "summary.json"


def write_summary(
    resources: list[dict],
    control_results: list[ControlResult],
    findings: list[RiskFinding],
    gaps: list[ExposureGap],
) -> Path:
    """Write summary.json and return the output path."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    mode = "azure" if os.getenv("AZURE_MODE", "false").lower() == "true" else "mock"
    total_resources = len(resources)
    total_checks = len(control_results)

    band_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        band = f.risk_band.lower()
        if band in band_counts:
            band_counts[band] += 1

    pass_count = sum(1 for r in control_results if r.status == "PASS")
    compliance_score = round((pass_count / total_checks * 100), 1) if total_checks > 0 else 0.0

    top_5 = [
        {
            "resource_name": f.resource_name,
            "resource_type": f.resource_type,
            "control_id": f.control_id,
            "control_title": f.control_title,
            "final_score": f.final_score,
            "risk_band": f.risk_band,
            "severity": f.severity,
            "priority": idx,
        }
        for idx, f in enumerate(findings[:5], start=1)
    ]

    gap_summaries = [
        {
            "gap_id": g.gap_id,
            "title": g.title,
            "section": g.section,
            "affected_resources": g.affected_resources,
            "aggregate_score": g.aggregate_score,
            "priority_rank": g.priority_rank,
            "finding_count": g.finding_count,
        }
        for g in gaps
    ]

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "total_resources": total_resources,
        "total_controls_checked": total_checks,
        "findings": {
            "critical": band_counts["critical"],
            "high": band_counts["high"],
            "medium": band_counts["medium"],
            "low": band_counts["low"],
            "pass": pass_count,
        },
        "top_5_findings": top_5,
        "exposure_gaps": gap_summaries,
        "compliance_score": compliance_score,
    }

    with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info("Summary written to %s (compliance score: %.1f%%)", SUMMARY_PATH, compliance_score)
    return SUMMARY_PATH
