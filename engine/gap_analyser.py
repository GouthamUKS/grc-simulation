"""
Identifies exposure gaps: clusters of related findings that together
indicate a systemic control weakness (e.g. 3+ storage accounts with
public access = "Public Storage Exposure Gap").
Returns a list of ExposureGap objects with:
  - gap_id, title, affected_resources (list), aggregate_score, priority_rank
"""

import logging
from dataclasses import dataclass, field

from engine.risk_scorer import RiskFinding

logger = logging.getLogger(__name__)

# Minimum aggregate score for a gap to be surfaced (filters single low-severity pairs)
MIN_GAP_AGGREGATE_SCORE = 20.0


@dataclass
class ExposureGap:
    gap_id: str
    title: str
    section: str
    control_id: str
    affected_resources: list[str] = field(default_factory=list)
    aggregate_score: float = 0.0
    priority_rank: int = 0
    finding_count: int = 0


def analyse_gaps(findings: list[RiskFinding]) -> list[ExposureGap]:
    """
    Identify systemic exposure gaps by grouping findings that share the
    same control_id (same control failed across multiple resources).
    A gap triggers when 2+ resources share the same FAIL control.
    """
    # Group findings by (control_id, section)
    groups: dict[str, list[RiskFinding]] = {}
    for finding in findings:
        key = finding.control_id
        groups.setdefault(key, []).append(finding)

    gaps: list[ExposureGap] = []
    for control_id, group_findings in groups.items():
        if len(group_findings) < 2:
            continue  # not a systemic gap

        aggregate_score = round(sum(f.final_score for f in group_findings), 2)
        if aggregate_score < MIN_GAP_AGGREGATE_SCORE:
            continue  # low-noise gap — below threshold

        first = group_findings[0]
        affected = [f.resource_name for f in group_findings]

        title = _gap_title(first.control_title, first.section, len(group_findings))

        gap = ExposureGap(
            gap_id=f"GAP-{control_id}",
            title=title,
            section=first.section,
            control_id=control_id,
            affected_resources=affected,
            aggregate_score=aggregate_score,
            finding_count=len(group_findings),
        )
        gaps.append(gap)

    gaps.sort(key=lambda g: g.aggregate_score, reverse=True)
    for rank, gap in enumerate(gaps, start=1):
        gap.priority_rank = rank

    logger.info("Identified %d exposure gaps", len(gaps))
    return gaps


def _gap_title(control_title: str, section: str, count: int) -> str:
    """Generate a human-readable gap title."""
    short_map = {
        "Ensure that 'Secure transfer required' is set to 'Enabled' for Storage Accounts": "Insecure Storage Transfer",
        "Ensure that storage account access is restricted (no public network access)": "Public Storage Exposure",
        "Ensure Storage Account Blob Public Access is disabled": "Blob Public Access Exposure",
        "Ensure that 'Soft Delete' is enabled for Azure Storage Blob": "Missing Blob Soft Delete",
        "Ensure that SSH access is restricted from the internet": "Internet SSH Exposure",
        "Ensure that RDP access is restricted from the internet": "Internet RDP Exposure",
        "Ensure Network Security Group Flow Logs are enabled": "Missing NSG Flow Logs",
        "Ensure that Azure Key Vault Soft Delete is enabled": "Key Vault Soft Delete Missing",
        "Ensure that Azure Key Vault Purge Protection is enabled": "Key Vault Purge Protection Missing",
        "Ensure Key Vault public network access is disabled": "Key Vault Public Exposure",
        "Ensure that 'Auditing' is set to 'On' for SQL Servers": "SQL Auditing Disabled",
        "Ensure that SQL Server public network access is disabled": "Public SQL Server Exposure",
        "Ensure SQL Server Advanced Threat Protection is enabled": "SQL Threat Protection Disabled",
        "Ensure that managed disk encryption is enabled for Virtual Machines": "VM Disk Encryption Missing",
        "Ensure that boot diagnostics are enabled for Virtual Machines": "VM Boot Diagnostics Missing",
        "Ensure diagnostic logs are enabled for Key Vaults": "Key Vault Logging Disabled",
        "Ensure that Azure Web Applications have HTTPS-only enabled": "Web App HTTP Exposure",
        "Ensure Web Application remote debugging is disabled": "Web App Remote Debug Enabled",
        "Ensure SQL Server Active Directory administrator is configured": "SQL AAD Admin Missing",
    }
    short = short_map.get(control_title, control_title[:50])
    return f"{short} ({count} resources affected)"
