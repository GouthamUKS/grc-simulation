# GRC Simulation — Cloud Security Risk Assessment (Azure)

A free, locally-runnable Cloud Security Risk Assessment and GRC Simulation tool modelled on real enterprise GRC workflows (ISO 27001, NIST CSF, CIS Azure Benchmark v2.0). The tool ingests either live Azure resource data (read-only) or local mock data (default) and produces a scored risk register, control gap report, and remediation plan — all from the terminal with a local web dashboard.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        cli.py (entry point)                      │
└────────────────────────────┬─────────────────────────────────────┘
                             │
          ┌──────────────────▼──────────────────┐
          │           engine/ pipeline           │
          │                                      │
          │  ingestor.py ──► control_mapper.py   │
          │       │                 │            │
          │  [resources]    [ControlResult[]]    │
          │                         │            │
          │                risk_scorer.py        │
          │                         │            │
          │                  [RiskFinding[]]     │
          │                    /        \        │
          │          gap_analyser   remediation  │
          │                    \        /        │
          │                  [gaps] [actions]   │
          └──────────────────┬──────────────────┘
                             │
          ┌──────────────────▼──────────────────┐
          │            reports/                  │
          │  risk_register.py  ► output/*.csv   │
          │  summary.py        ► output/*.json  │
          └──────────────────┬──────────────────┘
                             │
          ┌──────────────────▼──────────────────┐
          │     dashboard/app.py (Flask)         │
          │     localhost:5050 (local only)      │
          └─────────────────────────────────────┘
```

Data sources:
- `AZURE_MODE=false` (default) — reads `data/mock_resources.json`
- `AZURE_MODE=true` — queries live Azure via `DefaultAzureCredential` (read-only)

---

## Quick Start

**Step 1:** Clone the repository
```bash
git clone <repo-url>
cd grc-simulation
```

**Step 2:** Install dependencies
```bash
pip install -r requirements.txt
```

**Step 3:** Run the assessment with the local dashboard
```bash
python cli.py --mode mock --serve
```

**Step 4:** Open your browser to `http://localhost:5050`

The terminal will print a summary table immediately. The dashboard provides a visual SOC-style view of the findings, exposure gaps, and compliance score.

---

## Azure Mode Setup

To run against a live Azure subscription, create a service principal with **Reader** role only:

```bash
az ad sp create-for-rbac --name "grc-sim-reader" --role Reader \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

> **Security note:** This service principal has read-only access. It cannot create, modify, or delete any resource.

Copy `.env.example` to `.env` and populate the values printed by the command above:

```bash
cp .env.example .env
```

```
AZURE_MODE=true
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_TENANT_ID=<your-tenant-id>
AZURE_CLIENT_ID=<appId from sp create output>
AZURE_CLIENT_SECRET=<password from sp create output>
```

Then run:
```bash
python cli.py --mode azure --serve
```

> **Never commit `.env` to source control.** It is listed in `.gitignore`.

---

## Output Files

| File | Description |
|------|-------------|
| `output/risk_register.csv` | Full finding register with one row per resource-control failure. Columns: `finding_id`, `resource_name`, `resource_type`, `control_id`, `control_title`, `severity`, `status`, `likelihood`, `impact`, `asset_criticality`, `final_score`, `risk_band`, `remediation_priority`, `effort_estimate`, `owner_suggestion` |
| `output/summary.json` | Aggregated summary consumed by the dashboard. Contains total counts, compliance score, top 5 findings, and exposure gaps. |
| `logs/audit.log` | Timestamped audit trail of every scoring event, written by Python's `logging` module. |

---

## Extending the Framework

To add more CIS controls, edit `frameworks/cis_azure_benchmark.json`. Each control entry follows this schema:

```json
{
  "id": "CIS-X.Y",
  "section": "Section Name",
  "title": "Human-readable control title",
  "resource_types": ["Microsoft.ResourceProvider/resourceType"],
  "check_property": "properties.someNestedProperty",
  "expected_value": true,
  "severity": "critical | high | medium | low",
  "likelihood": 1,
  "impact": 5,
  "remediation_template": "Step-by-step remediation description."
}
```

- `check_property` supports dot notation for nested properties (e.g. `properties.networkAcls.defaultAction`)
- `resource_types` must match the Azure resource type string exactly
- `severity`, `likelihood`, and `impact` drive the risk scoring formula

No code changes are needed — the engine reads controls dynamically from the JSON file.

---

## Risk Scoring Formula

```
raw_score    = likelihood × impact
asset_weight = { critical: 1.5, high: 1.2, medium: 1.0, low: 0.7 }
final_score  = raw_score × asset_weight

risk_band:
  CRITICAL  final_score >= 15
  HIGH      final_score >= 10
  MEDIUM    final_score >= 5
  LOW       final_score < 5
```

`compliance_score = (PASS count / total checks) × 100`

---

## Portfolio Notes

**Skills demonstrated:**
- GRC framework implementation (CIS Azure Benchmark v2.0, ISO 27001 risk scoring model)
- Azure cloud security posture assessment (resource inventory, control mapping)
- Python software engineering: dataclasses, modular pipeline, type hints, defensive coding
- Security-first development: read-only operations, no hardcoded credentials, input validation
- Full-stack delivery: CLI tool + REST API + single-page dashboard
- Risk quantification: likelihood × impact scoring with asset-criticality weighting

**Framework alignment:**
- CIS Azure Benchmark v2.0 (controls across IAM, Storage, Networking, Key Vault, SQL, VMs, Logging)
- NIST CSF: Identify → Protect → Detect mapping via control sections
- ISO 27001 Annex A: risk register format with likelihood, impact, and treatment prioritisation

**Frameworks referenced:**
- CIS Azure Benchmark v2.0
- NIST Cybersecurity Framework (CSF) 2.0
- ISO/IEC 27001:2022
