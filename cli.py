"""
GRC Simulation — Cloud Security Risk Assessment CLI

Usage:
  python cli.py --mode mock          # Run with mock data (default)
  python cli.py --mode azure         # Run with live Azure data (requires .env)
  python cli.py --mode mock --serve  # Run mock + launch dashboard
  python cli.py --help
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Configure logging before other imports
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "audit.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("cli")

from rich.console import Console
from rich.table import Table
from rich import box

from engine.ingestor import load_resources
from engine.control_mapper import map_controls
from engine.risk_scorer import score_findings
from engine.gap_analyser import analyse_gaps
from engine.remediation import generate_remediation
from reports.risk_register import write_risk_register
from reports.summary import write_summary

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GRC Simulation — Cloud Security Risk Assessment (Azure)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["mock", "azure"],
        default="mock",
        help="Data source: 'mock' (default) or 'azure' (requires .env config)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Launch the Flask dashboard on localhost:5050 after assessment",
    )
    return parser.parse_args()


def run_assessment(mode: str) -> dict:
    """Run the full GRC assessment pipeline and return summary data."""
    logger.info("=== GRC Simulation started (mode=%s) ===", mode)

    if mode == "azure":
        os.environ["AZURE_MODE"] = "true"
    else:
        os.environ["AZURE_MODE"] = "false"

    console.print(f"\n[bold cyan]GRC Simulation[/bold cyan] — Cloud Security Risk Assessment")
    console.print(f"Mode: [bold]{'MOCK DATA' if mode == 'mock' else 'LIVE AZURE'}[/bold]\n")

    with console.status("[bold green]Loading resources..."):
        resources = load_resources()
    console.print(f"[green]Loaded {len(resources)} resources[/green]")

    with console.status("[bold green]Mapping controls..."):
        control_results = map_controls(resources)
    console.print(f"[green]Mapped {len(control_results)} control checks[/green]")

    with console.status("[bold green]Scoring findings..."):
        findings = score_findings(control_results, resources)
    console.print(f"[green]Scored {len(findings)} findings[/green]")

    with console.status("[bold green]Analysing exposure gaps..."):
        gaps = analyse_gaps(findings)
    console.print(f"[green]Identified {len(gaps)} exposure gaps[/green]")

    with console.status("[bold green]Generating remediation plan..."):
        actions = generate_remediation(findings)
    console.print(f"[green]Generated {len(actions)} remediation actions[/green]")

    with console.status("[bold green]Writing reports..."):
        rr_path = write_risk_register(findings, actions)
        summary_path = write_summary(resources, control_results, findings, gaps)

    console.print(f"[green]Reports written:[/green] {rr_path.name}, {summary_path.name}\n")
    logger.info("=== GRC Simulation completed successfully ===")

    # Load summary for display
    import json
    with open(summary_path, "r") as f:
        summary = json.load(f)

    return summary


def print_summary_table(summary: dict) -> None:
    """Print the terminal summary table using rich."""
    findings = summary.get("findings", {})
    total_resources = summary.get("total_resources", 0)
    total_controls = summary.get("total_controls_checked", 0)
    compliance = summary.get("compliance_score", 0.0)
    gap_count = len(summary.get("exposure_gaps", []))

    table = Table(
        title="GRC SIMULATION — RISK ASSESSMENT REPORT",
        box=box.HEAVY_HEAD,
        show_header=True,
        header_style="bold cyan",
        min_width=60,
    )
    table.add_column("Metric", style="bold white", width=28)
    table.add_column("Value", width=30)

    table.add_row("Total Resources", str(total_resources))
    table.add_row("Controls Checked", str(total_controls))

    score_colour = "green" if compliance >= 80 else ("yellow" if compliance >= 60 else "red")
    table.add_row("Compliance Score", f"[{score_colour}]{compliance}%[/{score_colour}]")

    crit = findings.get("critical", 0)
    high = findings.get("high", 0)
    med = findings.get("medium", 0)
    low = findings.get("low", 0)

    table.add_row("Critical Findings", f"[bold red]{crit}[/bold red]  " + ("🔴" if crit > 0 else ""))
    table.add_row("High Findings", f"[bold yellow]{high}[/bold yellow]  " + ("🟠" if high > 0 else ""))
    table.add_row("Medium Findings", f"[yellow]{med}[/yellow]  " + ("🟡" if med > 0 else ""))
    table.add_row("Low Findings", f"[green]{low}[/green]  " + ("🟢" if low > 0 else ""))
    table.add_row("Exposure Gaps", str(gap_count))

    console.print(table)

    # Top 5 findings
    top5 = summary.get("top_5_findings", [])
    if top5:
        console.print("\n[bold cyan]Top 5 Risk Findings[/bold cyan]")
        top_table = Table(box=box.SIMPLE, show_header=True, header_style="bold white")
        top_table.add_column("#", width=4)
        top_table.add_column("Resource", width=25)
        top_table.add_column("Control", width=10)
        top_table.add_column("Score", width=8)
        top_table.add_column("Band", width=10)

        band_colours = {"CRITICAL": "bold red", "HIGH": "bold yellow", "MEDIUM": "yellow", "LOW": "green"}
        for item in top5:
            band = item.get("risk_band", "LOW")
            colour = band_colours.get(band, "white")
            top_table.add_row(
                str(item.get("priority", "")),
                item.get("resource_name", "")[:25],
                item.get("control_id", ""),
                str(item.get("final_score", "")),
                f"[{colour}]{band}[/{colour}]",
            )
        console.print(top_table)

    console.print(
        "\n[dim]Output files: output/risk_register.csv · output/summary.json · logs/audit.log[/dim]\n"
    )


def launch_dashboard() -> None:
    """Start the Flask dashboard."""
    console.print("[bold cyan]Launching dashboard on http://localhost:5050[/bold cyan]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    # Add dashboard dir to path for Flask template resolution
    dashboard_dir = Path(__file__).parent / "dashboard"
    sys.path.insert(0, str(dashboard_dir))

    from dashboard.app import app
    app.run(host="127.0.0.1", port=5050, debug=False)


def main() -> None:
    args = parse_args()
    summary = run_assessment(args.mode)
    print_summary_table(summary)

    if args.serve:
        launch_dashboard()


if __name__ == "__main__":
    main()
