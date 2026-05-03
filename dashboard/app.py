"""
Flask dashboard for GRC Simulation — served on localhost:5050 only.
For local portfolio use. No authentication required (local only).
Debug mode is always False.
"""

import json
import logging
from pathlib import Path

from flask import Flask, jsonify, render_template

logger = logging.getLogger(__name__)

SUMMARY_PATH = Path(__file__).parent.parent / "output" / "summary.json"

app = Flask(__name__, template_folder="templates", static_folder="static")


@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    """Return summary.json as JSON API response."""
    if not SUMMARY_PATH.exists():
        return jsonify({"error": "No summary found. Run cli.py first."}), 404

    with open(SUMMARY_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    return jsonify(data)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
