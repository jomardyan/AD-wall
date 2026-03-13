"""
AD-Wall Web Dashboard
Flask application that reads JSON assessment output and serves a web UI.
"""

import os
import json
import glob
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file, abort
import io
import csv

app = Flask(__name__)

# Evidence store directory — override via ADWALL_DATA_DIR env var
DATA_DIR = os.environ.get("ADWALL_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "output"))
DATA_DIR = os.path.abspath(DATA_DIR)


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _list_assessment_files():
    """Return sorted list of ADWall_Assessment_*.json paths (newest first)."""
    pattern = os.path.join(DATA_DIR, "ADWall_Assessment_*.json")
    files = sorted(glob.glob(pattern), reverse=True)
    return files


def _load_assessment(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _latest_assessment() -> dict | None:
    files = _list_assessment_files()
    if not files:
        return None
    return _load_assessment(files[0])


def _get_findings(assessment: dict) -> list:
    return assessment.get("Findings", [])


def _severity_order(severity: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}.get(severity, 5)


# ---------------------------------------------------------------------------
# Routes — pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    assessment = _latest_assessment()
    return render_template("index.html", has_data=(assessment is not None))


# ---------------------------------------------------------------------------
# Routes — API
# ---------------------------------------------------------------------------

@app.route("/api/findings")
def api_findings():
    """Return findings from the latest assessment, with optional filters."""
    assessment = _latest_assessment()
    if not assessment:
        return jsonify({"error": "No assessment data found", "findings": [], "total": 0}), 404

    findings = _get_findings(assessment)

    # Query param filters
    severity = request.args.get("severity")
    category = request.args.get("category")
    search   = (request.args.get("search") or "").lower()

    if severity:
        findings = [f for f in findings if f.get("Severity", "").lower() == severity.lower()]
    if category:
        findings = [f for f in findings if f.get("Category", "").lower() == category.lower()]
    if search:
        findings = [
            f for f in findings
            if search in f.get("Title", "").lower() or search in f.get("Description", "").lower()
        ]

    findings = sorted(findings, key=lambda f: _severity_order(f.get("Severity", "")))

    return jsonify({
        "total": len(findings),
        "findings": findings,
        "generatedAt": assessment.get("GeneratedAt"),
        "tool": assessment.get("Tool"),
    })


@app.route("/api/score")
def api_score():
    """Return the overall posture grade and score."""
    assessment = _latest_assessment()
    if not assessment:
        return jsonify({"error": "No assessment data found"}), 404

    grade = assessment.get("PostureGrade") or {}
    findings = _get_findings(assessment)

    severity_counts = {}
    for f in findings:
        sev = f.get("Severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    category_counts = {}
    for f in findings:
        cat = f.get("Category", "Unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return jsonify({
        "grade": grade.get("Grade", "N/A"),
        "score": grade.get("Score", 0),
        "description": grade.get("Description", ""),
        "severityCounts": severity_counts,
        "categoryCounts": category_counts,
        "totalFindings": len(findings),
        "generatedAt": assessment.get("GeneratedAt"),
    })


@app.route("/api/snapshots")
def api_snapshots():
    """List all available assessment snapshots."""
    files = _list_assessment_files()
    snapshots = []
    for f in files:
        try:
            data = _load_assessment(f)
            grade_obj = data.get("PostureGrade") or {}
            snapshots.append({
                "file": os.path.basename(f),
                "generatedAt": data.get("GeneratedAt"),
                "grade": grade_obj.get("Grade", "N/A"),
                "score": grade_obj.get("Score", 0),
                "totalFindings": data.get("TotalFindings", 0),
                "criticalCount": grade_obj.get("CriticalCount", 0),
                "highCount": grade_obj.get("HighCount", 0),
            })
        except Exception:
            pass
    return jsonify({"snapshots": snapshots, "count": len(snapshots)})


@app.route("/api/drift")
def api_drift():
    """Compare the two most recent assessments to detect drift."""
    files = _list_assessment_files()
    if len(files) < 2:
        return jsonify({"error": "Need at least 2 assessments for drift comparison", "drift": {}}), 422

    newer = _load_assessment(files[0])
    older = _load_assessment(files[1])

    newer_findings = {f.get("RuleId"): f for f in _get_findings(newer)}
    older_findings = {f.get("RuleId"): f for f in _get_findings(older)}

    new_ids      = set(newer_findings.keys())
    old_ids      = set(older_findings.keys())
    appeared     = [newer_findings[rid] for rid in sorted(new_ids - old_ids)]
    resolved     = [older_findings[rid] for rid in sorted(old_ids - new_ids)]
    persisted    = [newer_findings[rid] for rid in sorted(new_ids & old_ids)]

    older_grade  = (older.get("PostureGrade") or {})
    newer_grade  = (newer.get("PostureGrade") or {})

    return jsonify({
        "baseline": {
            "file": os.path.basename(files[1]),
            "generatedAt": older.get("GeneratedAt"),
            "grade": older_grade.get("Grade", "N/A"),
            "score": older_grade.get("Score", 0),
            "totalFindings": older.get("TotalFindings", 0),
        },
        "current": {
            "file": os.path.basename(files[0]),
            "generatedAt": newer.get("GeneratedAt"),
            "grade": newer_grade.get("Grade", "N/A"),
            "score": newer_grade.get("Score", 0),
            "totalFindings": newer.get("TotalFindings", 0),
        },
        "drift": {
            "newFindings": appeared,
            "resolvedFindings": resolved,
            "persistedFindings": persisted,
            "newCount": len(appeared),
            "resolvedCount": len(resolved),
            "persistedCount": len(persisted),
            "scoreDelta": (newer_grade.get("Score", 0) or 0) - (older_grade.get("Score", 0) or 0),
        }
    })


@app.route("/api/export")
def api_export():
    """Export findings as CSV."""
    assessment = _latest_assessment()
    if not assessment:
        abort(404)

    findings = _get_findings(assessment)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["RuleId", "Severity", "Category", "Title", "AffectedCount",
                     "AffectedObjects", "Description", "Remediation", "MitreAttack", "DetectedAt"])
    for f in findings:
        affected_str = "; ".join(str(a) for a in (f.get("AffectedObjects") or [])[:10])
        writer.writerow([
            f.get("RuleId", ""),
            f.get("Severity", ""),
            f.get("Category", ""),
            f.get("Title", ""),
            f.get("AffectedCount", 0),
            affected_str,
            (f.get("Description") or "").replace("\n", " "),
            (f.get("Remediation") or "").replace("\n", " "),
            f.get("MitreAttack", ""),
            f.get("DetectedAt", ""),
        ])

    output.seek(0)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"ADWall_Findings_{timestamp}.csv",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("ADWALL_PORT", 5000))
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"AD-Wall Dashboard starting on http://localhost:{port}")
    print(f"Reading assessment data from: {DATA_DIR}")
    app.run(host="0.0.0.0", port=port, debug=False)
