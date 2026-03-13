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


@app.route("/api/export/cef")
def api_export_cef():
    """Export findings as CEF (Common Event Format) for SIEM ingestion."""
    assessment = _latest_assessment()
    if not assessment:
        abort(404)

    findings = _get_findings(assessment)
    severity_map = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3, "Informational": 1}

    lines = []
    for f in findings:
        sev     = severity_map.get(f.get("Severity", ""), 1)
        rule_id = (f.get("RuleId") or "UNKNOWN").replace("|", "/")
        title   = (f.get("Title") or "").replace("|", "/")
        desc    = (f.get("Description") or "").replace("|", "/").replace("\n", " ")
        remedi  = (f.get("Remediation") or "").replace("|", "/").replace("\n", " ")
        mitre   = (f.get("MitreAttack") or "").replace("|", "/")
        aff_cnt = f.get("AffectedCount", 0)
        det_at  = f.get("DetectedAt", "")
        ext = f"msg={desc} act={remedi} cs1={mitre} cs1Label=MitreAttack cnt={aff_cnt} rt={det_at}"
        lines.append(f"CEF:0|AD-Wall|AD-Wall|1.0.0|{rule_id}|{title}|{sev}|{ext}")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return send_file(
        io.BytesIO("\n".join(lines).encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"ADWall_SIEM_{timestamp}.cef",
    )


@app.route("/api/export/splunk")
def api_export_splunk():
    """Export findings as Splunk HEC-compatible NDJSON."""
    import time
    assessment = _latest_assessment()
    if not assessment:
        abort(404)

    findings = _get_findings(assessment)
    source_type = request.args.get("sourcetype", "adwall:finding")
    index = request.args.get("index", "security")

    events = []
    epoch = time.time()
    for f in findings:
        event = {
            "time": round(epoch, 3),
            "sourcetype": source_type,
            "index": index,
            "source": "ADWall",
            "event": {
                "rule_id": f.get("RuleId"),
                "title": f.get("Title"),
                "severity": f.get("Severity"),
                "category": f.get("Category"),
                "description": f.get("Description"),
                "affected_objects": f.get("AffectedObjects"),
                "affected_count": f.get("AffectedCount"),
                "remediation": f.get("Remediation"),
                "mitre_attack": f.get("MitreAttack"),
                "detected_at": f.get("DetectedAt"),
                "verification_command": f.get("VerificationCommand", ""),
            }
        }
        events.append(json.dumps(event))

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return send_file(
        io.BytesIO("\n".join(events).encode("utf-8")),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"ADWall_Splunk_{timestamp}.json",
    )


@app.route("/api/fix-guide/<rule_id>")
def api_fix_guide(rule_id: str):
    """Return the full fix guide for a specific finding by RuleId."""
    assessment = _latest_assessment()
    if not assessment:
        abort(404)

    findings = _get_findings(assessment)
    finding = next((f for f in findings if f.get("RuleId") == rule_id), None)
    if not finding:
        abort(404)

    # Verification commands index (mirrors WorkflowExport.ps1)
    verification_commands = {
        "IP-001": 'Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object SamAccountName, objectClass',
        "IP-003": 'Get-ADGroupMember -Identity "Schema Admins" | Select-Object SamAccountName',
        "IP-010": 'Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, ComplexityEnabled, LockoutThreshold',
        "IP-015": 'Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} | Select-Object SamAccountName',
        "IP-016": 'Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} | Select-Object SamAccountName',
        "IP-017": 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} | Select-Object SamAccountName',
        "IP-030": 'Get-ADUser -Filter {TrustedForDelegation -eq $true} | Select-Object SamAccountName, TrustedForDelegation',
        "IP-031": 'Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select-Object SamAccountName',
        "IP-040": 'Get-ADUser -Filter {ServicePrincipalNames -ne "$null" -and Enabled -eq $true} | Select-Object SamAccountName, ServicePrincipalNames',
        "IP-050": 'Get-ADGroup -Filter {Name -eq "Domain Admins"} | Get-ADGroupMember -Recursive | Select-Object SamAccountName, objectClass',
        "IP-060": 'Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2097152)" | Select-Object SamAccountName, UserAccountControl',
        "CG-001": 'Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature',
        "CG-002": 'Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" -Name "LDAPServerIntegrity"',
        "CG-004": 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, State',
        "CG-005": 'Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LmCompatibilityLevel"',
        "CG-010": 'Get-ChildItem -Path "\\\\$env:USERDNSDOMAIN\\SYSVOL" -Recurse -Filter "*.xml" | Select-String "cpassword"',
        "CG-020": 'Get-ADTrust -Filter * | Select-Object Name, TrustAttributes, SIDFilteringForestAware',
        "CG-030": '(Get-ACL "AD:DC=corp,DC=local").Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl" }',
        "CG-040": 'Get-ChildItem "\\\\$env:USERDNSDOMAIN\\SYSVOL" -Recurse -Filter "GptTmpl.inf" | Select-String "SeDebugPrivilege"',
        "EV-010": 'Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" -Name "FullSecureChannelProtection"',
        "EV-020": 'Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" -Name "LdapEnforceChannelBinding"',
        "EV-030": 'Get-Service -ComputerName (Get-ADDomainController -Filter *).HostName -Name "Spooler" | Select-Object MachineName, Status',
        "PB-001": '(Get-ACL "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local").Access | Select-Object IdentityReference, ActiveDirectoryRights',
        "PB-010": 'Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory } | Select-Object SamAccountName, SIDHistory',
        "PB-020": '(Get-ACL "AD:DC=corp,DC=local").Access | Where-Object { $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" }',
        "PB-050": 'Get-ChildItem "\\\\$env:USERDNSDOMAIN\\NETLOGON" | Select-Object Name, LastWriteTime, Attributes',
        "PB-060": 'Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\\Microsoft\\*" -and $_.Principal.UserId -match "SYSTEM" }',
        "DE-001": 'auditpol /get /category:"Account Logon","Logon/Logoff","DS Access","Account Management","Privilege Use","Policy Change"',
        "DE-002": 'Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, RecordCount',
    }

    return jsonify({
        "ruleId": finding.get("RuleId"),
        "title": finding.get("Title"),
        "severity": finding.get("Severity"),
        "category": finding.get("Category"),
        "whyItMatters": finding.get("Description"),
        "affectedObjects": finding.get("AffectedObjects", []),
        "affectedCount": finding.get("AffectedCount", 0),
        "remediationSteps": finding.get("Remediation"),
        "verificationCommand": (
            finding.get("VerificationCommand")
            or verification_commands.get(rule_id, f"# No verification command for {rule_id}")
        ),
        "mitreAttack": finding.get("MitreAttack"),
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("ADWALL_PORT", 5000))
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"AD-Wall Dashboard starting on http://localhost:{port}")
    print(f"Reading assessment data from: {DATA_DIR}")
    app.run(host="0.0.0.0", port=port, debug=False)
