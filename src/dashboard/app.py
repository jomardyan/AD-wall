"""
AD-Wall Web Dashboard
Flask application serving the AD-Wall dashboard and REST API.
Persists all runs, findings, logs and reports to SQLite via src/core/db.py.
"""

import glob
import io
import csv
import json
import os
import platform
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template, jsonify, request, send_file, abort

# ---------------------------------------------------------------------------
# DB setup — adjust sys.path so we can import from src/core
# ---------------------------------------------------------------------------
_SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import core.db as db

app = Flask(__name__)

# Evidence store directory — override via ADWALL_DATA_DIR env var
DATA_DIR = os.environ.get("ADWALL_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "output"))
DATA_DIR = os.path.abspath(DATA_DIR)

# Path to the PowerShell assessment script
_REPO_ROOT  = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_SCRIPT_PATH = os.path.join(_REPO_ROOT, "Invoke-ADWall.ps1")

# PowerShell executable (pwsh on Linux/Mac, powershell on Windows)
_PWSH = "pwsh" if platform.system() != "Windows" else "powershell"


# ---------------------------------------------------------------------------
# Startup — configure DB & auto-import existing JSON assessments
# ---------------------------------------------------------------------------

def _startup() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    db_path = os.path.join(DATA_DIR, "adwall.db")
    db.configure(db_path)
    db.init_db()
    # Auto-import any existing assessment JSON files
    pattern = os.path.join(DATA_DIR, "ADWall_Assessment_*.json")
    for json_file in sorted(glob.glob(pattern)):
        try:
            db.import_json_assessment(json_file)
        except Exception as exc:  # pragma: no cover
            app.logger.warning("Failed to import %s: %s", json_file, exc)


_startup()


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _list_assessment_files():
    """Return sorted list of ADWall_Assessment_*.json paths (newest first)."""
    pattern = os.path.join(DATA_DIR, "ADWall_Assessment_*.json")
    return sorted(glob.glob(pattern), reverse=True)


def _load_assessment(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _latest_assessment() -> dict | None:
    """
    Return the most-recent assessment as a dict.
    Checks SQLite first (converts the DB row + findings back to the JSON shape),
    falls back to JSON files if SQLite has no completed runs.
    """
    runs = db.list_runs(limit=1)
    completed = [r for r in runs if r.get("status") == "completed"]
    if completed:
        run = completed[0]
        findings = db.get_findings_api(run["id"])
        grade_obj = {
            "Grade": run.get("grade", "N/A"),
            "Score": run.get("score", 0),
            "Description": "",
            "CriticalCount": run.get("critical_count", 0),
            "HighCount":     run.get("high_count", 0),
        }
        return {
            "Findings":      findings,
            "TotalFindings": run.get("total_findings", 0),
            "PostureGrade":  grade_obj,
            "GeneratedAt":   run.get("completed_at"),
            "Tool":          "AD-Wall",
            "DomainController": run.get("domain_controller"),
            "_run_id":       run["id"],
        }
    # Fallback to JSON files
    files = _list_assessment_files()
    if not files:
        return None
    return _load_assessment(files[0])


def _assessment_for_run(run_id: str) -> dict | None:
    """Return an assessment-shaped dict for a specific run_id."""
    run = db.get_run(run_id)
    if not run:
        return None
    findings = db.get_findings_api(run_id)
    grade_obj = {
        "Grade": run.get("grade", "N/A"),
        "Score": run.get("score", 0),
        "Description": "",
        "CriticalCount": run.get("critical_count", 0),
        "HighCount":     run.get("high_count", 0),
    }
    return {
        "Findings":      findings,
        "TotalFindings": run.get("total_findings", 0),
        "PostureGrade":  grade_obj,
        "GeneratedAt":   run.get("completed_at"),
        "Tool":          "AD-Wall",
        "DomainController": run.get("domain_controller"),
        "_run_id":       run_id,
    }


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

@app.route("/api/info")
def api_info():
    """Return server-side metadata such as the PowerShell executable name."""
    return jsonify({"pwsh": _PWSH, "platform": platform.system()})

@app.route("/api/findings")
def api_findings():
    """Return findings with optional run_id, severity, category, search filters."""
    run_id   = request.args.get("run_id")
    severity = request.args.get("severity")
    category = request.args.get("category")
    search   = request.args.get("search") or ""

    if run_id:
        assessment = _assessment_for_run(run_id)
    else:
        assessment = _latest_assessment()

    if not assessment:
        return jsonify({"error": "No assessment data found", "findings": [], "total": 0}), 404

    findings = _get_findings(assessment)

    if severity:
        findings = [f for f in findings if f.get("Severity", "").lower() == severity.lower()]
    if category:
        findings = [f for f in findings if f.get("Category", "").lower() == category.lower()]
    if search:
        sl = search.lower()
        findings = [
            f for f in findings
            if sl in f.get("Title", "").lower() or sl in f.get("Description", "").lower()
        ]

    findings = sorted(findings, key=lambda f: _severity_order(f.get("Severity", "")))

    return jsonify({
        "total":       len(findings),
        "findings":    findings,
        "generatedAt": assessment.get("GeneratedAt"),
        "tool":        assessment.get("Tool"),
        "run_id":      assessment.get("_run_id"),
    })


@app.route("/api/score")
def api_score():
    """Return the overall posture grade and score, with optional run_id filter."""
    run_id = request.args.get("run_id")

    if run_id:
        assessment = _assessment_for_run(run_id)
    else:
        assessment = _latest_assessment()

    if not assessment:
        return jsonify({"error": "No assessment data found"}), 404

    grade    = assessment.get("PostureGrade") or {}
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
        "grade":          grade.get("Grade", "N/A"),
        "score":          grade.get("Score", 0),
        "description":    grade.get("Description", ""),
        "severityCounts": severity_counts,
        "categoryCounts": category_counts,
        "totalFindings":  len(findings),
        "generatedAt":    assessment.get("GeneratedAt"),
        "run_id":         assessment.get("_run_id"),
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
        "COMP-001": 'Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength',
        "COMP-002": 'Get-ADDefaultDomainPasswordPolicy | Select-Object PasswordComplexityEnabled',
        "COMP-003": 'Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow',
        "COMP-010": 'Get-ADGroupMember -Identity "Domain Admins" | Measure-Object | Select-Object Count',
        "COMP-011": 'Get-ADGroupMember -Identity "Schema Admins" | Select-Object SamAccountName, objectClass',
        "COMP-012": 'Get-ADUser -Identity Guest | Select-Object SamAccountName, Enabled',
        "COMP-013": 'Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true -and AdminCount -eq 1} | Select-Object SamAccountName',
        "COMP-020": 'Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LmCompatibilityLevel"',
        "COMP-030": 'Get-ADTrust -Filter * | Select-Object Name, TrustAttributes, SIDFilteringForestAware, SIDFilteringQuarantined',
        "COMP-040": 'Get-ADComputer -Filter * -Properties "ms-Mcs-AdmPwd" | Where-Object { -not $_."ms-Mcs-AdmPwd" } | Measure-Object | Select-Object Count',
        "COMP-050": 'Get-ADGroup -Identity "Protected Users" | Get-ADGroupMember | Select-Object SamAccountName',
        "COMP-051": 'Get-ADGroupMember -Identity "Domain Admins" | Select-Object SamAccountName',
        "COMP-060": 'Get-ADUser -Filter {ServicePrincipalNames -ne "$null" -and Enabled -eq $true} | Select-Object SamAccountName, ServicePrincipalNames',
        "COMP-061": 'Get-ADServiceAccount -Filter * | Select-Object SamAccountName, objectClass',
        "COMP-070": 'Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser -Properties EmailAddress | Where-Object {$_.EmailAddress} | Select-Object SamAccountName, EmailAddress',
    }

    return jsonify({
        "ruleId": finding.get("RuleId"),
        "title": finding.get("Title"),
        "severity": finding.get("Severity"),
        "category": finding.get("Category"),
        "cisControl": finding.get("CISControl", ""),
        "nistControl": finding.get("NISTControl", ""),
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


@app.route("/api/attack-paths")
def api_attack_paths():
    """Return attack path graph data from the latest scan."""
    graph_file = os.path.join(DATA_DIR, "attack_graph.json")
    if not os.path.exists(graph_file):
        # Fall back to deriving attack-path hints from findings
        assessment = _latest_assessment()
        if not assessment:
            return jsonify({"error": "No assessment data found", "paths": [], "summary": {}}), 404

        findings = _get_findings(assessment)
        # Build a simplified path list from findings that indicate attack paths
        attack_indicators = {
            "IP-030": "Unconstrained Delegation → DC Compromise",
            "IP-031": "Unconstrained Delegation (Computer) → TGT Capture",
            "IP-040": "Kerberoasting → Credential Recovery",
            "IP-041": "Privileged Kerberoasting → Instant Domain Admin",
            "IP-017": "AS-REP Roasting → Offline Hash Crack",
            "PB-020": "DCSync Rights → Credential Dump",
            "EV-040": "AD CS ESC1 → Impersonate Domain Admin",
            "EV-045": "AD CS ESC6 → Domain Compromise via Cert",
            "CG-001": "No SMB Signing → NTLM Relay",
            "CG-002": "No LDAP Signing → NTLM Relay → RBCD/DCSync",
            "PB-001": "AdminSDHolder Backdoor → Persistent Privileged Access",
            "PB-010": "SID History Injection → Privilege Escalation",
            "PB-011": "Privileged SID History → Immediate Domain Admin",
            "CG-020": "Trust Without SID Filtering → SID History Attack",
            "COMP-040": "No LAPS → Pass-the-Hash Lateral Movement",
            "COMP-051": "DA Not in Protected Users → NTLM Credential Theft",
        }

        paths = []
        for f in findings:
            rule_id = f.get("RuleId", "")
            if rule_id in attack_indicators:
                paths.append({
                    "ruleId": rule_id,
                    "pathName": attack_indicators[rule_id],
                    "severity": f.get("Severity"),
                    "affectedObjects": f.get("AffectedObjects", [])[:5],
                    "affectedCount": f.get("AffectedCount", 0),
                    "mitre": f.get("MitreAttack", ""),
                })

        return jsonify({
            "paths": sorted(paths, key=lambda x: _severity_order(x.get("severity", ""))),
            "summary": {
                "totalPaths": len(paths),
                "criticalPaths": sum(1 for p in paths if p["severity"] == "Critical"),
                "highPaths": sum(1 for p in paths if p["severity"] == "High"),
            },
            "source": "findings-derived",
        })

    # Return precomputed graph from attack_graph.json
    try:
        with open(graph_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return jsonify({
            "paths": data.get("Paths", []),
            "summary": data.get("Graph", {}),
            "source": "attack-graph-engine",
        })
    except Exception as exc:
        return jsonify({"error": str(exc), "paths": [], "summary": {}}), 500


@app.route("/api/compliance")
def api_compliance():
    """Return compliance findings grouped by CIS/NIST control."""
    assessment = _latest_assessment()
    if not assessment:
        return jsonify({"error": "No assessment data found", "controls": [], "summary": {}}), 404

    findings = _get_findings(assessment)
    comp_findings = [f for f in findings if (f.get("Category") == "Compliance" or
                                              str(f.get("RuleId", "")).startswith("COMP-"))]

    # Group by CIS control family
    by_control = {}
    for f in comp_findings:
        cis = f.get("CISControl") or f.get("ExtraData", {}).get("CISControl", "Uncategorized")
        if not cis:
            cis = "Uncategorized"
        family = cis.split(".")[0] if "." in cis else cis
        if family not in by_control:
            by_control[family] = {"family": family, "findings": [], "totalCount": 0}
        by_control[family]["findings"].append({
            "ruleId": f.get("RuleId"),
            "title": f.get("Title"),
            "severity": f.get("Severity"),
            "affectedCount": f.get("AffectedCount", 0),
            "cisControl": f.get("CISControl", ""),
            "nistControl": f.get("NISTControl", ""),
            "remediation": f.get("Remediation", ""),
        })
        by_control[family]["totalCount"] += 1

    controls = sorted(by_control.values(), key=lambda x: x["totalCount"], reverse=True)

    # Compliance score (percentage of controls with no critical/high findings)
    total_rules = len(comp_findings)
    pass_rules  = sum(1 for f in comp_findings if f.get("Severity") not in ("Critical", "High"))
    score = round(pass_rules / total_rules * 100, 1) if total_rules > 0 else 100.0

    return jsonify({
        "controls": controls,
        "findings": comp_findings,
        "summary": {
            "totalFindings": total_rules,
            "criticalCount": sum(1 for f in comp_findings if f.get("Severity") == "Critical"),
            "highCount":     sum(1 for f in comp_findings if f.get("Severity") == "High"),
            "mediumCount":   sum(1 for f in comp_findings if f.get("Severity") == "Medium"),
            "lowCount":      sum(1 for f in comp_findings if f.get("Severity") in ("Low", "Informational")),
            "complianceScore": score,
        },
    })


# ---------------------------------------------------------------------------
# Run management — PowerShell execution
# ---------------------------------------------------------------------------

def _build_ps_command(params: dict) -> list[str]:
    """Build the PowerShell argv list from posted params."""
    cmd = [
        _PWSH, "-NonInteractive", "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", _SCRIPT_PATH,
    ]
    if params.get("domainController"):
        cmd += ["-DomainController", params["domainController"]]
    if params.get("mode"):
        cmd += ["-Mode", params["mode"]]
    if params.get("orgName"):
        cmd += ["-OrgName", params["orgName"]]
    if params.get("outputPath"):
        cmd += ["-OutputPath", params["outputPath"]]
    if params.get("staleAccountDays") is not None:
        cmd += ["-StaleAccountDays", str(int(params["staleAccountDays"]))]
    if params.get("configFile"):
        cmd += ["-ConfigFile", params["configFile"]]
    if params.get("modules"):
        modules = params["modules"]
        if isinstance(modules, list):
            modules = ",".join(modules)
        cmd += ["-Modules", modules]
    if params.get("format"):
        fmt = params["format"]
        if isinstance(fmt, list):
            fmt = ",".join(fmt)
        cmd += ["-Format", fmt]
    if params.get("redTeam"):
        cmd += ["-RedTeam"]
    if params.get("safeMode") is False:
        cmd += ["-SafeMode", "$false"]
    if params.get("dashboardPort"):
        cmd += ["-DashboardPort", str(int(params["dashboardPort"]))]
    if params.get("siemExport"):
        cmd += ["-SIEMExport"]
    if params.get("jiraUrl"):
        cmd += ["-JiraUrl", params["jiraUrl"]]
    if params.get("jiraProject"):
        cmd += ["-JiraProject", params["jiraProject"]]
    if params.get("jiraUser"):
        cmd += ["-JiraUser", params["jiraUser"]]
    if params.get("jiraToken"):
        cmd += ["-JiraToken", params["jiraToken"]]
    if params.get("serviceNowUrl"):
        cmd += ["-ServiceNowUrl", params["serviceNowUrl"]]
    if params.get("serviceNowUser"):
        cmd += ["-ServiceNowUser", params["serviceNowUser"]]
    if params.get("serviceNowPass"):
        cmd += ["-ServiceNowPass", params["serviceNowPass"]]
    if params.get("alertEmail"):
        cmd += ["-AlertEmail", params["alertEmail"]]
    if params.get("alertSmtpServer"):
        cmd += ["-AlertSmtpServer", params["alertSmtpServer"]]
    if params.get("alertSmtpPort"):
        cmd += ["-AlertSmtpPort", str(int(params["alertSmtpPort"]))]
    if params.get("alertOnDrift"):
        cmd += ["-AlertOnDrift"]
    return cmd


_MAX_LOG_LINES_PER_RUN = 5000  # cap to prevent unbounded DB growth


def _run_assessment_thread(run_id: str, cmd: list[str], output_path: str) -> None:
    """Background thread: execute PowerShell, stream logs, import results."""
    db.add_log(run_id, "Starting PowerShell assessment…", level="INFO")
    db.add_log(run_id, "Command: " + " ".join(cmd), level="DEBUG")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        log_count = 0
        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip("\r\n")
            if line:
                if log_count >= _MAX_LOG_LINES_PER_RUN:
                    if log_count == _MAX_LOG_LINES_PER_RUN:
                        db.add_log(run_id, f"[Log output truncated at {_MAX_LOG_LINES_PER_RUN} lines]", level="WARN")
                    continue  # discard but keep reading so the pipe drains
                level = "ERROR" if "error:" in line.lower() or "exception:" in line.lower() else "INFO"
                db.add_log(run_id, line, level=level)
                log_count += 1
        proc.wait()
        if proc.returncode != 0:
            db.fail_run(run_id, f"Process exited with code {proc.returncode}")
            return
    except FileNotFoundError:
        db.fail_run(run_id, f"{_PWSH} not found on this system")
        return
    except Exception as exc:
        db.fail_run(run_id, str(exc))
        return

    # Import the generated JSON assessment
    db.add_log(run_id, "Assessment complete — importing results…", level="INFO")
    pattern = os.path.join(output_path, "ADWall_Assessment_*.json")
    candidates = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    if candidates:
        try:
            new_run_id = db.import_json_assessment(candidates[0])
            db.add_log(run_id, f"Results imported as run {new_run_id}", level="INFO")
            # Copy grade/score from the newly imported run to this run
            imported = db.get_run(new_run_id)
            if imported:
                db.complete_run(run_id, {
                    "total_findings": imported["total_findings"],
                    "critical_count": imported["critical_count"],
                    "high_count":     imported["high_count"],
                    "medium_count":   imported["medium_count"],
                    "low_count":      imported["low_count"],
                    "info_count":     imported["info_count"],
                    "score":          imported["score"],
                    "grade":          imported["grade"],
                })
                # Copy findings to this run too so it shows up with data
                findings = db.get_findings(new_run_id)
                if findings:
                    db.save_findings(run_id, [
                        {
                            "RuleId": f["rule_id"], "Severity": f["severity"],
                            "Category": f["category"], "Title": f["title"],
                            "Description": f["description"], "Remediation": f["remediation"],
                            "MitreAttack": f["mitre_attack"],
                            "AffectedCount": f["affected_count"],
                            "AffectedObjects": f.get("affected_objects"),
                            "DetectedAt": f["detected_at"],
                            "VerificationCommand": f["verification_command"],
                            "CISControl": f["cis_control"], "NISTControl": f["nist_control"],
                        }
                        for f in findings
                    ])
                # Register reports under this run_id too
                for rep in db.list_reports(new_run_id):
                    db.register_report(run_id, rep["filename"], rep["format"], rep["file_path"])
            else:
                db.complete_run(run_id, {})
        except Exception as exc:
            db.add_log(run_id, f"Import error: {exc}", level="ERROR")
            db.complete_run(run_id, {})
    else:
        db.add_log(run_id, "No assessment JSON found in output path", level="WARNING")
        db.complete_run(run_id, {})

    db.add_log(run_id, "Run finished", level="INFO")


@app.route("/api/run/start", methods=["POST"])
def api_run_start():
    """
    Start a new PowerShell assessment.
    Body JSON fields mirror Invoke-ADWall.ps1 parameters (camelCase).
    Pass preview_only=true to get the command without executing.
    """
    params = request.get_json(force=True) or {}
    cmd    = _build_ps_command(params)
    cmd_str = " ".join(cmd)

    if params.get("preview_only"):
        return jsonify({
            "status":  "preview",
            "command": cmd_str,
            "message": "Command preview only — not executed",
        })

    # Check PowerShell availability
    try:
        subprocess.run([_PWSH, "-Version"], capture_output=True, timeout=5)
        ps_available = True
    except FileNotFoundError:
        ps_available = False
    except subprocess.TimeoutExpired:
        # PowerShell is installed but took too long to respond — treat as unavailable
        import logging
        logging.warning("PowerShell version check timed out; treating as unavailable")
        ps_available = False

    run_id      = str(uuid.uuid4()) + "-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    output_path = params.get("outputPath") or DATA_DIR

    if not ps_available:
        return jsonify({
            "run_id":  run_id,
            "status":  "preview",
            "command": cmd_str,
            "message": f"{_PWSH} is not available on this system. Showing command preview only.",
        })

    db.create_run(run_id, params)
    db.add_log(run_id, "Run queued", level="INFO")

    t = threading.Thread(
        target=_run_assessment_thread,
        args=(run_id, cmd, output_path),
        daemon=True,
    )
    t.start()

    return jsonify({
        "run_id":  run_id,
        "status":  "running",
        "command": cmd_str,
        "message": "Assessment started",
    }), 202


@app.route("/api/run/<run_id>/status")
def api_run_status(run_id: str):
    run = db.get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    return jsonify({
        "run_id":         run["id"],
        "status":         run["status"],
        "started_at":     run["started_at"],
        "completed_at":   run["completed_at"],
        "total_findings": run["total_findings"],
        "grade":          run["grade"],
        "score":          run["score"],
    })


@app.route("/api/run/<run_id>/logs")
def api_run_logs(run_id: str):
    since_id = int(request.args.get("since_id", 0))
    logs = db.get_logs(run_id, since_id=since_id)
    return jsonify({"run_id": run_id, "logs": logs})


@app.route("/api/runs")
def api_runs():
    limit = int(request.args.get("limit", 100))
    runs  = db.list_runs(limit=limit)
    return jsonify({"runs": runs, "count": len(runs)})


@app.route("/api/runs/<run_id>")
def api_run_detail(run_id: str):
    run = db.get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    return jsonify(run)


@app.route("/api/runs/<run_id>/findings")
def api_run_findings(run_id: str):
    run = db.get_run(run_id)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    severity = request.args.get("severity")
    category = request.args.get("category")
    search   = request.args.get("search") or ""
    findings = db.get_findings_api(run_id, severity=severity, category=category, search=search or None)
    return jsonify({
        "total":    len(findings),
        "findings": findings,
        "run_id":   run_id,
    })


@app.route("/api/reports")
def api_reports():
    run_id = request.args.get("run_id")
    reports = db.list_reports(run_id=run_id)
    return jsonify({"reports": reports, "count": len(reports)})


@app.route("/api/report/<path:filename>")
def api_report_download(filename: str):
    """Serve a report file from DATA_DIR by filename.

    Security: validate the filename against the reports table so only files
    that AD-Wall itself registered can be served (prevents path traversal).
    """
    safe_name = os.path.basename(filename)
    # Reject any path component that escapes DATA_DIR
    if safe_name != filename.replace("\\", "/").split("/")[-1]:
        abort(400)
    # Validate against registered reports in the DB
    all_reports = db.list_reports()
    known_names = {r["filename"] for r in all_reports}
    if safe_name not in known_names:
        abort(404)
    file_path = os.path.join(DATA_DIR, safe_name)
    if not os.path.isfile(file_path):
        abort(404)
    return send_file(file_path, as_attachment=False)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("ADWALL_PORT", 5000))
    print(f"AD-Wall Dashboard starting on http://localhost:{port}")
    print(f"Reading assessment data from: {DATA_DIR}")
    app.run(host="0.0.0.0", port=port, debug=False)
