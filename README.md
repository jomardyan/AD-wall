# AD-Wall — Active Directory Security Assessment Framework

AD-Wall is a **read-only** Active Directory security assessment tool that audits an AD environment for misconfigurations, known vulnerabilities, and persistence mechanisms. It produces HTML, JSON, CSV, and Markdown reports and includes an optional web dashboard.

---

## Features

| Category | Checks |
|---|---|
| **Identity & Privilege** | Privileged group membership, password policies, stale accounts, delegation misuse, AS-REP Roasting, Kerberoasting |
| **Configuration & GPO** | SMB/LDAP signing, SMBv1, NTLMv1, cPassword in SYSVOL (MS14-025), trust security |
| **Exploits & Vulnerabilities** | Kerberoasting, Zerologon (CVE-2020-1472), PetitPotam mitigations, PrintNightmare (CVE-2021-34527), AD CS ESC1–ESC8 |
| **Persistence & Backdoors** | AdminSDHolder ACL, SID History abuse, DCSync-capable accounts, Skeleton Key indicators, rogue DCs |

---

## Prerequisites

- **PowerShell 5.1+** (Windows or PowerShell 7 on Windows)
- Network access to a domain controller (TCP 389/636 for LDAP, TCP 445 for SMB)
- Read-only domain account (Domain Users is sufficient for most checks)
- **Python 3.10+** (optional, only required for the web dashboard)

---

## Quick Start

### 1. Clone the repository

```powershell
git clone https://github.com/your-org/AD-wall.git
cd AD-wall
```

### 2. Run a basic assessment (current domain, current user)

```powershell
.\Invoke-ADWall.ps1
```

Reports are saved to `.\output\` by default.

### 3. Target a specific domain controller with credentials

```powershell
.\Invoke-ADWall.ps1 -DomainController dc01.corp.local -Credential (Get-Credential) -OutputPath C:\Reports
```

### 4. Run all report formats and launch the dashboard

```powershell
.\Invoke-ADWall.ps1 -DomainController dc01.corp.local -Format All -LaunchDashboard
```

### 5. Run only specific modules

```powershell
.\Invoke-ADWall.ps1 -Modules Identity,Exploit -Format HTML,JSON
```

### 6. Install dashboard dependencies (once)

```bash
pip install -r requirements.txt
```

### 7. Start the dashboard manually

```bash
export ADWALL_DATA_DIR=./output
python src/dashboard/app.py
# Open http://localhost:5000
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-DomainController` | String | Auto | DC FQDN or IP |
| `-Credential` | PSCredential | Current user | Authentication credential |
| `-OutputPath` | String | `./output` | Report output directory |
| `-Mode` | String | `Assessment` | `Assessment` / `Validation` / `Monitoring` |
| `-RedTeam` | Switch | Off | Enable write operations (requires `-SafeMode:$false`) |
| `-SafeMode` | Bool | `$true` | Enforce read-only operations |
| `-Modules` | String[] | All | `Identity`, `Config`, `Exploit`, `Persistence` |
| `-Format` | String[] | `HTML,JSON` | `HTML`, `JSON`, `CSV`, `Markdown`, `All` |
| `-LaunchDashboard` | Switch | Off | Launch Flask dashboard after scan |
| `-DashboardPort` | Int | `5000` | Dashboard HTTP port |
| `-StaleAccountDays` | Int | `90` | Inactivity threshold for stale account checks |
| `-OrgName` | String | `''` | Organisation name for report header |
| `-ConfigFile` | String | `''` | Path to a saved JSON config file |

---

## Module Descriptions

### Identity & Privilege (`src/modules/IdentityPrivilege.ps1`)

- **Privileged Group Check** — Enumerates Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, Account Operators and flags over-populated groups.
- **Password Policy Check** — Finds accounts with `PasswordNeverExpires`, `PasswordNotRequired`, or `DoesNotRequirePreAuth` (AS-REP Roasting).
- **Stale Account Check** — Identifies enabled accounts and computer accounts with no recent logon (configurable threshold).
- **Delegation Check** — Detects unconstrained delegation (critical — enables pass-the-ticket escalation) and constrained delegation misuse.
- **Kerberoastable Check** — Lists user accounts with SPNs, prioritised by password age and privilege level.

### Configuration & GPO (`src/modules/ConfigGpo.ps1`)

- **Weak Protocol Check** — Verifies SMB signing, LDAP signing, LDAP channel binding, SMBv1, and NTLMv1 settings on domain controllers.
- **GPO Security Check** — Scans SYSVOL for Group Policy Preferences files containing `cpassword` (MS14-025). Lists empty and disabled GPOs.
- **Trust Check** — Maps domain and forest trusts, flags SID filtering disabled trusts, bidirectional trusts, and external trusts.

### Exploits & Vulnerabilities (`src/modules/ExploitVuln.ps1`)

- **Kerberoasting Check** — Identifies Kerberoastable accounts and assesses cracking risk by password age and privilege level.
- **Zerologon Check** — READ-ONLY: Verifies `FullSecureChannelProtection=1` (enforcement mode) on all DCs.
- **PetitPotam Check** — Evaluates NTLM relay attack surface (LDAP signing + channel binding + SMB signing).
- **PrintNightmare Check** — Detects Print Spooler service running on domain controllers.
- **AD CS Vulnerability Check** — Detects ESC1 (enrollee SAN), ESC2 (any-purpose EKU), ESC3 (enrollment agent), ESC4 (template ACL), ESC6 (CA EditFlags).

### Persistence & Backdoors (`src/modules/PersistenceBackdoor.ps1`)

- **AdminSDHolder Check** — Reads the AdminSDHolder ACL for non-standard high-privilege entries and flags orphaned `AdminCount=1` accounts.
- **SID History Check** — Identifies accounts with SID History containing privileged RIDs.
- **DCSync Rights Check** — Finds non-DC accounts with `DS-Replication-Get-Changes-All` on the domain partition.
- **Skeleton Key Check** — Heuristic: looks for known malware process/service names on DCs.
- **Rogue DC Check** — Compares AD-registered DCs against DNS SRV records for discrepancies.

---

## Output Files

After running, the `output/` directory contains:

```
output/
├── ADWall_Report_<timestamp>.html       # Self-contained HTML report with charts
├── ADWall_Assessment_<timestamp>.json   # Full evidence store (used by dashboard)
├── ADWall_Findings_<timestamp>.csv      # CSV for spreadsheets / ticketing
├── ADWall_Report_<timestamp>.md         # Markdown report
├── adwall_evidence.json                 # Cumulative evidence + snapshot database
└── dashboard.log                        # Dashboard server log (if launched)
```

---

## Safety & Ethics

> **AD-Wall is designed for authorised security assessments only.**

- All operations are **read-only by default**. No changes are made to Active Directory.
- The `-RedTeam` flag enables write operations and requires explicit opt-in (`-SafeMode:$false`).
- Never run this tool against environments you do not have written authorisation to assess.
- Treat all output as sensitive — assessment reports contain detailed information about your AD attack surface.

---

## Risk Scoring

Findings are scored using a composite model:

- **Severity weight** (Critical=40, High=25, Medium=15, Low=5)
- **Exploitability factor** from MITRE ATT&CK technique
- **Affected scope factor** (log-scaled by number of affected objects)
- **Age factor** (findings persisting > 30/90 days score slightly higher)

**Overall grade bands:**

| Grade | Score | Meaning |
|---|---|---|
| A | 0–20 | Good security posture |
| B | 21–40 | Acceptable, some improvements needed |
| C | 41–60 | Moderate risk |
| D | 61–80 | High risk — immediate action required |
| F | 81–100 | Critical risk — possible active compromise |

---

## Dashboard

The optional Flask dashboard provides a live web UI reading from the JSON evidence store:

- **Overview** — Score gauge, severity distribution, category chart, top findings
- **Per-category pages** — Identity, Config, Exploits, Persistence
- **Drift Analysis** — Compare two assessment snapshots to track remediation progress
- **Export** — CSV download via `/api/export`

API endpoints: `/api/findings`, `/api/score`, `/api/snapshots`, `/api/drift`, `/api/export`

---

## Configuration File

Save and reuse a configuration:

```powershell
# Load config module and save
. .\src\core\Config.ps1
Set-ADWallConfig -Settings @{ DomainController='dc01.corp.local'; StaleAccountDays=60 }
Save-ADWallConfig -Path .\myconfig.json

# Use saved config
.\Invoke-ADWall.ps1 -ConfigFile .\myconfig.json
```

---

## Architecture

```
Collectors           Graph Model      Rule Engine       Risk Engine
─────────────        ──────────────   ─────────────     ───────────
LdapCollector   →    CollectedData  → RuleEngine.ps1 → RiskEngine.ps1
SmbCollector    →                  ↗
EventLogCollector→               ↗          ↓               ↓
AdcsCollector   →               ↗      Finding[]      Posture Grade
                                       Evidence Store  Roadmap
                                            ↓
                                     ReportGenerator   Dashboard
                                     HTML/JSON/CSV/MD  Flask app.py
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-check`
3. Implement your check following the `New-Finding` pattern in the relevant module
4. Add the rule to `RuleEngine.ps1` rule catalog
5. Submit a pull request

---

## License

See [LICENSE](LICENSE).