1) Product goal
Build an internal platform that continuously assesses AD security posture across identity, endpoints, protocols, trust boundaries, AD CS, and cloud-hybrid paths, then maps findings to severity and remediation playbooks.

Suggested task
Define product charter and legal guardrails for AD assessment platform

Start task
2) Functional scope (low → high severity coverage)
Your scanner should cover these major categories:

Tier 0 identity risks: Domain Admin exposure, nested privileged groups, stale privileged accounts.

AD misconfigurations: weak ACLs, dangerous delegation, unconstrained/constrained delegation abuse paths, GPO abuse.

Kerberos/NTLM weaknesses: AS-REP roastable users, Kerberoastable SPNs, NTLM fallback, weak encryption types.

AD CS risks: vulnerable certificate templates (ESC classes), enrollment abuse paths.

Replication and sync risks: DCSync rights, replication permissions misuse.

Trust and lateral movement paths: forest/domain trust misconfigs, SIDHistory abuse risk.

Persistence/backdoor indicators: suspicious AdminSDHolder changes, startup/logon script abuse, rogue scheduled tasks on DCs, unusual ACL drift.

Detection engineering checks: missing logging, weak SIEM coverage for AD attack techniques.

Patch/vulnerability context: CVE exposure posture of DCs and critical infra (metadata only if agentless).

Suggested task
Create a normalized AD security control catalog with severity mapping

Start task
3) Core architecture
Use a modular pipeline:

Collectors (read-only first)

LDAP/GC collector

SMB/WMI/WinRM metadata collector (least privilege)

Event log collector

AD CS enumerator

Graph model

Build attack-path graph (users, groups, computers, ACL edges, trusts, cert templates)

Rule engine

Deterministic checks (known misconfigs)

Risk engine

Severity + exploitability + business criticality + exposure age

Evidence store

Time-series snapshots for drift detection

Reporting/API

Dashboard, diff reports, remediation tickets

Suggested task
Implement modular scanner architecture with collector-rule-risk pipeline

Start task
4) Prioritization model for cyber team
Use a triage matrix:

Critical: exploitable path to Tier 0, DCSync, dangerous cert template enabling domain compromise.

High: delegation/ACL issues enabling privilege escalation.

Medium: insecure protocol options, stale privileged accounts.

Low: hygiene and policy drift.

Include “quick wins” tag for changes fixable in <1 day (e.g., remove inactive DA members).

Suggested task
Add risk scoring and remediation priority queue

Start task
5) Safe operation modes
Mode A: Assessment (default) – read-only, no exploit execution.

Mode B: Validation – controlled proof checks for selected findings (approved change window).

Mode C: Continuous monitoring – scheduled drift scans + alerting.

Suggested task
Add scan safety modes and approval workflow

Start task
6) Team workflow integration
Auto-create tickets in Jira/ServiceNow.

Export to SIEM/SOAR.

Provide “fix guide” per finding:

why it matters

exact AD object(s)

rollback-safe remediation steps

verification commands
