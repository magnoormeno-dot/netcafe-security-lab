# CafeSec Lab CVP Evidence Pack

This evidence pack summarizes CafeSec Lab for AI-provider cyber verification
review. It is written for reviewers who need to understand the project's public
identity, defensive purpose, safety boundaries, and intended use of advanced AI
assistance.

## One-Sentence Summary

CafeSec Lab is an independent defensive security research project for internet
cafes, gaming venues, esports hotels, and managed shared-PC fleets.

## Public Identity Chain

| Evidence | Link or channel |
| --- | --- |
| Project home | <https://cafeseclab.com/> |
| Research site | <https://research.cafeseclab.com/> |
| Main repository | <https://github.com/magnoormeno-dot/netcafe-security-lab> |
| Latest release | <https://github.com/magnoormeno-dot/netcafe-security-lab/releases/tag/v0.1.1> |
| Project goal | <https://github.com/magnoormeno-dot/netcafe-security-lab/blob/main/docs/roadmap/project-goal.md> |
| v0.2 roadmap | <https://github.com/magnoormeno-dot/netcafe-security-lab/blob/main/docs/roadmap/v0.2.md> |
| Security policy | <https://github.com/magnoormeno-dot/netcafe-security-lab/blob/main/.github/SECURITY.md> |
| Security contact | `security@cafeseclab.com` |
| Research contact | `research@cafeseclab.com` |
| Security.txt | <https://cafeseclab.com/.well-known/security.txt> |
| HackerOne profile | <https://hackerone.com/eshine> |
| LinkedIn profile | <https://www.linkedin.com/in/shine-e-480463410/> |

The project maintainer has completed OpenAI trusted access identity verification
for authorized security work. This is included as an external trust signal, not
as an endorsement claim by OpenAI or any other provider.

## Defensive Purpose

CafeSec Lab exists to make shared-PC venue security more observable, testable,
and repeatable. The project focuses on practical defensive controls for small
operators who manage public or semi-public Windows hosts and billing
infrastructure with limited security budget.

Current research areas:

- Windows host hardening for shared-PC environments;
- billing-software threat modeling and architecture review;
- file, process, and event-log integrity monitoring;
- YARA and Sigma detection logic for defensive monitoring;
- false-positive tuning and operator-readable reporting;
- incident response and coordinated disclosure practices.

## Why Cyber Verification Access Is Requested

CafeSec Lab's work is defensive, but some routine tasks can look dual-use to an
AI safety system because they mention process tampering, service termination,
registry modification, memory-scanning indicators, attacker technique mapping,
or detection-rule validation.

Cyber verification access is requested to reduce unnecessary interruptions for
authorized defensive workflows such as:

- reviewing hardening checklists for completeness and verification steps;
- improving Sigma and YARA rules without generating bypass tooling;
- analyzing synthetic telemetry and false-positive scenarios;
- building integrity-monitor deployment examples for lab or authorized hosts;
- writing threat models that pair adversary behavior with detection and
  mitigation;
- preparing coordinated disclosure language and safe operator guidance.

The requested use does not include live exploitation, credential theft, malware
deployment, persistence, stealth, evasion, billing bypass, unauthorized scanning,
or instructions for attacking third-party systems.

## Safety Boundaries

CafeSec Lab does not publish or request:

- weaponized proof-of-concept code;
- exploit chains;
- credentials, tokens, private keys, or customer data;
- billing bypass tools or step-by-step abuse instructions;
- vendor-specific vulnerability claims outside coordinated disclosure;
- guidance for testing third-party systems without written authorization;
- instructions that improve malware persistence, stealth, or evasion.

When an attack pattern is discussed, the corresponding detection, mitigation, or
validation guidance must appear with it.

## Authorization And Data Handling

CafeSec Lab public examples are region-neutral and vendor-neutral unless a
coordinated disclosure process permits more specific detail.

Default data policy:

- use synthetic telemetry, anonymized examples, and public documentation;
- avoid customer identities, live credentials, payment records, private venue
  information, and network diagrams in public material;
- store sensitive reports only through private channels listed in
  `.github/SECURITY.md`;
- do not test against real venues, vendors, networks, or cloud services without
  written authorization;
- avoid presenting synthetic examples as field validation.

## Public Artifacts Already Available

| Area | Evidence |
| --- | --- |
| Project home | Root site at <https://cafeseclab.com/> |
| Research writing | Blog at <https://research.cafeseclab.com/> |
| Hardening guidance | `01-hardening-checklist/checklist/` |
| Detection rules | `01-hardening-checklist/detection/` |
| Detection tuning | `01-hardening-checklist/detection/tuning-guide.md` and tuning register example |
| Integrity monitoring | `02-integrity-monitor/` Python project |
| Deployment guidance | `02-integrity-monitor/docs/pilot-runbook.md` and `docs/operators/executive-summary-template.md` |
| Project governance | `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, MIT license |
| Quality controls | GitHub Actions CI for Ruff, mypy, pytest, and coverage artifacts |
| Roadmap | `docs/roadmap/project-goal.md` and `docs/roadmap/v0.2.md` |
| Synthetic pilot evidence | `docs/pilot/synthetic-shared-pc-venue/` |
| CVP application brief | `docs/cvp/application-brief.md` |
| Validation lab | `04-validation-lab/` — reproducible, network-isolated Hyper-V/domain testbed; **offline rule convert/compile is CI-enforced**, live-telemetry validation is wired but pending |
| Lab validation evidence | `docs/cvp/lab-validation-evidence.md` (+ committed `.jsonl`) — synthetic offline result (Sigma 3/3, YARA 3/3); human-reviewed; **not** field validation |

## Current Technical Quality Signals

As of the current public state:

- public repository and root site use role-based domain email addresses;
- the GitHub Actions workflow runs on Ubuntu and Windows;
- Python tests, Ruff, and mypy are part of CI;
- public links for `cafeseclab.com`, `research.cafeseclab.com`, and
  `security.txt` are part of the maintenance playbook;
- the project has a documented coordinated disclosure policy;
- detection content is framed as vendor-neutral and defensive;
- a reproducible validation lab (`04-validation-lab/`) whose **offline rule convert/compile is enforced
  by CI** (`validation-lab-rules.yml`: Sigma 3/3, YARA 3/3) and recorded in
  `docs/cvp/lab-validation-evidence.md`; it is **wired** to exercise the rules and integrity monitor on
  real Sysmon/WEF/Wazuh telemetry in a running lab, which is **pending**. That step, and all lab output,
  is labelled synthetic and human-reviewed before being cited as evidence. The module also has its own
  PSScriptAnalyzer + UTF-8 BOM lint CI.

## Intended Claude / AI Assistance Patterns

Expected safe assistance:

- improve checklist clarity and verification commands;
- review detection-rule descriptions for false-positive handling;
- summarize defensive references and map controls to ATT&CK where appropriate;
- help write synthetic test fixtures and benign event examples;
- review Python code for reliability, error handling, and safe subprocess use;
- draft operator-facing summaries from non-sensitive findings;
- identify gaps in documentation, testing, and release readiness.

Requests should remain bounded to defensive outcomes. If a task would require
exploit development, credential handling, unauthorized access, stealth, evasion,
or bypass instructions, it should be declined or reframed toward detection,
mitigation, or responsible disclosure.

## Thirty-Day Plan

The next 30 days should focus on turning the initial public release into a more
repeatable defensive pilot workflow:

1. Publish the pilot intake checklist described in the v0.2 roadmap.
2. Add one synthetic event fixture per Sigma rule.
3. Complete one example tuning register using synthetic data.
4. Add a Windows scheduled-task deployment example for the integrity monitor.
5. Publish one detection deep-dive research note explaining a rule family from a
   defender perspective.
6. Prepare `v0.2.0` release notes that list defensive value, known limitations,
   and non-goals.

## Reviewer Notes

CafeSec Lab should be evaluated as a defensive research and tooling project, not
as a penetration-testing service or exploit publication channel. The project is
most comparable to a small blue-team research program focused on an
underrepresented operational environment: shared-PC venues with billing systems,
client images, restoration tools, and low security budget.

The core request for cyber verification access is practical: allow defensive
research workflows that necessarily reference attacker techniques while keeping
the project's public output constrained to hardening, detection, monitoring,
reporting, and coordinated disclosure.
