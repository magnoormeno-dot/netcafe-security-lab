# CafeSec Lab

![Status](https://img.shields.io/badge/status-active%20research-2ea44f)
![Research](https://img.shields.io/badge/focus-defensive%20security-0366d6)
![License](https://img.shields.io/badge/license-MIT-blue)
[![Integrity Monitor CI](https://github.com/magnoormeno-dot/netcafe-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/magnoormeno-dot/netcafe-security-lab/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/magnoormeno-dot/netcafe-security-lab?include_prereleases&label=release)](https://github.com/magnoormeno-dot/netcafe-security-lab/releases)

CafeSec Lab is an independent defensive security research project for internet cafes, gaming venues, esports hotels, and managed shared-PC environments. The project is global in scope and uses region-neutral public examples so operators can adapt the guidance to local law, vendor contracts, and business conditions.

The project exists to move venue billing and management systems from informal trust models toward security models that are observable, testable, and hardenable by small operators with limited budgets.

## Quick Links

- Research blog: <https://magnoormeno-dot.github.io/netcafe-security-lab/>
- Current public release: [`v0.1.0`](https://github.com/magnoormeno-dot/netcafe-security-lab/releases/tag/v0.1.0)
- Security policy: [`.github/SECURITY.md`](.github/SECURITY.md)

## Mission

CafeSec Lab develops practical security guidance, detection logic, and defensive tooling for venue operators and software vendors who manage fleets of public or semi-public Windows hosts. The work is grounded in real operations: billing servers, cashier workstations, client images, restoration systems, local networks, and the daily constraints of small gaming businesses.

The long-term research goals are:

- publish a defensible hardening baseline for internet cafe and gaming venue environments;
- produce detection rules that SOC and MSSP teams can adapt safely;
- build a file and process integrity monitor suitable for low-budget deployments;
- document vendor-neutral architectural weaknesses in legacy cafe management software;
- encourage coordinated remediation rather than public exploitation.

## Repository Map

| Path | Purpose |
| --- | --- |
| `01-hardening-checklist/` | Vendor-neutral hardening checklist, threat model, detection rules, and anonymized case studies. |
| `02-integrity-monitor/` | Python integrity monitoring tool for file, process, and event-log based detection. |
| `03-blog/` | Public research notes and long-form technical articles. |
| `.github/` | Security policy, issue templates, CI, and organization profile content. |

## Research Scope

CafeSec Lab focuses on defensive questions:

- How should billing servers, cashier workstations, and client PCs be isolated?
- Which Windows controls matter most in a shared-PC venue?
- How can operators verify that billing software binaries, services, and configuration files have not changed unexpectedly?
- What telemetry should a low-cost SOC collect first?
- How can vendors modernize trust boundaries, update mechanisms, and client-server integrity checks?

The project does not provide legal advice. Operators in any jurisdiction should validate compliance obligations with qualified local counsel and their technology providers.

## What This Project Will Not Publish

CafeSec Lab does not publish weaponized proof-of-concept code, bypass tools, exploit chains, credential material, or step-by-step abuse instructions for venue billing systems. When an attack pattern is discussed, the corresponding detection, mitigation, and validation guidance must appear with it.

The project also does not:

- target named vendors irresponsibly;
- accept cooperation from criminal or gray-market operators;
- fabricate data, commit history, deployment claims, or research outcomes;
- present AI-generated content as field-validated evidence without review;
- encourage testing against third-party systems without written authorization.

## Disclosure and Safety

Potential vulnerabilities must be reported through the private channels in [`.github/SECURITY.md`](.github/SECURITY.md). Public GitHub issues are not an acceptable disclosure channel for vulnerabilities.

The disclosure process is aligned with the [CERT/CC Guide to Coordinated Vulnerability Disclosure](https://certcc.github.io/CERT-Guide-to-CVD/) and GitHub's guidance on [repository security policies](https://docs.github.com/en/enterprise-cloud@latest/code-security/getting-started/adding-a-security-policy-to-your-repository). Project maturity work will track the [OpenSSF Best Practices Badge](https://openssf.org/projects/best-practices-badge/) criteria over time.

## Contact

Primary contact: `magnoormeno@gmail.com`

Public research identity: `CafeSec Lab Research Team`

Sensitive reports should follow the secure-channel instructions in [`.github/SECURITY.md`](.github/SECURITY.md).

## License

Code and documentation are released under the [MIT License](LICENSE), unless a file states otherwise.
