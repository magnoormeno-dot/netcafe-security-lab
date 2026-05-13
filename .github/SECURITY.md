# Security Policy

## Supported Versions

CafeSec Lab is currently in active research development. Security fixes apply to the default branch until versioned releases are created.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Unreleased forks | No |

## Reporting a Vulnerability

Do not report vulnerabilities through public GitHub issues, discussions, pull requests, or social media.

Preferred private channels:

- Email: `magnoormeno@gmail.com`
- PGP: public key pending publication. Until a key is published, send an initial contact request without exploit details.
- Signal: available by prior email coordination for sensitive follow-up.

Please include:

- affected component, file, rule, or document;
- impact and affected deployment assumptions;
- minimal reproduction steps that avoid third-party systems;
- defensive context, such as logs, detection ideas, or mitigation notes;
- whether you believe a vendor, venue operator, or upstream project is affected.

Do not include live credentials, customer data, private venue information, or instructions that enable billing bypass. If those details are essential for validation, coordinate privately before sending them.

## Coordinated Disclosure Timeline

CafeSec Lab follows a 90-day coordinated disclosure window by default. The timeline may be shortened when a fix is available and affected parties agree, or extended when the issue is complex and all parties are actively coordinating in good faith.

Expected process:

1. Acknowledge receipt within 7 calendar days when possible.
2. Triage impact, scope, and affected parties.
3. Coordinate with vendors, operators, or upstream maintainers when needed.
4. Prepare fixes, mitigations, or advisory text.
5. Publish defensive guidance after the coordination window or earlier by agreement.

This process is informed by the [CERT/CC Guide to Coordinated Vulnerability Disclosure](https://certcc.github.io/CERT-Guide-to-CVD/) and GitHub's guidance on [security policies](https://docs.github.com/en/enterprise-cloud@latest/code-security/getting-started/adding-a-security-policy-to-your-repository).

## Scope

In scope:

- vulnerabilities in CafeSec Lab code;
- unsafe detection rules that create unreasonable operational risk;
- documentation errors that could lead operators to weaken their environments;
- accidental exposure of sensitive research material.

Out of scope:

- testing third-party internet cafes, vendors, gaming venues, or cloud services without written authorization;
- denial-of-service testing against real production systems;
- social engineering, phishing, or physical intrusion;
- reports that require publishing exploit code or billing bypass procedures.

## Safe Harbor

Good-faith research against CafeSec Lab-owned assets that follows this policy is welcome. This policy does not authorize testing against third-party venues, vendors, networks, software installations, or customer systems.
