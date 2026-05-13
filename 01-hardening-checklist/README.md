# CafeSec Lab Hardening Checklist

This subproject contains the defensive baseline for internet cafes, gaming venues, esports hotels, and shared-PC environments. The first target environment is a Dubai-managed venue using Windows client PCs, one or more billing servers, cashier or reception workstations, restoration software, and a mixed wired/wireless network.

The checklist is vendor-neutral. It is intended to help operators ask better questions, verify control state, and prioritize security work without publishing bypass techniques or tool-specific exploitation steps.

## Contents

| File | Purpose |
| --- | --- |
| `checklist/00-threat-model.md` | Asset inventory, threat actors, attack surfaces, and risk matrix. |
| `checklist/01-windows-host.md` | Windows host hardening checklist. |
| `checklist/02-billing-software.md` | Billing software deployment and architecture checklist. |
| `checklist/03-network-isolation.md` | Network segmentation and traffic control checklist. |
| `checklist/04-physical-security.md` | Physical access, firmware, boot, and hardware control checklist. |
| `checklist/05-incident-response.md` | Incident response and evidence preservation checklist. |
| `detection/` | YARA and Sigma rules for defensive monitoring. |
| `case-studies/` | Fully anonymized case studies and submission template. |
| `references/` | Control and detection mapping references. |

## Safety Rule

Every checklist item must be actionable by a defender and verifiable by an operator. Any discussion of abuse patterns must include detection, prevention, containment, or recovery guidance.

## Intended Readers

- Venue owners and operators who need a practical baseline.
- IT contractors supporting gaming venues.
- SOC and MSSP analysts building low-cost detection for shared-PC fleets.
- Billing software vendors reviewing hardening expectations.

## Non-Goals

This project does not provide exploit instructions, bypass tools, or vendor-specific vulnerability claims. It also does not replace legal, insurance, or regulatory advice for Dubai, UAE, or any other jurisdiction.
