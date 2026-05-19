---
layout: post
title: "Restoration Systems Are Not Security Boundaries"
date: 2026-05-18
author: CafeSec Lab Research Team
categories: [operations, hardening]
tags: [restoration, windows-hardening, shared-pc, incident-response]
---

Restoration software is one of the defining technologies of internet cafes and
gaming venues. Operators depend on it because the business model depends on
fast turnover: a customer finishes a session, the machine returns to a known
state, and the next customer receives a clean desktop. In practice, this has
saved many venues from slow configuration drift, accidental damage, unwanted
software installs, and support calls that would otherwise consume the whole
day.

It is also one of the easiest controls to misunderstand.

A restoration product can be a strong operational recovery control. It can help
return customer-facing systems to an expected image. It can shorten support
cycles and keep game rooms usable. It can make unauthorized user-level changes
disappear after reboot. But it is not, by itself, a security boundary.

That distinction matters. When operators treat restoration as a security
boundary, they often stop asking the questions that would reveal real risk:
Which paths are excluded from restoration? Which services run before the reset
agent is fully active? Can the billing server see events from the client during
the live session? Are logs preserved outside the restored volume? Are policy
changes validated after reboot? Are updates staged and verified, or are they
simply trusted because the machine "comes back clean"?

The purpose of this article is not to criticize restoration vendors. The point
is to make the control more useful by putting it in the right layer of the
defense model.

## What Restoration Actually Solves

In a shared-PC venue, customer machines are hostile environments by default. A
customer has keyboard access, mouse access, a long interactive session, and
often enough time to experiment. Even without malicious intent, customer
activity can create heavy drift: browser changes, game launcher updates, cache
growth, saved credentials, accidental downloads, language settings, peripheral
drivers, and local configuration changes.

Restoration software addresses this operational problem. A well-managed
restoration setup can:

- return the operating system volume to a known state after reboot;
- remove user-installed software from protected locations;
- reduce support time after a bad session;
- preserve a clean golden image across many client machines;
- support rapid fleet recovery after accidental configuration changes;
- give staff confidence that normal customer activity will not permanently
  damage the client build.

Those are valuable outcomes. For a small venue, they can be the difference
between a manageable fleet and constant reinstallation work. A security program
that ignores restoration products will not match the reality of the industry.

The mistake is assuming that a reset after reboot proves that the live session
was safe, that evidence was preserved, or that business logic was protected.
Those are different properties.

## The Live Session Is Still Real

Many venue incidents happen during the active session. A customer does not need
permanent persistence to cause operational damage. A live-session action can
still affect billing state, local processes, service availability, logs,
network traffic, and the user experience of the next few minutes.

If a billing client agent is stopped for five minutes, the fact that the
machine returns to normal after reboot may not answer the business question:
what happened during those five minutes? If endpoint protection is disabled
until restart, the restored image does not automatically prove that nothing was
downloaded, injected, or executed during the session. If local logs vanish on
reboot, the reset can actively remove the evidence needed to understand the
event.

This is why the live session needs controls that operate before the reset:

- standard users should not be local administrators;
- application control should block unapproved execution from writable paths;
- billing, restoration, logging, and endpoint-protection services should have
  restricted service permissions;
- process creation and service events should be logged centrally;
- the billing server should not trust client-side claims without validation;
- time synchronization should be reliable enough to correlate events.

Restoration helps recovery. It does not replace least privilege, telemetry, or
server-side verification.

## Exclusions Are The Real Policy

Every restoration deployment has exceptions. Some are necessary. Game updates,
anti-cheat components, driver caches, billing configuration, local logs, and
launcher state may need to survive reboot. In many venues, the exception list
is where the real security posture lives.

The dangerous pattern is not "there are exclusions." The dangerous pattern is
"nobody can explain the exclusions."

In restoration-heavy rooms, the exception list is often more revealing than the
golden image itself. It shows where operational pressure has quietly rewritten
the original security plan.

An exception list should answer:

- what path is excluded;
- which application owns it;
- who approved it;
- whether customers or cashier users can write to it;
- whether the path can influence startup, services, billing configuration, or
  executable loading;
- how the path is monitored;
- how changes are reviewed after vendor updates.

An excluded writable directory that contains only cache files is very different
from an excluded writable directory that contains DLLs, scripts, plugins,
startup shortcuts, or configuration values used by a privileged service. The
first may be operational noise. The second may be an execution or persistence
path.

The practical recommendation is simple: treat restoration exceptions as a
security-sensitive inventory. Export them, review them, hash important files in
them, and compare them against the approved build record. Do not let exception
lists grow quietly for years.

## The Golden Image Is A Supply Chain

The golden image is often treated as a convenience artifact: a machine was set
up, games were installed, billing software worked, and the image was captured.
In reality, the golden image is a local supply chain. Every customer PC inherits
its assumptions.

If the image contains weak local accounts, excessive administrator rights,
disabled logging, unreviewed vendor tools, or stale security policy, the
restoration product will faithfully preserve those weaknesses. It will restore
the fleet to the same vulnerable state every day.

A defensible image process should include:

- a build checklist with date, operator, and source media;
- hash records for the image and core packages;
- signed installer verification where available;
- local administrator inventory;
- service inventory;
- application-control policy state;
- Defender and ASR configuration state;
- firewall and DNS settings;
- time synchronization settings;
- restoration exception list;
- a rollback plan for failed updates.

This does not require enterprise tooling on day one. Even a simple build record
with hashes, screenshots of key settings, and exported service/policy state is
better than memory. The important shift is cultural: the image is not just "the
working install." It is the root of trust for the client fleet.

## Server Trust Is The Hard Boundary

In legacy cafe systems, the client often has more influence than it should. The
client may report session state, process health, local time, or enforcement
status. Restoration software can keep the client clean between sessions, but it
cannot make the client trustworthy during the session.

The billing server should assume that client-side signals can be delayed,
missing, or inconsistent. That does not mean every venue needs a complex
zero-trust architecture. It means the server should make conservative choices:

- record heartbeat loss and service health changes;
- correlate client claims with server-side session records;
- alert when billing-agent state changes without a matching cashier or server
  event;
- keep authoritative billing state on the server side;
- require signed and authenticated update channels;
- minimize direct database access from cashier and client systems;
- preserve server logs outside any client restoration workflow.

When server-side records are authoritative, a client reset becomes a recovery
event, not a truth source.

## Evidence Must Survive Reboot

The most common operational failure is not that the venue lacks logs. It is that
logs exist only on the system that gets restored, overwritten, or reimaged.

For a restoration-heavy environment, evidence should leave the client quickly.
At minimum, a pilot should preserve:

- Windows Security events for logons, process creation, service installation,
  registry changes, and log clearing;
- System events for service stop, crash, and state changes;
- PowerShell operational logs where PowerShell is permitted;
- Defender and Code Integrity events where available;
- billing-agent health events;
- restoration-agent health and exception-change records;
- time synchronization state;
- integrity-monitor alerts and baseline verification results.

This does not have to begin with a full SIEM. Windows Event Forwarding, Wazuh,
restricted file shares, or even scheduled exports can be a starting point. The
standard is not perfection. The standard is that rebooting a suspicious client
does not destroy the only useful evidence.

## A Better Mental Model

Restoration belongs in a layered model:

| Layer | Question | Example control |
| --- | --- | --- |
| Prevention | Can the customer execute or modify sensitive components? | Least privilege, WDAC/AppLocker, ACLs, USB policy |
| Detection | Can the venue see suspicious live-session behavior? | Process creation logs, service events, registry auditing |
| Integrity | Can the venue prove critical files changed or did not change? | Hash baselines, HMAC-signed baselines, image hashes |
| Recovery | Can the venue return the client to service quickly? | Restoration software, tested images, rollback process |
| Evidence | Can the venue explain what happened after recovery? | Central logs, alert archives, preserved event exports |

Restoration is strongest in the recovery layer. It contributes to integrity
when image and exception state are measured. It contributes to detection only
when its own events are collected. It contributes to prevention only when
paired with permissions and application-control policy.

## A Practical Audit For Operators

A venue operator does not need to solve every architecture problem immediately.
Start with a small audit:

1. Export the restoration policy and exception list.
2. Identify every excluded path that can contain executable code, scripts, DLLs,
   drivers, plugins, shortcuts, or service configuration.
3. Run `icacls` on those paths and confirm that customers and cashier users
   cannot write to sensitive locations.
4. Hash critical billing and restoration binaries after a known-good build.
5. Confirm that service stop, service crash, and process creation events reach a
   location outside the restored volume.
6. Reboot a pilot client and verify that Defender, application control, time
   sync, billing agent, restoration agent, and logging are still healthy.
7. Record who is allowed to change restoration exceptions and how those changes
   are approved.

This audit is intentionally plain. It turns a vague belief into evidence.

## What Vendors Can Do Better

Vendors can help operators by making restoration security state easier to
verify. Useful features include:

- signed policy exports;
- clear exception inventories;
- tamper-evident logs;
- event forwarding support;
- role-based administration;
- documented service permissions;
- health checks that confirm restoration, billing, and logging components are
  all active after reboot;
- integration hooks for integrity monitoring.

The best vendor experience is not one where the operator is told to trust the
client. It is one where the operator can verify the client returned to the
approved state, and can still investigate what happened before the reboot.

## Conclusion

Restoration systems are essential in shared-PC venues. They make the business
operable. They reduce support burden. They help customers receive a consistent
machine at the start of a session.

But they should not be asked to do a job they cannot do alone. A reset is not a
log. A clean reboot is not proof of a clean session. A golden image is not
automatically a secure image. An exception list is not harmless just because the
product calls it an exception.

The right approach is not to remove restoration. The right approach is to
measure it, constrain it, monitor it, and surround it with controls that operate
before, during, and after the reset.

For small operators, that is a realistic path. It does not require buying a
large SOC on day one. It requires asking better questions and preserving enough
evidence to answer them.

## About This Research

This research note is published by the CafeSec Lab Research Team. It is based
on operational patterns common to restoration-heavy Windows fleets and is
intended as defensive guidance for operators, vendors, and SOC teams.

## Disclosure

This article does not describe a vendor-specific vulnerability and does not
include exploit steps, bypass instructions, or tool-specific abuse procedures.
Any future vendor-specific findings should follow coordinated disclosure before
publication.

## References

- NIST SP 800-53 Rev. 5, CM-2 Baseline Configuration and CM-6 Configuration Settings.
- NIST SP 800-92, Guide to Computer Security Log Management.
- NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide.
- Microsoft Windows Defender Application Control documentation.
- Microsoft AppLocker documentation.
- Microsoft Windows event auditing documentation.
- MITRE ATT&CK T1562.001, Disable or Modify Tools.
- MITRE ATT&CK T1547, Boot or Logon Autostart Execution.
- MITRE ATT&CK T1112, Modify Registry.
