# 04-validation-lab — reproducible, network-isolated validation testbed

A local, fully **network-isolated** virtualization testbed for studying Windows host hardening, Sysmon
logging, detection rules (Sigma/YARA), and SIEM alerting — and for **validating** the repository's
detection rules and integrity monitor.

- **Platform:** Hyper-V (the host already runs a hypervisor and is Windows 11 Pro, so native is optimal).
- **Network:** a **Private virtual switch** — fully isolated; VMs cannot reach the internet or touch the
  host's real LAN (a Private switch creates no host vEthernet adapter at all).
- **Domain:** **CSL-Server = internal domain controller `cafesec.lab`** (so source-initiated WEF can use
  Kerberos and configuration can be pushed by GPO); the AD DNS has no forwarders, so the air-gap holds.

> **Scope / safety boundary.** This is a **defensive engineering setup**. It contains only the deployment
> scripts and docs for virtualization, network isolation, and defensive tooling. It contains **no attack,
> exploit, penetration, or vulnerability-simulation code**, and configures nothing that points at a real
> device or real network. Any attack simulation, if performed, is done manually by the operator inside the
> fully isolated environment and is out of scope for this module.

---

## Where this fits in the CafeSec Lab repository

This module is the project's **reproducible validation testbed** — it turns the rest of the repo's *claims*
into *lab evidence*.

```
01-hardening-checklist  --(Sigma/YARA rules + hardening baselines NI-xx)--+
                                                                          v
       04-validation-lab (this module) -- isolated Hyper-V/domain + Sysmon/Wazuh/WEF telemetry
                                                                          | deploy & validate
       02-integrity-monitor (Python) -- runs in lab VMs --> real detections / false-positive tuning
                                                                          | lab evidence
       docs/pilot + docs/cvp (evidence pack) -- informs --> 03-blog (research)
```

**Five seams** (see [`COVERAGE.md`](COVERAGE.md)):

1. **Rule consumption** — `scripts\analysis\Invoke-RuleValidation.ps1` validates the **real** Sigma/YARA
   rules in [`../01-hardening-checklist/detection`](../01-hardening-checklist/detection) in place (Sigma
   converts to a Lucene query; YARA compiles). This **offline rung is enforced by CI**
   ([`validation-lab-rules.yml`](../.github/workflows/validation-lab-rules.yml)) and recorded in
   [`../docs/cvp/lab-validation-evidence.md`](../docs/cvp/lab-validation-evidence.md).
2. **Monitor deployment** — `scripts\guest\Deploy-IntegrityMonitor.ps1` installs
   [`../02-integrity-monitor`](../02-integrity-monitor) into a lab Windows VM to validate it on real
   Sysmon/WEF telemetry instead of synthetic fixtures (**wired; pending a run**).
3. **Isolation implementation** — [`docs/02-network-isolation.md`](docs/02-network-isolation.md) is the
   reference implementation of
   [`../01-hardening-checklist/checklist/03-network-isolation.md`](../01-hardening-checklist/checklist/03-network-isolation.md).
4. **Coverage matrix** — [`COVERAGE.md`](COVERAGE.md) maps NI-xx / detection rules to the lab scripts and
   telemetry that validate them, marking **✅ proven** vs **◐ wired-unrun**.
5. **Evidence export** — `scripts\analysis\Export-CvpEvidence.ps1` renders the latest rule-validation
   report into [`../docs/cvp/lab-validation-evidence.md`](../docs/cvp/lab-validation-evidence.md).

> **Honesty boundary.** As of now the **only ✅ (committed-artifact-proven)** item is the **offline rule
> convert/compile** (CI-enforced: Sigma 3/3, YARA 3/3). Everything that needs running VMs (live-fire
> detections, the integrity monitor on real logs, the isolation verifiers against real VMs) is **◐
> wired-unrun**. Lab output is reproducible synthetic evidence, **not** field validation, and must be
> human-reviewed before being cited in `docs/cvp/` or `docs/pilot/` per the repo's "What This Project Will
> Not Publish" policy.

---

## Directory structure

```
04-validation-lab/
├─ README.md                     <- this file
├─ COVERAGE.md                   <- rule/checklist -> lab mapping (proven vs wired)
├─ PSScriptAnalyzerSettings.psd1 <- lint settings (Write-Host allowed; all else on)
├─ config/
│  ├─ lab.psd1                   <- central config (IPs / specs / paths / domain)
│  ├─ wef/cafesec-subscription.xml
│  └─ ubuntu/                    <- CSL-Wazuh netplan + optional dnsmasq
├─ scripts/
│  ├─ Invoke-LabSetup.ps1        <- host-side orchestrator (runs 00->04, handles the Hyper-V reboot gate)
│  ├─ 00-Preflight-Check.ps1 .. 04-Verify-Isolation.ps1
│  ├─ Switch-LabNetwork.ps1 / Reset-Lab.ps1 / New-PayloadIso.ps1
│  ├─ lib/Common.ps1
│  ├─ domain/                    <- DC promotion, air-gap DNS, domain join, WEF GPO
│  ├─ guest/                     <- run inside VMs (Sysmon, Wazuh agent, WEF, static IP, isolation test)
│  ├─ wazuh/                     <- Ubuntu: Wazuh manager install + isolation test
│  └─ analysis/                  <- Setup-RuleEngines / Invoke-RuleValidation / Invoke-YaraScan / Export-CvpEvidence
├─ rules/{sigma,yara}/           <- lab-only overlay (source of truth is 01-hardening-checklist/detection)
├─ docs/                         <- overview, network isolation, domain+WEF, downloads
├─ reports/                      <- generated rule-validation reports (gitignored)
└─ downloads/                    <- downloaded installers/ISOs (gitignored)
```

## Execution order (deliverables are scripts you review and run yourself)

Run in an **administrator PowerShell**, working directory `04-validation-lab\scripts`. Scripts are
idempotent. Read [`docs/02-network-isolation.md`](docs/02-network-isolation.md) (the two-phase build) first.

- **A. Host prep (+ build VMs)** — recommended one-shot: `.\Invoke-LabSetup.ps1 -DryRun` then
  `.\Invoke-LabSetup.ps1` (preflight -> enable Hyper-V -> isolated switch -> 4 VMs -> verify).
- **B. Download images & tools** — see [`docs/downloads.md`](docs/downloads.md) (temporary-connectivity phase).
- **C. Build VMs** — `.\03-New-LabVMs.ps1` (Gen2 + Secure Boot + vTPM).
- **D. Build the domain** — `domain\Install-DomainController.ps1` -> `Set-DcDnsAirgap.ps1`; clients
  `domain\Join-LabDomain.ps1` (see [`docs/03-domain-and-wef.md`](docs/03-domain-and-wef.md)).
- **E. Deploy the defensive stack** — Ubuntu `wazuh\install-wazuh-manager.sh`; Windows
  `guest\Deploy-Sysmon.ps1` / `guest\Install-WazuhAgent.ps1`; DC `guest\Configure-WEC-Collector.ps1` ->
  `domain\New-WefGpo.ps1`; analysis `analysis\Setup-RuleEngines.ps1`.
- **F. Lock down isolation & verify** — `.\Switch-LabNetwork.ps1 -Phase Isolated`; configure static IPs;
  `.\04-Verify-Isolation.ps1` + in-VM `guest\Test-GuestIsolation.ps1` / `wazuh/test-guest-isolation.sh`.
  Both host-side and guest-side must PASS before any research.
- **G. Validate detection rules** — `analysis\Invoke-RuleValidation.ps1` (offline; CI-enforced) ->
  `analysis\Export-CvpEvidence.ps1`; drop your own rules in `rules\`, or submit them to
  `01-hardening-checklist/detection`.

## Safety notes

- Any research/attack simulation happens only in **Phase 2 (full isolation)** and only by the operator
  manually — out of scope for this module.
- After any structural change (new VM, NIC change), **re-run the isolation verification** before continuing.
- Get tools and images **from official sources only** (see [`docs/downloads.md`](docs/downloads.md)).
