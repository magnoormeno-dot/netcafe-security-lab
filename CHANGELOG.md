# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-04

Maturity pass on the `04-validation-lab` testbed: from "well-engineered but never run /
never tested" to **tested, automated, and producing real evidence** — culminating in a first
end-to-end **live-fire** run in a fully built, air-gapped lab.

### Added
- **Live-fire detection evidence** (`docs/cvp/live-fire-evidence.md`): in a running,
  network-isolated `cafesec.lab` (domain controller + Sysmon on three Windows VMs + Windows Event
  Forwarding), all three Sigma rules were **lit 3/3** by *benign, reversible, lab-owned* stimuli
  that target non-existent dummy objects — each captured with a timestamp and the verbatim event
  field (Sysmon EID 1 / System 7045 / Security 4657), plus a cross-host WEF forwarding proof
  (events reaching the central collector). `COVERAGE.md` is annotated with the run. This is the
  live-fire counterpart to the offline 6/6 convert/compile evidence; synthetic / benign /
  lab-owned, not field-validated, with a human reviewer gate.
- **Resumable M0->M4 build walkthrough** (`docs/06-build-walkthrough.md` + `.en.md`): a linear,
  copy-paste path from "not built" to live-fire evidence, with real install gotchas captured
  (Win11 vTPM `0xC000A002` key-protector reset, Ubuntu Gen2 Secure Boot template, native-command
  stderr under PowerShell Direct).
- **Defensive validation runbook** (`04-validation-lab/docs/04-defensive-validation-runbook.md`):
  nine benign-only test cases (3 Sigma rules, 3 YARA rules, integrity-monitor baseline/scan/verify,
  Sysmon/WEF/Wazuh telemetry path, lab isolation) with stimulus / expected telemetry / expected alert /
  evidence / FP-handling / rollback / safety-boundary, plus CVP wording and a reviewer gate.
- **Pester v5 test suite** (`04-validation-lab/tests/`, 58 tests, 100% `LabLogic` coverage): pure
  decision logic, config loading, the CVP evidence pipeline, and Reset-Lab safety wiring.
- **`scripts/lib/LabLogic.psm1`**: extracted, unit-testable pure logic — isolation route-leak filter,
  Hyper-V reboot gate, two-phase switch resolver, locale-safe Home-edition check, drive-root resolver,
  reset allowlist + switch-removal guard, artifact checksum, and version-manifest loader.
- **Reproducibility**: `config/versions.psd1` pinned-version + checksum manifest (SHA256 now filled
  from official first-download for Sysmon 15.20, the SwiftOnSecurity config at a reviewed commit, the
  Wazuh agent 4.9.2, and the three evaluation ISOs), verified at deploy time via
  `Test-LabArtifactChecksum`; plus drive-root override / auto-relocation (`CAFESEC_VMROOT` /
  `CAFESEC_ISOROOT`) so the lab no longer hard-codes `E:`.
- **Unattended provisioning** (`config/unattend/`, `scripts/New-UnattendIso.ps1`,
  `docs/05-unattended-provisioning.md`): Windows autounattend + Ubuntu cloud-init templates and a
  Pester-tested seed-ISO builder (reuses the IMAPI2 `New-PayloadIso` core) to automate Phase-1 OS
  install instead of manual clicking.
- **CI expansion** (`Validation Lab CI`): Pester job, ShellCheck job, and an offline rule-validation
  job (Sigma convert + YARA compile) that gates on any rule failure and regenerates the CVP evidence;
  plus a weekly scheduled health sweep to catch toolchain drift.
- **CVP evidence safety boundary** and a STUB "do not cite" banner, emitted by the generator and kept
  byte-identical in the committed file.
- Governance: `VERSION`, this `CHANGELOG.md`, and `.github/CODEOWNERS`.

### Fixed
- **`Invoke-RuleValidation.ps1` Sigma conversion** (rules previously failed to convert): the current
  pySigma OpenSearch backend target is `opensearch_lucene` (the old `opensearch` name was removed) and
  the `ecs_windows` pipeline needs `--disable-pipeline-check`; success is now judged by exit code, since
  sigma-cli writes progress to stderr and made `$?` unreliable. All six detection rules now convert/
  compile cleanly — the first real, all-pass lab evidence.
- **`Reset-Lab.ps1`**: switch removal is guarded by the unit-tested `Test-LabSwitchRemovable` allowlist
  and wrapped in try/catch, matching the resilient per-item teardown used for VMs and VHDX.
- **`04-Verify-Isolation.ps1`**: the layer-3 reachability probe read the VM IP with
  `Select-Object -ExpandProperty` (which throws on the hashtable config and silently fell back to a
  hard-coded default); it now projects the value with member access so the check uses the real IP.
- **`Setup-RuleEngines.ps1`**: the Sigma backend install no longer gates on `$?` (which `sigma plugin
  install` flips via stderr), matching the `Invoke-RuleValidation.ps1` fix — a clean install is no
  longer mis-reported as failed.

### Changed
- Cross-linked the runbook from `README`, `COVERAGE.md`, and `docs/00-overview.md`; documented the
  corrected `sigma convert` invocation in the README and `Setup-RuleEngines.ps1`.
- CI `ShellCheck` job gates on `--severity=warning` so intentional/benign info-level notes in the
  bash helpers don't fail the build (real warnings/errors still do).

## [0.1.1] - 2026-05-30

### Added
- Validation-lab scaffolding, detection rules (Sigma/YARA), the integrity monitor, and supporting
  docs. See git history prior to CHANGELOG adoption for detail.

## [0.1.0] - 2026-05-20

### Added
- Initial public scaffold of the CafeSec Lab repository.

[0.2.0]: https://github.com/magnoormeno-dot/netcafe-security-lab/releases/tag/v0.2.0
[0.1.1]: https://github.com/magnoormeno-dot/netcafe-security-lab/releases/tag/v0.1.1
[0.1.0]: https://github.com/magnoormeno-dot/netcafe-security-lab/releases/tag/v0.1.0
