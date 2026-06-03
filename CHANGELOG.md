# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-04

Maturity pass on the `04-validation-lab` testbed: from "well-engineered but never run /
never tested" toward "tested, automated, and producing real evidence."

### Added
- **Defensive validation runbook** (`04-validation-lab/docs/04-defensive-validation-runbook.md`):
  nine benign-only test cases (3 Sigma rules, 3 YARA rules, integrity-monitor baseline/scan/verify,
  Sysmon/WEF/Wazuh telemetry path, lab isolation) with stimulus / expected telemetry / expected alert /
  evidence / FP-handling / rollback / safety-boundary, plus CVP wording and a reviewer gate.
- **Pester v5 test suite** (`04-validation-lab/tests/`, 51 tests): pure decision logic, config loading,
  the CVP evidence pipeline, and Reset-Lab safety wiring.
- **`scripts/lib/LabLogic.psm1`**: extracted, unit-testable pure logic — isolation route-leak filter,
  Hyper-V reboot gate, two-phase switch resolver, locale-safe Home-edition check, drive-root resolver,
  reset allowlist + switch-removal guard, artifact checksum, and version-manifest loader.
- **Reproducibility**: `config/versions.psd1` pinned-version + checksum manifest, and drive-root
  override / auto-relocation (`CAFESEC_VMROOT` / `CAFESEC_ISOROOT`) so the lab no longer hard-codes `E:`.
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

### Changed
- Cross-linked the runbook from `README`, `COVERAGE.md`, and `docs/00-overview.md`; documented the
  corrected `sigma convert` invocation in the README and `Setup-RuleEngines.ps1`.

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
