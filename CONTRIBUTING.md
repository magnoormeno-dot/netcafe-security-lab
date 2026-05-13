# Contributing to CafeSec Lab

Thank you for considering a contribution. This project accepts defensive research, hardening guidance, detection logic, tests, documentation, and anonymized operational lessons that improve security for internet cafes and gaming venues.

## Contribution Principles

- Keep the work defensive, vendor-neutral, and verifiable.
- Pair any description of attacker behavior with detection or mitigation guidance.
- Avoid naming a vendor, customer, venue, or product unless the information is already public and the context is responsible.
- Prefer primary references such as NIST, MITRE ATT&CK, CIS Benchmarks, Microsoft documentation, CERT/CC, CVE records, and vendor security documentation.
- Do not submit weaponized proof-of-concept code, billing bypass instructions, credential material, or exploit chains.

## What to Submit

Good first contributions include:

- improvements to checklist wording or verification commands;
- mappings from controls to MITRE ATT&CK techniques;
- Sigma or YARA rule refinements with realistic false-positive notes;
- tests for the integrity monitor;
- anonymized case studies that remove venue, vendor, customer, staff, and infrastructure identifiers.

## Vulnerabilities

Do not open a public issue for a vulnerability. Follow [`.github/SECURITY.md`](.github/SECURITY.md) and send sensitive details through the private disclosure channel.

## Documentation Style

Primary project documentation is English. Keep writing precise, calm, and evidence-based. Avoid hype, vendor bashing, and claims that cannot be verified.

Each hardening recommendation should include:

- risk description;
- recommended configuration;
- verification command or procedure;
- authoritative reference.

## Code Style

Python code targets Python 3.10 and newer. Use:

- PEP 604 union type syntax;
- clear Google-style docstrings;
- structured logging;
- explicit error handling;
- tests for new behavior.

The integrity monitor uses Ruff, mypy, and pytest. Run the project test suite before submitting code once the tooling is available.

## Commit Messages

Use Conventional Commits:

- `feat:` for new functionality;
- `fix:` for bug fixes;
- `docs:` for documentation;
- `test:` for tests;
- `refactor:` for internal changes;
- `chore:` for maintenance.

Keep commits focused. One commit should explain one coherent change and why it exists.
