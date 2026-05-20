# CafeSec Lab Project Health Playbook

This playbook defines the recurring maintenance checks for CafeSec Lab. It is
intended to keep the public project credible, technically defensible, and aligned
with its defensive-security boundaries.

## Public Identity Inventory

Use these links as the current public identity chain for the project:

- Project home: <https://cafeseclab.com/>
- Repository: <https://github.com/magnoormeno-dot/netcafe-security-lab>
- Research site: <https://research.cafeseclab.com/>
- Latest release: <https://github.com/magnoormeno-dot/netcafe-security-lab/releases>
- Root site repository: <https://github.com/magnoormeno-dot/cafeseclab.com>
- Security contact: `security@cafeseclab.com`
- Research contact: `research@cafeseclab.com`
- General contact: `contact@cafeseclab.com`
- HackerOne profile: <https://hackerone.com/eshine>
- LinkedIn profile: <https://www.linkedin.com/in/shine-e-480463410/>

When any public profile changes, update this inventory and the relevant public
profile text in the same maintenance pass.

## Weekly Maintenance Sweep

Run this sweep once per week or before any external application, outreach post,
or release. The goal is not to create artificial activity; it is to catch stale
links, red CI, identity drift, and accidental overclaims.

```powershell
git status --short
gh run list --limit 8 --json workflowName,displayTitle,status,conclusion,createdAt,url
gh release list --limit 5
rg -n "magnoormeno@gmail|shine leek|Dubai|UAE|magnoormeno-dot.github.io/netcafe-security-lab|<contact placeholder>|TODO|FIXME" -S . --glob "!**/.git/**" --glob "!docs/maintenance/project-health.md"
```

Expected result:

- no uncommitted work unless a maintenance change is in progress;
- latest `Integrity Monitor CI` and `Publish Research Blog` runs are green;
- no old Gmail address, old author name, stale GitHub Pages URL, or placeholder
  contact text remains in public files;
- `TODO` or `FIXME` findings are either intentional roadmap notes or converted
  into tracked issues.

## Website And Contact Checks

Validate the public web and mail identity whenever DNS, Pages, or contact text
changes.

```powershell
Resolve-DnsName cafeseclab.com -Type A
Resolve-DnsName www.cafeseclab.com -Type CNAME
Resolve-DnsName research.cafeseclab.com -Type CNAME
(Invoke-WebRequest -UseBasicParsing https://cafeseclab.com/).StatusCode
(Invoke-WebRequest -UseBasicParsing https://cafeseclab.com/.well-known/security.txt).StatusCode
(Invoke-WebRequest -UseBasicParsing https://research.cafeseclab.com/).StatusCode
(Invoke-WebRequest -UseBasicParsing https://research.cafeseclab.com/about/).StatusCode
(Invoke-WebRequest -UseBasicParsing https://research.cafeseclab.com/feed.xml).StatusCode
```

Manual checks:

- send a test message to `research@cafeseclab.com`;
- send a test message to `security@cafeseclab.com`;
- confirm Cloudflare Email Routing shows all role addresses as active;
- confirm GitHub Pages still enforces HTTPS for `cafeseclab.com`;
- confirm GitHub Pages still enforces HTTPS for `research.cafeseclab.com`.

## Integrity Monitor Quality Gate

Run the local quality gate before changing Python code, configuration examples,
or tests.

```powershell
cd 02-integrity-monitor
python -m pip install -e .[dev]
ruff check .
ruff format --check .
mypy src tests
pytest
```

Any change that lowers coverage or weakens type checking should be justified in
the commit message or follow-up issue.

## Detection Content Quality Gate

Detection rules should remain vendor-neutral, defensive, and tunable. Before a
release, review each Sigma and YARA rule for:

- explicit defensive intent;
- honest false-positive documentation;
- clear ATT&CK mapping where applicable;
- no vendor-specific claims without coordinated disclosure;
- no offensive walkthroughs or bypass instructions.

If local tooling is available, compile YARA rules and validate Sigma syntax
before tagging a release.

## Blog And Outreach Review

Before publishing or promoting a post, check that the writing:

- names the defensive problem and the operational audience;
- avoids unverifiable field claims;
- does not imply vendor endorsement or OpenAI endorsement;
- pairs threat discussion with mitigation, detection, or validation guidance;
- uses `CafeSec Lab Research Team` consistently as the public research identity;
- points readers to `https://cafeseclab.com/`,
  `https://research.cafeseclab.com/`, and role-based email addresses.

Keep outreach modest. One thoughtful post in one community is better than broad
cross-posting without follow-up capacity.

## Release Readiness

Use a release only when there is a coherent user-visible improvement, not merely
because a week has passed.

Minimum release checklist:

- main branch is clean and pushed;
- CI is green after the final commit;
- release notes describe defensive value and known limitations;
- blog and README links are current;
- `SECURITY.md` still points to `security@cafeseclab.com`;
- no internal delivery notes or private operational details are present.

Suggested versioning:

- `v0.1.x`: hygiene, documentation, tuning, and bug-fix releases;
- `v0.2.0`: new operator-facing workflow or materially improved monitoring;
- `v1.0.0`: only after field validation and a stable support posture.

## Red Flags To Fix Immediately

- Red CI on `main`.
- Broken research-site HTTPS.
- Public files containing personal Gmail, old author names, or stale links.
- Claims that imply certification, endorsement, field deployment, or vendor
  validation without evidence.
- Detection rules that describe abuse without corresponding defensive handling.
- Any contribution, issue, or blog draft that asks for bypass tooling,
  credentials, or unauthorized testing guidance.
