# rocm-security-gh

This repository serves as the central source for ROCm security and governance automation. It provides reusable GitHub Actions workflows, security scanning integrations, and governance configurations to help ROCm repositories implement consistent security controls and comply with organizational and regulatory requirements.

The repository includes:

- Reusable GitHub Actions workflows
- Security scanning integrations and configurations (e.g., Bandit, CodeQL, Gitleaks, Trivy, Zizmor)
- Best practices for secure software development and repository management

All ROCm repository owners and maintainers should adopt these workflows and security controls to improve security posture, reduce risk, and maintain consistent governance across the ROCm ecosystem.

## Binary integrity

Scanner scripts that download a pinned artifact at run time (e.g.
`gitleaks.py`, `zizmor.py`, `trivy.py`, `bandit.py`) verify it against the
repo-root `checksums.sha256` file, via the shared
`security_scanners/utils/binary_checksums.py` helper,
before extracting or executing anything. A digest mismatch (or a
missing/malformed checksums file) makes the scan job fail closed rather
than run an unverified artifact.

## Scanners

`.github/workflows/security-baseline.yml` is the single `workflow_call`
entry point every ROCm repository calls. One job in the caller fans out
to one isolated job per scanner, which means:

- **What runs is org policy, not a repository setting.** Which scanners
  run and the severity that fails them are not inputs. A repository
  cannot opt out of a scanner or relax a threshold, and every
  repository picks up a newly added scanner on its next run without a
  pull request against it.
- **What counts as a finding is the repository's own business.** Which
  of its paths are vendored, which fixtures hold deliberately fake
  credentials, which findings it has already triaged: a scanned
  repository states that in its own config file, and that file wins over
  the default here. See [Per-repository
  configuration](#per-repository-configuration).
- **Scanners stay isolated.** Each one gets its own runner, its own
  workspace and its own check run, so no scanner can see another's
  leftover report files, and an individual scanner can be made a
  required status check in branch protection.
- **Callers don't learn per-scanner vocabulary.** The inputs are
  tool-independent and each scanner maps them onto its own flags. Ask
  for `report_formats: human` and every scanner produces whatever its
  reviewer-readable format happens to be called.

Inputs, all optional, describe the calling event and who reads the
output: `scan_mode`, `report_formats` and `scan_path`. The input
descriptions in the workflow file are the authoritative reference.

To change policy, edit this repository: `SCANNERS` in
`security_scanners/utils/compute_scan_matrix.py` decides which scanners
run, and each scanner script's own defaults decide the severity that
fails it and how sensitively it reports.

### Per-repository configuration

Each scanner reads the config file the scanned repository ships, and
falls back to the copy in this repository when it ships none. The scan
log names the file that was used, so it is always visible in the check
which one won:

| Scanner  | Read from the scanned repository                     | Default here    |
| -------- | ---------------------------------------------------- | --------------- |
| gitleaks | `gitleaks.toml`, `.gitleaks.toml`, `.gitleaksignore` | `gitleaks.toml` |
| zizmor   | `zizmor.yml`, `.github/zizmor.yml`                   | `zizmor.yml`    |
| bandit   | `bandit.yaml`, `bandit.yml`                          | `bandit.yaml`   |
| trivy    | `trivy.yaml`, `trivy.yml`, `.trivyignore`            | `trivy.yaml`    |

This covers detection: allowlists, excluded paths, per-rule
suppressions, and the fingerprints of findings already triaged. It does
not cover which scanners run or which severity fails the build, which
stay in code here for exactly that reason -- a config file cannot switch
a scanner off, only describe the repository it is scanning.

A repository that tunes detection this way owns the consequences: an
allowlist wide enough to hide real findings will hide them. Prefer the
narrowest expression of the exception (a path, a rule, a fingerprint)
over a blanket one, the same way this repository's own configs do.

The scanners below are what runs today.

### Zizmor

[zizmor](https://docs.zizmor.sh/) is a static analysis tool for GitHub
Actions. It reads workflow and composite-action definitions and reports
security weaknesses in the CI configuration itself -- template injection
through unquoted `${{ }}` expressions, over-broad `permissions:` grants,
action references pinned to a mutable tag, credentials left on disk for
later steps -- grading each finding by severity and confidence so a gate
can fail on the serious ones while a reviewer triages the rest.

- Check run: `zizmor`
- `report_formats`: `sarif` (default), `json`, `plain`, `github`, and
  `human` (an alias for `plain`)
- `scan_mode: changed` audits only the workflow / composite-action /
  dependabot files the calling event touched.
- Fails on findings at or above HIGH severity; reports still carry every
  finding. Audits with zizmor's `regular` persona, which surfaces
  high-signal findings rather than everything zizmor knows about.

### Gitleaks

[gitleaks](https://github.com/gitleaks/gitleaks) is a secret scanner. It
walks a repository's git history looking for committed credentials --
API keys, cloud tokens, private keys -- matching against a large set of
built-in detection rules plus any repo-specific rules in `gitleaks.toml`,
so a secret is caught even after it has been removed from the working
tree.

- Check run: `gitleaks`
- `report_formats`: `sarif` (default), `json`, `csv`, `junit`, and
  `human` (an alias for `csv`)
- `scan_mode: changed` scans only the commits the calling event
  introduced, and requires a `pull_request` or `push` payload.
- Has no severity scale: every leak fails the job.

### Bandit

[bandit](https://bandit.readthedocs.io/) is a static analysis tool for
Python. It walks each source file's AST and flags insecure constructs --
`subprocess` with `shell=True`, hardcoded passwords, weak hashes,
`yaml.load` without a safe loader, disabled TLS verification, `assert`
used as a runtime check -- grading each finding by severity and
confidence.

- Check run: `bandit`
- `report_formats`: `sarif` (default), `json`, `csv`, `html`, `txt`,
  `xml`, `yaml`, and `human` (an alias for `txt`)
- `scan_mode: changed` scans only the Python files the calling event
  touched; non-Python files are skipped in either mode.
- Fails on findings at or above HIGH severity; reports still carry every
  finding.

### Trivy

[trivy](https://trivy.dev/) scans a filesystem for known vulnerabilities
in declared dependencies and for infrastructure misconfigurations --
vulnerable package versions across language and OS manifests, plus
insecure Dockerfile, Kubernetes, Terraform and Helm settings -- matching
against its own regularly updated vulnerability and policy databases.

- Check run: `trivy`
- `report_formats`: `sarif` (default), `json`, `table`, `cyclonedx`,
  `spdx-json`, `github`, and `human` (an alias for `table`)
- `scan_mode: changed` is a no-op unless the calling event touched a
  dependency manifest, IaC or container file, and otherwise scans all of
  `scan_path`: trivy needs the whole subtree to resolve transitive
  dependencies and cross-file IaC references, so unlike bandit and zizmor
  it is never handed an individual file list.
- Fails on findings at or above HIGH severity; reports still carry every
  finding. Runs trivy's `misconfig` and `vuln` scanners; `secret` is
  deliberately left out because gitleaks already covers secret detection.

## Consuming these workflows from another repo

### Split scanning strategy

PRs (including fork PRs) and trusted/scheduled runs should request
different things:

- **PR-time scans** should request `report_formats: human` and grant only
  `contents: read`. Each scanner resolves that to its own
  reviewer-readable format, so there is nothing per-tool to remember.
  Findings are uploaded as a build artifact and printed to the job
  summary for a human to review; nothing touches the Security tab, so
  fork PRs (which never receive elevated tokens) work identically to
  same-repo PRs.
- **Trusted scans** (`schedule`, `workflow_dispatch`, `push` to the default
  branch) should request `report_formats: sarif` and grant both
  `contents: read` and `security-events: write` so findings land in
  Security -> Code scanning.

### Wiring it up

These two workflows are the whole integration, and they are the same in
every repository -- no per-scanner jobs to add or maintain.

1. Add a PR-time workflow:

   ```yaml
   name: Security scan (PR)
   on:
     pull_request:
   permissions:
     contents: read
   jobs:
     security:
       uses: ROCm/rocm-security-gh/.github/workflows/security-baseline.yml@v1.0.0
       with:
         report_formats: human
   ```

1. Add a scheduled workflow that uploads to the Security tab. Grant
   `security-events: write` on the `uses:` job itself -- the top-level
   `permissions:` block above it is not enough, since a `permissions:`
   block (wherever it's declared) implicitly zeroes out anything it
   doesn't list:

   ```yaml
   name: Weekly security scan
   on:
     schedule:
       - cron: "0 10 * * 6"
     workflow_dispatch:
   jobs:
     security:
       permissions:
         contents: read
         security-events: write
       uses: ROCm/rocm-security-gh/.github/workflows/security-baseline.yml@v1.0.0
       with:
         scan_mode: all
         report_formats: sarif
   ```

There is no opt-out from a scanner or its severity threshold. Tuning
what it reports is a different matter: ship the config file your scanner
looks for and it takes precedence over the default here, as described in
[Per-repository configuration](#per-repository-configuration). If a
scanner is wrong for your repository in a way its own config can't
express, raise it here rather than working around it locally, so the
exception is visible and reviewed in one place.

### Versioning

Pin the release tag, as above, rather than `@main`. The tag pins more
than the workflow file: the baseline checks its own tooling out at the
commit the caller pinned (via `job.workflow_repository` /
`job.workflow_sha`), so one tag fixes the scanner scripts, the shared
scanner configs, the pinned tool versions and their `checksums.sha256`
digests as a single reviewable bundle. A given tag therefore scans the
same way today and in six months, which is also what makes a finding
reproducible after the fact.

Tags are immutable and never moved, so picking up a new baseline is an
explicit bump in your repository. Enable the `github-actions` ecosystem
in your `.github/dependabot.yml` and Dependabot will raise that bump as
a PR, the same way it does for actions:

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

Security fixes to a scanner reach your repository only once that PR
merges, so treat these bumps as security updates rather than routine
dependency noise.

The two workflows in this repository call
`./.github/workflows/security-baseline.yml` by local path instead, on
purpose: the repository that develops the baseline scans itself with the
unreleased tip, so a regression is caught here before it is tagged.
