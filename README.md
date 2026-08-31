# rocm-security-gh

This repository serves as the central source for ROCm security and governance automation. It provides reusable GitHub Actions workflows, security scanning integrations, and governance configurations to help ROCm repositories implement consistent security controls and comply with organizational and regulatory requirements.

The repository includes:

- Reusable GitHub Actions workflows
- Security scanning integrations and configurations (e.g., Bandit, CodeQL, Gitleaks, Trivy, Zizmor)
- Best practices for secure software development and repository management

All ROCm repository owners and maintainers should adopt these workflows and security controls to improve security posture, reduce risk, and maintain consistent governance across the ROCm ecosystem.

## Scanners

Each scanner is a `workflow_call` reusable workflow that any ROCm
repository can call to scan itself. They all take the same three inputs --
`scan_mode` (`changed` by default, or `all`), `report_formats`, and
`scan_path` (`.` by default) -- so they are wired up identically; see
[Consuming these workflows from another repo](#consuming-these-workflows-from-another-repo)
below. The input descriptions in each workflow file are the authoritative
reference.

## Trivy

`.github/workflows/trivy.yml` is a `workflow_call` reusable workflow
that any ROCm repository can call to scan its own filesystem with
[trivy](https://trivy.dev/) for known vulnerabilities (`vuln`) and
misconfigurations (`misconfig`). It declares no `permissions:` of its
own -- every permission its steps use (`contents: read` to check out
code, `security-events: write` to upload SARIF) is whatever the
calling job explicitly grants. The `secret` scanner is intentionally
excluded from the default `scanners` input because gitleaks already
covers secret detection.
## Binary integrity

Scanner scripts that download a pinned artifact at run time (e.g.
`gitleaks.py`, `zizmor.py`, `trivy.py`, `bandit.py`) verify it against the
repo-root `checksums.sha256` file, via the shared
`security_scanners/utils/binary_checksums.py` helper,
before extracting or executing anything. A digest mismatch (or a
missing/malformed checksums file) makes the scan job fail closed rather
than run an unverified artifact.

### Zizmor

[zizmor](https://docs.zizmor.sh/) is a static analysis tool for GitHub
Actions. It reads workflow and composite-action definitions and reports
security weaknesses in the CI configuration itself -- template injection
through unquoted `${{ }}` expressions, over-broad `permissions:` grants,
action references pinned to a mutable tag, credentials left on disk for
later steps -- grading each finding by severity and confidence so a gate
can fail on the serious ones while a reviewer triages the rest.

- Workflow: `.github/workflows/zizmor.yml`
- `report_formats`: `sarif` (default), `json`, `plain`, `github`
- `scan_mode: changed` audits only the workflow / composite-action /
  dependabot files the calling event touched.
- Also accepts `severity_threshold` (`high` by default) to set which
  severity fails the job, and `persona` (`regular` by default) to widen
  or narrow what zizmor reports.

### Gitleaks

[gitleaks](https://github.com/gitleaks/gitleaks) is a secret scanner. It
walks a repository's git history looking for committed credentials --
API keys, cloud tokens, private keys -- matching against a large set of
built-in detection rules plus any repo-specific rules in `gitleaks.toml`,
so a secret is caught even after it has been removed from the working
tree.

- Workflow: `.github/workflows/gitleaks.yml`
- `report_formats`: `sarif` (default), `json`, `csv`, `junit`
- `scan_mode: changed` scans only the commits the calling event
  introduced, and requires a `pull_request` or `push` payload.

### Bandit

[bandit](https://bandit.readthedocs.io/) is a static analysis tool for
Python. It walks each source file's AST and flags insecure constructs --
`subprocess` with `shell=True`, hardcoded passwords, weak hashes,
`yaml.load` without a safe loader, disabled TLS verification, `assert`
used as a runtime check -- grading each finding by severity and
confidence.

- Workflow: `.github/workflows/bandit.yml`
- `report_formats`: `sarif` (default), `json`, `csv`, `html`, `txt`,
  `xml`, `yaml`
- `scan_mode: changed` scans only the Python files the calling event
  touched; non-Python files are skipped in either mode.
- Also accepts `severity_threshold` (`high` by default) to set which
  severity fails the job.

## Consuming these workflows from another repo

### Split scanning strategy

PRs (including fork PRs) and trusted/scheduled runs should request
different things:

- **PR-time scans** should request `report_formats: table` (or
  `json`) and grant only `contents: read`. Findings are uploaded as a
  build artifact and printed to the job summary for a human to
  review; nothing touches the Security tab, so fork PRs work
  identically to same-repo PRs.
- **Trusted scans** (`schedule`, `workflow_dispatch`) should request
  `report_formats: sarif` and grant both `contents: read` and
  `security-events: write` so findings land in Security -> Code
  scanning.

### Consuming this workflow from another repo

1. Add a PR-time job (can live alongside sibling scanner jobs in the
   same workflow):
- **PR-time scans** should request a human-readable format (`plain` for
  zizmor, `csv` for gitleaks, `txt` for bandit) and grant only
  `contents: read`. Findings are uploaded as a build artifact and printed
  to the job summary for a human to review; nothing touches the Security
  tab, so fork PRs (which never receive elevated tokens) work identically
  to same-repo PRs.
- **Trusted scans** (`schedule`, `workflow_dispatch`, `push` to the default
  branch) should request `report_formats: sarif` and grant both
  `contents: read` and `security-events: write` so findings land in
  Security -> Code scanning.

### Wiring it up

1. Add a PR-time workflow with one job per scanner you want:

   ```yaml
   name: Security scan (PR)
   on:
     pull_request:
   permissions:
     contents: read
   jobs:
     trivy:
       uses: ROCm/rocm-security-gh/.github/workflows/trivy.yml@main
       with:
         report_formats: table
   ```

1. Add a scheduled job that uploads to the Security tab (sibling
   scanners can live in the same workflow -- see `weekly-security-scan.yml`
   below). Grant `security-events: write` on the `uses:` job itself --
   the top-level `permissions:` block above it is not enough, since a
   `permissions:` block (wherever it's declared) implicitly zeroes out
   anything it doesn't list:
     zizmor:
       uses: ROCm/rocm-security-gh/.github/workflows/zizmor.yml@main
       with:
         report_formats: plain
     gitleaks:
       uses: ROCm/rocm-security-gh/.github/workflows/gitleaks.yml@main
       with:
         report_formats: csv
     bandit:
       uses: ROCm/rocm-security-gh/.github/workflows/bandit.yml@main
       with:
         report_formats: txt
   ```

1. Add a scheduled workflow that uploads to the Security tab. Grant
   `security-events: write` on each `uses:` job itself -- the top-level
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
     trivy:
       permissions:
         contents: read
         security-events: write
       uses: ROCm/rocm-security-gh/.github/workflows/trivy.yml@main
     zizmor:
       permissions:
         contents: read
         security-events: write
       uses: ROCm/rocm-security-gh/.github/workflows/zizmor.yml@main
       with:
         scan_mode: all
         report_formats: sarif
     gitleaks:
       permissions:
         contents: read
         security-events: write
       uses: ROCm/rocm-security-gh/.github/workflows/gitleaks.yml@main
       with:
         scan_mode: all
         report_formats: sarif
     bandit:
       permissions:
         contents: read
         security-events: write
       uses: ROCm/rocm-security-gh/.github/workflows/bandit.yml@main
       with:
         scan_mode: all
         report_formats: sarif
   ```

Pin `@main` to a tag or commit SHA once this workflow has a release; see
`.github/workflows/weekly-security-scan.yml` and
`.github/workflows/pr-security-scan.yml` in this repo for the
versions used to scan `rocm-security-gh` itself.
Pin `@main` to a tag or commit SHA once these workflows have a release; see
`.github/workflows/weekly-security-scan.yml` and
`.github/workflows/pr-security-scan.yml` in this repo for the versions
used to scan `rocm-security-gh` itself.
