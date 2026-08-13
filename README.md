# rocm-security-gh
This repository serves as the central source for ROCm security and governance automation. It provides reusable GitHub Actions workflows, security scanning integrations, and governance configurations to help ROCm repositories implement consistent security controls and comply with organizational and regulatory requirements.

The repository includes:
- Reusable GitHub Actions workflows
- Security scanning integrations and configurations (e.g., CodeQL, Gitleaks, Trivy, Zizmor)
- Best practices for secure software development and repository management

All ROCm repository owners and maintainers should adopt these workflows and security controls to improve security posture, reduce risk, and maintain consistent governance across the ROCm ecosystem.

## Gitleaks

`.github/workflows/gitleaks.yml` is a `workflow_call` reusable workflow that
any ROCm repository can call to scan itself with
[gitleaks](https://github.com/gitleaks/gitleaks).

### Split scanning strategy

PRs (including fork PRs) and trusted/scheduled runs should request
different things:

- **PR-time scans** should request `report_formats: csv` (or `json`/`junit`)
  and grant only `contents: read`. Findings are uploaded as a build
  artifact for a human to review; nothing touches the Security tab, so
  fork PRs (which never receive elevated tokens) work identically to
  same-repo PRs.
- **Trusted scans** (`schedule`, `workflow_dispatch`, `push` to the default
  branch) should request `report_formats: sarif` and grant both
  `contents: read` and `security-events: write` so findings land in
  Security -> Code scanning.

### Binary integrity

`security_scanners/github_actions/gitleaks.py` downloads the gitleaks
release tarball from a pinned S3 mirror and verifies it against
`checksums.sha256` (a repo-root file shared across all scanners that
download a binary, e.g. gitleaks, trivy) before extracting or executing
anything, via the shared `binary_checksums.py` helper. A digest mismatch
(or a missing/malformed checksums file) makes the scan job fail closed
rather than run an unverified binary.

### Consuming this workflow from another repo

1. Add a PR-time job (can live alongside a `zizmor` job in the same
   workflow):

   ```yaml
   name: Security scan (PR)
   on:
     pull_request:
   permissions:
     contents: read
   jobs:
     gitleaks:
       uses: ROCm/rocm-security-gh/.github/workflows/gitleaks.yml@main
       with:
         report_formats: csv
   ```

2. Add a scheduled job that uploads to the Security tab (sibling
   scanners, e.g. `zizmor`, can live in the same workflow -- see
   `weekly_security.yml` below). Grant `security-events: write` on the
   `uses:` job itself -- the top-level `permissions:` block above it is
   not enough, since a `permissions:` block (wherever it's declared)
   implicitly zeroes out anything it doesn't list:

   ```yaml
   name: Weekly security scan
   on:
     schedule:
       - cron: "0 10 * * 6"
     workflow_dispatch:
   jobs:
     gitleaks:
       permissions:
         contents: read
         security-events: write
       uses: ROCm/rocm-security-gh/.github/workflows/gitleaks.yml@main
       with:
         scan_mode: all
         report_formats: sarif
   ```

Pin `@main` to a tag or commit SHA once this workflow has a release; see
`.github/workflows/weekly_security.yml` and
`.github/workflows/pre_commit_security.yml` in this repo for the versions
used to scan `rocm-security-gh` itself.
