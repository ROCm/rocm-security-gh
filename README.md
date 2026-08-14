# rocm-security-gh

This repository serves as the central source for ROCm security and governance automation. It provides reusable GitHub Actions workflows, security scanning integrations, and governance configurations to help ROCm repositories implement consistent security controls and comply with organizational and regulatory requirements.

The repository includes:

- Reusable GitHub Actions workflows
- Security scanning integrations and configurations (e.g., CodeQL, Gitleaks, Trivy, Zizmor)
- Best practices for secure software development and repository management

All ROCm repository owners and maintainers should adopt these workflows and security controls to improve security posture, reduce risk, and maintain consistent governance across the ROCm ecosystem.

## Binary integrity

Scanner scripts that download a pinned release tarball at run time (e.g.
`gitleaks.py`, `zizmor.py`, `trivy.py`) verify it against the repo-root
`checksums.sha256` file, via the shared `binary_checksums.py` helper,
before extracting or executing anything. A digest mismatch (or a
missing/malformed checksums file) makes the scan job fail closed rather
than run an unverified binary.

## Zizmor

`.github/workflows/zizmor.yml` is a `workflow_call` reusable workflow that
any ROCm repository can call to audit its own GitHub Actions
workflows/composite actions/dependabot config with
[zizmor](https://docs.zizmor.sh/).

### Split scanning strategy

PRs (including fork PRs) and trusted/scheduled runs should request
different things:

- **PR-time scans** should request `report_formats: plain` (or `json`)
  and grant only `contents: read`. Findings are uploaded as a build
  artifact and printed to the job summary for a human to review; nothing
  touches the Security tab, so fork PRs work identically to same-repo
  PRs.
- **Trusted scans** (`schedule`, `workflow_dispatch`) should request
  `report_formats: sarif` and grant both `contents: read` and
  `security-events: write` so findings land in Security -> Code
  scanning.

### Consuming this workflow from another repo

1. Add a PR-time job (can live alongside a `gitleaks` job in the same
   workflow):

   ```yaml
   name: Security scan (PR)
   on:
     pull_request:
   permissions:
     contents: read
   jobs:
     zizmor:
       uses: ROCm/rocm-security-gh/.github/workflows/zizmor.yml@main
       with:
         report_formats: plain
   ```

2. Add a scheduled job that uploads to the Security tab (sibling
   scanners, e.g. `gitleaks`, can live in the same workflow -- see
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
     zizmor:
       permissions:
         contents: read
         security-events: write
       uses: ROCm/rocm-security-gh/.github/workflows/zizmor.yml@main
       with:
         scan_mode: all
         report_formats: sarif
   ```

Pin `@main` to a tag or commit SHA once this workflow has a release; see
`.github/workflows/weekly_security.yml` and
`.github/workflows/pre_commit_security.yml` in this repo for the versions
used to scan `rocm-security-gh` itself.
