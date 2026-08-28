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
`checksums.sha256` file, via the shared
`security_scanners/utils/binary_checksums.py` helper,
before extracting or executing anything. A digest mismatch (or a
missing/malformed checksums file) makes the scan job fail closed rather
than run an unverified binary.

## Scanners

`.github/workflows/security-baseline.yml` is the single `workflow_call`
entry point every ROCm repository calls. One job in the caller fans out
to one isolated job per scanner, which means:

- **What runs is org policy, not a repository setting.** Which scanners
  run and the severity that fails them are not inputs. A repository
  cannot opt out of a scanner or relax a threshold, and every
  repository picks up a newly added scanner on its next run without a
  pull request against it.
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

## Consuming these workflows from another repo

### Split scanning strategy

PRs (including fork PRs) and trusted/scheduled runs should request
different things:

- **PR-time scans** should request `report_formats: human` and grant only
  `contents: read`. Findings are uploaded as a build artifact and printed
  to the job summary for a human to review; nothing touches the Security
  tab, so fork PRs (which never receive elevated tokens) work identically
  to same-repo PRs.
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
       uses: ROCm/rocm-security-gh/.github/workflows/security-baseline.yml@main
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
       uses: ROCm/rocm-security-gh/.github/workflows/security-baseline.yml@main
       with:
         scan_mode: all
         report_formats: sarif
   ```

There is no opt-out. If a scanner is wrong for your repository, raise it
here rather than working around it locally, so the exception is visible
and reviewed in one place.

Pin `@main` to a tag or commit SHA once these workflows have a release; see
`.github/workflows/weekly-security-scan.yml` and
`.github/workflows/pr-security-scan.yml` in this repo for the versions
used to scan `rocm-security-gh` itself.
