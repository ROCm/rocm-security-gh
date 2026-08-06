# rocm-security-gh
This repository serves as the central source for ROCm security and governance automation. It provides reusable GitHub Actions workflows, security scanning integrations, and governance configurations to help ROCm repositories implement consistent security controls and comply with organizational and regulatory requirements.

The repository includes:
- Reusable GitHub Actions workflows
- Security scanning integrations and configurations (e.g., CodeQL, Gitleaks, Trivy, Zizmor)
- Best practices for secure software development and repository management

All ROCm repository owners and maintainers should adopt these workflows and security controls to improve security posture, reduce risk, and maintain consistent governance across the ROCm ecosystem.

## Zizmor

`.github/workflows/zizmor.yml` is a `workflow_call` reusable workflow that
any ROCm repository can call to audit its own GitHub Actions
workflows/composite actions/dependabot config with
[zizmor](https://docs.zizmor.sh/). It declares no `permissions:` of its
own -- every permission its steps use (`contents: read` to check out
code, `security-events: write` to upload SARIF) is whatever the calling
job explicitly grants. This is deliberate: a reusable workflow's
`permissions:` block can only preserve or reduce what a caller grants,
never elevate it, and a reusable workflow that itself *requests* a scope
the caller didn't grant fails the whole call at startup ("requesting
`security-events: write`, but is only allowed `security-events: none`"),
not just the step that needed it (this exact class of bug hit
[ROCm/rocm-tests#70](https://github.com/ROCm/rocm-tests/pull/70)).
Leaving the block out entirely lets each caller grant exactly what its
own use case needs.

### Split scanning strategy

PRs (including fork PRs) and trusted/scheduled runs should request
different things:

- **PR-time scans** should request `report_formats: plain` (or `json`)
  and grant only `contents: read`. Findings are uploaded as a build
  artifact and printed to the job summary for a human to review; nothing
  touches the Security tab, so fork PRs work identically to same-repo
  PRs.
- **Trusted scans** (`workflow_dispatch`, `push` to the default branch)
  should request `report_formats: sarif` and grant both `contents: read`
  and `security-events: write` so findings land in Security -> Code
  scanning.

### Consuming this workflow from another repo

1. Add a PR-time workflow:

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

2. Add a trusted workflow that uploads to the Security tab. Grant
   `security-events: write` on the `uses:` job itself -- the top-level
   `permissions:` block above it is not enough, since a `permissions:`
   block (wherever it's declared) implicitly zeroes out anything it
   doesn't list:

   ```yaml
   name: Security scan (post-merge)
   on:
     push:
       branches: [main]
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
`.github/workflows/zizmor_main.yml` and `.github/workflows/pre_commit_security.yml`
in this repo for the versions used to scan `rocm-security-gh` itself.

## Gitleaks

`.github/workflows/gitleaks.yml` is a `workflow_call` reusable workflow that
any ROCm repository can call to scan itself with
[gitleaks](https://github.com/gitleaks/gitleaks). It declares no
`permissions:` of its own -- every permission its steps use (`contents:
read` to check out code, `security-events: write` to upload SARIF) is
whatever the calling job explicitly grants. This is deliberate: a reusable
workflow's `permissions:` block can only preserve or reduce what a caller
grants, never elevate it, so a restrictive block here would silently zero
out a caller's `security-events: write` grant and break SARIF uploads with
no obvious error (this exact bug hit
[ROCm/rocm-tests#70](https://github.com/ROCm/rocm-tests/pull/70)).

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

## Zizmor

`.github/workflows/zizmor.yml` is a `workflow_call` reusable workflow that
any ROCm repository can call to audit its own GitHub Actions
workflows/composite actions/dependabot config with
[zizmor](https://docs.zizmor.sh/). Like `gitleaks.yml`, it declares no
`permissions:` of its own, for the same reason: a reusable workflow's
`permissions:` block can only preserve or reduce what a caller grants,
never elevate it, and a reusable workflow that itself *requests* a scope
the caller didn't grant fails the whole call at startup ("requesting
`security-events: write`, but is only allowed `security-events: none`"),
not just the step that needed it. Leaving the block out entirely lets
each caller grant exactly what its own use case needs.

### Split scanning strategy

Same split as gitleaks:

- **PR-time scans** should request `report_formats: plain` (or `json`)
  and grant only `contents: read`. Findings are uploaded as a build
  artifact and printed to the job summary for a human to review; nothing
  touches the Security tab, so fork PRs work identically to same-repo
  PRs.
- **Trusted scans** (`workflow_dispatch`, `push` to the default branch)
  should request `report_formats: sarif` and grant both `contents: read`
  and `security-events: write` so findings land in Security -> Code
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

2. Add a trusted workflow that uploads to the Security tab. Grant
   `security-events: write` on the `uses:` job itself -- the top-level
   `permissions:` block above it is not enough, since a `permissions:`
   block (wherever it's declared) implicitly zeroes out anything it
   doesn't list:

   ```yaml
   name: Security scan (post-merge)
   on:
     push:
       branches: [main]
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
`.github/workflows/zizmor_main.yml` and `.github/workflows/pre_commit_security.yml`
in this repo for the versions used to scan `rocm-security-gh` itself.
