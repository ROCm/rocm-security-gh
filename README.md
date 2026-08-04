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
[gitleaks](https://github.com/gitleaks/gitleaks). It never requires a caller
to hold any long-lived credentials: SARIF uploads authenticate with a
short-lived token minted from the `rocm-security-gh` GitHub App installation
on the caller's own repo, scoped to `security-events: write` only.

### Split scanning strategy

PRs (including fork PRs, which never receive org/repo secrets) and
trusted/scheduled runs are handled differently:

- **PR-time scans** should request `report_formats: csv` (or `json`/`junit`)
  and pass no secrets at all. Findings are uploaded as a build artifact for
  a human to review; nothing touches the Security tab, so no GitHub App
  credentials are needed and fork PRs work identically to same-repo PRs.
- **Trusted scans** (`schedule`, `workflow_dispatch`, `push` to the default
  branch) should request `report_formats: sarif` and pass the two App
  secrets below so findings land in Security -> Code scanning.

### Consuming this workflow from another repo

1. Install the `rocm-security-gh` GitHub App on your repository (contents:
   read, security-events: write) and confirm your repo has access to the
   org-level `GH_APP_SECURITY_GH_CID` / `GH_APP_SECURITY_GH_PRIVATE_KEY`
   secrets.
2. Add a PR-time workflow that needs no secrets:

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

3. Add a scheduled/trusted workflow that uploads to the Security tab:

   ```yaml
   name: Security scan (scheduled)
   on:
     schedule:
       - cron: "0 10 * * 6"
     workflow_dispatch:
   permissions:
     contents: read
   jobs:
     gitleaks:
       uses: ROCm/rocm-security-gh/.github/workflows/gitleaks.yml@main
       with:
         scan_mode: all
         report_formats: sarif
       secrets:
         GH_APP_SECURITY_GH_CID: ${{ secrets.GH_APP_SECURITY_GH_CID }}
         GH_APP_SECURITY_GH_PRIVATE_KEY: ${{ secrets.GH_APP_SECURITY_GH_PRIVATE_KEY }}
   ```

Pin `@main` to a tag or commit SHA once this workflow has a release; see
`.github/workflows/gitleaks_main.yml` and `.github/workflows/pre_commit_security.yml`
in this repo for the versions used to scan `rocm-security-gh` itself.

### TheRock dependency

`gitleaks.py` and `compute_pr_depth.py` call a handful of `gha_*` GitHub
Actions helpers (`gha_load_github_event`, `gha_set_output`,
`gha_append_step_summary`) that live in
[ROCm/TheRock's `github_actions_api` module](https://github.com/ROCm/TheRock/blob/main/build_tools/github_actions/github_actions_api.py)
rather than being duplicated here. `gitleaks.yml` checks out TheRock's
`main` branch (sparse, one file, `fetch-depth: 1`) alongside this repo's
own tooling and points `THEROCK_BUILD_TOOLS_DIR` at it before running
either script. This trades a small amount of build-time coupling to
TheRock's `main` for a single source of truth on those helpers.
