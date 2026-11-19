# Changelog

All notable changes to the reusable security workflows and the scanners
they run are recorded here. Releases are tagged `vX.Y.Z`; callers pin a
release by its commit SHA with the tag as a trailing comment, for example
`security-baseline.yml@<sha> # v1.0.9`.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Each release groups its entries under these headings, omitting the empty
ones:

- **Scanner versions**: every scanner or action whose pinned version
  changed, with the upstream release notes and what the change means for
  a scanned repository, such as new findings or a changed severity.
- **Added**: new inputs, scanners and capabilities.
- **Changed**: different behavior for an existing input, default or
  report, including anything that can make a passing scan fail.
- **Fixed**: bugs, with the symptom a caller would have seen.

## [Unreleased]

## [v1.0.9] - 2026-11-18

### Scanner versions

- **trivy 0.71.0 → 0.76.2**
  ([0.72.0](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0),
  [0.73.0](https://github.com/aquasecurity/trivy/releases/tag/v0.73.0),
  [0.74.0](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0),
  [0.75.0](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0),
  [0.76.0](https://github.com/aquasecurity/trivy/releases/tag/v0.76.0),
  [0.76.2](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2))
  ([#59](https://github.com/ROCm/rocm-security-gh/pull/59)).
  - Security fixes in trivy itself: `golang.org/x/net` (CVE-2026-78661,
    CVE-2026-97045) and `go-jose` (GHSA-mgcc-cww5-fp2q).
  - More license findings: JAR licenses are read from packaged `LICENSE`
    files, the embedded `pom.xml`, `Bundle-License` and Jenkins plugin
    manifests. A license name trivy cannot parse is reported with
    `UNKNOWN` severity.
  - More dependency coverage: uv workspace lockfiles, pnpm workspaces and
    multi-document `pnpm-lock.yaml`, PEP 621 `pyproject.toml` names, and
    the `go` directive when merging `go.sum`. Repositories using these
    may see vulnerability findings that were missed before.
  - A vulnerability without details is reported as `UNKNOWN` instead of
    being dropped.
  - Terraform: OpenTofu `language` blocks are supported, and
    `--skip-dirs` no longer overrides `--skip-files`.
- **zizmor 1.31.1 → 1.32.0**
  ([release notes](https://github.com/zizmorcore/zizmor/releases/tag/v1.32.0))
  ([#59](https://github.com/ROCm/rocm-security-gh/pull/59)).
  - Input collection is root-aware: full (`scan_mode: all`) scans no
    longer report workflows in directories GitHub Actions never runs,
    such as vendored copies.
  - `template-injection` now flags attacker-controlled contexts wrapped in
    `fromJSON(...)` or passed as values of `case(...)`, and
    `bot-conditions` checks jobs that call a reusable workflow. Expect new
    findings in workflows that use these patterns.
  - `obfuscation` no longer flags, or suggests a wrong fix for,
    expressions that reduce to other expressions.
- **CodeQL Action v4.39.0 → v4.39.3**
  ([v4.39.1](https://github.com/github/codeql-action/releases/tag/v4.39.1),
  [v4.39.2](https://github.com/github/codeql-action/releases/tag/v4.39.2),
  [v4.39.3](https://github.com/github/codeql-action/releases/tag/v4.39.3))
  ([#59](https://github.com/ROCm/rocm-security-gh/pull/59)).
  - Default CodeQL bundle 2.27.4.
  - Diff-informed filtering no longer drops alerts in changed files whose
    paths contain spaces, special or non-ASCII characters.

### Changed

- trivy in `scan_mode: changed` still scans all of `scan_path`, but fails
  only on findings in a changed file or in the same directory as one.
  Findings elsewhere still appear in the reports. A change to trivy's
  config or ignore file, or a missing diff range, gates on every finding
  as before ([#51](https://github.com/ROCm/rocm-security-gh/pull/51)).
- A repository's `codeql_config_path` is appended to the baseline's CodeQL
  config instead of replacing it. Its `queries` and `packs` run in
  addition to `security-extended`, its `query-filters` come after the
  baseline's and can override them, and every other key is the
  repository's. Changing any file in the config's directory widens
  changed-mode planning to every language. A config that is not a YAML
  mapping fails planning
  ([#58](https://github.com/ROCm/rocm-security-gh/pull/58)).
- CodeQL excludes the `actions/unpinned-tag` query by default. zizmor's
  `unpinned-uses` audit reports the same references and can scope an
  exception to a single repository
  ([#42](https://github.com/ROCm/rocm-security-gh/pull/42)).

### Fixed

- gitleaks in `scan_mode: changed` deepens a shallow clone until the PR's
  base and head share history, so the scan covers only the PR's commits.
  If the full history of both still has no common ancestor, the scan
  fails instead of scanning the wrong range
  ([#54](https://github.com/ROCm/rocm-security-gh/pull/54)).

## [v1.0.8] - 2026-10-26

### Added

- `.trivyignore.yaml` is read alongside `.trivyignore`
  ([#41](https://github.com/ROCm/rocm-security-gh/pull/41)).
- Ignore files are also looked up next to a scanner's configured
  `*_config_path`, and the README documents each scanner's ignore
  mechanism ([#38](https://github.com/ROCm/rocm-security-gh/pull/38)).

### Changed

- gitleaks runs without `--verbose`, so findings no longer appear in the
  job log. Reports are unchanged
  ([#40](https://github.com/ROCm/rocm-security-gh/pull/40)).
- Clearer scan-scope log messages from bandit, trivy and zizmor
  ([#34](https://github.com/ROCm/rocm-security-gh/pull/34)).

### Fixed

- The PR findings comment no longer lists the `Security scanners` and
  `codeql / complete` rollup jobs as failed scanners when a scanner they
  depend on fails ([#35](https://github.com/ROCm/rocm-security-gh/pull/35)).

## [v1.0.7] - 2026-10-16

### Scanner versions

- **trivy 0.70.0 → 0.71.0**
  ([release notes](https://github.com/aquasecurity/trivy/releases/tag/v0.71.0))
  ([#31](https://github.com/ROCm/rocm-security-gh/pull/31)).
  - CycloneDX 1.7 SBOMs and SHA-512 hashes in SPDX output.
  - Terraform filesystem functions can no longer read outside the scanned
    tree (path traversal fix), and nested values in Terraform plan lists
    render correctly.
  - npm lockfiles with legacy license formats are parsed.
- **zizmor 1.30.0 → 1.31.1**
  ([1.31.0](https://github.com/zizmorcore/zizmor/releases/tag/v1.31.0),
  [1.31.1](https://github.com/zizmorcore/zizmor/releases/tag/v1.31.1))
  ([#32](https://github.com/ROCm/rocm-security-gh/pull/32)).
  - `dangerous-triggers` treats `issue_comment` as dangerous. Workflows
    triggered by it get new findings.
  - `cache-poisoning` flags `cache-mode: write` and `write-only` combined
    with dangerous triggers, and skips jobs with `cache-mode: none`.
  - `self-hosted-runner` is more precise, and `typosquat-uses` checks
    pre-commit configs.
- **CodeQL Action v4.37.3 → v4.39.0**
  ([v4.38.0](https://github.com/github/codeql-action/releases/tag/v4.38.0),
  [v4.38.1](https://github.com/github/codeql-action/releases/tag/v4.38.1),
  [v4.38.2](https://github.com/github/codeql-action/releases/tag/v4.38.2),
  [v4.39.0](https://github.com/github/codeql-action/releases/tag/v4.39.0))
  ([#33](https://github.com/ROCm/rocm-security-gh/pull/33)).
  - Default CodeQL bundle 2.27.1, minimum supported bundle 2.20.7.
  - Unused CodeQL bundles are removed from the toolcache before a new one
    is downloaded, freeing disk space on GitHub-hosted runners.
  - `analyze` warns when `checkout_path` does not match the analyzed
    checkout.

### Fixed

- The PR checkout fetches the merge commit, the PR's commits and the base
  commit. One commit short before, the shallow clone was missing the base
  commit that changed-mode scans diff against
  ([#30](https://github.com/ROCm/rocm-security-gh/pull/30)).

## [v1.0.6] - 2026-10-13

### Added

- A single `Security scanners` job succeeds only when planning, every
  scanner and CodeQL succeed, so branch protection can require one check
  instead of one per scanner
  ([#27](https://github.com/ROCm/rocm-security-gh/pull/27)).

### Changed

- The default scanner configs carry comments explaining each setting
  ([#28](https://github.com/ROCm/rocm-security-gh/pull/28)).

### Fixed

- The PR findings comment accepts a trivy report with no `Results`, which
  trivy writes when nothing in the tree applies to its scanners
  ([#29](https://github.com/ROCm/rocm-security-gh/pull/29)).

## [v1.0.5] - 2026-10-01

### Added

- On pull requests from a branch of the scanned repository, a single
  comment lists the HIGH and CRITICAL findings of every scanner, in
  collapsible sections, with leaked secrets shown prominently. The comment
  is advisory and never blocks a merge. Pull requests from forks get no
  comment ([#24](https://github.com/ROCm/rocm-security-gh/pull/24)).

## [v1.0.4] - 2026-09-25

### Changed

- CodeQL skips C/C++ analysis when the repository has more than 1,000
  C/C++ files, or when the file count cannot be determined. Buildless
  C/C++ analysis of larger trees does not fit a standard runner. This is a
  temporary limit ([#23](https://github.com/ROCm/rocm-security-gh/pull/23)).

## [v1.0.3] - 2026-09-24

### Added

- `run_on_label_change` input. When `true`, the scanners also run on
  `pull_request` `labeled` and `unlabeled` events; the caller must list
  those activity types in its own trigger. Defaults to `false`, which
  skips those events
  ([#22](https://github.com/ROCm/rocm-security-gh/pull/22)).

## [v1.0.2] - 2026-09-21

### Changed

- trivy runs its `license` scanner by default, alongside `misconfig` and
  `vuln`. Repositories may see new license findings
  ([#21](https://github.com/ROCm/rocm-security-gh/pull/21)).
- Private repositories skip CodeQL. The planning and completion jobs
  still succeed and report that CodeQL was disabled; the other scanners
  run normally ([#20](https://github.com/ROCm/rocm-security-gh/pull/20)).
- The default scanner configs moved to `.github/scan_tools_configs/`.
  Config discovery in scanned repositories is unchanged
  ([#20](https://github.com/ROCm/rocm-security-gh/pull/20)).

## [v1.0.1] - 2026-09-10

### Fixed

- SARIF uploads pass `checkout_path`, so Code Scanning maps findings to
  files in the scanned repository
  ([#18](https://github.com/ROCm/rocm-security-gh/pull/18)).

## [v1.0.0] - 2026-09-09

First release of `security-baseline.yml`, a single reusable workflow that
plans and runs every scanner, each in its own job and check run.

### Scanner versions

- gitleaks 8.30.1: secrets in git history.
- zizmor 1.30.0: GitHub Actions workflow security.
- bandit 1.9.4: Python security issues.
- trivy 0.70.0: dependency vulnerabilities and IaC misconfigurations.
- CodeQL Action v4.37.3: `security-extended` code analysis for the
  languages found in the repository.

Every scanner binary or package is downloaded at a pinned version and
verified against `checksums.sha256`.

### Added

- `scan_mode: changed` scopes each scanner to what the calling event
  touched; `scan_mode: all` scans everything and is used for scheduled
  scans.
- Each scanner reads its config from the scanned repository and falls
  back to this repository's default. `*_config_path` inputs select a
  different file, and changing a config widens a changed-mode scan
  ([#13](https://github.com/ROCm/rocm-security-gh/pull/13),
  [#16](https://github.com/ROCm/rocm-security-gh/pull/16),
  [#17](https://github.com/ROCm/rocm-security-gh/pull/17)).
- `timeout_minutes` raises the timeout of every scanner job
  ([#14](https://github.com/ROCm/rocm-security-gh/pull/14)).
- CodeQL detects the repository's languages, and in `scan_mode: changed`
  analyzes only the languages a pull request touches
  ([#15](https://github.com/ROCm/rocm-security-gh/pull/15)).
- SARIF reports are uploaded to Code Scanning; other formats are uploaded
  as build artifacts and printed to the job log.

[unreleased]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.9...HEAD
[v1.0.0]: https://github.com/ROCm/rocm-security-gh/releases/tag/v1.0.0
[v1.0.1]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.0...v1.0.1
[v1.0.2]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.1...v1.0.2
[v1.0.3]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.2...v1.0.3
[v1.0.4]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.3...v1.0.4
[v1.0.5]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.4...v1.0.5
[v1.0.6]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.5...v1.0.6
[v1.0.7]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.6...v1.0.7
[v1.0.8]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.7...v1.0.8
[v1.0.9]: https://github.com/ROCm/rocm-security-gh/compare/v1.0.8...v1.0.9
