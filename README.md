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
entry point every ROCm repository calls -- the one other `workflow_call`
workflow here, `codeql.yml`, is called by the baseline rather than by
repositories. One job in the caller fans out to one isolated job per
scanner, which means:

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

Inputs, all optional, describe the calling event, who reads the output,
where repository-specific scanner configs live and how long the
repository is willing to wait: `scan_mode`, `report_formats`,
`scan_path`, `codeql_config_path`, the four script-backed scanners'
`<scanner>_config_path` inputs and `timeout_minutes`. The input descriptions
in the workflow file are the authoritative reference.

`timeout_minutes` is the one input that moves a scanner's own budget,
and it only ever moves it up. Each scanner gets 20 to 30 minutes here
(120 for each CodeQL language),
which a repository the size of `rocm-libraries` can outgrow; passing a
larger number raises every scanner below it, and a smaller one is
ignored. It isn't a policy lever in the way a severity threshold would
be: a scanner that runs out of time fails its check rather than passing
it, so waiting less can never turn a finding into a green run. The
ceiling is 360, where GitHub cancels the job regardless.

To change policy, edit this repository: `SCANNERS` in
`security_scanners/utils/compute_scan_matrix.py` decides which scanners
run, and each scanner script's own defaults decide the severity that
fails it and how sensitively it reports. CodeQL is the exception to the
"one job per scanner" shape -- it runs as GitHub's own action rather
than a script here, so it gets a planning job that discovers the
caller's languages and one analysis job per language. See
[CodeQL](#codeql).

### Per-repository configuration

Each scanner reads the config file the scanned repository ships, and
falls back to the copy in this repository when it ships none. The scan
log names the file that was used, so it is always visible in the check
which one won:

| Scanner  | Read from the scanned repository, first match wins                       | Default here    |
| -------- | ------------------------------------------------------------------------ | --------------- |
| gitleaks | `gitleaks.toml`, `.gitleaks.toml`, plus `.gitleaksignore`                | `gitleaks.toml` |
| zizmor   | `.github/zizmor.yml`, `.github/zizmor.yaml`, `zizmor.yml`, `zizmor.yaml` | `zizmor.yml`    |
| bandit   | `bandit.yaml`, `bandit.yml`                                              | `bandit.yaml`   |
| trivy    | `trivy.yaml`, `trivy.yml`, plus `.trivyignore`                           | `trivy.yaml`    |
| CodeQL   | The explicit `codeql_config_path`                                        | Action defaults |

Each scanner's candidates are listed in the order that scanner itself
searches, so the file CI reads is the one a local run of the same tool
would read.

Repositories that keep scanner configuration in a subdirectory can pass
an explicit repository-root-relative path for each scanner:

```yaml
jobs:
  security:
    uses: ROCm/rocm-security-gh/.github/workflows/security-baseline.yml@<full commit SHA>
    with:
      bandit_config_path: security_tools/bandit.yaml
      codeql_config_path: .github/codeql/codeql-config.yml
      gitleaks_config_path: security_tools/gitleaks.toml
      trivy_config_path: security_tools/trivy.yaml
      zizmor_config_path: security_tools/zizmor.yaml
```

An explicit path is the only location considered for that scanner. It must
name a file inside the scanned repository: a missing file, absolute path,
path traversal or symlink outside the checkout fails the scan instead of
silently selecting a default. Omitting a script-backed scanner's input
preserves the conventional-location discovery and fallback in the table
above. CodeQL config is intentionally explicit; omitting
`codeql_config_path` leaves the CodeQL action on its defaults.

This covers detection: allowlists, excluded paths, per-rule
suppressions, and the fingerprints of findings already triaged. It does
not cover which scanners run or which severity fails the build, which
stay in code here for exactly that reason -- a config file cannot switch
a scanner off, only describe the repository it is scanning.

A PR that touches an automatically discovered or explicitly configured
Bandit, Trivy or zizmor config is scanned in full rather than against its
changed files alone, since a config change applies to the whole repository.
A change to the explicit CodeQL config similarly runs every discovered
language. Gitleaks already scans the full commit range rather than a filtered
file list. That is what makes a suppression visible in the run that adds it,
and a broken config fail the PR that wrote it instead of the next unrelated
one.

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

### CodeQL

[CodeQL](https://codeql.github.com/) is GitHub's own analysis engine. It
builds a database of the repository and runs queries over it, so unlike
the four scanners above it reasons about data flow -- a value reaching a
dangerous sink several functions away from where it entered.

- Defined in `.github/workflows/codeql.yml`, which `security-baseline.yml`
  calls. Callers don't reference it directly: the baseline stays the one
  entry point, and calling it with `$/` means the version of it that runs
  is the version of the baseline the caller pinned.
- Check runs: `codeql / <language>`, one per language, plus
  `codeql / complete`, which reports the outcome of all of them. Require
  that one in branch protection: which per-language checks exist depends
  on what the repository is written in and, on a pull request, on what it
  touched.
- `scan_mode: changed` narrows which languages run to the ones the pull
  request touched.
- `codeql_config_path` passes a config file from the scanned repository to
  CodeQL. Unlike `scan_mode`, its `paths` and `paths-ignore` settings control
  which source files CodeQL puts in its database.

For example, a repository that vendors dependencies under
`build_tools/third_party` can keep `.github/codeql/codeql-config.yml`:

```yaml
paths-ignore:
  - build_tools/third_party/**
```

and pass that file as `codeql_config_path`. The config path is checked after
the scan target is checked out, before CodeQL initializes. Changing the file
in a pull request widens changed-mode planning to every discovered language
so the new analysis scope is exercised immediately.

**Languages are discovered per run, never configured.** A hard-coded
language list is wrong as soon as a repository grows a language, and
wrong in the other direction too: CodeQL fails with "No source code was
seen during the build" when it is initialised for a language the
repository doesn't have. So
`security_scanners/utils/compute_codeql_matrix.py` asks the GitHub API
what the repository is written in and emits one job per answer, reading
two sources because neither is enough alone:

| Source                                                  | What it knows                                                                          | Where it falls short                                                                        |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `GET /repos/{owner}/{repo}/languages`                   | Linguist's view of the default branch, the same signal GitHub's own default setup uses | Refreshes only after a default-branch push, so a PR that adds a language is invisible to it |
| `GET /repos/{owner}/{repo}/git/trees/{sha}?recursive=1` | Every file in the exact commit under scan                                              | GitHub truncates it past 100,000 entries or 7 MB                                            |

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

   A `scan_mode: all` run over a large repository is where the default
   per-scanner budget runs out first -- gitleaks walks the entire commit
   history. Add `timeout_minutes:` here if a scanner starts being
   cancelled rather than finishing.

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
`$/.github/workflows/security-baseline.yml` unpinned instead, on purpose:
the repository that develops the baseline scans itself with the
unreleased tip, so a regression is caught here before it is tagged. `$/`
is [GitHub's self-repository
syntax](https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax/),
which resolves to this repository at the running commit -- the same
reason the baseline uses it to call `codeql.yml`. It needs Actions runner
2.336.0 or newer and is not available on GitHub Enterprise Server.
