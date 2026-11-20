# Contributing to rocm-security-gh

Thanks for your interest in contributing! This repository hosts reusable
GitHub Actions workflows and the scanner tooling behind them, so ROCm
repositories can adopt consistent security and governance controls without
copy-pasting scanning logic. Please look over the general
[ROCm contributing guidelines](https://github.com/ROCm/ROCm/blob/develop/CONTRIBUTING.md#pull-requests)
before opening a pull request here.

## Getting started

1. Create a branch off `main` named `users/<your_name>/<short-description>`
   (e.g. `users/jdoe/add-trivy-scanner`) for your change.
1. Make your change, following the conventions below.
1. Open a pull request against `main`. Fill in the PR template completely;
   reviewers use the "Technical Details" and "Test Plan"/"Test Result"
   sections to understand *why* a change was made and how it was verified.

## Design decisions

A change that adds a scanner or scan target, changes which changes trigger a
scan or which findings fail a run, or runs code from the scanned repository
needs an RFC in [`docs/rfcs/`](docs/rfcs/README.md). Open it with the change
or before it.
## Changelog

Repositories that call these workflows read [CHANGELOG.md](CHANGELOG.md)
to learn what a new release changes for them; Dependabot also copies the
matching section into their version-bump pull requests. Add an entry under
`## [Unreleased]` in the same pull request when it:

- bumps a scanner (`_*_VERSION` and `checksums.sha256`) or a CodeQL Action
  pin. List the old and new version, link the upstream release notes of
  every release in between, and say what a scanned repository will notice:
  new or removed findings, changed severities, new file types covered.
- adds or changes a workflow input, a default config, the scan scope or
  what makes a scan fail.
- fixes a bug a caller could see.

Refactors, test-only and documentation-only changes need no entry. When a
release is tagged, rename `Unreleased` to the tag and date, start a new
empty `Unreleased` section, and update the compare links at the bottom.

## Code style

Follow the [ROCm/TheRock style guides](https://github.com/ROCm/TheRock/tree/main/docs/development/style_guides):

- [Bash style guide](https://github.com/ROCm/TheRock/blob/main/docs/development/style_guides/bash_style_guide.md)
- [CMake style guide](https://github.com/ROCm/TheRock/blob/main/docs/development/style_guides/cmake_style_guide.md)
- [GitHub Actions style guide](https://github.com/ROCm/TheRock/blob/main/docs/development/style_guides/github_actions_style_guide.md)
- [Python style guide](https://github.com/ROCm/TheRock/blob/main/docs/development/style_guides/python_style_guide.md)

## Testing

Scanner logic lives under `security_scanners/`; shared helpers (checksum
verification, GitHub Actions API wrappers, PR fetch-depth computation)
live in `security_scanners/utils/` with unit tests alongside them
(`*_test.py`, run via `pytest`). Before opening a PR:

```bash
# from repo root
pip install -r security_scanners/requirements-test.txt
python -m pytest security_scanners
```
