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
2. Make your change, following the conventions below.
3. Open a pull request against `main`. Fill in the PR template completely;
   reviewers use the "Technical Details" and "Test Plan"/"Test Result"
   sections to understand *why* a change was made and how it was verified.

## Code style

Follow the [ROCm/TheRock style guides](https://github.com/ROCm/TheRock/tree/main/docs/development/style_guides):

- [Bash style guide](https://github.com/ROCm/TheRock/blob/main/docs/development/style_guides/bash_style_guide.md)
- [CMake style guide](https://github.com/ROCm/TheRock/blob/main/docs/development/style_guides/cmake_style_guide.md)
- [GitHub Actions style guide](https://github.com/ROCm/TheRock/blob/main/docs/development/style_guides/github_actions_style_guide.md)
- [Python style guide](https://github.com/ROCm/TheRock/blob/main/docs/development/style_guides/python_style_guide.md)

## Testing

Scanner logic lives under `build_tools/scan_tools/` with unit tests
alongside it (`*_test.py`, run via `pytest`). Before opening a PR:

```bash
cd build_tools/scan_tools
pip install -r ../requirements-test.txt
pytest
```