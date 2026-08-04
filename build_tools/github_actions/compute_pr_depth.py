#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Compute the smallest `actions/checkout` fetch-depth for the current event."""

import os
import sys
from collections.abc import Mapping


def compute_fetch_depth(payload: Mapping[str, object]) -> str:
    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        return "0"

    commits = pr.get("commits")
    if not isinstance(commits, int) or commits <= 0:
        return "0"

    return str(commits + 1)


def main(argv: list[str]) -> int:
    # Deferred import: `gha_load_github_event`/`gha_set_output` live in
    # ROCm/TheRock's `github_actions_api` module rather than being
    # duplicated here, so unit tests of compute_fetch_depth (a pure
    # function) don't need a TheRock checkout. The workflow checks out
    # TheRock and points THEROCK_BUILD_TOOLS_DIR at its `build_tools/`
    # directory before running this script.
    therock_build_tools = os.environ.get("THEROCK_BUILD_TOOLS_DIR")
    if not therock_build_tools:
        raise RuntimeError(
            "THEROCK_BUILD_TOOLS_DIR is not set; expected the workflow to "
            "check out ROCm/TheRock and point this at its build_tools/ dir."
        )
    if therock_build_tools not in sys.path:
        sys.path.insert(0, therock_build_tools)
    from github_actions.github_actions_api import gha_load_github_event, gha_set_output

    value = compute_fetch_depth(gha_load_github_event())
    print(f"fetch-depth = {value}")
    gha_set_output({"value": value})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
