#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Compute the smallest `actions/checkout` fetch-depth for the current event."""

import sys
from collections.abc import Mapping

from security_scanners.utils.github_actions_api import import_github_actions_api


def compute_fetch_depth(payload: Mapping[str, object]) -> str:
    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        return "0"

    commits = pr.get("commits")
    if not isinstance(commits, int) or commits <= 0:
        return "0"

    return str(commits + 1)


def main(argv: list[str]) -> int:
    gha = import_github_actions_api()
    value = compute_fetch_depth(gha.load_github_event())
    print(f"fetch-depth = {value}")
    gha.set_output({"value": value})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
