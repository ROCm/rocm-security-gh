#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Compute the smallest `actions/checkout` fetch-depth for the current event."""

import os
import sys
from collections.abc import Mapping

from security_scanners.utils.github_actions_api import import_github_actions_api


def compute_fetch_depth(
    payload: Mapping[str, object],
    scan_mode: str = "changed",
    needs_history: bool = False,
) -> str:
    # `all` mode scans the working tree; only history scanners need commits.
    if scan_mode == "all":
        return "0" if needs_history else "1"

    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        return "0"

    commits = pr.get("commits")
    if not isinstance(commits, int) or commits <= 0:
        return "0"

    return str(commits + 2)


def main(argv: list[str]) -> int:
    gha = import_github_actions_api()
    value = compute_fetch_depth(
        gha.load_github_event(),
        scan_mode=os.environ.get("SCANNER_SCAN_MODE", "changed"),
        needs_history=os.environ.get("SCANNER_NEEDS_HISTORY", "").lower() == "true",
    )
    print(f"fetch-depth = {value}")
    gha.set_output({"value": value})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
