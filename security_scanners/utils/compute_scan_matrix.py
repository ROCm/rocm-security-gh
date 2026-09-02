#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Render the job matrix `security-baseline.yml` fans out to.

`SCANNERS` below is the org-wide policy: every scanner listed here runs
against every repository that calls the workflow. There is deliberately no
way for a caller to select a subset -- a repository must not be able to opt
out of a scanner -- so this takes no input, and adding a scanner here rolls
it out everywhere on the next run.

Everything a matrix leg needs (the module to run, the runner, the timeout,
and the name used for the check run, the SARIF category and the report
artifact) is decided here rather than in YAML.

The one thing a caller can move is the timeout, because a repository the
size of `rocm-libraries` takes longer to scan than the defaults below
allow, and a scanner that runs out of time *fails* its check rather than
passing it -- so unlike a severity threshold, the timeout can't be used
to make a finding disappear. It only ever moves up: `--timeout-minutes`
raises a scanner's budget and never lowers it below what the baseline
considers enough.
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass

from security_scanners.utils.github_actions_api import gha_set_output

# GitHub cancels a job on a hosted runner after 6 hours, so a larger
# budget than this is one the runner will never honour.
MAX_TIMEOUT_MINUTES = 360


@dataclass(frozen=True)
class ScannerSpec:
    """A scanner the security baseline workflow knows how to run.

    Attributes:
        name: Caller-facing name, also the SARIF category and the stem of
            the report artifact name.
        module: Module run as `python -m <module>`.
        timeout_minutes: Job timeout for this scanner's matrix leg.
        runner: `runs-on` label for this scanner's matrix leg. Pinned per
            scanner (rather than workflow-wide) because the scanners
            download platform-specific binaries.
    """

    name: str
    module: str
    timeout_minutes: int
    runner: str = "ubuntu-24.04"

    def budget(self, requested_minutes: int) -> int:
        """Return this scanner's timeout, honouring a caller's request.

        The caller's number is a floor raise, not a replacement: a
        repository knows it is large, but not that a scanner needs less
        room than the baseline gives it.
        """
        return max(self.timeout_minutes, requested_minutes)


SCANNERS: tuple[ScannerSpec, ...] = (
    ScannerSpec(
        name="gitleaks",
        module="security_scanners.github_actions.gitleaks",
        timeout_minutes=30,
    ),
    ScannerSpec(
        name="zizmor",
        module="security_scanners.github_actions.zizmor",
        timeout_minutes=20,
    ),
    ScannerSpec(
        name="bandit",
        module="security_scanners.github_actions.bandit",
        timeout_minutes=20,
    ),
    ScannerSpec(
        name="trivy",
        module="security_scanners.github_actions.trivy",
        timeout_minutes=20,
    ),
)


def build_matrix(specs: tuple[ScannerSpec, ...], timeout_minutes: int = 0) -> str:
    """Render specs as the JSON `strategy.matrix.include` list."""
    return json.dumps(
        [
            {
                "scanner": spec.name,
                "module": spec.module,
                "timeout_minutes": spec.budget(timeout_minutes),
                "runner": spec.runner,
            }
            for spec in specs
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--timeout-minutes",
        type=int,
        default=os.environ.get("SCANNER_TIMEOUT_MINUTES") or 0,
        help=(
            "Minimum job timeout for every scanner, in minutes. 0 (the "
            "default) leaves each scanner on its own budget. A larger "
            "number raises any scanner whose budget is smaller, for "
            "repositories too large to scan in it. Maximum "
            f"{MAX_TIMEOUT_MINUTES} (GitHub cancels the job there anyway)."
        ),
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    requested = args.timeout_minutes
    if requested < 0 or requested > MAX_TIMEOUT_MINUTES:
        parser.error(
            f"--timeout-minutes must be between 0 and {MAX_TIMEOUT_MINUTES}, "
            f"got {requested}"
        )

    matrix = build_matrix(SCANNERS, requested)
    print(
        "Scanners: "
        + ", ".join(f"{spec.name} ({spec.budget(requested)}m)" for spec in SCANNERS)
    )
    raised = [
        spec for spec in SCANNERS if spec.budget(requested) > spec.timeout_minutes
    ]
    if raised:
        print(
            f"Caller raised the timeout to {requested}m for: "
            + ", ".join(
                f"{spec.name} (default {spec.timeout_minutes}m)" for spec in raised
            )
        )
    print(f"matrix = {matrix}")
    gha_set_output({"matrix": matrix})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
