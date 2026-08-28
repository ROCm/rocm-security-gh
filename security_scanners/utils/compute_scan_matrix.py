#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Render the job matrix `security-scan.yml` fans out to.

`SCANNERS` below is the org-wide policy: every scanner listed here runs
against every repository that calls the workflow. There is deliberately no
way for a caller to select a subset -- a repository must not be able to opt
out of a scanner -- so this takes no input, and adding a scanner here rolls
it out everywhere on the next run.

Everything a matrix leg needs (the module to run, the runner, the timeout,
and the name used for the check run, the SARIF category and the report
artifact) is decided here rather than in YAML.
"""

import argparse
import json
import sys
from dataclasses import dataclass

from security_scanners.utils.github_actions_api import gha_set_output


@dataclass(frozen=True)
class ScannerSpec:
    """A scanner the security-scan workflow knows how to run.

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
)


def build_matrix(specs: tuple[ScannerSpec, ...]) -> str:
    """Render specs as the JSON `strategy.matrix.include` list."""
    return json.dumps(
        [
            {
                "scanner": spec.name,
                "module": spec.module,
                "timeout_minutes": spec.timeout_minutes,
                "runner": spec.runner,
            }
            for spec in specs
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(description=__doc__)


def main(argv: list[str]) -> int:
    build_parser().parse_args(argv)

    matrix = build_matrix(SCANNERS)
    print(f"Scanners: {', '.join(spec.name for spec in SCANNERS)}")
    print(f"matrix = {matrix}")
    gha_set_output({"matrix": matrix})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
