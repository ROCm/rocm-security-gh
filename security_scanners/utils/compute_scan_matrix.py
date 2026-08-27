#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Turn a `scanners` input into the job matrix `security-scan.yml` fans out to.

Every entry the matrix carries -- the module to run, the runner, the
timeout, the SARIF category, the artifact name -- is decided here rather
than in YAML, so adding a scanner is one entry in `SCANNERS` plus its
module, and callers never change. Unknown names are rejected instead of
skipped: a typo in a caller's `scanners` input must fail the workflow, not
quietly leave a scanner out of the run.
"""

import argparse
import json
import os
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


# Ordered for stable matrix output; GitHub runs the legs in parallel.
SCANNERS: tuple[ScannerSpec, ...] = (
    ScannerSpec(
        name="gitleaks",
        module="security_scanners.github_actions.gitleaks",
        # Walks git history, so it scales with repo size rather than
        # working-tree size and needs the longest leash.
        timeout_minutes=30,
    ),
    ScannerSpec(
        name="zizmor",
        module="security_scanners.github_actions.zizmor",
        timeout_minutes=20,
    ),
)

_SCANNERS_BY_NAME = {spec.name: spec for spec in SCANNERS}


def parse_scanners(raw: str) -> list[ScannerSpec]:
    """Parse a comma-separated `scanners` value into specs, input order.

    Raises:
        ValueError: If a name is unknown or nothing is selected.
    """
    specs: list[ScannerSpec] = []
    seen: set[str] = set()
    for raw_name in raw.split(","):
        name = raw_name.strip().lower()
        if not name or name in seen:
            continue
        spec = _SCANNERS_BY_NAME.get(name)
        if spec is None:
            raise ValueError(
                f"Unknown scanner '{name}' "
                f"(expected one or more of: {', '.join(_SCANNERS_BY_NAME)})"
            )
        seen.add(name)
        specs.append(spec)
    if not specs:
        raise ValueError(
            "scanners is empty (expected one or more of: "
            f"{', '.join(_SCANNERS_BY_NAME)})"
        )
    return specs


def build_matrix(specs: list[ScannerSpec]) -> str:
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
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--scanners",
        default=os.environ.get(
            "SCANNER_NAMES", ",".join(spec.name for spec in SCANNERS)
        ),
        help=(
            "Comma-separated list of scanners to run. Allowed values: "
            f"{', '.join(_SCANNERS_BY_NAME)}. Defaults to all of them."
        ),
    )
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)

    try:
        specs = parse_scanners(args.scanners)
    except ValueError as exc:
        print(f"::error::{exc}")
        return 1

    matrix = build_matrix(specs)
    print(f"Scanners: {', '.join(spec.name for spec in specs)}")
    print(f"matrix = {matrix}")
    gha_set_output({"matrix": matrix})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
