#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Pick the config file a scanner runs with.

A scanned repository knows things this repo can't: which of its paths are
vendored, which fixtures hold deliberately fake credentials, which of its
own findings have already been triaged. So when it ships the config file
its scanner looks for, that file wins, and the copy at the root of
`rocm-security-gh` is the default for the repositories that ship none.

What a repository tunes this way is detection: allowlists, excluded
paths, per-rule suppressions. What it can't touch is which scanners run
and which severity fails the build -- those live in code
(`compute_scan_matrix.py`, each scanner's severity threshold) precisely
so a config file can't opt out of them.
"""

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResolvedConfig:
    """A scanner config file, and where it was found."""

    path: Path
    from_scan_target: bool


def resolve_scanner_config(
    *,
    scanner: str,
    checkout_root: Path,
    candidates: Sequence[str],
    fallback: Path,
) -> ResolvedConfig:
    """Return the scan target's own config, or `fallback` if it has none.

    `candidates` are the conventional locations for this scanner's config,
    relative to `checkout_root` (the scan target's checkout), tried in
    order. `fallback` is this repo's default config, which must exist:
    a missing default means the tooling checkout is broken, not that the
    scan should quietly run unconfigured.
    """
    for candidate in candidates:
        candidate_path = checkout_root / candidate
        if candidate_path.is_file():
            log.info(
                "Using %s config from the scanned repository: %s",
                scanner,
                candidate_path,
            )
            return ResolvedConfig(path=candidate_path, from_scan_target=True)

    if not fallback.is_file():
        raise FileNotFoundError(
            f"{scanner} config not found at '{fallback}'. Expected it "
            "alongside this script's rocm-security-gh checkout."
        )
    log.info(
        "Using default %s config: %s (the scanned repository ships none of %s)",
        scanner,
        fallback,
        ", ".join(candidates),
    )
    return ResolvedConfig(path=fallback, from_scan_target=False)


def resolve_ignore_file(
    *, scanner: str, checkout_root: Path, filename: str
) -> Path | None:
    """Return the scan target's suppression file, if it ships one.

    Tools like gitleaks and trivy look for these next to their working
    directory, which is this repo's checkout rather than the scanned one,
    so the path has to be passed explicitly or a repository's triaged
    findings come back on every run.
    """
    ignore_path = checkout_root / filename
    if not ignore_path.is_file():
        return None
    log.info(
        "Using %s ignore file from the scanned repository: %s", scanner, ignore_path
    )
    return ignore_path
