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
from collections.abc import Iterable, Sequence
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
    configured_path: str = "",
) -> ResolvedConfig:
    """Return the requested config, an automatically found config, or `fallback`.

    `candidates` are the conventional locations for this scanner's config,
    relative to `checkout_root` (the scan target's checkout), tried in
    order. `fallback` is this repo's default config, which must exist:
    a missing default means the tooling checkout is broken, not that the
    scan should quietly run unconfigured. When `configured_path` is set,
    it is the only candidate: it must name a file inside `checkout_root`
    rather than silently falling back after a typo.
    """
    effective_candidates = scanner_config_paths(
        checkout_root=checkout_root,
        configured_path=configured_path,
        candidates=candidates,
    )
    checkout_root_resolved = checkout_root.resolve()
    for candidate in effective_candidates:
        candidate_path = (checkout_root_resolved / candidate).resolve()
        try:
            candidate_path.relative_to(checkout_root_resolved)
        except ValueError as exc:
            raise ValueError(
                f"{scanner} config path '{candidate}' resolves outside the "
                "scanned repository"
            ) from exc
        if candidate_path.is_file():
            log.info(
                "Using %s config from the scanned repository: %s",
                scanner,
                candidate_path,
            )
            return ResolvedConfig(path=candidate_path, from_scan_target=True)

    if configured_path.strip():
        raise FileNotFoundError(
            f"{scanner} config path '{effective_candidates[0]}' does not "
            "exist or is not a file in the scanned repository"
        )

    if not fallback.is_file():
        raise FileNotFoundError(
            f"{scanner} config not found at '{fallback}'. Expected it "
            "alongside this script's rocm-security-gh checkout."
        )
    log.info(
        "Using default %s config: %s (the scanned repository ships none of %s)",
        scanner,
        fallback,
        ", ".join(effective_candidates),
    )
    return ResolvedConfig(path=fallback, from_scan_target=False)


def scanner_config_paths(
    *,
    checkout_root: Path,
    configured_path: str,
    candidates: Sequence[str],
) -> tuple[str, ...]:
    """Return repository-relative config paths used for lookup and diff checks."""
    raw = configured_path.strip()
    if not raw:
        return tuple(candidates)

    supplied = Path(raw)
    if supplied.is_absolute():
        raise ValueError(
            f"config path '{configured_path}' must be relative to the "
            "scanned repository"
        )

    checkout_root_resolved = checkout_root.resolve()
    resolved = (checkout_root_resolved / supplied).resolve()
    try:
        relative = resolved.relative_to(checkout_root_resolved)
    except ValueError as exc:
        raise ValueError(
            f"config path '{configured_path}' resolves outside the "
            "scanned repository"
        ) from exc
    if not relative.parts:
        raise ValueError(f"config path '{configured_path}' does not name a file")
    return (relative.as_posix(),)


def find_config_change(
    changed_paths: Iterable[str], *, filenames: Sequence[str]
) -> str | None:
    """Return the first changed path that is one of `filenames`, if any.

    A scanner's changed-file filter keeps only the files that scanner
    audits, which never includes its own config: a PR that edits nothing
    else would be filtered down to an empty set and pass without the new
    config ever reaching the tool. Config changes affect every file, so
    callers use this to widen such a run into a full scan -- which also
    means a malformed config fails the PR that introduced it rather than
    the next unrelated one.
    """
    # `git diff --name-only` prints repository-root-relative POSIX paths
    # on every platform, so these compare as plain strings.
    wanted = set(filenames)
    for raw in changed_paths:
        relpath = raw.strip()
        if relpath in wanted:
            return relpath
    return None


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
