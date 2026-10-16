# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Scanner-side view of what a fork changed relative to its upstream.

`compute_fork_diff` writes the fork-only file list and the upstream commits
that fork history shares; the workflow hands both to each scanner through the
environment variables below. Unset means the repository isn't a fork (or the
lookup failed), and nothing is filtered.
"""

import json
import logging
import os
from collections.abc import Callable, Iterable
from pathlib import Path

log = logging.getLogger(__name__)

CHANGES_FILE_ENV = "SCANNER_FORK_CHANGES_FILE"
# Space-separated SHAs; everything reachable from them is upstream history.
UPSTREAM_COMMITS_ENV = "SCANNER_FORK_UPSTREAM_COMMITS"


def fork_changed_paths() -> list[str] | None:
    """Return the repo-relative paths the fork changed, or None if not a fork.

    The file is a JSON array of strings (as `compute_fork_diff` writes it)
    or one path per line. An unreadable list also returns None: a failure
    must widen the scan, never shrink it.
    """
    changes_file = os.environ.get(CHANGES_FILE_ENV, "")
    if not changes_file:
        return None
    try:
        text = Path(changes_file).read_text(encoding="utf-8")
    except OSError as exc:
        log.warning(
            "Cannot read fork changes %s (%s); not filtering", changes_file, exc
        )
        return None
    if text.lstrip().startswith("["):
        try:
            paths = json.loads(text)
        except json.JSONDecodeError as exc:
            log.warning(
                "Cannot parse fork changes %s (%s); not filtering", changes_file, exc
            )
            return None
        if not isinstance(paths, list) or not all(
            isinstance(path, str) for path in paths
        ):
            log.warning(
                "Fork changes %s is not a JSON string array; not filtering",
                changes_file,
            )
            return None
        return paths
    return [line for line in text.splitlines() if line]


def split_git_paths(output: str) -> list[str]:
    """Parse `git --name-only` output, preferring its NUL-delimited form."""
    if "\0" in output:
        return [path for path in output.split("\0") if path]
    return output.splitlines()


def restrict_to_fork_changes(paths: Iterable[str]) -> list[str]:
    """Keep only the repo-relative `paths` that the fork changed."""
    paths = list(paths)
    fork_paths = fork_changed_paths()
    if fork_paths is None:
        return paths
    fork_set = set(fork_paths)
    kept = [path for path in paths if path in fork_set]
    log.info(
        "Fork filter: %d of %d changed file(s) differ from upstream",
        len(kept),
        len(paths),
    )
    return kept


def select_files(
    changed: Iterable[str],
    scan_path: Path,
    checkout_root: Path,
    is_wanted: Callable[[str], bool],
) -> list[Path]:
    """Return the existing files of `changed` that a scanner audits under `scan_path`.

    `changed` holds repo-relative paths, so each one is re-anchored at
    `checkout_root` (the scan target's repo root, not necessarily this
    process's cwd) before it is checked. A path is kept when `is_wanted`
    accepts it, it resolves inside `scan_path`, and it is a regular file.
    """
    scan_root = scan_path.resolve()
    files: list[Path] = []
    for relpath in changed:
        if not relpath or not is_wanted(relpath):
            continue
        candidate = checkout_root / relpath
        try:
            candidate.resolve().relative_to(scan_root)
        except ValueError:
            continue
        if not candidate.is_file():
            continue
        files.append(candidate)
    return files


def fork_only_files(
    scan_path: Path, checkout_root: Path, is_wanted: Callable[[str], bool]
) -> list[Path] | None:
    """Return the fork-owned files `select_files` keeps, or None.

    None means the repository isn't a fork, so the whole tree is in scope.
    """
    fork_paths = fork_changed_paths()
    if fork_paths is None:
        return None
    return select_files(fork_paths, scan_path, checkout_root, is_wanted)


def upstream_commits() -> list[str]:
    """Return the SHAs whose history is upstream's, or [] when not a fork."""
    return os.environ.get(UPSTREAM_COMMITS_ENV, "").split()
