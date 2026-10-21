#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""List the files a fork changed relative to its upstream.

The upstream default branch and the checked-out commit are compared through
the GitHub compare API, which reports their merge base even when the fork is
tens of thousands of commits apart. Only that one commit is fetched, and the
file list is a tree diff from it to the checked-out commit.

Outputs: `changes_file` (a JSON array of repo-relative paths) and
`upstream_commits` (the merge base and the upstream branch head, space
separated). Both are empty when the diff couldn't be computed, in which
case scanners aren't filtered.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote

from security_scanners.utils.compute_codeql_matrix import (
    DiscoveryError,
    JsonFetcher,
    github_get,
)
from security_scanners.utils.fork_changes import split_git_paths
from security_scanners.utils.github_actions_api import (
    gha_append_step_summary,
    gha_set_output,
)

_SHA_RE = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class ForkDiff:
    merge_base: str
    upstream_tip: str
    paths: tuple[str, ...]


def _commit_sha(payload: object, key: str) -> str:
    commit = payload.get(key) if isinstance(payload, Mapping) else None
    sha = commit.get("sha") if isinstance(commit, Mapping) else None
    return sha if isinstance(sha, str) and _SHA_RE.fullmatch(sha) else ""


def _git(checkout_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=checkout_root,
        check=False,
        capture_output=True,
        text=True,
        errors="surrogateescape",
    )


def compute_fork_diff(
    fetcher: JsonFetcher,
    *,
    repository: str,
    upstream_repository: str,
    upstream_branch: str,
    head_sha: str,
    checkout_root: Path,
) -> ForkDiff | None:
    """Return the fork's own changes, or None if they can't be determined."""
    owner = upstream_repository.split("/", 1)[0]
    # per_page=1: only the commit SHAs are used, not the (capped) file list.
    basehead = quote(f"{owner}:{upstream_branch}...{head_sha}", safe=":.")
    try:
        comparison = fetcher(f"/repos/{repository}/compare/{basehead}?per_page=1")
    except (DiscoveryError, HTTPError) as exc:
        print(f"::warning::Could not compare with {upstream_repository}: {exc}")
        return None

    merge_base = _commit_sha(comparison, "merge_base_commit")
    tip = _commit_sha(comparison, "base_commit")
    if not merge_base or not tip:
        print(f"::warning::No merge base with {upstream_repository}; not filtering")
        return None

    # The checkout may not hold the merge base (a shallow clone, or a commit
    # that only upstream has). A failed fetch needs no handling here: the
    # diff below then fails and the caller runs unfiltered.
    if _git(checkout_root, "cat-file", "-e", f"{merge_base}^{{commit}}").returncode:
        _git(checkout_root, "fetch", "--no-tags", "--depth=1", "origin", merge_base)
    diff = _git(
        checkout_root,
        "diff",
        "--name-only",
        "-z",
        "--diff-filter=ACDMR",
        merge_base,
        head_sha,
    )
    if diff.returncode:
        print(f"::warning::git diff from merge base failed: {diff.stderr.strip()}")
        return None
    return ForkDiff(merge_base, tip, tuple(split_git_paths(diff.stdout)))


def main(argv: list[str]) -> int:
    if argv:
        print(f"unexpected arguments: {' '.join(argv)}", file=sys.stderr)
        return 2

    checkout_root = Path(os.environ.get("SCANNER_CHECKOUT_ROOT", ".scan-target"))
    head = _git(checkout_root, "rev-parse", "HEAD")
    if head.returncode:
        print(f"::warning::Cannot resolve HEAD: {head.stderr.strip()}")
        gha_set_output({"changes_file": "", "upstream_commits": ""})
        return 0

    token = os.environ.get("GITHUB_TOKEN", "")
    api_root = os.environ.get("GITHUB_API_URL") or "https://api.github.com"
    result = compute_fork_diff(
        lambda path: github_get(path, token=token, api_root=api_root),
        repository=os.environ["GITHUB_REPOSITORY"],
        upstream_repository=os.environ["SCANNER_UPSTREAM_REPOSITORY"],
        upstream_branch=os.environ["SCANNER_UPSTREAM_DEFAULT_BRANCH"],
        head_sha=head.stdout.strip(),
        checkout_root=checkout_root,
    )
    if result is None:
        gha_set_output({"changes_file": "", "upstream_commits": ""})
        return 0

    changes_file = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()) / (
        "fork-changes.json"
    )
    changes_file.write_text(json.dumps(result.paths), encoding="utf-8")
    gha_append_step_summary(
        f"Fork filter: {len(result.paths)} file(s) differ from "
        f"`{os.environ['SCANNER_UPSTREAM_REPOSITORY']}` "
        f"(merge base `{result.merge_base[:12]}`)."
    )
    gha_set_output(
        {
            "changes_file": str(changes_file),
            "upstream_commits": f"{result.merge_base} {result.upstream_tip}",
        }
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
