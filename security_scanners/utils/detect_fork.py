#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Report whether the repository running the workflow is a fork, and of what.

Fork status comes from the event payload; the upstream needs one repository
API call. A failed lookup never fails the run.
"""

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.error import HTTPError

from security_scanners.utils.compute_codeql_matrix import (
    DiscoveryError,
    JsonFetcher,
    github_get,
)
from security_scanners.utils.github_actions_api import (
    gha_append_step_summary,
    gha_load_github_event,
    gha_set_output,
)

# Values land in workflow outputs and Markdown, so reject anything unexpected.
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_BRANCH_RE = re.compile(r"[^\s`]+")


@dataclass(frozen=True)
class ForkInfo:
    """Upstream fields are '' when the repository isn't a fork or it's unknown."""

    is_fork: bool
    upstream_repository: str = ""
    upstream_default_branch: str = ""


def _payload_fork_flag(event: Mapping[str, object]) -> bool | None:
    repository = event.get("repository")
    if not isinstance(repository, Mapping):
        return None
    flag = repository.get("fork")
    return flag if isinstance(flag, bool) else None


def _parent_of(payload: object) -> tuple[str, str]:
    """Return the parent's `(owner/name, default_branch)`; '' for a bad value."""
    if not isinstance(payload, Mapping):
        return "", ""
    parent = payload.get("parent")
    if not isinstance(parent, Mapping):
        return "", ""
    name = parent.get("full_name")
    branch = parent.get("default_branch")
    return (
        name if isinstance(name, str) and _REPOSITORY_RE.fullmatch(name) else "",
        branch if isinstance(branch, str) and _BRANCH_RE.fullmatch(branch) else "",
    )


def detect_fork(
    event: Mapping[str, object], fetcher: JsonFetcher, repository: str
) -> ForkInfo:
    flag = _payload_fork_flag(event)
    if flag is False:
        return ForkInfo(is_fork=False)

    try:
        payload = fetcher(f"/repos/{repository}")
    except (DiscoveryError, HTTPError) as exc:
        # Fail open: keep what the payload said; unknown counts as not a fork.
        print(f"::warning::Could not look up {repository}: {exc}")
        return ForkInfo(is_fork=flag is True)

    if flag is None:
        flag = isinstance(payload, Mapping) and payload.get("fork") is True
    if not flag:
        return ForkInfo(is_fork=False)

    upstream, branch = _parent_of(payload)
    if not upstream:
        return ForkInfo(is_fork=True)
    return ForkInfo(
        is_fork=True, upstream_repository=upstream, upstream_default_branch=branch
    )


def render_summary(info: ForkInfo) -> str:
    if not info.upstream_repository:
        return (
            "### Fork detection\n\nThis repository is a fork; its upstream is unknown."
        )
    branch = (
        f" (default branch `{info.upstream_default_branch}`)"
        if info.upstream_default_branch
        else ""
    )
    return (
        "### Fork detection\n\n"
        f"This repository is a fork of `{info.upstream_repository}`{branch}."
    )


def main(argv: list[str]) -> int:
    if argv:
        print(f"unexpected arguments: {' '.join(argv)}", file=sys.stderr)
        return 2

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    event: Mapping[str, object] = {}
    if os.environ.get("GITHUB_EVENT_PATH"):
        try:
            event = gha_load_github_event()
        except (KeyError, FileNotFoundError, ValueError, RuntimeError) as exc:
            print(f"Ignoring unreadable event payload: {exc}")

    if not _REPOSITORY_RE.fullmatch(repository):
        print(f"::warning::GITHUB_REPOSITORY is not 'owner/name': {repository!r}")
        info = ForkInfo(is_fork=False)
    else:
        token = os.environ.get("GITHUB_TOKEN", "")
        api_root = os.environ.get("GITHUB_API_URL") or "https://api.github.com"
        info = detect_fork(
            event,
            lambda path: github_get(path, token=token, api_root=api_root),
            repository,
        )

    if info.is_fork:
        print(
            f"{repository} is a fork of "
            f"{info.upstream_repository or '<unknown upstream>'}"
        )
        gha_append_step_summary(render_summary(info))
    else:
        print(f"{repository} is not a fork")
    gha_set_output(
        {
            "is_fork": "true" if info.is_fork else "false",
            "upstream_repository": info.upstream_repository,
            "upstream_default_branch": info.upstream_default_branch,
        }
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
