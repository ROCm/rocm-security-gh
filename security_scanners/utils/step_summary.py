#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Surface scanner reports in the job log and a size-bounded job summary."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Sequence
from pathlib import Path

log = logging.getLogger(__name__)

# GitHub renders at most 1 MiB of job summary per step and drops anything
# beyond it, so leave headroom for the headings and fences reports are
# wrapped in.
STEP_SUMMARY_BUDGET_BYTES = 900 * 1024


def md_code_fence(content: str) -> str:
    """Return a backtick fence longer than any backtick run in `content`.

    Ensures markdown summaries stay intact even when reports contain backticks.
    """
    longest = max((len(m) for m in re.findall(r"`+", content)), default=0)
    return "`" * max(3, longest + 1)


def clip_to_budget(content: str, budget_bytes: int) -> tuple[str, bool]:
    """Return `content` clipped to `budget_bytes`, and whether it was clipped.

    Clips on a line boundary so a report never ends mid-record.
    """
    encoded = content.encode("utf-8")
    if len(encoded) <= budget_bytes:
        return content, False
    if budget_bytes <= 0:
        return "", True
    clipped = encoded[:budget_bytes].decode("utf-8", errors="ignore")
    last_newline = clipped.rfind("\n")
    return (clipped[: last_newline + 1] if last_newline != -1 else clipped), True


def emit_reports(
    label: str,
    paths: Sequence[Path],
    append_step_summary: Callable[[str], None],
    *,
    budget_bytes: int = STEP_SUMMARY_BUDGET_BYTES,
) -> None:
    """Print each report to the job log and append a budgeted job summary.

    Every report reaches the job log in full and is uploaded as an artifact by
    the workflow; only the job summary is budgeted, since GitHub discards
    summaries that run past its size limit. `budget_bytes` is shared across
    `paths`, so a single oversized report cannot starve the rest of its
    heading.
    """
    summary_chunks: list[str] = []
    remaining = budget_bytes
    for path in paths:
        if not path.is_file():
            log.warning(
                "non-SARIF report '%s' missing; skipping log + summary emission",
                path,
            )
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        print(f"::group::{label} report: {path}")
        print(content)
        print("::endgroup::")

        shown, clipped = clip_to_budget(content, remaining)
        remaining -= len(shown.encode("utf-8"))
        chunk = f"### {label} report: `{path}`"
        if shown:
            fence = md_code_fence(shown)
            chunk += f"\n\n{fence}\n{shown}\n{fence}"
        if clipped:
            log.warning(
                "report '%s' exceeds the job-summary budget; summary truncated",
                path,
            )
            chunk += (
                "\n\n_Truncated to stay under GitHub's job-summary limit. "
                "The full report is in the uploaded artifact._"
            )
        summary_chunks.append(chunk)
    if summary_chunks:
        append_step_summary("\n\n".join(summary_chunks))
