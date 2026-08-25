#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Import `gha_*` helpers from ROCm/TheRock's `github_actions_api` module.

Shared by scanner drivers and workflow helper scripts that need GitHub
Actions event/output helpers without duplicating TheRock's module locally.
"""

import os
import sys
from collections.abc import Callable, Mapping
from typing import NamedTuple


class GithubActionsApi(NamedTuple):
    """The subset of ROCm/TheRock's `github_actions_api` module we use."""

    append_step_summary: Callable[[str], None]
    load_github_event: Callable[[], Mapping[str, object]]
    set_output: Callable[[Mapping[str, str]], None]


def import_github_actions_api() -> GithubActionsApi:
    """Import `gha_*` helpers from ROCm/TheRock's `github_actions_api` module.

    Deferred (rather than a module-level import) so unit tests exercising
    pure logic don't need a TheRock checkout. Workflows check out TheRock and
    point ``THEROCK_BUILD_TOOLS_DIR`` at its ``build_tools/`` directory
    before running scripts that call this.
    """
    therock_build_tools = os.environ.get("THEROCK_BUILD_TOOLS_DIR")
    if not therock_build_tools:
        raise RuntimeError(
            "THEROCK_BUILD_TOOLS_DIR is not set; expected the workflow to "
            "check out ROCm/TheRock and point this at its build_tools/ dir."
        )
    if therock_build_tools not in sys.path:
        sys.path.insert(0, therock_build_tools)
    from github_actions.github_actions_api import (
        gha_append_step_summary,
        gha_load_github_event,
        gha_set_output,
    )

    return GithubActionsApi(
        append_step_summary=gha_append_step_summary,
        load_github_event=gha_load_github_event,
        set_output=gha_set_output,
    )
