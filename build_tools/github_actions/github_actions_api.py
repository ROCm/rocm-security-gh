#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Minimal GitHub Actions workflow-command helpers.

Vendored (trimmed) from TheRock's `build_tools/github_actions/github_actions_api.py`:
https://github.com/ROCm/TheRock/blob/main/build_tools/github_actions/github_actions_api.py

Only the handful of functions used by scanners in this repo are kept here;
this module intentionally does not pull in TheRock's broader GitHub REST API
client, which has no purpose outside that monorepo.
"""

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path


def _log(*args: object, **kwargs: object) -> None:
    print(*args, **kwargs)
    sys.stdout.flush()


def gha_set_output(vars: Mapping[str, str | Path]) -> None:
    """Sets values in a step's output parameters.

    This appends to the file located at the $GITHUB_OUTPUT environment variable.
    Multi-line values are written using the heredoc form required by GitHub
    Actions (see "Multiline strings" in the workflow-commands reference).

    See
      * https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-an-output-parameter
      * https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#multiline-strings
    """
    _log(
        f"Setting github output:\n{json.dumps({k: str(v) for k, v in vars.items()}, indent=2)}"
    )

    step_output_file = os.getenv("GITHUB_OUTPUT")
    if not step_output_file:
        _log("  Warning: GITHUB_OUTPUT env var not set, can't set github outputs")
        return

    with open(step_output_file, "a", encoding="utf-8") as f:
        for k, v in vars.items():
            value = "" if v is None else str(v)
            if "\n" in value:
                f.write(f"{k}<<EOF\n{value}\nEOF\n")
            else:
                f.write(f"{k}={value}\n")


def gha_append_step_summary(summary: str) -> None:
    """Appends a string to the GitHub Actions job summary.

    This appends to the file located at the $GITHUB_STEP_SUMMARY environment variable.

    See
      * https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#adding-a-job-summary
    """
    _log(f"Writing job summary:\n{summary}")

    step_summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if not step_summary_file:
        _log("  Warning: GITHUB_STEP_SUMMARY env var not set, can't write job summary")
        return

    with open(step_summary_file, "a", encoding="utf-8") as f:
        # Use double newlines to split sections in markdown.
        f.write(summary + "\n\n")


def gha_load_github_event() -> Mapping[str, object]:
    """Loads the JSON event payload pointed to by $GITHUB_EVENT_PATH.

    Raises:
        KeyError: $GITHUB_EVENT_PATH is not set (not running under GitHub
            Actions, or the step was given no event payload).
        FileNotFoundError: $GITHUB_EVENT_PATH is set but the file
            doesn't exist (CI misconfiguration).
        ValueError: the file contains invalid JSON, or the top-level
            payload is not a JSON object.
        RuntimeError: the file exists but couldn't be read (permissions,
            disk error, etc.).

    See: https://docs.github.com/en/actions/reference/variables-reference#default-environment-variables
         https://docs.github.com/en/webhooks/webhook-events-and-payloads
    """
    event_path = Path(os.environ["GITHUB_EVENT_PATH"])
    if not event_path.is_file():
        raise FileNotFoundError(
            f"GITHUB_EVENT_PATH is set to '{event_path}' but no such file exists"
        )
    try:
        with open(event_path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"GITHUB_EVENT_PATH '{event_path}' contains invalid JSON: {exc}"
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Cannot read GITHUB_EVENT_PATH '{event_path}': {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"GITHUB_EVENT_PATH '{event_path}' must contain a JSON object, "
            f"got {type(data).__name__}"
        )
    return data
