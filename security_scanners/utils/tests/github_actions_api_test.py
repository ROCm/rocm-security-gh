# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from security_scanners.utils.github_actions_api import (
    gha_append_step_summary,
    gha_load_github_event,
    gha_set_output,
    import_github_actions_api,
)


class ImportGithubActionsApiTest(unittest.TestCase):
    """Tests for import_github_actions_api."""

    def test_returns_vendored_helpers_without_external_checkout(self):
        gha = import_github_actions_api()
        self.assertIs(gha.append_step_summary, gha_append_step_summary)
        self.assertIs(gha.load_github_event, gha_load_github_event)
        self.assertIs(gha.set_output, gha_set_output)


class GhaLoadGithubEventTest(unittest.TestCase):
    """Tests for gha_load_github_event."""

    def test_loads_event_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            event_path = Path(tmp) / "event.json"
            event_path.write_text('{"pull_request": {"commits": 2}}', encoding="utf-8")
            with mock.patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event_path)}):
                payload = gha_load_github_event()
        self.assertEqual(payload, {"pull_request": {"commits": 2}})

    def test_raises_when_env_var_unset(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(KeyError):
                gha_load_github_event()


class GhaSetOutputTest(unittest.TestCase):
    """Tests for gha_set_output."""

    def test_writes_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "output.txt"
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output_path)}):
                gha_set_output({"value": "4", "flag": "ok"})
            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                "value=4\nflag=ok\n",
            )


class GhaAppendStepSummaryTest(unittest.TestCase):
    """Tests for gha_append_step_summary."""

    def test_appends_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary_path = Path(tmp) / "summary.md"
            with mock.patch.dict(
                os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}
            ):
                gha_append_step_summary("findings attached")
            self.assertEqual(
                summary_path.read_text(encoding="utf-8"),
                "findings attached\n\n",
            )


if __name__ == "__main__":
    unittest.main()
