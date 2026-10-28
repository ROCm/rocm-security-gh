# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

from security_scanners.utils.compute_codeql_matrix import DiscoveryError
from security_scanners.utils.detect_fork import (
    ForkInfo,
    detect_fork,
    main,
    render_summary,
)

_FORK_PAYLOAD = {
    "fork": True,
    "parent": {"full_name": "llvm/llvm-project", "default_branch": "main"},
}


class FakeFetcher:
    """Returns a canned response (or raises) and records the paths requested."""

    def __init__(self, response: object = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.paths: list[str] = []

    def __call__(self, path: str) -> object:
        self.paths.append(path)
        if self.error is not None:
            raise self.error
        return self.response


def _event(fork: object) -> dict[str, object]:
    return {"repository": {"fork": fork}}


class DetectForkTest(unittest.TestCase):
    def test_payload_without_fork_flag_skips_the_api(self):
        fetcher = FakeFetcher()
        info = detect_fork(_event(False), fetcher, "ROCm/example")
        self.assertEqual(info, ForkInfo(is_fork=False))
        self.assertEqual(fetcher.paths, [])

    def test_fork_reports_its_upstream(self):
        fetcher = FakeFetcher(_FORK_PAYLOAD)
        info = detect_fork(_event(True), fetcher, "ROCm/llvm-project")
        self.assertEqual(
            info,
            ForkInfo(
                is_fork=True,
                upstream_repository="llvm/llvm-project",
                upstream_default_branch="main",
            ),
        )
        self.assertEqual(fetcher.paths, ["/repos/ROCm/llvm-project"])

    def test_failed_lookup_keeps_a_payload_fork_with_unknown_upstream(self):
        fetcher = FakeFetcher(error=DiscoveryError("boom"))
        info = detect_fork(_event(True), fetcher, "ROCm/llvm-project")
        self.assertEqual(info, ForkInfo(is_fork=True))

    def test_http_error_is_not_fatal(self):
        error = HTTPError("https://api.github.com/x", 403, "Forbidden", {}, None)
        info = detect_fork(_event(True), FakeFetcher(error=error), "ROCm/x")
        self.assertEqual(info, ForkInfo(is_fork=True))

    def test_missing_flag_falls_back_to_the_api(self):
        info = detect_fork({}, FakeFetcher(_FORK_PAYLOAD), "ROCm/llvm-project")
        self.assertTrue(info.is_fork)
        self.assertEqual(info.upstream_repository, "llvm/llvm-project")

    def test_missing_flag_and_non_fork_response_is_not_a_fork(self):
        info = detect_fork({}, FakeFetcher({"fork": False}), "ROCm/example")
        self.assertEqual(info, ForkInfo(is_fork=False))

    def test_missing_flag_and_failed_lookup_is_not_a_fork(self):
        info = detect_fork({}, FakeFetcher(error=DiscoveryError("x")), "ROCm/x")
        self.assertEqual(info, ForkInfo(is_fork=False))

    def test_non_boolean_flag_is_treated_as_missing(self):
        info = detect_fork(_event("yes"), FakeFetcher({"fork": False}), "ROCm/x")
        self.assertFalse(info.is_fork)

    def test_fork_without_a_parent_has_unknown_upstream(self):
        info = detect_fork(_event(True), FakeFetcher({"fork": True}), "ROCm/x")
        self.assertEqual(info, ForkInfo(is_fork=True))

    def test_malformed_parent_values_are_dropped(self):
        payload = {
            "fork": True,
            "parent": {"full_name": "not a repo", "default_branch": "a b"},
        }
        info = detect_fork(_event(True), FakeFetcher(payload), "ROCm/x")
        self.assertEqual(info, ForkInfo(is_fork=True))

    def test_malformed_branch_alone_keeps_the_repository(self):
        payload = {
            "fork": True,
            "parent": {"full_name": "llvm/llvm-project", "default_branch": "a\nb"},
        }
        info = detect_fork(_event(True), FakeFetcher(payload), "ROCm/x")
        self.assertEqual(info.upstream_repository, "llvm/llvm-project")
        self.assertEqual(info.upstream_default_branch, "")


class RenderSummaryTest(unittest.TestCase):
    def test_names_upstream_and_branch(self):
        text = render_summary(ForkInfo(True, "llvm/llvm-project", "main"))
        self.assertIn("fork of `llvm/llvm-project` (default branch `main`)", text)

    def test_unknown_upstream(self):
        self.assertIn("upstream is unknown", render_summary(ForkInfo(True)))


class MainTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.output = Path(tmp.name) / "output"
        self.summary = Path(tmp.name) / "summary"
        self.event = Path(tmp.name) / "event.json"
        self.env = {
            "GITHUB_OUTPUT": str(self.output),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "GITHUB_EVENT_PATH": str(self.event),
            "GITHUB_REPOSITORY": "ROCm/llvm-project",
        }

    def _run(self, event_json: str, fetcher: FakeFetcher) -> int:
        self.event.write_text(event_json, encoding="utf-8")
        with (
            mock.patch.dict(os.environ, self.env, clear=True),
            mock.patch(
                "security_scanners.utils.detect_fork.github_get",
                side_effect=lambda path, **_: fetcher(path),
            ),
        ):
            return main([])

    def test_fork_writes_outputs_and_summary(self):
        code = self._run('{"repository": {"fork": true}}', FakeFetcher(_FORK_PAYLOAD))
        self.assertEqual(code, 0)
        outputs = self.output.read_text(encoding="utf-8")
        self.assertIn("is_fork=true\n", outputs)
        self.assertIn("upstream_repository=llvm/llvm-project\n", outputs)
        self.assertIn("upstream_default_branch=main\n", outputs)
        self.assertIn("fork of `llvm/llvm-project`", self.summary.read_text("utf-8"))

    def test_non_fork_writes_empty_upstream_and_no_summary(self):
        fetcher = FakeFetcher()
        code = self._run('{"repository": {"fork": false}}', fetcher)
        self.assertEqual(code, 0)
        outputs = self.output.read_text(encoding="utf-8")
        self.assertIn("is_fork=false\n", outputs)
        self.assertIn("upstream_repository=\n", outputs)
        self.assertFalse(self.summary.exists())
        self.assertEqual(fetcher.paths, [])

    def test_malformed_repository_name_is_reported_as_not_a_fork(self):
        self.env["GITHUB_REPOSITORY"] = "nonsense"
        code = self._run('{"repository": {"fork": true}}', FakeFetcher())
        self.assertEqual(code, 0)
        self.assertIn("is_fork=false\n", self.output.read_text(encoding="utf-8"))

    def test_unexpected_arguments_are_rejected(self):
        self.assertEqual(main(["--nope"]), 2)


if __name__ == "__main__":
    unittest.main()
