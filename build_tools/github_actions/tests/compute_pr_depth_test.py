# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

from pathlib import Path
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.fspath(Path(__file__).parent.parent))
import compute_pr_depth


class ComputeFetchDepthTest(unittest.TestCase):
    """Tests for compute_pr_depth.compute_fetch_depth."""

    def test_pull_request_returns_commits_plus_one(self):
        self.assertEqual(
            compute_pr_depth.compute_fetch_depth({"pull_request": {"commits": 3}}),
            "4",
        )

    def test_single_commit_pull_request(self):
        self.assertEqual(
            compute_pr_depth.compute_fetch_depth({"pull_request": {"commits": 1}}),
            "2",
        )

    def test_empty_payload_returns_full_history(self):
        self.assertEqual(compute_pr_depth.compute_fetch_depth({}), "0")

    def test_push_payload_returns_full_history(self):
        self.assertEqual(
            compute_pr_depth.compute_fetch_depth({"before": "abc123"}), "0"
        )

    def test_non_dict_pull_request_returns_full_history(self):
        self.assertEqual(
            compute_pr_depth.compute_fetch_depth({"pull_request": None}), "0"
        )

    def test_missing_commits_returns_full_history(self):
        self.assertEqual(
            compute_pr_depth.compute_fetch_depth({"pull_request": {}}), "0"
        )

    def test_zero_commits_returns_full_history(self):
        self.assertEqual(
            compute_pr_depth.compute_fetch_depth({"pull_request": {"commits": 0}}),
            "0",
        )

    def test_negative_commits_returns_full_history(self):
        self.assertEqual(
            compute_pr_depth.compute_fetch_depth({"pull_request": {"commits": -5}}),
            "0",
        )

    def test_non_int_commits_returns_full_history(self):
        self.assertEqual(
            compute_pr_depth.compute_fetch_depth({"pull_request": {"commits": "3"}}),
            "0",
        )

    def test_returns_string(self):
        result = compute_pr_depth.compute_fetch_depth({"pull_request": {"commits": 2}})
        self.assertIsInstance(result, str)


class MainTest(unittest.TestCase):
    """Tests for compute_pr_depth.main's TheRock dependency handling."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("THEROCK_BUILD_TOOLS_DIR", None)

    def test_raises_when_therock_build_tools_dir_unset(self):
        with self.assertRaises(RuntimeError) as ctx:
            compute_pr_depth.main([])
        self.assertIn("THEROCK_BUILD_TOOLS_DIR", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
