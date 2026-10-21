# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import os
import unittest
from unittest import mock

from security_scanners.utils.compute_pr_depth import compute_fetch_depth, main


class ComputeFetchDepthTest(unittest.TestCase):
    """Tests for compute_pr_depth.compute_fetch_depth."""

    def test_pull_request_includes_merge_pr_and_base_commits(self):
        self.assertEqual(
            compute_fetch_depth({"pull_request": {"commits": 3}}),
            "5",
        )

    def test_single_commit_pull_request(self):
        self.assertEqual(
            compute_fetch_depth({"pull_request": {"commits": 1}}),
            "3",
        )

    def test_all_mode_history_scanner_fetches_full_history(self):
        self.assertEqual(
            compute_fetch_depth(
                {"pull_request": {"commits": 3}}, "all", needs_history=True
            ),
            "0",
        )

    def test_all_mode_tree_scanner_fetches_only_the_tip(self):
        for payload in ({"pull_request": {"commits": 3}}, {"before": "abc"}, {}):
            with self.subTest(payload=payload):
                self.assertEqual(compute_fetch_depth(payload, "all"), "1")

    def test_empty_payload_returns_full_history(self):
        self.assertEqual(compute_fetch_depth({}), "0")

    def test_push_payload_returns_full_history(self):
        self.assertEqual(compute_fetch_depth({"before": "abc123"}), "0")

    def test_non_dict_pull_request_returns_full_history(self):
        self.assertEqual(compute_fetch_depth({"pull_request": None}), "0")

    def test_missing_commits_returns_full_history(self):
        self.assertEqual(compute_fetch_depth({"pull_request": {}}), "0")

    def test_zero_commits_returns_full_history(self):
        self.assertEqual(
            compute_fetch_depth({"pull_request": {"commits": 0}}),
            "0",
        )

    def test_negative_commits_returns_full_history(self):
        self.assertEqual(
            compute_fetch_depth({"pull_request": {"commits": -5}}),
            "0",
        )

    def test_non_int_commits_returns_full_history(self):
        self.assertEqual(
            compute_fetch_depth({"pull_request": {"commits": "3"}}),
            "0",
        )

    def test_returns_string(self):
        result = compute_fetch_depth({"pull_request": {"commits": 2}})
        self.assertIsInstance(result, str)


class MainTest(unittest.TestCase):
    """Tests for compute_pr_depth.main."""

    def test_raises_when_github_event_path_unset(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(KeyError):
                main([])


if __name__ == "__main__":
    unittest.main()
