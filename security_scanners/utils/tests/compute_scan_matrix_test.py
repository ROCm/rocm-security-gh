# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import json
import unittest
from unittest import mock

from security_scanners.utils.compute_scan_matrix import (
    SCANNERS,
    build_matrix,
    main,
)


class ScannerRegistryTest(unittest.TestCase):
    """Tests for the `SCANNERS` policy list."""

    def test_names_are_unique(self):
        names = [spec.name for spec in SCANNERS]
        self.assertCountEqual(names, set(names))

    def test_modules_are_importable(self):
        for spec in SCANNERS:
            __import__(spec.module)

    def test_runner_labels_are_pinned_not_latest(self):
        for spec in SCANNERS:
            self.assertNotIn("latest", spec.runner)

    def test_every_scanner_has_a_timeout(self):
        for spec in SCANNERS:
            self.assertGreater(spec.timeout_minutes, 0)


class BuildMatrixTest(unittest.TestCase):
    """Tests for compute_scan_matrix.build_matrix."""

    def test_emits_one_entry_per_scanner(self):
        entries = json.loads(build_matrix(SCANNERS))
        self.assertEqual(len(entries), len(SCANNERS))

    def test_entry_carries_everything_the_workflow_needs(self):
        entries = json.loads(build_matrix(SCANNERS[:1]))
        self.assertEqual(
            entries[0],
            {
                "scanner": "gitleaks",
                "module": "security_scanners.github_actions.gitleaks",
                "timeout_minutes": 30,
                "runner": "ubuntu-24.04",
            },
        )

    def test_output_is_valid_json_for_fromjson(self):
        self.assertIsInstance(json.loads(build_matrix(SCANNERS)), list)

    def test_preserves_registry_order(self):
        entries = json.loads(build_matrix(SCANNERS))
        self.assertEqual(
            [e["scanner"] for e in entries],
            [spec.name for spec in SCANNERS],
        )


class MainTest(unittest.TestCase):
    """Tests for compute_scan_matrix.main."""

    def test_sets_matrix_output_for_every_scanner(self):
        with mock.patch(
            "security_scanners.utils.compute_scan_matrix.gha_set_output"
        ) as set_output:
            self.assertEqual(main([]), 0)
        entries = json.loads(set_output.call_args.args[0]["matrix"])
        self.assertEqual(
            [e["scanner"] for e in entries],
            [spec.name for spec in SCANNERS],
        )

    def test_takes_no_arguments_so_callers_cannot_select_scanners(self):
        with self.assertRaises(SystemExit):
            main(["--scanners", "gitleaks"])


if __name__ == "__main__":
    unittest.main()
