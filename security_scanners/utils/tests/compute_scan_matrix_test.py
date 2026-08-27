# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import json
import unittest
from unittest import mock

from security_scanners.utils.compute_scan_matrix import (
    SCANNERS,
    build_matrix,
    main,
    parse_scanners,
)


class ParseScannersTest(unittest.TestCase):
    """Tests for compute_scan_matrix.parse_scanners."""

    def test_single_scanner(self):
        self.assertEqual([s.name for s in parse_scanners("gitleaks")], ["gitleaks"])

    def test_preserves_input_order(self):
        self.assertEqual(
            [s.name for s in parse_scanners("zizmor,gitleaks")],
            ["zizmor", "gitleaks"],
        )

    def test_tolerates_whitespace_and_case(self):
        self.assertEqual(
            [s.name for s in parse_scanners(" GitLeaks , zizmor ")],
            ["gitleaks", "zizmor"],
        )

    def test_deduplicates(self):
        self.assertEqual(
            [s.name for s in parse_scanners("zizmor,zizmor")],
            ["zizmor"],
        )

    def test_unknown_scanner_raises(self):
        with self.assertRaises(ValueError) as ctx:
            parse_scanners("gitleaks,semgrep")
        self.assertIn("semgrep", str(ctx.exception))

    def test_unknown_scanner_lists_valid_names(self):
        with self.assertRaises(ValueError) as ctx:
            parse_scanners("nope")
        for spec in SCANNERS:
            self.assertIn(spec.name, str(ctx.exception))

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            parse_scanners("")

    def test_only_separators_raises(self):
        with self.assertRaises(ValueError):
            parse_scanners(" , , ")

    def test_every_registered_scanner_is_selectable(self):
        names = ",".join(spec.name for spec in SCANNERS)
        self.assertEqual(
            [s.name for s in parse_scanners(names)],
            [spec.name for spec in SCANNERS],
        )


class BuildMatrixTest(unittest.TestCase):
    """Tests for compute_scan_matrix.build_matrix."""

    def test_emits_one_entry_per_scanner(self):
        entries = json.loads(build_matrix(list(SCANNERS)))
        self.assertEqual(len(entries), len(SCANNERS))

    def test_entry_carries_everything_the_workflow_needs(self):
        entries = json.loads(build_matrix(parse_scanners("gitleaks")))
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
        self.assertIsInstance(json.loads(build_matrix(list(SCANNERS))), list)

    def test_runner_labels_are_pinned_not_latest(self):
        for spec in SCANNERS:
            self.assertNotIn("latest", spec.runner)

    def test_modules_are_importable(self):
        for spec in SCANNERS:
            __import__(spec.module)


class MainTest(unittest.TestCase):
    """Tests for compute_scan_matrix.main."""

    def test_sets_matrix_output(self):
        with mock.patch(
            "security_scanners.utils.compute_scan_matrix.gha_set_output"
        ) as set_output:
            self.assertEqual(main(["--scanners", "zizmor"]), 0)
        entries = json.loads(set_output.call_args.args[0]["matrix"])
        self.assertEqual([e["scanner"] for e in entries], ["zizmor"])

    def test_defaults_to_every_scanner(self):
        with mock.patch(
            "security_scanners.utils.compute_scan_matrix.gha_set_output"
        ) as set_output:
            self.assertEqual(main([]), 0)
        entries = json.loads(set_output.call_args.args[0]["matrix"])
        self.assertEqual(
            [e["scanner"] for e in entries],
            [spec.name for spec in SCANNERS],
        )

    def test_unknown_scanner_fails_without_setting_output(self):
        with mock.patch(
            "security_scanners.utils.compute_scan_matrix.gha_set_output"
        ) as set_output:
            self.assertEqual(main(["--scanners", "semgrep"]), 1)
        set_output.assert_not_called()


if __name__ == "__main__":
    unittest.main()
