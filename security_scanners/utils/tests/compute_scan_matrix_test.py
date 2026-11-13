# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import json
import os
import unittest
from unittest import mock

from security_scanners.utils.compute_scan_matrix import (
    MAX_TIMEOUT_MINUTES,
    SCANNERS,
    TRIVY_IMAGE_TIMEOUT_MINUTES,
    build_matrix,
    main,
)
from security_scanners.utils.trivy_targets import TrivyImageTarget, TrivyPlan


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
                "name": "gitleaks",
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

    def test_default_trivy_leg_scans_the_filesystem(self):
        (trivy,) = [
            e for e in json.loads(build_matrix(SCANNERS)) if e["name"] == "trivy"
        ]
        self.assertEqual(trivy["trivy_scan_type"], "filesystem")


class TrivyLegsTest(unittest.TestCase):
    """Tests for the Trivy filesystem and per-image legs."""

    _IMAGE = TrivyImageTarget(
        name="trivy-image-rocm-dev",
        dockerfile="docker/Dockerfile",
        image="rocm-dev:scan",
        build_commands="./build.sh",
    )

    def _trivy_entries(self, plan: TrivyPlan, timeout: int = 0) -> list[dict]:
        entries = json.loads(build_matrix(SCANNERS, timeout, plan))
        return [e for e in entries if e["scanner"] == "trivy"]

    def test_each_image_gets_its_own_leg_beside_the_filesystem_leg(self):
        entries = self._trivy_entries(TrivyPlan(filesystem=True, images=(self._IMAGE,)))
        self.assertEqual(
            entries[1],
            {
                "name": "trivy-image-rocm-dev",
                "scanner": "trivy",
                "module": "security_scanners.github_actions.trivy",
                "timeout_minutes": TRIVY_IMAGE_TIMEOUT_MINUTES,
                "runner": "ubuntu-24.04",
                "trivy_scan_type": "image",
                "trivy_image": "rocm-dev:scan",
                "trivy_dockerfile": "docker/Dockerfile",
                "trivy_build_commands": "./build.sh",
            },
        )
        self.assertEqual(entries[0]["name"], "trivy")

    def test_image_only_drops_the_filesystem_leg(self):
        entries = self._trivy_entries(
            TrivyPlan(filesystem=False, images=(self._IMAGE,))
        )
        self.assertEqual([e["name"] for e in entries], ["trivy-image-rocm-dev"])

    def test_a_caller_timeout_raises_image_legs_too(self):
        entries = self._trivy_entries(
            TrivyPlan(images=(self._IMAGE,)), timeout=MAX_TIMEOUT_MINUTES
        )
        self.assertEqual({e["timeout_minutes"] for e in entries}, {MAX_TIMEOUT_MINUTES})

    def test_workflow_inputs_arrive_through_the_environment(self):
        env = {
            "SCANNER_TRIVY_SCAN_TYPE": "filesystem,image",
            "SCANNER_TRIVY_IMAGES": "- dockerfile: Dockerfile\n",
        }
        with (
            mock.patch.dict(os.environ, env),
            mock.patch(
                "security_scanners.utils.compute_scan_matrix.gha_set_output"
            ) as set_output,
        ):
            self.assertEqual(main([]), 0)
        entries = json.loads(set_output.call_args.args[0]["matrix"])
        self.assertIn("trivy", [e["name"] for e in entries])
        self.assertIn("trivy-image-dockerfile", [e["name"] for e in entries])

    def test_invalid_trivy_inputs_fail_planning(self):
        with mock.patch.dict(
            os.environ, {"SCANNER_TRIVY_SCAN_TYPE": "image", "SCANNER_TRIVY_IMAGES": ""}
        ):
            with self.assertRaises(SystemExit):
                main([])


class TimeoutBudgetTest(unittest.TestCase):
    """Tests for the caller-raisable scanner timeout."""

    def _timeouts(self, argv: list[str]) -> dict[str, int]:
        with mock.patch(
            "security_scanners.utils.compute_scan_matrix.gha_set_output"
        ) as set_output:
            self.assertEqual(main(argv), 0)
        entries = json.loads(set_output.call_args.args[0]["matrix"])
        return {e["name"]: e["timeout_minutes"] for e in entries}

    def test_defaults_leave_every_scanner_on_its_own_budget(self):
        self.assertEqual(
            self._timeouts([]),
            {spec.name: spec.timeout_minutes for spec in SCANNERS},
        )

    def test_a_larger_request_raises_every_smaller_budget(self):
        # The rocm-libraries case: a repository too large to scan in the
        # default budget asks for more, and gets it.
        timeouts = self._timeouts(["--timeout-minutes", "120"])
        self.assertEqual(set(timeouts.values()), {120})

    def test_a_smaller_request_never_lowers_a_scanner(self):
        # A caller can say its repository needs longer, but not that a
        # scanner needs less room than the baseline gives it.
        smallest = min(spec.timeout_minutes for spec in SCANNERS)
        timeouts = self._timeouts(["--timeout-minutes", str(smallest - 5)])
        self.assertEqual(
            timeouts, {spec.name: spec.timeout_minutes for spec in SCANNERS}
        )

    def test_a_request_between_budgets_raises_only_the_smaller_ones(self):
        budgets = sorted({spec.timeout_minutes for spec in SCANNERS})
        self.assertGreater(len(budgets), 1, "expected scanners to differ")
        requested = budgets[-1]
        timeouts = self._timeouts(["--timeout-minutes", str(requested)])
        for spec in SCANNERS:
            with self.subTest(scanner=spec.name):
                self.assertEqual(timeouts[spec.name], requested)

    def test_the_workflow_input_arrives_through_the_environment(self):
        with mock.patch.dict(os.environ, {"SCANNER_TIMEOUT_MINUTES": "90"}):
            self.assertEqual(set(self._timeouts([]).values()), {90})

    def test_an_unset_workflow_input_is_treated_as_no_request(self):
        # `type: number` inputs arrive as an empty string when a caller
        # omits them from a `with:` block it built dynamically.
        with mock.patch.dict(os.environ, {"SCANNER_TIMEOUT_MINUTES": ""}):
            self.assertEqual(
                self._timeouts([]),
                {spec.name: spec.timeout_minutes for spec in SCANNERS},
            )

    def test_beyond_githubs_own_limit_is_rejected(self):
        # Silently accepting it would promise a budget the runner kills.
        with self.assertRaises(SystemExit):
            main(["--timeout-minutes", str(MAX_TIMEOUT_MINUTES + 1)])

    def test_a_negative_request_is_rejected(self):
        with self.assertRaises(SystemExit):
            main(["--timeout-minutes", "-1"])

    def test_a_non_integer_request_is_rejected_without_a_traceback(self):
        with mock.patch.dict(os.environ, {"SCANNER_TIMEOUT_MINUTES": "20.5"}):
            with self.assertRaises(SystemExit):
                main([])


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
