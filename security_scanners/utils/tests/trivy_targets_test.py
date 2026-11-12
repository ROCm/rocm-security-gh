# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import unittest

from security_scanners.utils.trivy_targets import (
    TrivyImageTarget,
    TrivyPlan,
    TrivyTargetError,
    parse_image_targets,
    parse_scan_types,
    plan_trivy,
    validate_image_reference,
)


class ParseScanTypesTest(unittest.TestCase):
    def test_accepts_both_targets_in_any_case_and_spacing(self):
        self.assertEqual(
            parse_scan_types(" Image , filesystem,"), {"filesystem", "image"}
        )

    def test_rejects_an_unknown_target(self):
        with self.assertRaisesRegex(TrivyTargetError, "'repo'"):
            parse_scan_types("filesystem,repo")

    def test_rejects_an_empty_value(self):
        with self.assertRaises(TrivyTargetError):
            parse_scan_types(" , ")


class ValidateImageReferenceTest(unittest.TestCase):
    def test_strips_outer_whitespace(self):
        self.assertEqual(validate_image_reference(" alpine:3.20 "), "alpine:3.20")

    def test_accepts_a_registry_digest(self):
        reference = "registry.example.com/team/app@sha256:" + "a" * 64
        self.assertEqual(validate_image_reference(reference), reference)

    def test_rejects_invalid_references(self):
        for reference in ("", "  ", "app latest", "--output=x", "-app", "app;id"):
            with self.subTest(reference=reference):
                with self.assertRaises(TrivyTargetError):
                    validate_image_reference(reference)


class ParseImageTargetsTest(unittest.TestCase):
    def test_empty_input_lists_no_images(self):
        self.assertEqual(parse_image_targets(""), ())
        self.assertEqual(parse_image_targets("  \n"), ())

    def test_defaults_name_and_image_from_the_dockerfile(self):
        (target,) = parse_image_targets("- dockerfile: ./docker/Dockerfile.ubuntu\n")
        self.assertEqual(
            target,
            TrivyImageTarget(
                name="trivy-image-docker-dockerfile-ubuntu",
                dockerfile="docker/Dockerfile.ubuntu",
                image="security-scan/docker-dockerfile-ubuntu:ci",
            ),
        )

    def test_keeps_explicit_fields(self):
        (target,) = parse_image_targets(
            "- dockerfile: Dockerfile\n"
            "  name: rocm-dev\n"
            "  image: rocm-dev:scan\n"
            "  build_commands: |\n"
            '    ./build.sh "$SCANNER_TRIVY_IMAGE"\n'
        )
        self.assertEqual(
            target,
            TrivyImageTarget(
                name="trivy-image-rocm-dev",
                dockerfile="Dockerfile",
                image="rocm-dev:scan",
                build_commands='./build.sh "$SCANNER_TRIVY_IMAGE"',
            ),
        )

    def test_shared_dockerfile_needs_distinct_names(self):
        with self.assertRaisesRegex(TrivyTargetError, "duplicate"):
            parse_image_targets("- dockerfile: Dockerfile\n- dockerfile: Dockerfile\n")
        targets = parse_image_targets(
            "- {dockerfile: Dockerfile, name: a}\n- {dockerfile: Dockerfile, name: b}\n"
        )
        self.assertEqual([t.name for t in targets], ["trivy-image-a", "trivy-image-b"])

    def test_rejects_invalid_entries(self):
        cases = {
            "not a list": "dockerfile: Dockerfile\n",
            "not a mapping": "- Dockerfile\n",
            "missing dockerfile": "- image: app:ci\n",
            "absolute dockerfile": "- dockerfile: /etc/Dockerfile\n",
            "escaping dockerfile": "- dockerfile: ../other/Dockerfile\n",
            "unknown key": "- dockerfile: Dockerfile\n  context: .\n",
            "bad name": "- dockerfile: Dockerfile\n  name: Bad_Name\n",
            "bad image": "- dockerfile: Dockerfile\n  image: '-x'\n",
            "non-string build": "- dockerfile: Dockerfile\n  build_commands: [a]\n",
            "invalid yaml": "- dockerfile: [\n",
        }
        for label, raw in cases.items():
            with self.subTest(label):
                with self.assertRaises(TrivyTargetError):
                    parse_image_targets(raw)


class PlanTrivyTest(unittest.TestCase):
    def test_default_is_the_filesystem_scan_alone(self):
        self.assertEqual(plan_trivy("filesystem", ""), TrivyPlan())

    def test_both_targets(self):
        plan = plan_trivy("filesystem,image", "- dockerfile: Dockerfile\n")
        self.assertTrue(plan.filesystem)
        self.assertEqual([t.name for t in plan.images], ["trivy-image-dockerfile"])

    def test_image_alone(self):
        plan = plan_trivy("image", "- dockerfile: Dockerfile\n")
        self.assertFalse(plan.filesystem)
        self.assertEqual(len(plan.images), 1)

    def test_image_type_without_images_is_rejected(self):
        with self.assertRaisesRegex(TrivyTargetError, "no images"):
            plan_trivy("filesystem,image", "")

    def test_images_without_the_image_type_are_rejected(self):
        with self.assertRaisesRegex(TrivyTargetError, "does not include 'image'"):
            plan_trivy("filesystem", "- dockerfile: Dockerfile\n")


if __name__ == "__main__":
    unittest.main()
