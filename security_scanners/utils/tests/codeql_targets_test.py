# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import tempfile
import unittest
from pathlib import Path

from security_scanners.utils.codeql_targets import (
    MAX_TARGETS,
    CodeqlTarget,
    TargetsError,
    load_targets,
    minimal_scopes,
    normalize_repo_path,
    parse_targets,
    path_in_scope,
    target_from_build_inputs,
)

DIGEST = "sha256:" + "a" * 64
IMAGE = f"example/builder:7.2@{DIGEST}"

MINIMAL = """
[[target]]
name = "app-build"
language = "c-cpp"
scope = ["src/app/"]
build_command = "make -C src/app"
"""


class NormalizeRepoPathTest(unittest.TestCase):
    def test_equivalent_spellings_normalise_alike(self):
        for raw in (
            "src/app",
            "src/app/",
            "./src//app",
            " src/app ",
        ):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_repo_path(raw, what="p"), "src/app")

    def test_dot_names_the_whole_repository(self):
        self.assertEqual(normalize_repo_path("./", what="p"), ".")

    def test_refuses_paths_that_leave_the_repository(self):
        for raw in ("/etc", "..", "../x", "a/../../x"):
            with self.subTest(raw=raw), self.assertRaises(TargetsError):
                normalize_repo_path(raw, what="p")

    def test_refuses_globs_rather_than_matching_nothing(self):
        for raw in ("src/**", "src/*.cpp", "src/[ab]", "src/{a,b}", "a?"):
            with self.subTest(raw=raw), self.assertRaises(TargetsError):
                normalize_repo_path(raw, what="p")

    def test_refuses_empty_and_non_posix_paths(self):
        for raw in ("", "   ", "a\\b", "a\nb"):
            with self.subTest(raw=raw), self.assertRaises(TargetsError):
                normalize_repo_path(raw, what="p")


class PathInScopeTest(unittest.TestCase):
    def test_matches_on_whole_segments(self):
        self.assertTrue(path_in_scope("src/app/a.cpp", "src/app"))
        self.assertTrue(path_in_scope("src/app", "src/app"))
        self.assertFalse(path_in_scope("src/app_other/a.cpp", "src/app"))
        self.assertFalse(path_in_scope("projects/hr", "src/app"))

    def test_dot_holds_everything(self):
        self.assertTrue(path_in_scope("a/b.c", "."))


class MinimalScopesTest(unittest.TestCase):
    def test_drops_nested_scopes_and_duplicates(self):
        self.assertEqual(
            minimal_scopes(["a/b", "a", "c", "a", "a/b/c", "ab"]), ("a", "ab", "c")
        )

    def test_dot_swallows_the_rest(self):
        self.assertEqual(minimal_scopes(["a", ".", "b"]), (".",))


class ParseTargetsTest(unittest.TestCase):
    def test_minimal_target_gets_conservative_defaults(self):
        (target,) = parse_targets(MINIMAL)
        self.assertEqual(
            target,
            CodeqlTarget(
                name="app-build",
                language="c-cpp",
                scope=("src/app",),
                build_command="make -C src/app",
            ),
        )
        self.assertFalse(target.fail_on_findings)
        self.assertEqual(target.container, "")

    def test_every_option_is_read(self):
        (target,) = parse_targets(
            f"""
            [[target]]
            name = "t.1_x"
            language = "c-cpp"
            scope = ["a", "b/"]
            container = "{IMAGE}"
            build_command = '''
            cmake -S . -B build
            cmake --build build
            '''
            trigger_paths = [".github/scripts/build.sh", "cmake"]
            sparse_checkout = ["third_party/", "cmake"]
            timeout_minutes = 240
            fail_on_findings = true
            """
        )
        self.assertEqual(target.scope, ("a", "b"))
        self.assertEqual(target.container, IMAGE)
        self.assertEqual(target.trigger_paths, (".github/scripts/build.sh", "cmake"))
        self.assertEqual(target.sparse_checkout, ("third_party", "cmake"))
        self.assertEqual(target.timeout_minutes, 240)
        self.assertTrue(target.fail_on_findings)
        self.assertIn("cmake --build build", target.build_command)

    def test_several_targets(self):
        targets = parse_targets(MINIMAL + MINIMAL.replace("app-build", "app-other"))
        self.assertEqual([t.name for t in targets], ["app-build", "app-other"])

    def test_duplicate_names_are_refused(self):
        with self.assertRaisesRegex(TargetsError, "duplicate"):
            parse_targets(MINIMAL + MINIMAL)

    def test_an_unknown_key_is_refused_so_a_typo_cannot_do_nothing(self):
        with self.assertRaisesRegex(TargetsError, "unknown key"):
            parse_targets(MINIMAL + "fail_on_finding = true\n")

    def test_an_unknown_top_level_key_is_refused(self):
        with self.assertRaisesRegex(TargetsError, "top-level"):
            parse_targets(MINIMAL + '[targets]\nname = "x"\n')

    def test_required_keys(self):
        for key in ("name", "language", "scope", "build_command"):
            text = "\n".join(
                line for line in MINIMAL.splitlines() if not line.startswith(f"{key} =")
            )
            with self.subTest(key=key), self.assertRaisesRegex(TargetsError, key):
                parse_targets(text)

    def test_no_targets_is_refused(self):
        for text in ("", "# nothing\n"):
            with self.subTest(text=text), self.assertRaisesRegex(
                TargetsError, "no targets"
            ):
                parse_targets(text)

    def test_too_many_targets_are_refused(self):
        text = "".join(
            MINIMAL.replace("app-build", f"t{i}") for i in range(MAX_TARGETS + 1)
        )
        with self.assertRaisesRegex(TargetsError, "at most"):
            parse_targets(text)

    def test_malformed_toml_is_refused(self):
        with self.assertRaisesRegex(TargetsError, "not valid TOML"):
            parse_targets("[[target]\n")

    def test_names_that_cannot_be_artifact_names_are_refused(self):
        for name in ("", "-lead", "has space", "a/b", "x" * 49, "über"):
            with self.subTest(name=name), self.assertRaises(TargetsError):
                parse_targets(MINIMAL.replace("app-build", name))

    def test_only_c_cpp_is_supported(self):
        with self.assertRaisesRegex(TargetsError, "not supported"):
            parse_targets(MINIMAL.replace("c-cpp", "go"))

    def test_scope_must_name_something(self):
        with self.assertRaisesRegex(TargetsError, "at least one"):
            parse_targets(MINIMAL.replace('["src/app/"]', "[]"))

    def test_scope_must_be_a_list_of_strings(self):
        for value in ('"src/app"', "[1]", "[['a']]"):
            with self.subTest(value=value), self.assertRaisesRegex(
                TargetsError, "list of strings"
            ):
                parse_targets(MINIMAL.replace('["src/app/"]', value))

    def test_a_container_has_to_be_pinned_by_digest(self):
        for image in (
            "example/builder:7.2",
            "example/builder@sha256:abc",
            f"x y@{DIGEST}",
            f"-x@{DIGEST}",
        ):
            with self.subTest(image=image), self.assertRaisesRegex(
                TargetsError, "digest"
            ):
                parse_targets(MINIMAL + f'container = "{image}"\n')

    def test_sparse_checkout_is_a_list_of_directories(self):
        with self.assertRaisesRegex(TargetsError, "list of strings"):
            parse_targets(MINIMAL + 'sparse_checkout = "a"\n')
        with self.assertRaises(TargetsError):
            parse_targets(MINIMAL + 'sparse_checkout = ["a/*"]\n')

    def test_sparse_checkout_cannot_be_combined_with_the_whole_repository(self):
        for text in (
            MINIMAL.replace('["src/app/"]', '["."]') + 'sparse_checkout = ["a"]\n',
            MINIMAL + 'sparse_checkout = ["."]\n',
        ):
            with self.subTest(text=text), self.assertRaisesRegex(
                TargetsError, "whole repository"
            ):
                parse_targets(text)

    def test_an_empty_sparse_checkout_means_a_full_checkout(self):
        (target,) = parse_targets(MINIMAL + "sparse_checkout = []\n")
        self.assertEqual(target.sparse_checkout, ())

    def test_timeout_is_a_bounded_integer(self):
        for value in ("-1", "99999", '"60"', "true", "1.5"):
            with self.subTest(value=value), self.assertRaisesRegex(
                TargetsError, "timeout_minutes"
            ):
                parse_targets(MINIMAL + f"timeout_minutes = {value}\n")

    def test_fail_on_findings_is_a_boolean(self):
        with self.assertRaisesRegex(TargetsError, "true or false"):
            parse_targets(MINIMAL + 'fail_on_findings = "yes"\n')


class LoadTargetsTest(unittest.TestCase):
    def test_reads_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.toml"
            path.write_text(MINIMAL, encoding="utf-8")
            self.assertEqual(load_targets(path)[0].name, "app-build")

    def test_a_missing_or_undecodable_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(TargetsError, "cannot read"):
                load_targets(Path(tmp) / "missing.toml")
            binary = Path(tmp) / "binary.toml"
            binary.write_bytes(b"\xff\xfe\x00")
            with self.assertRaisesRegex(TargetsError, "cannot read"):
                load_targets(binary)


class TargetFromBuildInputsTest(unittest.TestCase):
    def test_no_mode_or_none_describes_no_target(self):
        for mode in ("", "none", " none "):
            with self.subTest(mode=mode):
                self.assertIsNone(target_from_build_inputs(build_mode=mode))

    def test_manual_describes_a_c_cpp_target_over_the_whole_repository(self):
        target = target_from_build_inputs(build_mode="manual", build_command="make")
        self.assertEqual(
            target,
            CodeqlTarget(
                name="c-cpp", language="c-cpp", scope=(".",), build_command="make"
            ),
        )

    def test_every_input_is_carried_over(self):
        target = target_from_build_inputs(
            build_mode="manual",
            build_command="make -j",
            container=IMAGE,
            scope="src/app/\n\n tools \n",
            sparse_checkout="third_party",
            trigger_paths="scripts/build.sh",
            fail_on_findings=True,
        )
        self.assertEqual(target.scope, ("src/app", "tools"))
        self.assertEqual(target.container, IMAGE)
        self.assertEqual(target.sparse_checkout, ("third_party",))
        self.assertEqual(target.trigger_paths, ("scripts/build.sh",))
        self.assertTrue(target.fail_on_findings)

    def test_an_unknown_mode_is_refused(self):
        for mode in ("autobuild", "Manual", "true"):
            with self.subTest(mode=mode), self.assertRaisesRegex(
                TargetsError, "not one of"
            ):
                target_from_build_inputs(build_mode=mode)

    def test_manual_needs_a_build_command(self):
        for command in ("", "  \n"):
            with self.subTest(command=command), self.assertRaisesRegex(
                TargetsError, "needs a build command"
            ):
                target_from_build_inputs(build_mode="manual", build_command=command)

    def test_build_inputs_without_manual_are_refused_not_ignored(self):
        for field in (
            {"build_command": "make"},
            {"container": IMAGE},
            {"scope": "src"},
            {"sparse_checkout": "src"},
            {"trigger_paths": "src"},
            {"fail_on_findings": True},
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                TargetsError, "need build mode"
            ):
                target_from_build_inputs(build_mode="none", **field)

    def test_invalid_inputs_are_refused_like_the_targets_file(self):
        with self.assertRaisesRegex(TargetsError, "digest"):
            target_from_build_inputs(
                build_mode="manual", build_command="make", container="img:1"
            )
        with self.assertRaises(TargetsError):
            target_from_build_inputs(
                build_mode="manual", build_command="make", scope="../x"
            )


if __name__ == "__main__":
    unittest.main()
