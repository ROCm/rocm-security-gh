# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError, URLError

from security_scanners.utils.compute_codeql_matrix import (
    DEFAULT_TIMEOUT_MINUTES,
    DETECTION_LANGUAGES_AND_CHANGED_FILES,
    DETECTION_LANGUAGES_AND_TREE,
    DETECTION_LANGUAGES_ONLY,
    DETECTION_PRIVATE_REPOSITORY_POLICY,
    DETECTION_TREE_ONLY,
    MAX_BUILDLESS_CPP_FILES,
    ChangedFiles,
    CodeqlPlan,
    Discovery,
    DiscoveryError,
    TargetPlan,
    _github_get,
    build_plan,
    count_cpp_files,
    count_scope_cpp_files,
    discover,
    languages_from_paths,
    main,
    plan_targets,
    render_summary,
    render_targets_summary,
    resolve_timeout,
    touches_actions,
)
from security_scanners.utils.codeql_targets import CodeqlTarget, TargetsError


def _tree(paths: list[str], truncated: bool = False) -> dict[str, object]:
    return {
        "tree": [{"path": path, "type": "blob"} for path in paths],
        "truncated": truncated,
    }


class FakeApi:
    """A stand-in for the GitHub REST API, recording what was asked for."""

    def __init__(
        self,
        *,
        languages: dict[str, int] | None = None,
        tree: dict[str, object] | None = None,
        pull_files: list[list[dict[str, str]]] | None = None,
        subtrees: dict[str, dict[str, object]] | None = None,
    ):
        self._languages = languages
        self._tree = tree
        self._pull_files = pull_files or []
        # Directory -> its tree. A directory that isn't here is a 404.
        self._subtrees = subtrees or {}
        self.paths_requested: list[str] = []

    def __call__(self, path: str) -> object:
        self.paths_requested.append(path)
        if "/languages" in path:
            if self._languages is None:
                raise DiscoveryError("languages unavailable")
            return self._languages
        if "/git/trees/" in path:
            ref = path.split("/git/trees/", 1)[1].split("?", 1)[0]
            if ":" in ref:
                directory = ref.split(":", 1)[1]
                if directory not in self._subtrees:
                    raise HTTPError(path, 404, "Not Found", None, None)  # type: ignore[arg-type]
                return self._subtrees[directory]
            if self._tree is None:
                raise DiscoveryError("tree unavailable")
            return self._tree
        if "/pulls/" in path:
            page = int(path.rsplit("page=", 1)[1])
            if page - 1 < len(self._pull_files):
                return self._pull_files[page - 1]
            return []
        raise AssertionError(f"unexpected API path: {path}")


class LanguagesFromPathsTest(unittest.TestCase):
    """Tests for the file-extension evidence."""

    def test_recognises_the_languages_codeql_reads_from_source(self):
        found = languages_from_paths(
            [
                "src/main.c",
                "include/api.hpp",
                "app/Program.cs",
                "src/Main.java",
                "web/app.tsx",
                "tools/build.py",
                "lib/thing.rb",
            ]
        )
        self.assertEqual(
            found,
            {
                "c-cpp",
                "csharp",
                "java-kotlin",
                "javascript-typescript",
                "python",
                "ruby",
            },
        )

    def test_rust_needs_a_cargo_project(self):
        # CodeQL's Rust extractor reads a Cargo project, so a loose .rs
        # file is not something it can analyse.
        self.assertEqual(languages_from_paths(["src/lib.rs"]), set())
        self.assertEqual(languages_from_paths(["Cargo.toml", "src/lib.rs"]), {"rust"})
        self.assertEqual(
            languages_from_paths(["rust-project.json", "src/lib.rs"]), {"rust"}
        )

    def test_ignores_files_no_extractor_reads(self):
        self.assertEqual(
            languages_from_paths(
                [
                    "README.md",
                    "CMakeLists.txt",
                    "build.sh",
                    "kernels/gemm.hip",
                    "kernels/gemm.cu",
                ]
            ),
            set(),
        )

    def test_counts_only_recognised_c_cpp_sources_and_headers(self):
        self.assertEqual(
            count_cpp_files(
                [
                    "src/main.c",
                    "src/api.hpp",
                    "kernels/gemm.hip",
                    "kernels/gemm.cu",
                    "tools/build.py",
                ]
            ),
            2,
        )


class BuildPlanTest(unittest.TestCase):
    """Tests for the language policy."""

    def test_python_from_github_languages(self):
        plan = build_plan(
            Discovery(
                linguist_languages=("Python",),
                linguist_available=True,
                paths=("tools/build.py",),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions", "python"))
        self.assertEqual(plan.detection_source, DETECTION_LANGUAGES_AND_TREE)

    def test_c_and_cpp_collapse_to_one_language(self):
        plan = build_plan(
            Discovery(
                linguist_languages=("C", "C++"),
                linguist_available=True,
                paths=("a.c", "b.cpp"),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions", "c-cpp"))

    def test_c_cpp_at_the_standard_runner_limit_is_selected(self):
        paths = tuple(
            f"src/file_{index}.cpp" for index in range(MAX_BUILDLESS_CPP_FILES)
        )
        plan = build_plan(
            Discovery(
                linguist_languages=("C++",),
                linguist_available=True,
                paths=paths,
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions", "c-cpp"))

    def test_c_cpp_over_the_standard_runner_limit_is_skipped(self):
        paths = tuple(
            f"src/file_{index}.cpp" for index in range(MAX_BUILDLESS_CPP_FILES + 1)
        )
        plan = build_plan(
            Discovery(
                linguist_languages=("C++",),
                linguist_available=True,
                paths=paths,
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions",))
        self.assertIn(
            f"c-cpp ({MAX_BUILDLESS_CPP_FILES + 1:,} C/C++ files exceeds the "
            f"{MAX_BUILDLESS_CPP_FILES:,}-file standard-runner limit)",
            plan.skipped,
        )

    def test_the_exact_tree_finds_a_language_github_has_not_counted_yet(self):
        # Linguist statistics only refresh after a push to the default
        # branch, so a pull request adding a language is invisible to it.
        plan = build_plan(
            Discovery(
                linguist_languages=("Python",),
                linguist_available=True,
                paths=("tools/build.py", "web/app.ts"),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions", "javascript-typescript", "python"))

    def test_changed_files_find_a_language_when_the_tree_is_truncated(self):
        plan = build_plan(
            Discovery(
                linguist_languages=("C++",),
                linguist_available=True,
                paths=("bindings/app.py",),
                path_source="changed-files",
                tree_truncated=True,
            )
        )
        self.assertEqual(plan.selected, ("actions", "python"))
        self.assertEqual(plan.detection_source, DETECTION_LANGUAGES_AND_CHANGED_FILES)
        self.assertTrue(plan.tree_truncated)
        self.assertTrue(
            any("file count is unavailable" in item for item in plan.skipped)
        )

    def test_a_truncated_tree_outside_a_pull_request_uses_github_languages(self):
        plan = build_plan(
            Discovery(
                linguist_languages=("Python",),
                linguist_available=True,
                tree_truncated=True,
            )
        )
        self.assertEqual(plan.selected, ("actions", "python"))
        self.assertEqual(plan.detection_source, DETECTION_LANGUAGES_ONLY)

    def test_actions_is_selected_without_any_yaml_evidence(self):
        # A repository calling this workflow necessarily has a workflow
        # file in the commit under scan, and Linguist calls workflows
        # YAML rather than Actions, so this needs no discovery.
        plan = build_plan(
            Discovery(
                linguist_languages=(),
                linguist_available=True,
                paths=("README.md",),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions",))

    def test_ordinary_yaml_does_not_stand_in_for_a_language(self):
        plan = build_plan(
            Discovery(
                linguist_languages=("YAML",),
                linguist_available=True,
                paths=("config/values.yaml",),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions",))

    def test_build_required_languages_are_reported_and_excluded(self):
        plan = build_plan(
            Discovery(
                linguist_languages=("Go", "Swift", "Python"),
                linguist_available=True,
                paths=("main.go", "App.swift", "tool.py"),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions", "python"))
        self.assertEqual(plan.skipped, ("Go (needs a build)", "Swift (needs a build)"))

    def test_java_alone_is_analysed(self):
        plan = build_plan(
            Discovery(
                linguist_languages=("Java",),
                linguist_available=True,
                paths=("src/Main.java",),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions", "java-kotlin"))
        self.assertEqual(plan.skipped, ())

    def test_java_with_kotlin_analyses_java_and_says_kotlin_is_not_covered(self):
        # build-mode: none analyses the Java and warns that it skipped
        # the Kotlin, so the summary has to say so too.
        plan = build_plan(
            Discovery(
                linguist_languages=("Java", "Kotlin"),
                linguist_available=True,
                paths=("src/Main.java", "src/Main.kt"),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions", "java-kotlin"))
        self.assertEqual(
            plan.skipped, ("Kotlin (needs a build (Java is still analysed))",)
        )

    def test_kotlin_alone_selects_nothing_to_analyse(self):
        plan = build_plan(
            Discovery(
                linguist_languages=("Kotlin",),
                linguist_available=True,
                paths=("src/Main.kt",),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions",))
        self.assertEqual(
            plan.skipped, ("Kotlin (needs a build (Java is still analysed))",)
        )

    def test_hip_and_cuda_are_reported_as_unread(self):
        # ROCm repositories are full of these and CodeQL has no
        # extractor for either, so silence would read as "clean".
        plan = build_plan(
            Discovery(
                linguist_languages=("HIP", "Cuda"),
                linguist_available=True,
                paths=("kernels/gemm.hip",),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions",))
        self.assertEqual(
            plan.skipped,
            ("Cuda (no CodeQL extractor)", "HIP (no CodeQL extractor)"),
        )

    def test_the_tree_overrules_github_languages_for_c_cpp(self):
        # Linguist counts .hip and .cu as C++, but CodeQL's C/C++
        # extractor doesn't read them: initialising c-cpp for a
        # repository with no C/C++ files it recognises fails the run
        # with "No source code was seen during the build".
        plan = build_plan(
            Discovery(
                linguist_languages=("C++",),
                linguist_available=True,
                paths=("kernels/gemm.hip", "tools/run.py"),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions", "python"))

    def test_c_cpp_is_skipped_without_an_exact_tree(self):
        # The standard runner only accepts buildless C/C++ when the
        # complete tree proves that the repository is within its file
        # ceiling.
        plan = build_plan(
            Discovery(
                linguist_languages=("C++",),
                linguist_available=True,
                tree_truncated=True,
            )
        )
        self.assertEqual(plan.selected, ("actions",))
        self.assertTrue(
            any("file count is unavailable" in item for item in plan.skipped)
        )

    def test_an_exact_tree_alone_is_enough(self):
        plan = build_plan(
            Discovery(
                paths=("tools/build.py",),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, ("actions", "python"))
        self.assertEqual(plan.detection_source, DETECTION_TREE_ONLY)

    def test_no_sources_at_all_fails_rather_than_scanning_nothing(self):
        with self.assertRaises(DiscoveryError):
            build_plan(Discovery())

    def test_no_languages_and_no_tree_fails_rather_than_guessing(self):
        # 'the repository has no code' and 'detection is broken' look
        # identical here, and one of them is a false clean run.
        with self.assertRaises(DiscoveryError):
            build_plan(
                Discovery(
                    linguist_languages=(),
                    linguist_available=True,
                    tree_truncated=True,
                )
            )

    def test_selection_is_sorted_so_check_names_are_stable(self):
        plan = build_plan(
            Discovery(
                linguist_languages=("Python", "Ruby", "C", "TypeScript"),
                linguist_available=True,
                paths=("a.c", "b.py", "c.rb", "d.ts"),
                path_source="exact-tree",
            )
        )
        self.assertEqual(plan.selected, tuple(sorted(plan.selected)))
        self.assertEqual(
            plan.selected,
            ("actions", "c-cpp", "javascript-typescript", "python", "ruby"),
        )


class ManuallyBuiltLanguageTest(unittest.TestCase):
    def _discovery(self, count: int = 3) -> Discovery:
        return Discovery(
            linguist_languages=("C++", "Python"),
            linguist_available=True,
            paths=tuple(_cpp("src", count) + ["tool.py"]),
            path_source="exact-tree",
        )

    def test_a_manually_built_language_is_left_out_and_says_so(self):
        plan = build_plan(self._discovery(), manually_built=frozenset({"c-cpp"}))
        self.assertEqual(plan.selected, ("actions", "python"))
        self.assertEqual(plan.skipped, ("c-cpp (analysed by its manual build)",))

    def test_the_file_limit_does_not_apply_to_a_language_it_no_longer_scans(self):
        plan = build_plan(
            self._discovery(MAX_BUILDLESS_CPP_FILES + 1),
            manually_built=frozenset({"c-cpp"}),
        )
        self.assertEqual(plan.skipped, ("c-cpp (analysed by its manual build)",))

    def test_a_language_the_repository_lacks_is_not_mentioned(self):
        discovery = Discovery(
            linguist_languages=("Python",),
            linguist_available=True,
            paths=("tool.py",),
            path_source="exact-tree",
        )
        plan = build_plan(discovery, manually_built=frozenset({"c-cpp"}))
        self.assertEqual(plan.skipped, ())

    def test_a_pull_request_note_does_not_contradict_the_manual_build(self):
        plan = build_plan(
            self._discovery(),
            restrict_to=ChangedFiles(("tool.py",)),
            manually_built=frozenset({"c-cpp"}),
        )
        self.assertIn("c-cpp (analysed by its manual build)", plan.skipped)
        self.assertFalse([n for n in plan.skipped if n.startswith("c-cpp (not")])


class ChangedModeRestrictionTest(unittest.TestCase):
    """Tests for narrowing a pull request to the languages it touches."""

    def _discovery(self) -> Discovery:
        return Discovery(
            linguist_languages=("C++", "Python", "Ruby"),
            linguist_available=True,
            paths=("src/a.cpp", "tools/b.py", "lib/c.rb"),
            path_source="exact-tree",
        )

    def test_only_the_touched_languages_are_analysed(self):
        # CodeQL can't analyse a file list, only a whole repository, so
        # narrowing happens per language: a docs-only pull request
        # against a monorepo shouldn't spend two hours building a C/C++
        # database its alerts can't come from.
        plan = build_plan(
            self._discovery(),
            restrict_to=ChangedFiles(paths=("tools/b.py",)),
        )
        self.assertEqual(plan.selected, ("python",))
        self.assertTrue(plan.restricted_to_changes)
        self.assertIn("c-cpp (not touched by this pull request)", plan.skipped)
        self.assertIn("ruby (not touched by this pull request)", plan.skipped)

    def test_actions_is_analysed_only_when_a_workflow_changes(self):
        plan = build_plan(
            self._discovery(),
            restrict_to=ChangedFiles(paths=(".github/workflows/ci.yml",)),
        )
        self.assertEqual(plan.selected, ("actions",))

    def test_a_touched_language_outside_the_repository_is_ignored(self):
        # A pull request adding the first Go file shouldn't conjure a
        # language the buildless policy excludes.
        plan = build_plan(
            self._discovery(), restrict_to=ChangedFiles(paths=("main.go",))
        )
        self.assertEqual(plan.selected, ())

    def test_a_documentation_only_pull_request_analyses_nothing(self):
        plan = build_plan(
            self._discovery(), restrict_to=ChangedFiles(paths=("README.md",))
        )
        self.assertEqual(plan.selected, ())

    def test_touching_rust_code_counts_without_touching_the_manifest(self):
        # The Cargo project is what makes Rust analysable at all, and
        # it's a property of the repository, not of the diff.
        discovery = Discovery(
            linguist_languages=("Rust",),
            linguist_available=True,
            paths=("Cargo.toml", "src/lib.rs"),
            path_source="exact-tree",
        )
        plan = build_plan(discovery, restrict_to=ChangedFiles(paths=("src/lib.rs",)))
        self.assertEqual(plan.selected, ("rust",))

    def test_an_incomplete_file_list_narrows_nothing(self):
        # GitHub stops listing at 3,000 files, and an unread file can't
        # be evidence that a language is untouched.
        plan = build_plan(
            self._discovery(),
            restrict_to=ChangedFiles(paths=("tools/b.py",), complete=False),
        )
        self.assertEqual(plan.selected, ("actions", "c-cpp", "python", "ruby"))
        self.assertFalse(plan.restricted_to_changes)
        self.assertTrue(any("incomplete" in w for w in plan.warnings))

    def test_the_summary_explains_why_a_language_is_missing(self):
        summary = render_summary(
            build_plan(
                self._discovery(), restrict_to=ChangedFiles(paths=("tools/b.py",))
            )
        )
        self.assertIn("Narrowed to the languages this pull request touches", summary)
        self.assertIn("c-cpp (not touched by this pull request)", summary)


class TouchesActionsTest(unittest.TestCase):
    """Tests for telling workflow files apart from ordinary YAML."""

    def test_recognises_what_the_actions_extractor_reads(self):
        self.assertTrue(touches_actions([".github/workflows/ci.yml"]))
        self.assertTrue(touches_actions([".github/workflows/ci.yaml"]))
        self.assertTrue(touches_actions(["action.yml"]))
        self.assertTrue(touches_actions([".github/actions/setup/action.yaml"]))

    def test_ignores_ordinary_yaml(self):
        self.assertFalse(touches_actions(["config/values.yaml"]))
        self.assertFalse(touches_actions([".github/dependabot.yml"]))
        self.assertFalse(touches_actions(["docs/workflows/example.yml"]))


class DiscoverTest(unittest.TestCase):
    """Tests for the API orchestration."""

    def test_uses_the_languages_endpoint_and_the_exact_tree(self):
        api = FakeApi(languages={"Python": 100}, tree=_tree(["tool.py"]))
        discovery = discover(api, repo="ROCm/x", sha="abc", event={})
        self.assertEqual(discovery.linguist_languages, ("Python",))
        self.assertEqual(discovery.paths, ("tool.py",))
        self.assertTrue(discovery.has_exact_tree)
        self.assertEqual(discovery.warnings, ())

    def test_planning_never_checks_out_the_repository(self):
        api = FakeApi(languages={"Python": 1}, tree=_tree(["tool.py"]))
        discovery = discover(api, repo="ROCm/x", sha="abc", event={})
        self.assertEqual(
            api.paths_requested,
            ["/repos/ROCm/x/languages", "/repos/ROCm/x/git/trees/abc?recursive=1"],
        )
        self.assertTrue(discovery.has_exact_tree)

    def test_a_truncated_tree_falls_back_to_a_pull_requests_files(self):
        api = FakeApi(
            languages={"C++": 1},
            tree=_tree(["a.cpp"], truncated=True),
            pull_files=[[{"filename": "new/app.py"}]],
        )
        discovery = discover(
            api,
            repo="ROCm/x",
            sha="abc",
            event={"pull_request": {"number": 7}},
        )
        self.assertEqual(discovery.path_source, "changed-files")
        self.assertEqual(discovery.paths, ("new/app.py",))
        self.assertTrue(discovery.tree_truncated)
        self.assertTrue(any("truncated" in w for w in discovery.warnings))

    def test_a_truncated_tree_discards_the_partial_file_list(self):
        # A partial tree would look like proof that a language is absent.
        api = FakeApi(languages={"C++": 1}, tree=_tree(["a.cpp"], truncated=True))
        discovery = discover(api, repo="ROCm/x", sha="abc", event={})
        self.assertEqual(discovery.paths, ())
        self.assertFalse(discovery.has_exact_tree)

    def test_pull_request_files_are_paginated(self):
        api = FakeApi(
            languages={"C++": 1},
            tree=_tree([], truncated=True),
            pull_files=[
                [{"filename": f"f{i}.py"} for i in range(100)],
                [{"filename": "last.ts"}],
            ],
        )
        discovery = discover(
            api, repo="ROCm/x", sha="abc", event={"pull_request": {"number": 7}}
        )
        self.assertEqual(len(discovery.paths), 101)
        self.assertIn("last.ts", discovery.paths)

    def test_a_failed_language_lookup_leaves_the_tree_in_charge(self):
        api = FakeApi(languages=None, tree=_tree(["tool.py"]))
        discovery = discover(api, repo="ROCm/x", sha="abc", event={})
        self.assertFalse(discovery.linguist_available)
        self.assertTrue(discovery.has_exact_tree)
        self.assertTrue(any("language API failed" in w for w in discovery.warnings))
        self.assertEqual(build_plan(discovery).detection_source, DETECTION_TREE_ONLY)

    def test_both_sources_failing_is_reported_as_a_failure(self):
        api = FakeApi(languages=None, tree=None)
        discovery = discover(api, repo="ROCm/x", sha="abc", event={})
        self.assertEqual(len(discovery.warnings), 2)
        with self.assertRaises(DiscoveryError):
            build_plan(discovery)


class GithubGetTest(unittest.TestCase):
    """Tests for the authenticated REST call."""

    def _response(self, payload: object):
        response = mock.MagicMock()
        response.read.return_value = json.dumps(payload).encode()
        response.__enter__.return_value = response
        return response

    def test_sends_the_token_and_api_version(self):
        with mock.patch(
            "security_scanners.utils.compute_codeql_matrix.urlopen"
        ) as urlopen:
            urlopen.return_value = self._response({"Python": 1})
            payload = _github_get(
                "/repos/ROCm/x/languages",
                token="t0ken",
                api_root="https://api.github.com",
            )
        request = urlopen.call_args.args[0]
        self.assertEqual(payload, {"Python": 1})
        self.assertEqual(request.get_header("Authorization"), "Bearer t0ken")
        self.assertEqual(request.get_header("X-github-api-version"), "2022-11-28")

    def test_refuses_a_non_https_api_root(self):
        with self.assertRaises(DiscoveryError):
            _github_get("/x", token="t", api_root="http://api.github.internal")

    def test_retries_a_transient_server_error(self):
        with (
            mock.patch(
                "security_scanners.utils.compute_codeql_matrix.urlopen"
            ) as urlopen,
            mock.patch("security_scanners.utils.compute_codeql_matrix.time.sleep"),
        ):
            urlopen.side_effect = [
                HTTPError("u", 503, "unavailable", {}, None),  # type: ignore[arg-type]
                self._response({"Python": 1}),
            ]
            payload = _github_get(
                "/repos/ROCm/x/languages",
                token="t",
                api_root="https://api.github.com",
            )
        self.assertEqual(payload, {"Python": 1})

    def test_gives_up_after_repeated_failures(self):
        with (
            mock.patch(
                "security_scanners.utils.compute_codeql_matrix.urlopen"
            ) as urlopen,
            mock.patch("security_scanners.utils.compute_codeql_matrix.time.sleep"),
        ):
            urlopen.side_effect = URLError("no route")
            with self.assertRaises(DiscoveryError):
                _github_get("/x", token="t", api_root="https://api.github.com")

    def test_does_not_retry_an_authentication_failure(self):
        with (
            mock.patch(
                "security_scanners.utils.compute_codeql_matrix.urlopen"
            ) as urlopen,
            mock.patch("security_scanners.utils.compute_codeql_matrix.time.sleep"),
        ):
            urlopen.side_effect = HTTPError("u", 401, "unauthorized", {}, None)  # type: ignore[arg-type]
            with self.assertRaises(HTTPError):
                _github_get("/x", token="t", api_root="https://api.github.com")
        self.assertEqual(urlopen.call_count, 1)


class MatrixAndSummaryTest(unittest.TestCase):
    """Tests for what the workflow and a reviewer receive."""

    def _plan(self, **overrides: object) -> CodeqlPlan:
        defaults: dict[str, object] = {
            "selected": ("actions", "python"),
            "skipped": (),
            "detection_source": DETECTION_LANGUAGES_AND_TREE,
            "tree_truncated": False,
            "warnings": (),
        }
        defaults.update(overrides)
        return CodeqlPlan(**defaults)  # type: ignore[arg-type]

    def test_matrix_is_shaped_for_strategy_matrix(self):
        matrix = json.loads(self._plan().matrix(120))
        self.assertEqual(
            matrix,
            {
                "include": [
                    {"language": "actions", "timeout_minutes": 120},
                    {"language": "python", "timeout_minutes": 120},
                ]
            },
        )

    def test_the_caller_can_only_raise_the_codeql_budget(self):
        self.assertEqual(resolve_timeout(0), DEFAULT_TIMEOUT_MINUTES)
        self.assertEqual(resolve_timeout(30), DEFAULT_TIMEOUT_MINUTES)
        self.assertEqual(resolve_timeout(240), 240)

    def test_summary_states_the_source_and_the_selection(self):
        summary = render_summary(self._plan())
        self.assertIn(DETECTION_LANGUAGES_AND_TREE, summary)
        self.assertIn("`actions`", summary)
        self.assertIn("`python`", summary)

    def test_summary_admits_an_incomplete_answer(self):
        summary = render_summary(
            self._plan(
                detection_source=DETECTION_LANGUAGES_AND_CHANGED_FILES,
                skipped=("Go (needs a build)",),
                tree_truncated=True,
                warnings=("the commit tree API failed (boom)",),
            )
        )
        self.assertIn("truncated", summary)
        self.assertIn("Go (needs a build)", summary)
        self.assertIn("the commit tree API failed (boom)", summary)


class MainTest(unittest.TestCase):
    """Tests for the step's outputs and exit codes."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._output = Path(self._tmp.name) / "output"
        self._summary = Path(self._tmp.name) / "summary"
        self._checkout_root = Path(self._tmp.name) / "scan-target"
        self._checkout_root.mkdir()
        self._env = {
            "GITHUB_REPOSITORY": "ROCm/x",
            "GITHUB_SHA": "abc",
            "GITHUB_TOKEN": "t0ken",
            "GITHUB_OUTPUT": str(self._output),
            "GITHUB_STEP_SUMMARY": str(self._summary),
            "GITHUB_EVENT_PATH": "",
            "SCANNER_CHECKOUT_ROOT": str(self._checkout_root),
            "SCANNER_CODEQL_CONFIG_PATH": "",
            "SCANNER_REPOSITORY_PRIVATE": "false",
            "SCANNER_TIMEOUT_MINUTES": "",
        }

    def _configure_codeql(self, config_path: str) -> None:
        target = self._checkout_root / config_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("paths-ignore: []\n", encoding="utf-8")
        self._env["SCANNER_CODEQL_CONFIG_PATH"] = config_path

    def _run(self, api: FakeApi) -> int:
        with (
            mock.patch.dict(os.environ, self._env, clear=False),
            mock.patch(
                "security_scanners.utils.compute_codeql_matrix._github_get",
                side_effect=lambda path, **kwargs: api(path),
            ),
        ):
            return main([])

    def _outputs(self) -> dict[str, str]:
        values: dict[str, str] = {}
        if not self._output.is_file():
            return values
        for line in self._output.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        return values

    def test_writes_every_output_the_workflow_reads(self):
        api = FakeApi(
            languages={"Python": 1, "Go": 1},
            tree=_tree(["tool.py", "main.go"]),
        )
        self.assertEqual(self._run(api), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["enabled"], "true")
        self.assertEqual(outputs["selected_languages"], "actions,python")
        self.assertEqual(outputs["skipped_languages"], "Go (needs a build)")
        self.assertEqual(outputs["detection_source"], DETECTION_LANGUAGES_AND_TREE)
        self.assertEqual(outputs["tree_truncated"], "false")
        self.assertEqual(outputs["config_path"], "")
        self.assertEqual(
            json.loads(outputs["matrix"])["include"][0],
            {"language": "actions", "timeout_minutes": DEFAULT_TIMEOUT_MINUTES},
        )

    def test_writes_the_summary_a_reviewer_reads(self):
        api = FakeApi(languages={"Python": 1}, tree=_tree(["tool.py"]))
        self.assertEqual(self._run(api), 0)
        self.assertIn(
            "CodeQL language discovery",
            self._summary.read_text(encoding="utf-8"),
        )

    def test_discovery_failure_exits_non_zero_with_no_matrix(self):
        self.assertEqual(self._run(FakeApi(languages=None, tree=None)), 2)
        self.assertNotIn("matrix", self._outputs())
        self.assertIn("Failed", self._summary.read_text(encoding="utf-8"))

    def test_private_repository_disables_codeql_without_api_calls(self):
        self._env["SCANNER_REPOSITORY_PRIVATE"] = "true"
        self._env["GITHUB_REPOSITORY"] = ""
        self._env["GITHUB_SHA"] = ""
        api = FakeApi(languages={"Python": 1}, tree=_tree(["tool.py"]))

        self.assertEqual(self._run(api), 0)

        outputs = self._outputs()
        self.assertEqual(outputs["enabled"], "false")
        self.assertEqual(json.loads(outputs["matrix"]), {"include": []})
        self.assertEqual(
            outputs["detection_source"], DETECTION_PRIVATE_REPOSITORY_POLICY
        )
        self.assertEqual(api.paths_requested, [])
        self.assertIn(
            "Disabled by policy",
            self._summary.read_text(encoding="utf-8"),
        )

    def test_a_missing_repository_or_sha_is_a_failure_not_a_guess(self):
        self._env["GITHUB_SHA"] = ""
        self.assertEqual(self._run(FakeApi(languages={"Python": 1})), 2)

    def test_the_callers_timeout_reaches_the_matrix(self):
        self._env["SCANNER_TIMEOUT_MINUTES"] = "240"
        api = FakeApi(languages={"Python": 1}, tree=_tree(["tool.py"]))
        self.assertEqual(self._run(api), 0)
        entries = json.loads(self._outputs()["matrix"])["include"]
        self.assertEqual({e["timeout_minutes"] for e in entries}, {240})

    def test_a_malformed_timeout_is_rejected(self):
        self._env["SCANNER_TIMEOUT_MINUTES"] = "twenty"
        self.assertEqual(self._run(FakeApi(languages={"Python": 1})), 2)

    def _with_pull_request(self, number: int = 7) -> None:
        event = Path(self._tmp.name) / "event.json"
        event.write_text(
            json.dumps({"pull_request": {"number": number}}), encoding="utf-8"
        )
        self._env["GITHUB_EVENT_PATH"] = str(event)

    def test_changed_mode_narrows_to_the_pull_requests_languages(self):
        self._with_pull_request()
        self._env["SCANNER_SCAN_MODE"] = "changed"
        api = FakeApi(
            languages={"C++": 1, "Python": 1},
            tree=_tree(["src/a.cpp", "tools/b.py"]),
            pull_files=[[{"filename": "tools/b.py"}]],
        )
        self.assertEqual(self._run(api), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["selected_languages"], "python")
        self.assertEqual(outputs["enabled"], "true")

    def test_a_documentation_only_pull_request_skips_the_codeql_job(self):
        self._with_pull_request()
        self._env["SCANNER_SCAN_MODE"] = "changed"
        api = FakeApi(
            languages={"Python": 1},
            tree=_tree(["tools/b.py"]),
            pull_files=[[{"filename": "README.md"}]],
        )
        self.assertEqual(self._run(api), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["enabled"], "false")
        self.assertEqual(json.loads(outputs["matrix"]), {"include": []})

    def test_a_codeql_config_change_analyses_every_discovered_language(self):
        self._with_pull_request()
        self._env["SCANNER_SCAN_MODE"] = "changed"
        self._configure_codeql(".github/codeql/codeql-config.yml")
        self._env["SCANNER_CODEQL_CONFIG_PATH"] = "./.github/codeql/codeql-config.yml"
        api = FakeApi(
            languages={"C++": 1, "Python": 1},
            tree=_tree(["src/a.cpp", "tools/b.py"]),
            pull_files=[[{"filename": ".github/codeql/codeql-config.yml"}]],
        )
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["selected_languages"], "actions,c-cpp,python")
        self.assertEqual(
            self._outputs()["config_path"], ".github/codeql/codeql-config.yml"
        )

    def test_an_unchanged_codeql_config_does_not_widen_a_pull_request(self):
        self._with_pull_request()
        self._env["SCANNER_SCAN_MODE"] = "changed"
        self._configure_codeql(".github/codeql/codeql-config.yml")
        api = FakeApi(
            languages={"Python": 1},
            tree=_tree(["tools/b.py"]),
            pull_files=[[{"filename": "README.md"}]],
        )
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["enabled"], "false")

    def test_a_codeql_config_path_outside_the_repository_is_rejected(self):
        self._env["SCANNER_CODEQL_CONFIG_PATH"] = "../codeql.yml"
        api = FakeApi(languages={"Python": 1}, tree=_tree(["tool.py"]))
        self.assertEqual(self._run(api), 2)

    def test_a_missing_codeql_config_file_is_rejected(self):
        self._env["SCANNER_CODEQL_CONFIG_PATH"] = "missing.yml"
        api = FakeApi(languages={"Python": 1}, tree=_tree(["tool.py"]))
        self.assertEqual(self._run(api), 2)

    def test_a_codeql_config_symlink_outside_the_repository_is_rejected(self):
        outside = Path(self._tmp.name) / "outside.yml"
        outside.write_text("paths-ignore: []\n", encoding="utf-8")
        (self._checkout_root / "codeql.yml").symlink_to(outside)
        self._env["SCANNER_CODEQL_CONFIG_PATH"] = "codeql.yml"
        api = FakeApi(languages={"Python": 1}, tree=_tree(["tool.py"]))
        self.assertEqual(self._run(api), 2)

    def test_scan_mode_all_analyses_every_discovered_language(self):
        self._with_pull_request()
        self._env["SCANNER_SCAN_MODE"] = "all"
        api = FakeApi(
            languages={"C++": 1, "Python": 1},
            tree=_tree(["src/a.cpp", "tools/b.py"]),
        )
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["selected_languages"], "actions,c-cpp,python")

    def test_takes_no_arguments_so_callers_cannot_select_languages(self):
        with mock.patch.dict(os.environ, self._env, clear=False):
            self.assertEqual(main(["--languages", "python"]), 2)


def _exact(paths: list[str]) -> Discovery:
    return Discovery(
        linguist_languages=("C++",),
        linguist_available=True,
        paths=tuple(paths),
        path_source="exact-tree",
    )


def _truncated() -> Discovery:
    return Discovery(
        linguist_languages=("C++",),
        linguist_available=True,
        tree_truncated=True,
    )


def _target(name: str = "app", **overrides: object) -> CodeqlTarget:
    fields: dict[str, object] = {
        "name": name,
        "language": "c-cpp",
        "scope": ("src/app",),
        "build_command": "make",
    }
    fields.update(overrides)
    return CodeqlTarget(**fields)  # type: ignore[arg-type]


def _cpp(directory: str, count: int) -> list[str]:
    return [f"{directory}/f{i}.cpp" for i in range(count)]


class CountScopeCppFilesTest(unittest.TestCase):
    """Tests for counting the files a target would build."""

    def test_the_exact_tree_is_counted_under_the_scope_only(self):
        discovery = _exact(
            _cpp("src/app", 3)
            + _cpp("src/app_other", 5)
            + _cpp("src/lib", 7)
            + ["src/app/README.md", "src/app/kernel.cu"]
        )
        api = FakeApi()
        self.assertEqual(
            count_scope_cpp_files(
                api, repo="o/r", sha="abc", discovery=discovery, scope=["src/app"]
            ),
            3,
        )
        self.assertEqual(api.paths_requested, [])

    def test_nested_and_repeated_scopes_are_counted_once(self):
        discovery = _exact(_cpp("a", 2) + _cpp("a/b", 3))
        self.assertEqual(
            count_scope_cpp_files(
                FakeApi(),
                repo="o/r",
                sha="abc",
                discovery=discovery,
                scope=["a", "a/b", "a"],
            ),
            5,
        )

    def test_a_truncated_tree_reads_each_scope_directory(self):
        api = FakeApi(
            subtrees={
                "src/app": _tree(_cpp("src", 4) + ["README.md"]),
                "tools": _tree(_cpp("t", 2)),
            }
        )
        self.assertEqual(
            count_scope_cpp_files(
                api,
                repo="o/r",
                sha="abc",
                discovery=_truncated(),
                scope=["src/app", "tools"],
            ),
            6,
        )
        self.assertEqual(
            sorted(api.paths_requested),
            [
                "/repos/o/r/git/trees/abc:src/app?recursive=1",
                "/repos/o/r/git/trees/abc:tools?recursive=1",
            ],
        )

    def test_a_scope_directory_that_does_not_exist_is_an_error(self):
        with self.assertRaisesRegex(TargetsError, "'gone' has no files"):
            count_scope_cpp_files(
                FakeApi(),
                repo="o/r",
                sha="abc",
                discovery=_truncated(),
                scope=["gone"],
            )

    def test_an_empty_subtree_is_an_error(self):
        api = FakeApi(subtrees={"gone": _tree([])})
        with self.assertRaises(TargetsError):
            count_scope_cpp_files(
                api, repo="o/r", sha="abc", discovery=_truncated(), scope=["gone"]
            )

    def test_an_exact_tree_without_the_scope_directory_is_an_error(self):
        discovery = _exact(_cpp("src/app", 3))
        with self.assertRaisesRegex(TargetsError, "'srcc/typo' has no files"):
            count_scope_cpp_files(
                FakeApi(),
                repo="o/r",
                sha="abc",
                discovery=discovery,
                scope=["src/app", "srcc/typo"],
            )

    def test_a_scope_directory_without_c_cpp_files_counts_zero(self):
        discovery = _exact(["src/app/README.md"])
        self.assertEqual(
            count_scope_cpp_files(
                FakeApi(),
                repo="o/r",
                sha="abc",
                discovery=discovery,
                scope=["src/app"],
            ),
            0,
        )

    def test_a_truncated_scope_directory_cannot_be_counted(self):
        api = FakeApi(subtrees={"big": _tree(_cpp("x", 3), truncated=True)})
        self.assertIsNone(
            count_scope_cpp_files(
                api, repo="o/r", sha="abc", discovery=_truncated(), scope=["big"]
            )
        )

    def test_the_whole_repository_cannot_be_counted_without_its_tree(self):
        self.assertIsNone(
            count_scope_cpp_files(
                FakeApi(), repo="o/r", sha="abc", discovery=_truncated(), scope=["."]
            )
        )

    def test_a_failed_lookup_is_unknown_not_empty(self):
        class Failing:
            def __call__(self, path: str) -> object:
                raise HTTPError(path, 500, "boom", None, None)  # type: ignore[arg-type]

        class Broken:
            def __call__(self, path: str) -> object:
                raise DiscoveryError("nope")

        for fetcher in (Failing(), Broken()):
            with self.subTest(fetcher=type(fetcher).__name__):
                self.assertIsNone(
                    count_scope_cpp_files(
                        fetcher,
                        repo="o/r",
                        sha="abc",
                        discovery=_truncated(),
                        scope=["a"],
                    )
                )


class PlanTargetsTest(unittest.TestCase):
    """Tests for choosing which targets run."""

    def _plan(
        self,
        targets: list[CodeqlTarget],
        paths: list[str],
        *,
        restrict_to: ChangedFiles | None = None,
        api: FakeApi | None = None,
        discovery: Discovery | None = None,
    ) -> TargetPlan:
        return plan_targets(
            targets,
            fetcher=api or FakeApi(),
            repo="o/r",
            sha="abc",
            discovery=discovery or _exact(paths),
            restrict_to=restrict_to,
        )

    def test_a_missing_scope_directory_names_the_target(self):
        with self.assertRaisesRegex(TargetsError, "target 'app'.*'src/app'"):
            self._plan([_target()], _cpp("src/other", 3))

    def test_a_target_a_pull_request_does_not_touch_is_not_checked(self):
        plan = self._plan(
            [_target()],
            _cpp("src/other", 3),
            restrict_to=ChangedFiles(("README.md",)),
        )
        self.assertEqual(plan.selected, ())

    def test_a_target_within_the_limit_is_selected(self):
        plan = self._plan([_target()], _cpp("src/app", 3))
        self.assertEqual([t.name for t in plan.selected], ["app"])
        self.assertEqual(plan.skipped, ())

    def test_the_limit_is_counted_over_the_scope_not_the_repository(self):
        # The point of a target: a repository far over the limit can
        # still scan the part it names.
        paths = _cpp("src/app", 10) + _cpp("src/lib", 5 * MAX_BUILDLESS_CPP_FILES)
        plan = self._plan([_target()], paths)
        self.assertEqual([t.name for t in plan.selected], ["app"])

    def test_a_scope_at_the_limit_is_selected(self):
        plan = self._plan([_target()], _cpp("src/app", MAX_BUILDLESS_CPP_FILES))
        self.assertEqual(len(plan.selected), 1)

    def test_a_scope_over_the_limit_is_skipped_and_says_so(self):
        plan = self._plan([_target()], _cpp("src/app", MAX_BUILDLESS_CPP_FILES + 1))
        self.assertEqual(plan.selected, ())
        self.assertEqual(
            plan.skipped,
            (
                f"app ({MAX_BUILDLESS_CPP_FILES + 1:,} C/C++ files under "
                f"src/app exceeds the {MAX_BUILDLESS_CPP_FILES:,}-file "
                "standard-runner limit)",
            ),
        )

    def test_a_scope_without_c_cpp_files_is_skipped(self):
        plan = self._plan([_target()], ["src/app/README.md"] + _cpp("other", 4))
        self.assertEqual(plan.selected, ())
        self.assertEqual(plan.skipped, ("app (no C/C++ files under src/app)",))

    def test_an_uncountable_scope_is_skipped_rather_than_assumed_small(self):
        api = FakeApi(subtrees={"src/app": _tree([], truncated=True)})
        plan = self._plan([_target()], [], api=api, discovery=_truncated())
        self.assertEqual(plan.selected, ())
        self.assertIn("cannot be verified", plan.skipped[0])

    def test_a_truncated_repository_still_scans_a_countable_scope(self):
        api = FakeApi(subtrees={"src/app": _tree(_cpp("src", 5))})
        plan = self._plan([_target()], [], api=api, discovery=_truncated())
        self.assertEqual([t.name for t in plan.selected], ["app"])

    def test_targets_are_judged_one_by_one(self):
        paths = _cpp("small", 2) + _cpp("big", MAX_BUILDLESS_CPP_FILES + 1)
        plan = self._plan(
            [_target("a", scope=("small",)), _target("b", scope=("big",))], paths
        )
        self.assertEqual([t.name for t in plan.selected], ["a"])
        self.assertEqual(len(plan.skipped), 1)
        self.assertTrue(plan.skipped[0].startswith("b ("))

    def test_a_pull_request_runs_only_the_targets_it_touches(self):
        paths = _cpp("src/app", 2) + _cpp("tools", 2)
        targets = [_target("a"), _target("b", scope=("tools",))]
        plan = self._plan(targets, paths, restrict_to=ChangedFiles(("src/app/f0.cpp",)))
        self.assertEqual([t.name for t in plan.selected], ["a"])
        self.assertEqual(plan.skipped, ("b (not touched by this pull request)",))

    def test_a_trigger_path_runs_the_target(self):
        plan = self._plan(
            [_target(trigger_paths=(".github/scripts/build.sh",))],
            _cpp("src/app", 2),
            restrict_to=ChangedFiles((".github/scripts/build.sh",)),
        )
        self.assertEqual(len(plan.selected), 1)

    def test_a_sibling_directory_does_not_trigger_the_target(self):
        plan = self._plan(
            [_target()],
            _cpp("src/app", 2),
            restrict_to=ChangedFiles(("src/app_other/a.cpp",)),
        )
        self.assertEqual(plan.selected, ())

    def test_an_incomplete_file_list_narrows_nothing(self):
        plan = self._plan(
            [_target()],
            _cpp("src/app", 2),
            restrict_to=ChangedFiles(("README.md",), complete=False),
        )
        self.assertEqual(len(plan.selected), 1)

    def test_an_untouched_target_costs_no_api_calls(self):
        api = FakeApi()
        self._plan(
            [_target()],
            [],
            restrict_to=ChangedFiles(("README.md",)),
            api=api,
            discovery=_truncated(),
        )
        self.assertEqual(api.paths_requested, [])


class TargetPlanOutputTest(unittest.TestCase):
    def test_matrix_carries_what_the_job_needs(self):
        plan = TargetPlan(
            selected=(
                _target(
                    scope=("a", "b"),
                    container="img@sha256:" + "0" * 64,
                    build_command="make -j",
                    fail_on_findings=True,
                ),
            )
        )
        self.assertEqual(
            json.loads(plan.matrix(120)),
            {
                "include": [
                    {
                        "name": "app",
                        "language": "c-cpp",
                        "scope": ["a", "b"],
                        "build_command": "make -j",
                        "container": "img@sha256:" + "0" * 64,
                        "sparse_checkout": "",
                        "timeout_minutes": 120,
                        "fail_on_findings": True,
                    }
                ]
            },
        )

    def test_a_target_can_raise_its_budget_but_not_lower_it(self):
        plan = TargetPlan(
            selected=(
                _target("a", timeout_minutes=300),
                _target("b", timeout_minutes=30),
            )
        )
        budgets = {
            e["name"]: e["timeout_minutes"]
            for e in json.loads(plan.matrix(120))["include"]
        }
        self.assertEqual(budgets, {"a": 300, "b": 120})

    def test_a_sparse_checkout_lists_the_scope_and_the_extra_directories(self):
        plan = TargetPlan(
            selected=(_target(scope=("src/app",), sparse_checkout=("third_party",)),)
        )
        (entry,) = json.loads(plan.matrix(120, (".github/codeql",)))["include"]
        self.assertEqual(
            entry["sparse_checkout"], ".github/codeql\nsrc/app\nthird_party"
        )

    def test_nested_sparse_directories_are_listed_once(self):
        plan = TargetPlan(
            selected=(_target(scope=("src",), sparse_checkout=("src/app", "lib")),)
        )
        (entry,) = json.loads(plan.matrix(120))["include"]
        self.assertEqual(entry["sparse_checkout"], "lib\nsrc")

    def test_no_targets_is_an_empty_matrix(self):
        self.assertEqual(json.loads(TargetPlan().matrix(120)), {"include": []})

    def test_summary_lists_selected_and_skipped_targets(self):
        summary = render_targets_summary(
            TargetPlan(
                selected=(_target("a"),), skipped=("b (no C/C++ files under x)",)
            )
        )
        self.assertIn("`a`", summary)
        self.assertIn("Skipped: b (no C/C++ files under x)", summary)
        self.assertIn("nothing", render_targets_summary(TargetPlan()))


class TargetsMainTest(unittest.TestCase):
    """Tests for how the step reads the targets file and reports the plan."""

    TARGETS = """
[[target]]
name = "app"
language = "c-cpp"
scope = ["src/app"]
build_command = "make"
trigger_paths = ["build.sh"]
"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self._output = root / "output"
        self._summary = root / "summary"
        self._checkout_root = root / "scan-target"
        self._checkout_root.mkdir()
        self._env = {
            "GITHUB_REPOSITORY": "o/x",
            "GITHUB_SHA": "abc",
            "GITHUB_TOKEN": "t0ken",
            "GITHUB_OUTPUT": str(self._output),
            "GITHUB_STEP_SUMMARY": str(self._summary),
            "GITHUB_EVENT_PATH": "",
            "SCANNER_CHECKOUT_ROOT": str(self._checkout_root),
            "SCANNER_CODEQL_CONFIG_PATH": "",
            "SCANNER_CODEQL_TARGETS_PATH": "",
            "SCANNER_REPOSITORY_PRIVATE": "false",
            "SCANNER_TIMEOUT_MINUTES": "",
            "SCANNER_SCAN_MODE": "changed",
        }
        self._root = root

    def _configure(self, text: str | None = None, path: str = "targets.toml") -> None:
        target = self._checkout_root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.TARGETS if text is None else text, encoding="utf-8")
        self._env["SCANNER_CODEQL_TARGETS_PATH"] = path

    def _pull_request(self) -> None:
        event = self._root / "event.json"
        event.write_text(json.dumps({"pull_request": {"number": 7}}), encoding="utf-8")
        self._env["GITHUB_EVENT_PATH"] = str(event)

    def _run(self, api: FakeApi) -> int:
        with (
            mock.patch.dict(os.environ, self._env, clear=False),
            mock.patch(
                "security_scanners.utils.compute_codeql_matrix._github_get",
                side_effect=lambda path, **kwargs: api(path),
            ),
        ):
            return main([])

    def _outputs(self) -> dict[str, str]:
        values: dict[str, str] = {}
        if self._output.is_file():
            for line in self._output.read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    values[key] = value
        return values

    def _api(self, **kwargs: object) -> FakeApi:
        defaults: dict[str, object] = {
            "languages": {"C++": 1},
            "tree": _tree(_cpp("src/app", 3) + ["build.sh"]),
        }
        defaults.update(kwargs)
        return FakeApi(**defaults)  # type: ignore[arg-type]

    def test_without_a_targets_file_there_are_no_targets(self):
        self.assertEqual(self._run(self._api()), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["targets_enabled"], "false")
        self.assertEqual(json.loads(outputs["targets_matrix"]), {"include": []})
        self.assertNotIn("CodeQL targets", self._summary.read_text("utf-8"))

    def test_a_targets_file_produces_a_matrix_and_the_outputs(self):
        self._configure()
        self.assertEqual(self._run(self._api()), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["targets_enabled"], "true")
        self.assertEqual(outputs["selected_targets"], "app")
        self.assertEqual(outputs["skipped_targets"], "")
        (entry,) = json.loads(outputs["targets_matrix"])["include"]
        self.assertEqual(entry["name"], "app")
        self.assertEqual(entry["scope"], ["src/app"])
        self.assertEqual(entry["timeout_minutes"], DEFAULT_TIMEOUT_MINUTES)
        self.assertIn("CodeQL targets", self._summary.read_text("utf-8"))

    def test_targets_do_not_change_the_discovered_languages(self):
        self._configure()
        self.assertEqual(self._run(self._api()), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["selected_languages"], "actions,c-cpp")

    def test_a_sparse_target_keeps_the_codeql_config_directory(self):
        self._configure(self.TARGETS + 'sparse_checkout = ["third_party"]\n')
        config = self._checkout_root / ".github/codeql/config.yml"
        config.parent.mkdir(parents=True)
        config.write_text("paths-ignore: []\n", encoding="utf-8")
        self._env["SCANNER_CODEQL_CONFIG_PATH"] = ".github/codeql/config.yml"
        self.assertEqual(self._run(self._api()), 0)
        (entry,) = json.loads(self._outputs()["targets_matrix"])["include"]
        self.assertEqual(
            entry["sparse_checkout"], ".github/codeql\nsrc/app\nthird_party"
        )

    def test_the_callers_timeout_reaches_the_targets(self):
        self._configure()
        self._env["SCANNER_TIMEOUT_MINUTES"] = "240"
        self.assertEqual(self._run(self._api()), 0)
        (entry,) = json.loads(self._outputs()["targets_matrix"])["include"]
        self.assertEqual(entry["timeout_minutes"], 240)

    def test_a_large_repository_still_gets_its_scoped_target(self):
        self._configure()
        paths = _cpp("src/app", 3) + _cpp("src/lib", 2 * MAX_BUILDLESS_CPP_FILES)
        api = self._api(tree=_tree(paths))
        self.assertEqual(self._run(api), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["selected_targets"], "app")
        self.assertNotIn("c-cpp", outputs["selected_languages"])

    def test_a_truncated_repository_counts_the_scope_directory(self):
        self._configure()
        api = self._api(
            tree=_tree([], truncated=True),
            pull_files=None,
            subtrees={"src/app": _tree(_cpp("src", 4))},
        )
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["selected_targets"], "app")

    def test_a_skipped_target_is_reported(self):
        self._configure()
        api = self._api(tree=_tree(_cpp("src/app", MAX_BUILDLESS_CPP_FILES + 1)))
        self.assertEqual(self._run(api), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["targets_enabled"], "false")
        self.assertIn("standard-runner limit", outputs["skipped_targets"])
        self.assertIn("Skipped: app", self._summary.read_text("utf-8"))

    def test_a_pull_request_that_misses_every_target_runs_none(self):
        self._configure()
        self._pull_request()
        api = self._api(pull_files=[[{"filename": "README.md"}]])
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["targets_enabled"], "false")

    def test_a_pull_request_touching_the_scope_runs_the_target(self):
        self._configure()
        self._pull_request()
        api = self._api(pull_files=[[{"filename": "src/app/f0.cpp"}]])
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["selected_targets"], "app")

    def test_changing_the_targets_file_runs_every_target(self):
        self._configure()
        self._pull_request()
        api = self._api(pull_files=[[{"filename": "targets.toml"}]])
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["selected_targets"], "app")

    def test_changing_the_codeql_config_runs_every_target(self):
        self._configure()
        self._pull_request()
        config = self._checkout_root / "codeql.yml"
        config.write_text("paths-ignore: []\n", encoding="utf-8")
        self._env["SCANNER_CODEQL_CONFIG_PATH"] = "codeql.yml"
        api = self._api(pull_files=[[{"filename": "codeql.yml"}]])
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["selected_targets"], "app")

    def test_scan_mode_all_runs_every_target(self):
        self._configure()
        self._pull_request()
        self._env["SCANNER_SCAN_MODE"] = "all"
        api = self._api(pull_files=[[{"filename": "README.md"}]])
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["selected_targets"], "app")

    def _build_inputs(self, **overrides: str) -> None:
        self._env.update(
            {
                "SCANNER_CODEQL_BUILD_MODE": "manual",
                "SCANNER_CODEQL_BUILD_COMMAND": "make",
                "SCANNER_CODEQL_SCOPE": "src/app",
                **overrides,
            }
        )

    def test_manual_build_mode_makes_a_target_and_replaces_discovered_c_cpp(self):
        self._build_inputs(SCANNER_CODEQL_FAIL_ON_FINDINGS="true")
        self.assertEqual(self._run(self._api()), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["selected_targets"], "c-cpp")
        self.assertEqual(outputs["selected_languages"], "actions")
        (entry,) = json.loads(outputs["targets_matrix"])["include"]
        self.assertEqual(entry["build_command"], "make")
        self.assertEqual(entry["scope"], ["src/app"])
        self.assertTrue(entry["fail_on_findings"])

    def test_a_misspelled_scope_fails_the_step(self):
        self._build_inputs(SCANNER_CODEQL_SCOPE="srcc/app")
        self.assertEqual(self._run(self._api()), 2)
        self.assertNotIn("targets_matrix", self._outputs())
        self.assertIn("'srcc/app' has no files", self._summary.read_text("utf-8"))

    def test_build_inputs_report_their_targets_in_the_summary(self):
        self._build_inputs()
        self.assertEqual(self._run(self._api()), 0)
        self.assertIn("Selected: `c-cpp`", self._summary.read_text("utf-8"))

    def test_a_skipped_build_target_is_explained_in_the_summary(self):
        self._build_inputs()
        self._pull_request()
        api = self._api(pull_files=[[{"filename": "README.md"}]])
        self.assertEqual(self._run(api), 0)
        self.assertIn(
            "c-cpp (not touched by this pull request)",
            self._summary.read_text("utf-8"),
        )

    def test_manual_build_mode_gates_the_scope_not_the_repository(self):
        self._build_inputs()
        paths = _cpp("src/app", 3) + _cpp("src/lib", 2 * MAX_BUILDLESS_CPP_FILES)
        self.assertEqual(self._run(self._api(tree=_tree(paths))), 0)
        self.assertEqual(self._outputs()["selected_targets"], "c-cpp")

    def test_manual_build_mode_reports_a_scope_over_the_limit(self):
        self._build_inputs()
        paths = _cpp("src/app", MAX_BUILDLESS_CPP_FILES + 1)
        self.assertEqual(self._run(self._api(tree=_tree(paths))), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["targets_enabled"], "false")
        self.assertIn("standard-runner limit", outputs["skipped_targets"])

    def test_manual_build_mode_runs_on_a_pull_request_only_when_touched(self):
        self._build_inputs()
        self._pull_request()
        api = self._api(pull_files=[[{"filename": "README.md"}]])
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["targets_enabled"], "false")

    def test_a_targets_file_change_does_not_widen_the_manual_build(self):
        self._build_inputs()
        self._configure()
        self._pull_request()
        api = self._api(pull_files=[[{"filename": "targets.toml"}]])
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["selected_targets"], "app")

    def test_manual_build_mode_and_a_targets_file_run_together(self):
        self._build_inputs()
        self._configure()
        self.assertEqual(self._run(self._api()), 0)
        self.assertEqual(self._outputs()["selected_targets"], "c-cpp,app")

    def test_the_targets_file_cannot_take_the_build_inputs_name(self):
        self._build_inputs()
        self._configure(self.TARGETS.replace('"app"', '"c-cpp"'))
        self.assertEqual(self._run(self._api()), 2)

    def test_manual_build_mode_without_a_command_fails_the_step(self):
        self._build_inputs(SCANNER_CODEQL_BUILD_COMMAND="")
        self.assertEqual(self._run(self._api()), 2)

    def test_build_inputs_without_manual_mode_fail_the_step(self):
        self._env["SCANNER_CODEQL_BUILD_COMMAND"] = "make"
        self.assertEqual(self._run(self._api()), 2)

    def test_a_private_repository_ignores_the_build_inputs(self):
        self._build_inputs()
        self._env["SCANNER_REPOSITORY_PRIVATE"] = "true"
        api = self._api()
        self.assertEqual(self._run(api), 0)
        self.assertEqual(self._outputs()["targets_enabled"], "false")
        self.assertEqual(api.paths_requested, [])

    def test_a_malformed_targets_file_fails_the_step(self):
        self._configure("[[target]\n")
        self.assertEqual(self._run(self._api()), 2)
        self.assertNotIn("targets_matrix", self._outputs())
        self.assertIn("Failed", self._summary.read_text("utf-8"))

    def test_a_targets_file_with_an_unknown_key_fails_the_step(self):
        self._configure(self.TARGETS + "typo = 1\n")
        self.assertEqual(self._run(self._api()), 2)

    def test_a_targets_path_outside_the_repository_is_rejected(self):
        self._env["SCANNER_CODEQL_TARGETS_PATH"] = "../targets.toml"
        self.assertEqual(self._run(self._api()), 2)

    def test_a_missing_targets_file_is_rejected(self):
        self._env["SCANNER_CODEQL_TARGETS_PATH"] = "missing.toml"
        self.assertEqual(self._run(self._api()), 2)

    def test_a_targets_file_symlinked_outside_the_repository_is_rejected(self):
        outside = self._root / "outside.toml"
        outside.write_text(self.TARGETS, encoding="utf-8")
        (self._checkout_root / "targets.toml").symlink_to(outside)
        self._env["SCANNER_CODEQL_TARGETS_PATH"] = "targets.toml"
        self.assertEqual(self._run(self._api()), 2)

    def test_a_private_repository_runs_no_targets_and_reads_nothing(self):
        self._env["SCANNER_REPOSITORY_PRIVATE"] = "true"
        self._env["SCANNER_CODEQL_TARGETS_PATH"] = "missing.toml"
        api = self._api()
        self.assertEqual(self._run(api), 0)
        outputs = self._outputs()
        self.assertEqual(outputs["targets_enabled"], "false")
        self.assertEqual(json.loads(outputs["targets_matrix"]), {"include": []})
        self.assertEqual(api.paths_requested, [])


if __name__ == "__main__":
    unittest.main()
