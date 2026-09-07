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
    DETECTION_TREE_ONLY,
    ChangedFiles,
    CodeqlPlan,
    Discovery,
    DiscoveryError,
    _github_get,
    build_plan,
    discover,
    languages_from_paths,
    main,
    render_summary,
    resolve_timeout,
    touches_actions,
)


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
    ):
        self._languages = languages
        self._tree = tree
        self._pull_files = pull_files or []
        self.paths_requested: list[str] = []

    def __call__(self, path: str) -> object:
        self.paths_requested.append(path)
        if "/languages" in path:
            if self._languages is None:
                raise DiscoveryError("languages unavailable")
            return self._languages
        if "/git/trees/" in path:
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
        self.assertEqual(plan.selected, ("actions", "c-cpp", "python"))
        self.assertEqual(plan.detection_source, DETECTION_LANGUAGES_AND_CHANGED_FILES)
        self.assertTrue(plan.tree_truncated)

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

    def test_github_languages_still_carry_c_cpp_without_an_exact_tree(self):
        # Without the tree there is nothing better to go on, and missing
        # the C/C++ analysis is worse than a run that finds nothing.
        plan = build_plan(
            Discovery(
                linguist_languages=("C++",),
                linguist_available=True,
                tree_truncated=True,
            )
        )
        self.assertEqual(plan.selected, ("actions", "c-cpp"))

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
        plan = build_plan(
            discovery, restrict_to=ChangedFiles(paths=("src/lib.rs",))
        )
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
        self._env = {
            "GITHUB_REPOSITORY": "ROCm/x",
            "GITHUB_SHA": "abc",
            "GITHUB_TOKEN": "t0ken",
            "GITHUB_OUTPUT": str(self._output),
            "GITHUB_STEP_SUMMARY": str(self._summary),
            "GITHUB_EVENT_PATH": "",
            "SCANNER_TIMEOUT_MINUTES": "",
        }

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

    def test_scan_mode_all_analyses_every_discovered_language(self):
        self._with_pull_request()
        self._env["SCANNER_SCAN_MODE"] = "all"
        api = FakeApi(
            languages={"C++": 1, "Python": 1},
            tree=_tree(["src/a.cpp", "tools/b.py"]),
        )
        self.assertEqual(self._run(api), 0)
        self.assertEqual(
            self._outputs()["selected_languages"], "actions,c-cpp,python"
        )

    def test_takes_no_arguments_so_callers_cannot_select_languages(self):
        with mock.patch.dict(os.environ, self._env, clear=False):
            self.assertEqual(main(["--languages", "python"]), 2)


if __name__ == "__main__":
    unittest.main()
