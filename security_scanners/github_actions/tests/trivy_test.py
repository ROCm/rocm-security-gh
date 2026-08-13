# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.fspath(Path(__file__).parent.parent))
from trivy import (
    _CONFIG_PATH,
    _SEVERITY_ORDER,
    _determine_changed_audited_files,
    _diff_range,
    _GithubActionsApi,
    _import_github_actions_api,
    _is_audited_path,
    _parse_report_formats,
    _parse_scanners,
    _resolve_config_path,
    _tally_findings_by_severity,
    _trivy_subprocess_env,
    main,
)


class ImportGithubActionsApiTest(unittest.TestCase):
    """Tests for `_import_github_actions_api`."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("THEROCK_BUILD_TOOLS_DIR", None)

    def test_raises_when_env_var_unset(self):
        with self.assertRaises(RuntimeError) as ctx:
            _import_github_actions_api()
        self.assertIn("THEROCK_BUILD_TOOLS_DIR", str(ctx.exception))

    def test_imports_from_env_var_path(self):
        # Isolate this test's sys.path/sys.modules mutations: importing a
        # real `github_actions.github_actions_api` module (even a stub)
        # caches it in sys.modules, which must not leak into other tests.
        self.addCleanup(sys.modules.pop, "github_actions.github_actions_api", None)
        self.addCleanup(sys.modules.pop, "github_actions", None)
        with tempfile.TemporaryDirectory() as tmp:
            build_tools = Path(tmp) / "build_tools"
            (build_tools / "github_actions").mkdir(parents=True)
            (build_tools / "github_actions" / "github_actions_api.py").write_text(
                "def gha_append_step_summary(summary):\n"
                "    return 'summary:' + summary\n"
                "def gha_load_github_event():\n"
                "    return {'stub': True}\n"
                "def gha_set_output(vars):\n"
                "    return dict(vars)\n",
                encoding="utf-8",
            )
            os.environ["THEROCK_BUILD_TOOLS_DIR"] = str(build_tools)
            self.addCleanup(sys.path.remove, str(build_tools))
            gha = _import_github_actions_api()

        self.assertEqual(gha.append_step_summary("x"), "summary:x")
        self.assertEqual(gha.load_github_event(), {"stub": True})
        self.assertEqual(gha.set_output({"a": "b"}), {"a": "b"})


class MainTest(unittest.TestCase):
    """Tests for main()'s documented exit-code contract."""

    def _stub_gha(self, set_output=None) -> _GithubActionsApi:
        return _GithubActionsApi(
            append_step_summary=lambda summary: None,
            load_github_event=lambda: {},
            set_output=set_output or (lambda outputs: None),
        )

    def test_import_failure_returns_2_without_raising(self):
        # _import_github_actions_api() runs before argument parsing; a
        # missing THEROCK_BUILD_TOOLS_DIR must map to exit code 2, not an
        # unhandled traceback.
        with mock.patch(
            "trivy._import_github_actions_api",
            side_effect=RuntimeError("THEROCK_BUILD_TOOLS_DIR is not set"),
        ):
            self.assertEqual(main([]), 2)

    def test_unexpected_scanner_exception_returns_2_without_raising(self):
        # _ensure_trivy()/_run_trivy() can fail with exception types
        # other than RuntimeError (e.g. OSError from a download
        # failure); those must still map to exit code 2 per this
        # module's documented contract, not escape main() as an
        # unhandled exception.
        with (
            mock.patch(
                "trivy._import_github_actions_api",
                return_value=self._stub_gha(),
            ),
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch("trivy._ensure_trivy", side_effect=OSError("network down")),
        ):
            self.assertEqual(main(["--scan-mode", "all", "--source-dir", "."]), 2)

    def test_scan_failure_never_reports_a_nonexistent_sarif_path(self):
        # `set_output` must not be called with a non-empty sarif_path
        # before the report file actually exists: the workflow's upload
        # step runs whenever `sarif_path != ''`, so reporting the path
        # ahead of (or despite) a failed run would make that step fire
        # against a missing file and mask the real failure.
        set_output = mock.Mock()
        with (
            mock.patch(
                "trivy._import_github_actions_api",
                return_value=self._stub_gha(set_output=set_output),
            ),
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch(
                "trivy._ensure_trivy",
                side_effect=RuntimeError("failed to install trivy"),
            ),
        ):
            self.assertEqual(main(["--scan-mode", "all", "--source-dir", "."]), 2)
        for call in set_output.call_args_list:
            (outputs,) = call.args
            self.assertEqual(outputs.get("sarif_path", ""), "")

    def test_changed_mode_with_no_audited_files_is_a_clean_noop(self):
        set_output = mock.Mock()
        with (
            mock.patch(
                "trivy._import_github_actions_api",
                return_value=self._stub_gha(set_output=set_output),
            ),
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch(
                "trivy._determine_changed_audited_files", return_value=[]
            ),
            mock.patch("trivy._ensure_trivy") as ensure_trivy,
        ):
            rc = main(["--scan-mode", "changed", "--source-dir", "."])
        self.assertEqual(rc, 0)
        ensure_trivy.assert_not_called()
        set_output.assert_called_once_with({"sarif_path": "", "non_sarif_paths": ""})

    def test_invalid_report_formats_returns_1(self):
        with mock.patch(
            "trivy._import_github_actions_api", return_value=self._stub_gha()
        ):
            rc = main(
                [
                    "--scan-mode",
                    "all",
                    "--source-dir",
                    ".",
                    "--report-formats",
                    "pdf",
                ]
            )
        self.assertEqual(rc, 1)

    def test_invalid_scanners_returns_1(self):
        with mock.patch(
            "trivy._import_github_actions_api", return_value=self._stub_gha()
        ):
            rc = main(
                ["--scan-mode", "all", "--source-dir", ".", "--scanners", "bogus"]
            )
        self.assertEqual(rc, 1)


class ParseReportFormatsTest(unittest.TestCase):
    """Tests for `_parse_report_formats`."""

    def test_default_sarif(self):
        targets = _parse_report_formats("sarif")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].fmt, "sarif")
        self.assertEqual(targets[0].path, Path("trivy-report.sarif"))

    def test_multiple_formats_with_whitespace_and_dedup(self):
        targets = _parse_report_formats(" sarif , json , sarif ,table,cyclonedx ")
        self.assertEqual(
            [t.fmt for t in targets], ["sarif", "json", "table", "cyclonedx"]
        )
        self.assertEqual(
            [t.path for t in targets],
            [
                Path("trivy-report.sarif"),
                Path("trivy-report.json"),
                Path("trivy-report.txt"),
                Path("trivy-report.cdx.json"),
            ],
        )

    def test_empty_input_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("")
        self.assertIn("report_formats is empty", str(ctx.exception))

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("sarif,pdf")
        self.assertIn("'pdf'", str(ctx.exception))


class ParseScannersTest(unittest.TestCase):
    """Tests for `_parse_scanners`."""

    def test_default_misconfig_and_vuln(self):
        self.assertEqual(_parse_scanners("misconfig,vuln"), ["misconfig", "vuln"])

    def test_whitespace_case_and_dedup(self):
        self.assertEqual(
            _parse_scanners(" Vuln , misconfig , VULN ,secret "),
            ["vuln", "misconfig", "secret"],
        )

    def test_empty_input_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_scanners("")
        self.assertIn("scanners is empty", str(ctx.exception))

    def test_unknown_scanner_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_scanners("vuln,bogus")
        self.assertIn("'bogus'", str(ctx.exception))


class TrivySubprocessEnvTest(unittest.TestCase):
    """Tests for `_trivy_subprocess_env`."""

    def test_strips_trivy_prefixed_vars(self):
        with mock.patch.dict(
            os.environ,
            {"TRIVY_SEVERITY": "HIGH", "TRIVY_SCANNERS": "vuln", "PATH": "/bin"},
            clear=False,
        ):
            env = _trivy_subprocess_env()
        self.assertNotIn("TRIVY_SEVERITY", env)
        self.assertNotIn("TRIVY_SCANNERS", env)
        self.assertEqual(env.get("PATH"), "/bin")


class DiffRangeTest(unittest.TestCase):
    """Tests for `_diff_range`."""

    def test_pull_request_returns_base_head(self):
        event = {"pull_request": {"base": {"sha": "aaa"}, "head": {"sha": "bbb"}}}
        self.assertEqual(_diff_range("pull_request", event), ("aaa", "bbb"))

    def test_pull_request_missing_shas_returns_none(self):
        event = {"pull_request": {"base": {}, "head": {}}}
        self.assertIsNone(_diff_range("pull_request", event))

    def test_push_returns_before_after(self):
        self.assertEqual(
            _diff_range("push", {"before": "abc", "after": "def"}),
            ("abc", "def"),
        )

    def test_push_new_ref_returns_none(self):
        self.assertIsNone(_diff_range("push", {"before": "0" * 40, "after": "abc"}))

    def test_unknown_event_returns_none(self):
        self.assertIsNone(_diff_range("workflow_dispatch", {}))


class IsAuditedPathTest(unittest.TestCase):
    """Tests for `_is_audited_path`."""

    def test_matches_dependency_manifests(self):
        self.assertTrue(_is_audited_path("requirements.txt"))
        self.assertTrue(_is_audited_path("services/api/requirements-dev.txt"))
        self.assertTrue(_is_audited_path("package-lock.json"))
        self.assertTrue(_is_audited_path("go.sum"))

    def test_matches_container_and_iac_files(self):
        self.assertTrue(_is_audited_path("Dockerfile"))
        self.assertTrue(_is_audited_path("docker/Dockerfile.prod"))
        self.assertTrue(_is_audited_path("infra/main.tf"))

    def test_matches_trivy_config_itself(self):
        self.assertTrue(_is_audited_path("trivy.yaml"))
        self.assertTrue(_is_audited_path("trivy.yml"))

    def test_rejects_unrelated_files(self):
        self.assertFalse(_is_audited_path("README.md"))
        self.assertFalse(_is_audited_path("src/main.py"))
        self.assertFalse(_is_audited_path(".github/workflows/ci.yml"))


class DetermineChangedAuditedFilesTest(unittest.TestCase):
    """Tests for `_determine_changed_audited_files`."""

    def setUp(self):
        self._original_cwd = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        Path("app").mkdir(parents=True)
        Path("docs").mkdir(parents=True)
        Path("app/requirements.txt").write_text("flask\n", encoding="utf-8")
        Path("docs/readme.md").write_text("# docs\n", encoding="utf-8")

    def tearDown(self):
        os.chdir(self._original_cwd)
        self._tmp.cleanup()

    def test_returns_only_changed_audited_files_under_scan_path(self):
        with mock.patch("trivy.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(
                    returncode=0,
                    stdout="app/requirements.txt\ndocs/readme.md\n",
                    stderr="",
                ),
            ]
            files = _determine_changed_audited_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=Path("."),
            )
        self.assertEqual(files, [Path("app/requirements.txt")])

    def test_returns_empty_list_when_diff_has_no_audited_files(self):
        with mock.patch("trivy.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(returncode=0, stdout="docs/readme.md\n", stderr=""),
            ]
            files = _determine_changed_audited_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=Path("."),
            )
        self.assertEqual(files, [])

    def test_returns_none_when_diff_command_fails(self):
        with mock.patch("trivy.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                subprocess.CalledProcessError(
                    returncode=1, cmd=["git", "diff"], stderr="bad range"
                ),
            ]
            files = _determine_changed_audited_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=Path("."),
            )
        self.assertIsNone(files)

    def test_reanchors_paths_on_a_checkout_root_other_than_cwd(self):
        # `git diff --name-only` reports paths relative to the repo
        # root regardless of which directory `git` was invoked from;
        # when the scan target's checkout root isn't this process's
        # cwd (e.g. a sibling `.scan-target/` directory), returned
        # paths must be re-anchored there, not treated as relative to
        # cwd.
        checkout_root = Path("scan-target")
        (checkout_root / "app").mkdir(parents=True)
        (checkout_root / "app" / "requirements.txt").write_text(
            "flask\n", encoding="utf-8"
        )
        with mock.patch("trivy.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(
                    returncode=0,
                    stdout="app/requirements.txt\n",
                    stderr="",
                ),
            ]
            files = _determine_changed_audited_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=checkout_root,
                checkout_root=checkout_root,
            )
        self.assertEqual(files, [checkout_root / "app" / "requirements.txt"])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs.get("cwd"), checkout_root)


class TallyFindingsBySeverityTest(unittest.TestCase):
    """Tests for `_tally_findings_by_severity`."""

    def _write_json(self, payload: object) -> Path:
        fd, name = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        path = Path(name)
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def test_counts_across_finding_kinds_and_results(self):
        path = self._write_json(
            {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {"Severity": "HIGH"},
                            {"Severity": "critical"},
                        ],
                        "Misconfigurations": [{"Severity": "Medium"}],
                    },
                    {
                        "Secrets": [{"Severity": "HIGH"}],
                        "Licenses": [{"Severity": "Unknown"}, {}],
                    },
                ]
            }
        )
        counts = _tally_findings_by_severity(path)
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["UNKNOWN"], 2)
        for sev in _SEVERITY_ORDER:
            self.assertIn(sev, counts)

    def test_no_results_returns_zero_counts(self):
        path = self._write_json({"Results": []})
        counts = _tally_findings_by_severity(path)
        self.assertEqual(sum(counts.values()), 0)

    def test_invalid_json_raises(self):
        fd, name = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        path = Path(name)
        path.write_text("not json", encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        with self.assertRaises(RuntimeError):
            _tally_findings_by_severity(path)

    def test_non_object_json_raises(self):
        fd, name = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        path = Path(name)
        path.write_text("[]", encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        with self.assertRaises(RuntimeError):
            _tally_findings_by_severity(path)


class ResolveConfigPathTest(unittest.TestCase):
    """Tests for `_resolve_config_path`."""

    def setUp(self):
        # `_resolve_config_path` resolves _CONFIG_PATH relative to
        # REPO_ROOT (this script's own checkout), not the cwd, so patch
        # REPO_ROOT to a tempdir to isolate each test from the real repo.
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        patcher = mock.patch("trivy.REPO_ROOT", self._tmp_root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_returns_config_path_when_present(self):
        expected = self._tmp_root / _CONFIG_PATH
        expected.write_text("scan:\n  skip-dirs: []\n", encoding="utf-8")
        self.assertEqual(_resolve_config_path(), str(expected))

    def test_raises_when_missing(self):
        with self.assertRaises(FileNotFoundError):
            _resolve_config_path()


if __name__ == "__main__":
    unittest.main()
