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
    _DEFAULT_SCANNERS,
    _ReportTarget,
    _SEVERITY_ORDER,
    _TRIVY_TARBALL_FILENAME,
    _TRIVY_VERSION,
    _determine_changed_audited_files,
    _diff_range,
    _is_audited_path,
    _parse_report_formats,
    _parse_scanners,
    _resolve_config_path,
    _run_trivy,
    _tally_findings_by_severity,
    _trivy_subprocess_env,
    get_trivy_binary,
    main,
)


class MainTest(unittest.TestCase):
    """Tests for main()'s documented exit-code contract."""

    def test_unexpected_scanner_exception_returns_2_without_raising(self):
        # get_trivy_binary()/_run_trivy() can fail with exception types
        # other than RuntimeError (e.g. OSError from a download
        # failure); those must still map to exit code 2 per this
        # module's documented contract, not escape main() as an
        # unhandled exception.
        with (
            mock.patch("trivy.gha_load_github_event", return_value={}),
            mock.patch("trivy.gha_append_step_summary"),
            mock.patch("trivy.gha_set_output"),
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch("trivy.get_trivy_binary", side_effect=OSError("network down")),
        ):
            self.assertEqual(main(["--scan-mode", "all", "--source-dir", "."]), 2)

    def test_scan_failure_never_reports_a_nonexistent_sarif_path(self):
        # `set_output` must not be called with a non-empty sarif_path
        # before the report file actually exists: the workflow's upload
        # step runs whenever `sarif_path != ''`, so reporting the path
        # ahead of (or despite) a failed run would make that step fire
        # against a missing file and mask the real failure.
        with (
            mock.patch("trivy.gha_load_github_event", return_value={}),
            mock.patch("trivy.gha_append_step_summary"),
            mock.patch("trivy.gha_set_output") as set_output,
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch(
                "trivy.get_trivy_binary",
                side_effect=RuntimeError("failed to install trivy"),
            ),
        ):
            self.assertEqual(main(["--scan-mode", "all", "--source-dir", "."]), 2)
        for call in set_output.call_args_list:
            (outputs,) = call.args
            self.assertEqual(outputs.get("sarif_path", ""), "")

    def test_changed_mode_with_no_audited_files_is_a_clean_noop(self):
        with (
            mock.patch("trivy.gha_load_github_event", return_value={}),
            mock.patch("trivy.gha_append_step_summary"),
            mock.patch("trivy.gha_set_output") as set_output,
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch("trivy._determine_changed_audited_files", return_value=[]),
            mock.patch("trivy.get_trivy_binary") as get_binary,
        ):
            rc = main(["--scan-mode", "changed", "--source-dir", "."])
        self.assertEqual(rc, 0)
        get_binary.assert_not_called()
        set_output.assert_called_once_with({"sarif_path": "", "non_sarif_paths": ""})

    def test_invalid_report_formats_returns_1(self):
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
        rc = main(["--scan-mode", "all", "--source-dir", ".", "--scanners", "bogus"])
        self.assertEqual(rc, 1)

    def test_default_scanners_include_license(self):
        # License scanning is org policy for every trivy run, so omitting
        # --scanners must still pass 'license' through to the tool. A
        # caller can still drop it explicitly; they just cannot do so by
        # accident via the default.
        with (
            mock.patch("trivy.gha_append_step_summary"),
            mock.patch("trivy.gha_set_output"),
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch("trivy.get_trivy_binary", return_value=Path("trivy")),
            mock.patch(
                "trivy._run_trivy",
                return_value={sev: 0 for sev in _SEVERITY_ORDER},
            ) as run_trivy,
        ):
            rc = main(["--scan-mode", "all", "--source-dir", "."])
        self.assertEqual(rc, 0)
        self.assertEqual(
            run_trivy.call_args.kwargs["scanners"],
            ["misconfig", "vuln", "license"],
        )
        self.assertIsNone(run_trivy.call_args.kwargs["files"])

    def test_changed_mode_hands_trivy_the_audited_files(self):
        audited = [Path("modules/vpc/main.tf")]
        with (
            mock.patch("trivy.gha_load_github_event", return_value={}),
            mock.patch("trivy.gha_append_step_summary"),
            mock.patch("trivy.gha_set_output"),
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch("trivy._determine_changed_audited_files", return_value=audited),
            mock.patch("trivy.get_trivy_binary", return_value=Path("trivy")),
            mock.patch(
                "trivy._run_trivy",
                return_value={sev: 0 for sev in _SEVERITY_ORDER},
            ) as run_trivy,
        ):
            rc = main(["--scan-mode", "changed", "--source-dir", "."])
        self.assertEqual(rc, 0)
        self.assertEqual(run_trivy.call_args.kwargs["files"], audited)


class SeverityGateTest(unittest.TestCase):
    """Tests for the severity threshold that decides pass (0) vs fail (1)."""

    def _main_with_counts(self, counts: dict[str, int], threshold: str) -> int:
        """Run main() over a scan that reported `counts`, and return its exit code."""
        with (
            mock.patch("trivy.gha_append_step_summary"),
            mock.patch("trivy.gha_set_output"),
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch("trivy.get_trivy_binary", return_value=Path("trivy")),
            mock.patch("trivy._run_trivy", return_value=counts),
        ):
            return main(
                [
                    "--scan-mode",
                    "all",
                    "--source-dir",
                    ".",
                    "--severity-threshold",
                    threshold,
                ]
            )

    def test_threshold_decides_the_exit_code(self):
        # The gate is inclusive: a finding *at* the threshold fails the
        # job, anything strictly below it passes while still being
        # reported. Each threshold is checked at its own boundary, since
        # an off-by-one in _SEVERITY_ORDER slicing would either let
        # CRITICAL findings through or fail every job that has a LOW note.
        cases = [
            ("critical", {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 1}, 1),
            ("critical", {"LOW": 3, "MEDIUM": 2, "HIGH": 9, "CRITICAL": 0}, 0),
            ("high", {"LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0}, 1),
            ("high", {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 1}, 1),
            ("high", {"LOW": 7, "MEDIUM": 4, "HIGH": 0, "CRITICAL": 0}, 0),
            ("medium", {"LOW": 0, "MEDIUM": 1, "HIGH": 0, "CRITICAL": 0}, 1),
            ("medium", {"LOW": 7, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, 0),
            ("low", {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, 1),
            ("low", {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}, 0),
        ]
        for threshold, counts, expected in cases:
            with self.subTest(threshold=threshold, counts=counts):
                self.assertEqual(self._main_with_counts(counts, threshold), expected)

    def test_clean_scan_passes(self):
        counts = {sev: 0 for sev in _SEVERITY_ORDER}
        self.assertEqual(self._main_with_counts(counts, "high"), 0)

    def test_severity_trivy_does_not_grade_never_fails_the_job(self):
        # _tally_findings_by_severity passes through any severity string
        # trivy emits, including one this script doesn't rank (e.g.
        # UNKNOWN on an advisory with no CVSS data). Such a finding is
        # logged but must not be silently treated as failing: only the
        # ranked severities feed the gate.
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 3}
        self.assertEqual(self._main_with_counts(counts, "high"), 0)

    def test_all_mode_never_touches_the_github_event(self):
        # 'all' mode derives no diff range, so it must not depend on a
        # payload: the weekly scan runs on `schedule`, whose payload this
        # script has no reason to parse.
        with mock.patch("trivy.gha_load_github_event") as load_event:
            self.assertEqual(
                self._main_with_counts({sev: 0 for sev in _SEVERITY_ORDER}, "high"), 0
            )
        load_event.assert_not_called()


class ParseReportFormatsTest(unittest.TestCase):
    """Tests for `_parse_report_formats`."""

    def test_default_sarif(self):
        targets = _parse_report_formats("sarif")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].fmt, "sarif")
        self.assertEqual(targets[0].path, Path("trivy-report.sarif"))

    def test_human_alias_resolves_to_table(self):
        targets = _parse_report_formats("human")
        self.assertEqual([t.fmt for t in targets], ["table"])
        self.assertEqual(targets[0].path, Path("trivy-report.txt"))

    def test_human_alias_dedups_against_its_native_name(self):
        targets = _parse_report_formats("human,table")
        self.assertEqual([t.fmt for t in targets], ["table"])

    def test_unknown_format_error_advertises_the_alias(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("nope")
        self.assertIn("human", str(ctx.exception))

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

    def test_default_scanners_parse(self):
        self.assertEqual(
            _parse_scanners(_DEFAULT_SCANNERS),
            ["misconfig", "vuln", "license"],
        )

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

    def test_config_files_are_not_part_of_the_filter(self):
        # A config change widens the run to a full scan instead of being
        # filtered in as though it were a manifest, so that changed Trivy
        # configuration and ignore files count too. See
        # ConfigChangeWidensTheScanTest.
        self.assertFalse(_is_audited_path("trivy.yaml"))
        self.assertFalse(_is_audited_path(".trivyignore"))

    def test_rejects_unrelated_files(self):
        self.assertFalse(_is_audited_path("README.md"))
        self.assertFalse(_is_audited_path("src/main.py"))
        self.assertFalse(_is_audited_path(".github/workflows/ci.yml"))


class ConfigChangeWidensTheScanTest(unittest.TestCase):
    """A PR that only edits trivy's config or ignore file must exercise it."""

    def setUp(self):
        self._original_cwd = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(os.chdir, self._original_cwd)

    def _changed(self, diff_output: str):
        with mock.patch("trivy.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(returncode=0, stdout=diff_output, stderr=""),
            ]
            return _determine_changed_audited_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=Path("."),
            )

    def test_config_and_ignore_file_changes_widen_the_scan(self):
        # Ignore files are invisible to the manifest/IaC filter, so a
        # suppression could otherwise land without a scan confirming it.
        for config in (
            "trivy.yaml",
            "trivy.yml",
            ".trivyignore.yaml",
            ".trivyignore",
        ):
            with self.subTest(config=config):
                self.assertIsNone(self._changed(f"{config}\n"))

    def test_config_change_alongside_other_files_still_widens(self):
        self.assertIsNone(self._changed("README.md\n.trivyignore\n"))

    def test_explicit_nested_config_change_widens(self):
        with mock.patch("trivy.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(
                    returncode=0,
                    stdout="security_tools/trivy.yaml\n",
                    stderr="",
                ),
            ]
            changed = _determine_changed_audited_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=Path("."),
                config_paths=(
                    "security_tools/trivy.yaml",
                    ".trivyignore",
                ),
            )
        self.assertIsNone(changed)

    def test_unrelated_files_do_not_widen_the_scan(self):
        self.assertEqual(self._changed("README.md\ndocs/trivy.yaml\n"), [])

    def test_deleting_a_config_or_ignore_file_widens_the_scan(self):
        # Deleting either switches the repository back to the default
        # config, which changes what counts as a finding everywhere. Git
        # only reports deletions when D is in --diff-filter, so this also
        # guards that flag.
        for config in ("trivy.yaml", ".trivyignore.yaml", ".trivyignore"):
            with self.subTest(config=config):
                self.assertIsNone(self._changed(f"{config}\n"))

    def test_the_diff_asks_git_for_deletions(self):
        with mock.patch("trivy.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(returncode=0, stdout="", stderr=""),
            ]
            _determine_changed_audited_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=Path("."),
            )
        diff_argv = run.call_args_list[1].args[0]
        self.assertIn("--diff-filter=ACDMR", diff_argv)

    def test_a_deleted_manifest_is_not_scanned(self):
        # D widens the diff, so the filter now sees paths that no longer
        # exist; they must not reach trivy as scan targets.
        self.assertEqual(self._changed("deleted/requirements.txt\n"), [])

    def test_a_broken_config_fails_the_pr_that_introduces_it(self):
        # The point of widening: trivy rejects the malformed config, and
        # that surfaces as a failed run on the PR that wrote it, rather
        # than a green no-op that defers the breakage to someone else.
        with (
            mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "push"}),
            mock.patch(
                "trivy.gha_load_github_event",
                return_value={"before": "abc", "after": "def"},
            ),
            mock.patch("trivy.gha_append_step_summary"),
            mock.patch("trivy.gha_set_output"),
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch("trivy.subprocess.run") as run,
            mock.patch("trivy.get_trivy_binary", return_value=Path("trivy")),
            mock.patch(
                "trivy._run_trivy",
                side_effect=RuntimeError("trivy: failed to parse config"),
            ) as run_trivy,
        ):
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(returncode=0, stdout="trivy.yaml\n", stderr=""),
            ]
            exit_code = main(["--scan-mode", "changed", "--source-dir", "."])
        self.assertEqual(exit_code, 2)
        run_trivy.assert_called_once()


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


class RunTrivyIgnoreFileTest(unittest.TestCase):
    """Tests that a scanned repository's Trivy ignore file is honoured."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _run(self, ignore_path: Path | None) -> list[str]:
        """Run `_run_trivy` against a stub trivy, return its first argv."""
        commands: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            commands.append(cmd)
            output = Path(cmd[cmd.index("--output") + 1])
            output.write_text('{"Results": []}', encoding="utf-8")
            return mock.Mock(returncode=0, stdout="", stderr="")

        target = _ReportTarget(fmt="json", path=self._tmp_root / "report.json")
        with mock.patch("trivy.subprocess.run", side_effect=fake_run):
            _run_trivy(
                Path("trivy"),
                [target],
                config_path="trivy.yaml",
                scanners=["vuln"],
                scan_path=self._tmp_root,
                ignore_path=ignore_path,
            )
        return commands[0]

    def test_ignorefile_is_passed_when_the_target_ships_one(self):
        # Trivy resolves an ignore filename against its working directory,
        # which is this repo's checkout, so a scanned repository's
        # accepted-risk entries only apply if the path is explicit.
        ignore_path = self._tmp_root / ".trivyignore"
        ignore_path.write_text("CVE-2021-44228\n", encoding="utf-8")
        cmd = self._run(ignore_path)
        self.assertIn("--ignorefile", cmd)
        self.assertEqual(cmd[cmd.index("--ignorefile") + 1], str(ignore_path))

    def test_yaml_ignorefile_is_passed_when_the_target_ships_one(self):
        ignore_path = self._tmp_root / ".trivyignore.yaml"
        ignore_path.write_text("misconfigurations: []\n", encoding="utf-8")
        cmd = self._run(ignore_path)
        self.assertEqual(cmd[cmd.index("--ignorefile") + 1], str(ignore_path))

    def test_no_ignorefile_flag_when_the_target_ships_none(self):
        self.assertNotIn("--ignorefile", self._run(None))


class RunTrivyChangedFilesTest(unittest.TestCase):
    """Changed mode passes each audited file to `trivy fs`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self._main_tf = self._root / "modules" / "vpc" / "main.tf"
        self._variables_tf = self._root / "modules" / "vpc" / "variables.tf"
        self._main_tf.parent.mkdir(parents=True)
        self._main_tf.write_text('variable "x" {}\n', encoding="utf-8")
        self._variables_tf.write_text('variable "y" {}\n', encoding="utf-8")

    def _fake_run(self, commands: list[tuple[list[str], Path | None]]):
        def fake_run(cmd, **kwargs):
            commands.append((cmd, kwargs.get("cwd")))
            output = Path(cmd[cmd.index("--output") + 1])
            if cmd[1] == "fs":
                output.write_text(
                    json.dumps(
                        {
                            "SchemaVersion": 2,
                            "Results": [
                                {
                                    "Target": cmd[-1],
                                    "Vulnerabilities": [{"Severity": "HIGH"}],
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
            else:
                output.write_text("converted\n", encoding="utf-8")
            return mock.Mock(returncode=0, stdout="", stderr="")

        return fake_run

    def test_each_changed_file_is_scanned_from_the_scan_root(self):
        # trivy fs takes one path. The path is relative to the scan root
        # and the process runs there, so the report Target is the
        # repository path (modules/vpc/main.tf) rather than the checkout
        # prefix the workflow uses (.scan-target/...).
        commands: list[tuple[list[str], Path | None]] = []
        report = self._root / "trivy-report.json"
        table = self._root / "trivy-report.txt"
        with mock.patch("trivy.subprocess.run", side_effect=self._fake_run(commands)):
            counts = _run_trivy(
                Path("trivy"),
                [
                    _ReportTarget(fmt="json", path=report),
                    _ReportTarget(fmt="table", path=table),
                ],
                config_path="trivy.yaml",
                scanners=["misconfig", "vuln"],
                scan_path=self._root,
                files=[self._main_tf, self._variables_tf],
            )
        fs_cmds = [(cmd, cwd) for cmd, cwd in commands if cmd[1] == "fs"]
        self.assertEqual(
            [cmd[-1] for cmd, _cwd in fs_cmds],
            ["modules/vpc/main.tf", "modules/vpc/variables.tf"],
        )
        self.assertEqual([cwd for _cmd, cwd in fs_cmds], [self._root, self._root])
        convert_cmds = [cmd for cmd, _cwd in commands if cmd[1] == "convert"]
        self.assertEqual(len(convert_cmds), 1)
        self.assertEqual(
            convert_cmds[0][convert_cmds[0].index("--format") + 1], "table"
        )
        self.assertEqual(table.read_text(encoding="utf-8"), "converted\n")
        targets = [
            result["Target"]
            for result in json.loads(report.read_text(encoding="utf-8"))["Results"]
        ]
        self.assertEqual(targets, ["modules/vpc/main.tf", "modules/vpc/variables.tf"])
        self.assertEqual(counts["HIGH"], 2)

    def test_a_directory_scan_still_targets_the_scan_path(self):
        commands: list[tuple[list[str], Path | None]] = []
        report = self._root / "trivy-report.json"
        with mock.patch("trivy.subprocess.run", side_effect=self._fake_run(commands)):
            _run_trivy(
                Path("trivy"),
                [_ReportTarget(fmt="json", path=report)],
                config_path="trivy.yaml",
                scanners=["vuln"],
                scan_path=self._root,
            )
        cmd, cwd = commands[0]
        self.assertEqual(cmd[1], "fs")
        self.assertEqual(cmd[-1], str(self._root))
        self.assertIsNone(cwd)
        self.assertNotIn("convert", [item[0][1] for item in commands])


class IgnoreFileLocationTest(unittest.TestCase):
    """Where main() looks for Trivy ignore files relative to the config."""

    CONFIG_DIR = ".github/scan_tools_configs"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        (self._root / self.CONFIG_DIR).mkdir(parents=True)
        (self._root / self.CONFIG_DIR / "trivy.yml").write_text(
            "# repository config\n", encoding="utf-8"
        )

    def _main(self, scan_mode: str, *extra_args: str):
        """Run main() over `self._root`; return (exit code, _run_trivy mock)."""
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        with (
            mock.patch("trivy.gha_append_step_summary"),
            mock.patch("trivy.gha_set_output"),
            mock.patch("trivy.get_trivy_binary", return_value=Path("trivy")),
            mock.patch("trivy._run_trivy", return_value=counts) as run_trivy,
        ):
            rc = main(
                [
                    "--scan-mode",
                    scan_mode,
                    "--source-dir",
                    str(self._root),
                    "--checkout-root",
                    str(self._root),
                    *extra_args,
                ]
            )
        return rc, run_trivy

    def _ignore_path_passed_to_trivy(self, *extra_args: str) -> Path | None:
        rc, run_trivy = self._main("all", *extra_args)
        self.assertEqual(rc, 0)
        return run_trivy.call_args.kwargs["ignore_path"]

    def test_explicit_config_directory_is_searched_for_the_ignore_file(self):
        ignore = self._root / self.CONFIG_DIR / ".trivyignore"
        ignore.write_text("CVE-2021-44228\n", encoding="utf-8")
        self.assertEqual(
            self._ignore_path_passed_to_trivy(
                "--config-path", f"{self.CONFIG_DIR}/trivy.yml"
            ),
            ignore,
        )

    def test_yaml_ignore_file_is_preferred_beside_the_config(self):
        ignore = self._root / self.CONFIG_DIR / ".trivyignore.yaml"
        ignore.write_text("misconfigurations: []\n", encoding="utf-8")
        self.assertEqual(
            self._ignore_path_passed_to_trivy(
                "--config-path", f"{self.CONFIG_DIR}/trivy.yml"
            ),
            ignore,
        )

    def test_yaml_ignore_file_wins_over_plain_file_in_the_same_location(self):
        yaml_ignore = self._root / self.CONFIG_DIR / ".trivyignore.yaml"
        yaml_ignore.write_text("misconfigurations: []\n", encoding="utf-8")
        (self._root / self.CONFIG_DIR / ".trivyignore").write_text(
            "CVE-2021-44228\n", encoding="utf-8"
        )
        self.assertEqual(
            self._ignore_path_passed_to_trivy(
                "--config-path", f"{self.CONFIG_DIR}/trivy.yml"
            ),
            yaml_ignore,
        )

    def test_root_ignore_file_applies_when_none_sits_beside_the_config(self):
        ignore = self._root / ".trivyignore"
        ignore.write_text("CVE-2021-44228\n", encoding="utf-8")
        self.assertEqual(
            self._ignore_path_passed_to_trivy(
                "--config-path", f"{self.CONFIG_DIR}/trivy.yml"
            ),
            ignore,
        )

    def test_yaml_root_ignore_file_applies_when_none_sits_beside_the_config(self):
        ignore = self._root / ".trivyignore.yaml"
        ignore.write_text("misconfigurations: []\n", encoding="utf-8")
        self.assertEqual(
            self._ignore_path_passed_to_trivy(
                "--config-path", f"{self.CONFIG_DIR}/trivy.yml"
            ),
            ignore,
        )

    def test_config_directory_is_not_searched_without_an_explicit_config(self):
        (self._root / self.CONFIG_DIR / ".trivyignore").write_text(
            "CVE-2021-44228\n", encoding="utf-8"
        )
        self.assertIsNone(self._ignore_path_passed_to_trivy())

    def test_editing_the_ignore_file_beside_the_config_widens_the_scan(self):
        # A PR that only touches the nested ignore file must still reach
        # Trivy: the manifest/IaC filter would otherwise see no audited
        # file and skip the run, leaving the suppression unexercised.
        for filename in (".trivyignore.yaml", ".trivyignore"):
            with self.subTest(filename=filename):
                with (
                    mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "push"}),
                    mock.patch(
                        "trivy.gha_load_github_event",
                        return_value={"before": "abc", "after": "def"},
                    ),
                    mock.patch("trivy.subprocess.run") as run,
                ):
                    run.side_effect = [
                        mock.Mock(returncode=0, stdout="", stderr=""),
                        mock.Mock(
                            returncode=0,
                            stdout=f"{self.CONFIG_DIR}/{filename}\n",
                            stderr="",
                        ),
                    ]
                    rc, run_trivy = self._main(
                        "changed", "--config-path", f"{self.CONFIG_DIR}/trivy.yml"
                    )
                self.assertEqual(rc, 0)
                run_trivy.assert_called_once()


class ResolveConfigPathTest(unittest.TestCase):
    """Tests for `_resolve_config_path`."""

    def setUp(self):
        # The default config is resolved relative to REPO_ROOT (this
        # script's own checkout), not the cwd, so patch REPO_ROOT to a
        # tempdir to isolate each test from the real repo.
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self._tooling_root = self._tmp_root / "tooling"
        self._tooling_root.mkdir()
        self._target_root = self._tmp_root / "scan-target"
        self._target_root.mkdir()
        patcher = mock.patch("trivy.REPO_ROOT", self._tooling_root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def _write_default_config(self) -> Path:
        path = self._tooling_root / _CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("scan:\n  skip-dirs: []\n", encoding="utf-8")
        return path

    def test_falls_back_to_the_default_when_the_target_ships_none(self):
        expected = self._write_default_config()
        self.assertEqual(_resolve_config_path(self._target_root), str(expected))

    def test_the_scanned_repository_config_wins(self):
        # A repo's own skip-dirs and policy tuning describe its own tree,
        # so its config takes precedence over the org-wide default.
        self._write_default_config()
        target_config = self._target_root / "trivy.yaml"
        target_config.write_text("scan:\n  skip-dirs:\n  - vendor\n", encoding="utf-8")
        self.assertEqual(_resolve_config_path(self._target_root), str(target_config))

    def test_yml_spelling_is_also_honoured(self):
        self._write_default_config()
        target_config = self._target_root / "trivy.yml"
        target_config.write_text("scan:\n  skip-dirs: []\n", encoding="utf-8")
        self.assertEqual(_resolve_config_path(self._target_root), str(target_config))

    def test_explicit_nested_config_is_honoured(self):
        self._write_default_config()
        target_config = self._target_root / "security_tools" / "trivy.yaml"
        target_config.parent.mkdir()
        target_config.write_text("scan:\n  skip-dirs: []\n", encoding="utf-8")
        self.assertEqual(
            _resolve_config_path(self._target_root, "security_tools/trivy.yaml"),
            str(target_config),
        )

    def test_raises_when_neither_the_target_nor_the_default_has_one(self):
        with self.assertRaises(FileNotFoundError):
            _resolve_config_path(self._target_root)


class GetTrivyBinaryTest(unittest.TestCase):
    """Tests for `get_trivy_binary`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self._tmp_root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self._install_dir = self._tmp_root / f"trivy-{_TRIVY_VERSION}"
        self._binary = self._install_dir / "trivy"

    def _fake_download(self, **_kwargs) -> Path:
        self._install_dir.mkdir(parents=True, exist_ok=True)
        self._binary.write_text("#!/bin/sh\n", encoding="utf-8")
        return self._binary

    def test_always_reverifies_even_if_a_file_already_exists_at_the_path(self):
        # A stale/tampered file already sitting at the install path must
        # never be trusted without a fresh digest check: this asserts
        # download_and_verify_tarball() (and therefore the checksum
        # check inside it) always runs, regardless of what's on disk
        # beforehand.
        self._install_dir.mkdir(parents=True)
        self._binary.write_text("pre-existing, unverified content", encoding="utf-8")
        self._binary.chmod(0o755)
        with (
            mock.patch("trivy.expected_sha256", return_value="a" * 64),
            mock.patch(
                "trivy.download_and_verify_tarball", side_effect=self._fake_download
            ) as download,
            mock.patch(
                "trivy.subprocess.run",
                return_value=mock.Mock(
                    returncode=0, stdout=f"Version: {_TRIVY_VERSION}\n"
                ),
            ),
        ):
            get_trivy_binary()
        download.assert_called_once()

    def test_downloads_verifies_and_installs(self):
        with (
            mock.patch("trivy.expected_sha256", return_value="a" * 64) as exp_sha,
            mock.patch(
                "trivy.download_and_verify_tarball", side_effect=self._fake_download
            ) as download,
            mock.patch(
                "trivy.subprocess.run",
                return_value=mock.Mock(
                    returncode=0, stdout=f"Version: {_TRIVY_VERSION}\n"
                ),
            ),
        ):
            result = get_trivy_binary()
        exp_sha.assert_called_once_with(mock.ANY, _TRIVY_TARBALL_FILENAME)
        download.assert_called_once()
        self.assertEqual(result, self._binary)
        self.assertTrue(os.access(self._binary, os.X_OK))

    def test_binary_fails_to_execute_raises(self):
        with (
            mock.patch("trivy.expected_sha256", return_value="a" * 64),
            mock.patch(
                "trivy.download_and_verify_tarball", side_effect=self._fake_download
            ),
            mock.patch("trivy.subprocess.run", side_effect=OSError("cannot execute")),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                get_trivy_binary()
        self.assertIn("failed to execute", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
