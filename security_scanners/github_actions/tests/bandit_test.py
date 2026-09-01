# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.fspath(Path(__file__).parent.parent))
from bandit import (
    _BANDIT_SDIST_FILENAME,
    _BANDIT_VERSION,
    _CONFIG_PATH,
    _SEVERITY_ORDER,
    _determine_changed_python_files,
    _diff_range,
    _enrich_sarif_with_security_severity,
    _parse_report_formats,
    _resolve_config_path,
    _tally_findings_by_severity,
    get_bandit_binary,
    main,
)


class MainTest(unittest.TestCase):
    """Tests for main()'s documented exit-code contract."""

    def test_unexpected_scanner_exception_returns_2_without_raising(self):
        # get_bandit_binary()/_run_bandit() can fail with exception types
        # other than RuntimeError (e.g. OSError from a pip/network
        # failure); those must still map to exit code 2 per this
        # module's documented contract, not escape main() as an
        # unhandled exception.
        with (
            mock.patch("bandit.gha_load_github_event", return_value={}),
            mock.patch("bandit.gha_append_step_summary"),
            mock.patch("bandit.gha_set_output"),
            mock.patch("bandit._resolve_config_path", return_value="bandit.yaml"),
            mock.patch("bandit.get_bandit_binary", side_effect=OSError("network down")),
        ):
            self.assertEqual(main(["--scan-mode", "all", "--source-dir", "."]), 2)

    def test_scan_failure_never_reports_a_nonexistent_sarif_path(self):
        # `set_output` must not be called with a non-empty sarif_path
        # before the report file actually exists: the workflow's upload
        # step runs whenever `sarif_path != ''`, so reporting the path
        # ahead of (or despite) a failed run would make that step fire
        # against a missing file and mask the real failure.
        with (
            mock.patch("bandit.gha_load_github_event", return_value={}),
            mock.patch("bandit.gha_append_step_summary"),
            mock.patch("bandit.gha_set_output") as set_output,
            mock.patch("bandit._resolve_config_path", return_value="bandit.yaml"),
            mock.patch(
                "bandit.get_bandit_binary",
                side_effect=RuntimeError("failed to install bandit"),
            ),
        ):
            self.assertEqual(main(["--scan-mode", "all", "--source-dir", "."]), 2)
        for call in set_output.call_args_list:
            (outputs,) = call.args
            self.assertEqual(outputs.get("sarif_path", ""), "")

    def test_partial_failure_only_reports_files_that_exist(self):
        # A multi-format run can write some reports before a later
        # format fails; only the reports that actually landed on disk
        # should be reported, never a path for a format that never ran.
        def fake_run_bandit(binary, targets, *, config_path, files, scan_path):
            for tgt in targets:
                if tgt.fmt == "sarif":
                    tgt.path.write_text("{}", encoding="utf-8")
            raise RuntimeError(
                "bandit exited unexpectedly with code 3 for format 'csv'"
            )

        with tempfile.TemporaryDirectory() as tmp:
            original_cwd = Path.cwd()
            os.chdir(tmp)
            try:
                with (
                    mock.patch("bandit.gha_load_github_event", return_value={}),
                    mock.patch("bandit.gha_append_step_summary"),
                    mock.patch("bandit.gha_set_output"),
                    mock.patch(
                        "bandit._resolve_config_path", return_value="bandit.yaml"
                    ),
                    mock.patch("bandit.get_bandit_binary", return_value=Path("bandit")),
                    mock.patch("bandit._run_bandit", side_effect=fake_run_bandit),
                ):
                    rc = main(
                        [
                            "--scan-mode",
                            "all",
                            "--source-dir",
                            ".",
                            "--report-formats",
                            "sarif,csv",
                        ]
                    )
            finally:
                os.chdir(original_cwd)
        self.assertEqual(rc, 2)


class SeverityGateTest(unittest.TestCase):
    """Tests for the severity threshold that decides pass (0) vs fail (1)."""

    def _main_with_counts(self, counts: dict[str, int], threshold: str) -> int:
        """Run main() over a scan that reported `counts`, and return its exit code."""
        with (
            mock.patch("bandit.gha_append_step_summary"),
            mock.patch("bandit.gha_set_output"),
            mock.patch("bandit._resolve_config_path", return_value="bandit.yaml"),
            mock.patch("bandit.get_bandit_binary", return_value=Path("bandit")),
            mock.patch("bandit._run_bandit", return_value=counts),
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
        # an off-by-one in _SEVERITY_ORDER slicing would either let HIGH
        # findings through or fail every job that has a LOW note.
        cases = [
            ("high", {"LOW": 0, "MEDIUM": 0, "HIGH": 1}, 1),
            ("high", {"LOW": 7, "MEDIUM": 4, "HIGH": 0}, 0),
            ("medium", {"LOW": 0, "MEDIUM": 1, "HIGH": 0}, 1),
            ("medium", {"LOW": 0, "MEDIUM": 0, "HIGH": 1}, 1),
            ("medium", {"LOW": 7, "MEDIUM": 0, "HIGH": 0}, 0),
            ("low", {"LOW": 1, "MEDIUM": 0, "HIGH": 0}, 1),
            ("low", {"LOW": 0, "MEDIUM": 0, "HIGH": 0}, 0),
        ]
        for threshold, counts, expected in cases:
            with self.subTest(threshold=threshold, counts=counts):
                self.assertEqual(self._main_with_counts(counts, threshold), expected)

    def test_clean_scan_passes(self):
        counts = {sev: 0 for sev in _SEVERITY_ORDER}
        self.assertEqual(self._main_with_counts(counts, "high"), 0)

    def test_severity_bandit_does_not_grade_never_fails_the_job(self):
        # _tally_findings_by_severity passes through any severity string
        # bandit emits, including one this script doesn't rank. Such a
        # finding is logged but must not be silently treated as failing:
        # only the ranked severities feed the gate.
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNDEFINED": 3}
        self.assertEqual(self._main_with_counts(counts, "high"), 0)


class ParseReportFormatsTest(unittest.TestCase):
    """Tests for `_parse_report_formats`."""

    def test_default_sarif(self):
        targets = _parse_report_formats("sarif")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].fmt, "sarif")
        self.assertEqual(targets[0].path, Path("bandit-report.sarif"))

    def test_human_alias_resolves_to_txt(self):
        targets = _parse_report_formats("human")
        self.assertEqual([t.fmt for t in targets], ["txt"])
        self.assertEqual(targets[0].path, Path("bandit-report.txt"))

    def test_human_alias_dedups_against_its_native_name(self):
        targets = _parse_report_formats("human,txt")
        self.assertEqual([t.fmt for t in targets], ["txt"])

    def test_unknown_format_error_advertises_the_alias(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("nope")
        self.assertIn("human", str(ctx.exception))

    def test_multiple_formats_with_whitespace_and_dedup(self):
        targets = _parse_report_formats(" sarif , json , sarif ,csv,html ")
        self.assertEqual([t.fmt for t in targets], ["sarif", "json", "csv", "html"])
        self.assertEqual(
            [t.path for t in targets],
            [
                Path("bandit-report.sarif"),
                Path("bandit-report.json"),
                Path("bandit-report.csv"),
                Path("bandit-report.html"),
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


class DetermineChangedPythonFilesTest(unittest.TestCase):
    """Tests for `_determine_changed_python_files`."""

    def setUp(self):
        self._original_cwd = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        Path("pkg").mkdir(parents=True)
        Path("docs").mkdir(parents=True)
        Path("pkg/module.py").write_text("x = 1\n", encoding="utf-8")
        Path("docs/readme.md").write_text("# docs\n", encoding="utf-8")

    def tearDown(self):
        os.chdir(self._original_cwd)
        self._tmp.cleanup()

    def test_returns_only_changed_python_files_under_scan_path(self):
        with mock.patch("bandit.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(
                    returncode=0,
                    stdout="pkg/module.py\ndocs/readme.md\n",
                    stderr="",
                ),
            ]
            files = _determine_changed_python_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=Path("."),
            )
        self.assertEqual(files, [Path("pkg/module.py")])

    def test_returns_empty_list_when_diff_has_no_python_files(self):
        with mock.patch("bandit.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(returncode=0, stdout="docs/readme.md\n", stderr=""),
            ]
            files = _determine_changed_python_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=Path("."),
            )
        self.assertEqual(files, [])

    def test_returns_none_when_diff_command_fails(self):
        with mock.patch("bandit.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                subprocess.CalledProcessError(
                    returncode=1, cmd=["git", "diff"], stderr="bad range"
                ),
            ]
            files = _determine_changed_python_files(
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
        (checkout_root / "pkg").mkdir(parents=True)
        (checkout_root / "pkg" / "module.py").write_text("x = 1\n", encoding="utf-8")
        with mock.patch("bandit.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(returncode=0, stdout="pkg/module.py\n", stderr=""),
            ]
            files = _determine_changed_python_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=checkout_root,
                checkout_root=checkout_root,
            )
        self.assertEqual(files, [checkout_root / "pkg" / "module.py"])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs.get("cwd"), checkout_root)


class EnrichSarifSeverityTest(unittest.TestCase):
    """Tests for `_enrich_sarif_with_security_severity`."""

    def _write_sarif(self, payload: object) -> Path:
        fd, name = tempfile.mkstemp(suffix=".sarif")
        os.close(fd)
        path = Path(name)
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def test_injects_security_severity_from_issue_severity(self):
        path = self._write_sarif(
            {
                "runs": [
                    {
                        "results": [
                            {"properties": {"issue_severity": "HIGH"}},
                            {"properties": {"issue_severity": "low"}},
                        ]
                    }
                ]
            }
        )
        _enrich_sarif_with_security_severity(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        results = data["runs"][0]["results"]
        self.assertEqual(results[0]["properties"]["security-severity"], "8.5")
        self.assertEqual(results[1]["properties"]["security-severity"], "1.0")

    def test_warns_when_no_result_carries_an_issue_severity(self):
        # Enrichment reads bandit's own `properties.issue_severity`. If a
        # future release renames or drops that field, every finding would
        # quietly lose its Security-tab tier, so the no-op is reported
        # rather than passed over in silence.
        path = self._write_sarif(
            {"runs": [{"results": [{"ruleId": "B602"}, {"ruleId": "B404"}]}]}
        )
        with self.assertLogs("bandit", level="WARNING") as logs:
            _enrich_sarif_with_security_severity(path)
        self.assertIn("issue_severity", logs.output[0])

    def test_no_warning_when_there_is_simply_nothing_to_enrich(self):
        path = self._write_sarif({"runs": [{"results": []}]})
        with mock.patch("bandit.log") as logger:
            _enrich_sarif_with_security_severity(path)
        logger.warning.assert_not_called()

    def test_preserves_existing_security_severity(self):
        path = self._write_sarif(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "properties": {
                                    "issue_severity": "HIGH",
                                    "security-severity": "9.9",
                                }
                            }
                        ]
                    }
                ]
            }
        )
        _enrich_sarif_with_security_severity(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        props = data["runs"][0]["results"][0]["properties"]
        self.assertEqual(props["security-severity"], "9.9")

    def test_unknown_severity_is_left_unmapped(self):
        path = self._write_sarif(
            {"runs": [{"results": [{"properties": {"issue_severity": "unknown"}}]}]}
        )
        _enrich_sarif_with_security_severity(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        props = data["runs"][0]["results"][0]["properties"]
        self.assertNotIn("security-severity", props)


class TallyFindingsBySeverityTest(unittest.TestCase):
    """Tests for `_tally_findings_by_severity`."""

    def test_counts_known_and_unknown_severities(self):
        fd, name = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        path = Path(name)
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_text(
            json.dumps(
                {
                    "results": [
                        {"issue_severity": "HIGH"},
                        {"issue_severity": "Medium"},
                        {"issue_severity": "high"},
                        {"issue_severity": "Undefined"},
                        {},
                    ]
                }
            ),
            encoding="utf-8",
        )
        counts = _tally_findings_by_severity(path)
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["UNDEFINED"], 2)
        for sev in _SEVERITY_ORDER:
            self.assertIn(sev, counts)

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
        # The default config is resolved relative to REPO_ROOT (this
        # script's own checkout), not the cwd, so patch REPO_ROOT to a
        # tempdir to isolate each test from the real repo.
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self._tooling_root = self._tmp_root / "tooling"
        self._tooling_root.mkdir()
        self._target_root = self._tmp_root / "scan-target"
        self._target_root.mkdir()
        patcher = mock.patch("bandit.REPO_ROOT", self._tooling_root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def _write_default_config(self) -> Path:
        path = self._tooling_root / _CONFIG_PATH
        path.write_text("exclude_dirs: []\n", encoding="utf-8")
        return path

    def test_falls_back_to_the_default_when_the_target_ships_none(self):
        expected = self._write_default_config()
        self.assertEqual(_resolve_config_path(self._target_root), str(expected))

    def test_the_scanned_repository_config_wins(self):
        # A repo's own exclude_dirs describe its own tree, so its config
        # takes precedence over the org-wide default.
        self._write_default_config()
        target_config = self._target_root / "bandit.yaml"
        target_config.write_text("exclude_dirs:\n  - third_party\n", encoding="utf-8")
        self.assertEqual(_resolve_config_path(self._target_root), str(target_config))

    def test_yml_spelling_is_also_honoured(self):
        self._write_default_config()
        target_config = self._target_root / "bandit.yml"
        target_config.write_text("exclude_dirs: []\n", encoding="utf-8")
        self.assertEqual(_resolve_config_path(self._target_root), str(target_config))

    def test_raises_when_neither_the_target_nor_the_default_has_one(self):
        with self.assertRaises(FileNotFoundError):
            _resolve_config_path(self._target_root)


class GetBanditBinaryTest(unittest.TestCase):
    """Tests for `get_bandit_binary`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self._tmp_root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self._sdist_path = self._tmp_root / _BANDIT_SDIST_FILENAME
        self._binary = self._tmp_root / "bandit"

    def _fake_download(self, *, dest_path, **_kwargs) -> Path:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(b"fake sdist contents")
        return dest_path

    def test_reuses_cached_sdist_once_its_digest_is_verified(self):
        cached = b"already downloaded"
        self._sdist_path.write_bytes(cached)
        with (
            mock.patch(
                "bandit.expected_sha256",
                return_value=hashlib.sha256(cached).hexdigest(),
            ),
            mock.patch("bandit.download_and_verify_file") as download,
            mock.patch("bandit.subprocess.run") as run,
        ):
            run.side_effect = [
                mock.Mock(returncode=0),  # pip install
                mock.Mock(
                    returncode=0, stdout=f"bandit {_BANDIT_VERSION}\n"
                ),  # --version
            ]
            with mock.patch("bandit.sys.executable", str(self._tmp_root / "python")):
                self._binary.write_text("#!/bin/sh\n", encoding="utf-8")
                get_bandit_binary()
        download.assert_not_called()

    def test_cached_sdist_with_an_unexpected_digest_is_never_installed(self):
        # A cache hit must not be a way around verification: whatever is
        # already sitting at the sdist path is checked against
        # checksums.sha256 before pip is allowed near it.
        self._sdist_path.write_bytes(b"tampered")
        with (
            mock.patch("bandit.expected_sha256", return_value="a" * 64),
            mock.patch("bandit.subprocess.run") as run,
            self.assertRaises(RuntimeError) as ctx,
        ):
            get_bandit_binary()
        self.assertIn("Refusing to use this artifact", str(ctx.exception))
        run.assert_not_called()

    def test_downloads_verifies_installs_and_checks_version(self):
        with (
            mock.patch("bandit.expected_sha256", return_value="a" * 64) as exp_sha,
            mock.patch(
                "bandit.download_and_verify_file", side_effect=self._fake_download
            ) as download,
            mock.patch("bandit.subprocess.run") as run,
        ):
            run.side_effect = [
                mock.Mock(returncode=0),  # pip install
                mock.Mock(
                    returncode=0, stdout=f"bandit {_BANDIT_VERSION}\n"
                ),  # --version
            ]
            with mock.patch("bandit.sys.executable", str(self._tmp_root / "python")):
                self._binary.write_text("#!/bin/sh\n", encoding="utf-8")
                result = get_bandit_binary()
        exp_sha.assert_called_once()
        download.assert_called_once()
        install_cmd = run.call_args_list[0].args[0]
        self.assertIn(f"{self._sdist_path}[sarif]", install_cmd)
        self.assertEqual(result, self._binary)

    def test_pip_install_failure_raises(self):
        with (
            mock.patch("bandit.expected_sha256", return_value="a" * 64),
            mock.patch(
                "bandit.download_and_verify_file", side_effect=self._fake_download
            ),
            mock.patch(
                "bandit.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, ["pip"]),
            ),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                get_bandit_binary()
        self.assertIn("Failed to install", str(ctx.exception))

    def test_version_mismatch_raises(self):
        with (
            mock.patch("bandit.expected_sha256", return_value="a" * 64),
            mock.patch(
                "bandit.download_and_verify_file", side_effect=self._fake_download
            ),
            mock.patch("bandit.subprocess.run") as run,
        ):
            run.side_effect = [
                mock.Mock(returncode=0),  # pip install
                mock.Mock(returncode=0, stdout="bandit 0.0.1\n"),  # --version
            ]
            with mock.patch("bandit.sys.executable", str(self._tmp_root / "python")):
                self._binary.write_text("#!/bin/sh\n", encoding="utf-8")
                with self.assertRaises(RuntimeError) as ctx:
                    get_bandit_binary()
        self.assertIn("0.0.1", str(ctx.exception))

    def test_version_line_with_extra_output_is_parsed(self):
        # Real `bandit --version` output has extra lines (python version,
        # etc) after the "bandit <version>" line.
        with (
            mock.patch("bandit.expected_sha256", return_value="a" * 64),
            mock.patch(
                "bandit.download_and_verify_file", side_effect=self._fake_download
            ),
            mock.patch("bandit.subprocess.run") as run,
        ):
            run.side_effect = [
                mock.Mock(returncode=0),  # pip install
                mock.Mock(
                    returncode=0,
                    stdout=f"bandit {_BANDIT_VERSION}\n  python version = 3.12.0\n",
                ),  # --version
            ]
            with mock.patch("bandit.sys.executable", str(self._tmp_root / "python")):
                self._binary.write_text("#!/bin/sh\n", encoding="utf-8")
                result = get_bandit_binary()
        self.assertEqual(result, self._binary)

    def test_binary_not_found_after_install_raises(self):
        with (
            mock.patch("bandit.expected_sha256", return_value="a" * 64),
            mock.patch(
                "bandit.download_and_verify_file", side_effect=self._fake_download
            ),
            mock.patch("bandit.subprocess.run", return_value=mock.Mock(returncode=0)),
            mock.patch("bandit.shutil.which", return_value=None),
        ):
            with mock.patch("bandit.sys.executable", str(self._tmp_root / "python")):
                with self.assertRaises(RuntimeError) as ctx:
                    get_bandit_binary()
        self.assertIn("bandit CLI not found", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
