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
from zizmor import (
    _CONFIG_PATH,
    _SEVERITY_ORDER,
    _ZIZMOR_VERSION,
    _determine_changed_audited_files,
    _diff_range,
    _enrich_sarif_with_security_severity,
    _GithubActionsApi,
    _is_audited_path,
    _parse_report_formats,
    _resolve_config_path,
    _tally_findings_by_severity,
    _tally_findings_from_sarif,
    get_zizmor_binary,
    main,
)


class MainTest(unittest.TestCase):
    """Tests for main()'s documented exit-code contract."""

    def _stub_gha(self, set_output=None) -> _GithubActionsApi:
        return _GithubActionsApi(
            append_step_summary=lambda summary: None,
            load_github_event=lambda: {},
            set_output=set_output or (lambda outputs: None),
        )

    def test_unexpected_scanner_exception_returns_2_without_raising(self):
        # get_zizmor_binary()/_run_zizmor() can fail with exception types
        # other than RuntimeError (e.g. OSError from a download/network
        # failure); those must still map to exit code 2 per this
        # module's documented contract, not escape main() as an
        # unhandled exception.
        with (
            mock.patch(
                "zizmor.import_github_actions_api",
                return_value=self._stub_gha(),
            ),
            mock.patch("zizmor._resolve_config_path", return_value="zizmor.yml"),
            mock.patch("zizmor.get_zizmor_binary", side_effect=OSError("network down")),
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
                "zizmor.import_github_actions_api",
                return_value=self._stub_gha(set_output=set_output),
            ),
            mock.patch("zizmor._resolve_config_path", return_value="zizmor.yml"),
            mock.patch(
                "zizmor.get_zizmor_binary",
                side_effect=RuntimeError("failed to install zizmor"),
            ),
        ):
            self.assertEqual(main(["--scan-mode", "all", "--source-dir", "."]), 2)
        for call in set_output.call_args_list:
            (outputs,) = call.args
            self.assertEqual(outputs.get("sarif_path", ""), "")


class ParseReportFormatsTest(unittest.TestCase):
    """Tests for `_parse_report_formats`."""

    def test_default_sarif(self):
        targets = _parse_report_formats("sarif")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].fmt, "sarif")
        self.assertEqual(targets[0].path, Path("zizmor-report.sarif"))

    def test_multiple_formats_with_whitespace_and_dedup(self):
        targets = _parse_report_formats(" sarif , json , sarif ,plain,github ")
        self.assertEqual([t.fmt for t in targets], ["sarif", "json", "plain", "github"])
        self.assertEqual(
            [t.path for t in targets],
            [
                Path("zizmor-report.sarif"),
                Path("zizmor-report.json"),
                Path("zizmor-report.txt"),
                Path("zizmor-report.txt"),
            ],
        )

    def test_human_alias_resolves_to_plain(self):
        targets = _parse_report_formats("human")
        self.assertEqual([t.fmt for t in targets], ["plain"])
        self.assertEqual(targets[0].path, Path("zizmor-report.txt"))

    def test_human_alias_dedups_against_its_native_name(self):
        targets = _parse_report_formats("human,plain")
        self.assertEqual([t.fmt for t in targets], ["plain"])

    def test_unknown_format_error_advertises_the_alias(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("nope")
        self.assertIn("human", str(ctx.exception))

    def test_empty_input_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("")
        self.assertIn("report_formats is empty", str(ctx.exception))

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("sarif,xml")
        self.assertIn("'xml'", str(ctx.exception))


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

    def test_matches_workflow_paths(self):
        self.assertTrue(_is_audited_path(".github/workflows/ci.yml"))
        self.assertTrue(_is_audited_path(".github/workflows/release.yaml"))

    def test_matches_action_files_anywhere(self):
        self.assertTrue(_is_audited_path("action.yml"))
        self.assertTrue(_is_audited_path("tools/my-action/action.yaml"))

    def test_matches_dependabot(self):
        self.assertTrue(_is_audited_path(".github/dependabot.yml"))
        self.assertTrue(_is_audited_path(".github/dependabot.yaml"))

    def test_rejects_non_audited_files(self):
        self.assertFalse(_is_audited_path("README.md"))
        self.assertFalse(_is_audited_path("build_tools/script.py"))

    def test_double_star_does_not_cross_into_unrelated_top_level_dirs(self):
        # `**/action.yml` must match nested `action.yml` files, but the
        # segment-aware matcher must not let `**` swallow the entire
        # path in a way that also matches an unrelated single-segment
        # pattern; this guards the fix for the fnmatch-based version's
        # over-matching (fnmatch's `*` matches `/`, `**` didn't mean
        # what it looked like).
        self.assertTrue(_is_audited_path("deeply/nested/dir/action.yml"))
        self.assertFalse(_is_audited_path("deeply/nested/dir/action.yml.bak"))


class DetermineChangedAuditedFilesTest(unittest.TestCase):
    """Tests for `_determine_changed_audited_files`."""

    def setUp(self):
        self._original_cwd = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        Path(".github/workflows").mkdir(parents=True)
        Path("docs").mkdir(parents=True)
        Path(".github/workflows/ci.yml").write_text("name: ci\n", encoding="utf-8")
        Path("docs/readme.md").write_text("# docs\n", encoding="utf-8")

    def tearDown(self):
        os.chdir(self._original_cwd)
        self._tmp.cleanup()

    def test_returns_only_changed_audited_files_under_scan_path(self):
        with mock.patch("zizmor.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(
                    returncode=0,
                    stdout=".github/workflows/ci.yml\ndocs/readme.md\n",
                    stderr="",
                ),
            ]
            files = _determine_changed_audited_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=Path("."),
            )
        self.assertEqual(files, [Path(".github/workflows/ci.yml")])

    def test_returns_empty_list_when_diff_has_no_audited_files(self):
        with mock.patch("zizmor.subprocess.run") as run:
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
        with mock.patch("zizmor.subprocess.run") as run:
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
        (checkout_root / ".github/workflows").mkdir(parents=True)
        (checkout_root / ".github/workflows/ci.yml").write_text(
            "name: ci\n", encoding="utf-8"
        )
        with mock.patch("zizmor.subprocess.run") as run:
            run.side_effect = [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(
                    returncode=0,
                    stdout=".github/workflows/ci.yml\n",
                    stderr="",
                ),
            ]
            files = _determine_changed_audited_files(
                event_name="push",
                event={"before": "abc", "after": "def"},
                scan_path=checkout_root,
                checkout_root=checkout_root,
            )
        self.assertEqual(files, [checkout_root / ".github/workflows/ci.yml"])
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

    def test_injects_security_severity_from_zizmor_severity(self):
        path = self._write_sarif(
            {
                "runs": [
                    {
                        "results": [
                            {"properties": {"zizmor/severity": "High"}},
                            {"properties": {"zizmor/severity": "informational"}},
                        ]
                    }
                ]
            }
        )
        _enrich_sarif_with_security_severity(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        results = data["runs"][0]["results"]
        self.assertEqual(results[0]["properties"]["security-severity"], "8.5")
        self.assertEqual(results[1]["properties"]["security-severity"], "0.3")

    def test_unknown_severity_is_left_unmapped(self):
        path = self._write_sarif(
            {"runs": [{"results": [{"properties": {"zizmor/severity": "unknown"}}]}]}
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
                [
                    {"determinations": {"severity": "High"}},
                    {"determinations": {"severity": "Medium"}},
                    {"determinations": {"severity": "high"}},
                    {"determinations": {"severity": "Unknown"}},
                    {},
                ]
            ),
            encoding="utf-8",
        )
        counts = _tally_findings_by_severity(path)
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["UNKNOWN"], 2)
        for sev in _SEVERITY_ORDER:
            self.assertIn(sev, counts)


class TallyFindingsFromSarifTest(unittest.TestCase):
    """Tests for `_tally_findings_from_sarif`."""

    def _write_sarif(self, payload: object) -> Path:
        fd, name = tempfile.mkstemp(suffix=".sarif")
        os.close(fd)
        path = Path(name)
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def test_counts_known_and_unknown_severities_across_runs(self):
        path = self._write_sarif(
            {
                "runs": [
                    {
                        "results": [
                            {"properties": {"zizmor/severity": "High"}},
                            {"properties": {"zizmor/severity": "medium"}},
                        ]
                    },
                    {"results": [{"properties": {"zizmor/severity": "High"}}, {}]},
                ]
            }
        )
        counts = _tally_findings_from_sarif(path)
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["UNKNOWN"], 1)
        for sev in _SEVERITY_ORDER:
            self.assertIn(sev, counts)

    def test_no_results_returns_zero_counts(self):
        path = self._write_sarif({"runs": [{"results": []}]})
        counts = _tally_findings_from_sarif(path)
        self.assertEqual(sum(counts.values()), 0)

    def test_invalid_json_raises(self):
        fd, name = tempfile.mkstemp(suffix=".sarif")
        os.close(fd)
        path = Path(name)
        path.write_text("not json", encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        with self.assertRaises(RuntimeError):
            _tally_findings_from_sarif(path)


class ResolveConfigPathTest(unittest.TestCase):
    """Tests for `_resolve_config_path`."""

    def setUp(self):
        # `_resolve_config_path` resolves _CONFIG_PATH relative to
        # REPO_ROOT (this script's own checkout), not the cwd, so patch
        # REPO_ROOT to a tempdir to isolate each test from the real repo.
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        patcher = mock.patch("zizmor.REPO_ROOT", self._tmp_root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_returns_config_path_when_present(self):
        expected = self._tmp_root / _CONFIG_PATH
        expected.write_text("rules: {}\n", encoding="utf-8")
        self.assertEqual(_resolve_config_path(), str(expected))

    def test_raises_when_missing(self):
        with self.assertRaises(FileNotFoundError):
            _resolve_config_path()


class GetZizmorBinaryTest(unittest.TestCase):
    """Tests for `get_zizmor_binary`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self._tmp_root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self._install_dir = self._tmp_root / f"zizmor-{_ZIZMOR_VERSION}"
        self._binary = self._install_dir / "zizmor"

    def _fake_download(self, **_kwargs) -> Path:
        self._install_dir.mkdir(parents=True, exist_ok=True)
        self._binary.write_text("#!/bin/sh\n", encoding="utf-8")
        return self._binary

    def test_returns_cached_binary_without_downloading(self):
        self._install_dir.mkdir(parents=True)
        self._binary.write_text("#!/bin/sh\n", encoding="utf-8")
        self._binary.chmod(0o755)
        with mock.patch("zizmor.download_and_verify_tarball") as download:
            result = get_zizmor_binary()
        download.assert_not_called()
        self.assertEqual(result, self._binary)

    def test_downloads_verifies_and_checks_version(self):
        with (
            mock.patch("zizmor.expected_sha256", return_value="a" * 64) as exp_sha,
            mock.patch(
                "zizmor.download_and_verify_tarball", side_effect=self._fake_download
            ) as download,
            mock.patch(
                "zizmor.subprocess.run",
                return_value=mock.Mock(
                    returncode=0, stdout=f"zizmor {_ZIZMOR_VERSION}\n"
                ),
            ),
        ):
            result = get_zizmor_binary()
        exp_sha.assert_called_once()
        download.assert_called_once()
        self.assertEqual(result, self._binary)
        self.assertTrue(os.access(self._binary, os.X_OK))

    def test_version_mismatch_raises(self):
        with (
            mock.patch("zizmor.expected_sha256", return_value="a" * 64),
            mock.patch(
                "zizmor.download_and_verify_tarball", side_effect=self._fake_download
            ),
            mock.patch(
                "zizmor.subprocess.run",
                return_value=mock.Mock(returncode=0, stdout="zizmor 0.0.1\n"),
            ),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                get_zizmor_binary()
        self.assertIn("0.0.1", str(ctx.exception))

    def test_binary_fails_to_execute_raises(self):
        with (
            mock.patch("zizmor.expected_sha256", return_value="a" * 64),
            mock.patch(
                "zizmor.download_and_verify_tarball", side_effect=self._fake_download
            ),
            mock.patch("zizmor.subprocess.run", side_effect=OSError("cannot execute")),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                get_zizmor_binary()
        self.assertIn("failed to execute", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
