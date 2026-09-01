# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.fspath(Path(__file__).parent.parent))
from gitleaks import (
    _CONFIG_PATH,
    _LEAK_SECURITY_SEVERITY_HIGH,
    _ReportTarget,
    _STEP_SUMMARY_BUDGET_BYTES,
    _SUPPORTED_FORMATS,
    _clip_to_budget,
    _determine_log_opts,
    _emit_non_sarif_reports,
    _enrich_sarif_with_security_severity,
    _md_code_fence,
    _parse_report_formats,
    _resolve_config_path,
    _run_gitleaks,
    get_gitleaks_binary,
    main,
)


class MainTest(unittest.TestCase):
    """Tests for main()'s documented exit-code contract."""

    def test_unexpected_scanner_exception_returns_2_without_raising(self):
        # get_gitleaks_binary()/_run_gitleaks() can fail with exception
        # types other than RuntimeError (e.g. KeyError from a malformed
        # tarball, OSError from a download failure); those must still map
        # to exit code 2 per this module's documented contract, not
        # escape main() as an unhandled exception.
        with (
            mock.patch("gitleaks.gha_load_github_event", return_value={}),
            mock.patch("gitleaks.gha_append_step_summary"),
            mock.patch("gitleaks.gha_set_output"),
            mock.patch("gitleaks._resolve_config_path", return_value="gitleaks.toml"),
            mock.patch(
                "gitleaks.get_gitleaks_binary", side_effect=KeyError("gitleaks")
            ),
        ):
            self.assertEqual(main(["--scan-mode", "all", "--source-dir", "."]), 2)

    def test_scan_failure_never_reports_a_nonexistent_sarif_path(self):
        # `gha_set_output` must not be called with a non-empty sarif_path
        # before the report file actually exists: the workflow's upload
        # step runs whenever `sarif_path != ''`, so reporting the path
        # ahead of (or despite) a failed run would make that step fire
        # against a missing file and mask the real failure.
        with (
            mock.patch("gitleaks.gha_load_github_event", return_value={}),
            mock.patch("gitleaks.gha_append_step_summary"),
            mock.patch("gitleaks.gha_set_output") as set_output,
            mock.patch("gitleaks._resolve_config_path", return_value="gitleaks.toml"),
            mock.patch(
                "gitleaks.get_gitleaks_binary",
                side_effect=RuntimeError("download failed"),
            ),
        ):
            self.assertEqual(main(["--scan-mode", "all", "--source-dir", "."]), 2)
        for call in set_output.call_args_list:
            (outputs,) = call.args
            self.assertEqual(outputs.get("sarif_path", ""), "")


class LeakGateTest(unittest.TestCase):
    """Tests for the gate that decides pass (0) vs fail (1).

    Gitleaks has no severity scale, so unlike the other scanners there is
    no threshold to tune: any leak fails the job.
    """

    def _main_with_leaks(self, leaks_found: bool) -> int:
        """Run main() over a scan that did (or didn't) find leaks."""
        with (
            mock.patch("gitleaks.gha_append_step_summary"),
            mock.patch("gitleaks.gha_set_output"),
            mock.patch("gitleaks._resolve_config_path", return_value="gitleaks.toml"),
            mock.patch("gitleaks.get_gitleaks_binary", return_value=Path("gitleaks")),
            mock.patch("gitleaks._run_gitleaks", return_value=leaks_found),
        ):
            return main(["--scan-mode", "all", "--source-dir", "."])

    def test_any_leak_fails_the_job(self):
        self.assertEqual(self._main_with_leaks(True), 1)

    def test_clean_scan_passes(self):
        self.assertEqual(self._main_with_leaks(False), 0)

    def test_all_mode_never_touches_the_github_event(self):
        # 'all' mode scans the full history and derives no git range, so
        # it must not depend on a payload: the weekly scan runs on
        # `schedule`, whose payload this script has no reason to parse.
        with mock.patch("gitleaks.gha_load_github_event") as load_event:
            self.assertEqual(self._main_with_leaks(False), 0)
        load_event.assert_not_called()


class ParseReportFormatsTest(unittest.TestCase):
    """Tests for `_parse_report_formats`."""

    def test_default_sarif(self):
        targets = _parse_report_formats("sarif")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].fmt, "sarif")
        self.assertEqual(targets[0].path, Path("gitleaks-report.sarif"))

    def test_multiple_formats_with_whitespace_and_dedup(self):
        targets = _parse_report_formats(" sarif , json , sarif ,csv ")
        self.assertEqual([t.fmt for t in targets], ["sarif", "json", "csv"])
        self.assertEqual(
            [t.path for t in targets],
            [
                Path("gitleaks-report.sarif"),
                Path("gitleaks-report.json"),
                Path("gitleaks-report.csv"),
            ],
        )

    def test_junit_uses_xml_extension(self):
        targets = _parse_report_formats("junit")
        self.assertEqual(targets[0].path, Path("gitleaks-report.xml"))

    def test_human_alias_resolves_to_csv(self):
        targets = _parse_report_formats("human")
        self.assertEqual([t.fmt for t in targets], ["csv"])
        self.assertEqual(targets[0].path, Path("gitleaks-report.csv"))

    def test_human_alias_dedups_against_its_native_name(self):
        targets = _parse_report_formats("human,csv")
        self.assertEqual([t.fmt for t in targets], ["csv"])

    def test_unknown_format_error_advertises_the_alias(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("nope")
        self.assertIn("human", str(ctx.exception))

    def test_empty_input_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("")
        self.assertIn("report_formats is empty", str(ctx.exception))

    def test_only_whitespace_raises(self):
        with self.assertRaises(ValueError):
            _parse_report_formats(" , , ")

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _parse_report_formats("sarif,xml")
        self.assertIn("'xml'", str(ctx.exception))


class RunGitleaksIgnoreFileTest(unittest.TestCase):
    """Tests that a scanned repository's `.gitleaksignore` is honoured."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _run(self, ignore_path: Path | None) -> list[str]:
        """Run `_run_gitleaks` against a stub gitleaks, return its argv."""
        commands: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            commands.append(cmd)
            self._kwargs = kwargs
            Path(cmd[cmd.index("--report-path") + 1]).write_text("", encoding="utf-8")
            return mock.Mock(returncode=0)

        target = _ReportTarget(fmt="csv", path=self._tmp_root / "report.csv")
        with mock.patch("gitleaks.subprocess.run", side_effect=fake_run):
            _run_gitleaks(
                Path("gitleaks"),
                [target],
                config_path="gitleaks.toml",
                log_opts="",
                source_dir=self._tmp_root,
                checkout_root=self._tmp_root,
                ignore_path=ignore_path,
            )
        return commands[0]

    def test_ignore_path_is_passed_when_the_target_ships_one(self):
        # gitleaks reads .gitleaksignore from its working directory, so
        # passing the path explicitly keeps the scanned repository's
        # already-triaged fingerprints applied regardless of where the
        # scan is invoked from.
        ignore_path = self._tmp_root / ".gitleaksignore"
        ignore_path.write_text("fingerprint-1\n", encoding="utf-8")
        cmd = self._run(ignore_path)
        self.assertIn("--gitleaks-ignore-path", cmd)
        self.assertEqual(
            cmd[cmd.index("--gitleaks-ignore-path") + 1],
            str(ignore_path.resolve()),
        )

    def test_no_ignore_flag_when_the_target_ships_none(self):
        self.assertNotIn("--gitleaks-ignore-path", self._run(None))


class RunGitleaksWorkingDirectoryTest(unittest.TestCase):
    """gitleaks must run from the scanned repository, not this checkout."""

    def setUp(self):
        self._original_cwd = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        self._tooling_root = Path(self._tmp.name) / "tooling"
        self._target_root = Path(self._tmp.name) / "tooling" / ".scan-target"
        self._target_root.mkdir(parents=True)
        os.chdir(self._tooling_root)
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(os.chdir, self._original_cwd)

    def _invoke(self) -> tuple[list[str], dict[str, object]]:
        """Return the argv and subprocess kwargs of a stubbed gitleaks run."""
        calls: list[tuple[list[str], dict[str, object]]] = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            Path(cmd[cmd.index("--report-path") + 1]).write_text("", encoding="utf-8")
            return mock.Mock(returncode=0)

        # Paths as main() has them: relative to this process's cwd, which
        # is the tooling checkout rather than the scanned repository.
        with mock.patch("gitleaks.subprocess.run", side_effect=fake_run):
            _run_gitleaks(
                Path("bin/gitleaks"),
                [_ReportTarget(fmt="csv", path=Path("gitleaks-report.csv"))],
                config_path=".scan-target/gitleaks.toml",
                log_opts="",
                source_dir=Path(".scan-target"),
                checkout_root=Path(".scan-target"),
                ignore_path=Path(".scan-target/.gitleaksignore"),
            )
        return calls[0]

    def test_runs_from_the_scanned_repository(self):
        # A scanned repo's config may extend another by relative path,
        # which gitleaks resolves from wherever it was invoked -- from the
        # tooling checkout that path is missing, or is a different file.
        _, kwargs = self._invoke()
        self.assertEqual(kwargs["cwd"], Path(".scan-target"))

    def test_every_path_is_absolute(self):
        # The paths above are relative to the tooling checkout, so moving
        # the working directory would silently repoint all of them.
        cmd, _ = self._invoke()
        flags = ("--source", "--config", "--gitleaks-ignore-path", "--report-path")
        for flag in flags:
            with self.subTest(flag=flag):
                self.assertTrue(Path(cmd[cmd.index(flag) + 1]).is_absolute())
        self.assertTrue(Path(cmd[0]).is_absolute())

    def test_the_report_still_lands_in_the_tooling_checkout(self):
        # The workflow uploads the report by its relative path, so it has
        # to stay next to this process, not follow gitleaks into the scan
        # target.
        cmd, _ = self._invoke()
        report = Path(cmd[cmd.index("--report-path") + 1])
        self.assertEqual(report, (self._tooling_root / "gitleaks-report.csv").resolve())


class DetermineLogOptsTest(unittest.TestCase):
    """Tests for `_determine_log_opts`."""

    def test_scan_mode_all_returns_empty(self):
        self.assertEqual(_determine_log_opts("all", "pull_request", {}), "")
        self.assertEqual(_determine_log_opts("all", "release", {"unrelated": 1}), "")

    def test_pull_request_returns_sha_range_without_no_merges(self):
        event = {"pull_request": {"base": {"sha": "aaa"}, "head": {"sha": "bbb"}}}
        with mock.patch("gitleaks.subprocess.run") as run:
            # `_determine_log_opts` does a best-effort fetch and then
            # verifies the base commit is reachable with `rev-parse`.
            run.side_effect = [
                mock.Mock(returncode=0, stderr=""),
                mock.Mock(returncode=0, stderr=""),
            ]
            log_opts = _determine_log_opts("changed", "pull_request", event)
        self.assertEqual(log_opts, "aaa..bbb")
        self.assertNotIn("--no-merges", log_opts)

    def test_pull_request_target_is_explicitly_rejected(self):
        event = {"pull_request": {"base": {"sha": "aaa"}, "head": {"sha": "bbb"}}}
        with self.assertRaises(ValueError) as ctx:
            _determine_log_opts("changed", "pull_request_target", event)
        self.assertIn("pull_request_target is not supported", str(ctx.exception))

    def test_push_returns_sha_range_without_no_merges(self):
        log_opts = _determine_log_opts(
            "changed", "push", {"before": "xxx", "after": "yyy"}
        )
        self.assertEqual(log_opts, "xxx..yyy")
        self.assertNotIn("--no-merges", log_opts)

    def test_push_new_ref_returns_empty(self):
        log_opts = _determine_log_opts(
            "changed", "push", {"before": "0" * 40, "after": "yyy"}
        )
        self.assertEqual(log_opts, "")

    def test_unknown_event_type_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _determine_log_opts("changed", "release", {})
        self.assertIn("'release'", str(ctx.exception))
        self.assertIn("scan_mode='all'", str(ctx.exception))

    def test_unset_event_name_raises(self):
        with self.assertRaises(ValueError) as ctx:
            _determine_log_opts("changed", "", {})
        self.assertIn("'<unset>'", str(ctx.exception))

    def test_pull_request_malformed_payload_raises_key_error(self):
        with self.assertRaises(KeyError):
            _determine_log_opts("changed", "pull_request", {"pull_request": {}})

    def test_push_malformed_payload_raises_key_error(self):
        with self.assertRaises(KeyError):
            _determine_log_opts("changed", "push", {})


class EnrichSarifTest(unittest.TestCase):
    """Tests for `_enrich_sarif_with_security_severity`."""

    def _write_sarif(self, payload: object) -> Path:
        fd, name = tempfile.mkstemp(suffix=".sarif")
        os.close(fd)
        path = Path(name)
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def test_backfills_level_and_security_severity(self):
        path = self._write_sarif(
            {"runs": [{"results": [{"message": {"text": "leak"}}]}]}
        )
        _enrich_sarif_with_security_severity(path)
        data = json.loads(path.read_text())
        result = data["runs"][0]["results"][0]
        self.assertEqual(result["level"], "error")
        self.assertEqual(
            result["properties"]["security-severity"],
            _LEAK_SECURITY_SEVERITY_HIGH,
        )

    def test_preserves_existing_level(self):
        path = self._write_sarif({"runs": [{"results": [{"level": "warning"}]}]})
        _enrich_sarif_with_security_severity(path)
        data = json.loads(path.read_text())
        self.assertEqual(data["runs"][0]["results"][0]["level"], "warning")

    def test_preserves_existing_security_severity(self):
        path = self._write_sarif(
            {"runs": [{"results": [{"properties": {"security-severity": "3.5"}}]}]}
        )
        _enrich_sarif_with_security_severity(path)
        data = json.loads(path.read_text())
        self.assertEqual(
            data["runs"][0]["results"][0]["properties"]["security-severity"],
            "3.5",
        )

    def test_empty_runs_raises(self):
        path = self._write_sarif({"runs": []})
        original = path.read_text()
        with self.assertRaises(ValueError) as ctx:
            _enrich_sarif_with_security_severity(path)
        self.assertIn("empty 'runs' array", str(ctx.exception))
        # File is left untouched when we bail out.
        self.assertEqual(path.read_text(), original)

    def test_clean_scan_with_empty_results_is_valid(self):
        # Gitleaks emits {"runs": [{"results": [], ...}]} on a clean scan;
        # that's a valid SARIF and must NOT raise (this is the normal,
        # no-leaks-found path).
        path = self._write_sarif({"runs": [{"results": []}]})
        _enrich_sarif_with_security_severity(path)
        data = json.loads(path.read_text())
        self.assertEqual(data["runs"][0]["results"], [])

    def test_malformed_top_level_raises(self):
        path = self._write_sarif(["not", "a", "dict"])
        original = path.read_text()
        with self.assertRaises(ValueError) as ctx:
            _enrich_sarif_with_security_severity(path)
        self.assertIn("top-level must be a JSON object", str(ctx.exception))
        # File should be left unchanged when payload is unexpectedly shaped.
        self.assertEqual(path.read_text(), original)

    def test_invalid_json_raises(self):
        fd, name = tempfile.mkstemp(suffix=".sarif")
        os.close(fd)
        path = Path(name)
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_text("{not valid json", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            _enrich_sarif_with_security_severity(path)
        self.assertIn("not valid JSON", str(ctx.exception))

    def test_runs_must_be_a_list(self):
        path = self._write_sarif({"runs": "oops"})
        with self.assertRaises(ValueError) as ctx:
            _enrich_sarif_with_security_severity(path)
        self.assertIn("'runs' must be a list", str(ctx.exception))

    def test_missing_file_raises(self):
        path = Path(tempfile.gettempdir()) / "does-not-exist.sarif"
        if path.exists():
            path.unlink()
        with self.assertRaises(FileNotFoundError):
            _enrich_sarif_with_security_severity(path)


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
        patcher = mock.patch("gitleaks.REPO_ROOT", self._tooling_root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def _write_default_config(self) -> Path:
        path = self._tooling_root / _CONFIG_PATH
        path.write_text("# stub config", encoding="utf-8")
        return path

    def test_falls_back_to_the_default_when_the_target_ships_none(self):
        expected = self._write_default_config()
        self.assertEqual(_resolve_config_path(self._target_root), str(expected))

    def test_the_scanned_repository_config_wins(self):
        # A repo's own allowlists describe its own tree -- vendored paths,
        # fake credentials in fixtures -- so its config takes precedence
        # over the org-wide default.
        self._write_default_config()
        target_config = self._target_root / "gitleaks.toml"
        target_config.write_text("title = 'TheRock gitleaks config'", encoding="utf-8")
        self.assertEqual(_resolve_config_path(self._target_root), str(target_config))

    def test_dotfile_location_is_also_honoured(self):
        self._write_default_config()
        target_config = self._target_root / ".gitleaks.toml"
        target_config.write_text("title = 'dotfile config'", encoding="utf-8")
        self.assertEqual(_resolve_config_path(self._target_root), str(target_config))

    def test_raises_when_neither_the_target_nor_the_default_has_one(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            _resolve_config_path(self._target_root)
        self.assertIn(str(self._tooling_root / _CONFIG_PATH), str(ctx.exception))


class MdCodeFenceTest(unittest.TestCase):
    """Tests for `_md_code_fence`."""

    def test_default_three_backticks_when_no_backticks(self):
        self.assertEqual(_md_code_fence("plain,csv,content"), "```")

    def test_three_backticks_when_content_has_short_runs(self):
        self.assertEqual(_md_code_fence("a `b` c"), "```")

    def test_grows_beyond_triple_backtick_run(self):
        self.assertEqual(_md_code_fence("before ``` after"), "````")

    def test_grows_to_longest_run(self):
        self.assertEqual(_md_code_fence("x ````` y"), "``````")

    def test_fence_actually_wraps_content(self):
        content = "with ``` inside"
        fence = _md_code_fence(content)
        block = f"{fence}\n{content}\n{fence}"
        # The closing fence must be on its own line and not appear within
        # the content, so the block is unambiguous.
        self.assertNotIn(fence, content)
        self.assertTrue(block.startswith(fence + "\n"))
        self.assertTrue(block.endswith("\n" + fence))


class ClipToBudgetTest(unittest.TestCase):
    """Tests for `_clip_to_budget`."""

    def test_content_within_budget_is_untouched(self):
        self.assertEqual(_clip_to_budget("a,b,c\n", 1024), ("a,b,c\n", False))

    def test_oversized_content_is_clipped_on_a_line_boundary(self):
        content = "".join(f"line{i}\n" for i in range(100))
        shown, clipped = _clip_to_budget(content, 50)
        self.assertTrue(clipped)
        self.assertLessEqual(len(shown.encode("utf-8")), 50)
        # Clipping mid-record would render a partial finding in the summary.
        self.assertTrue(shown.endswith("\n"))
        self.assertTrue(content.startswith(shown))

    def test_exhausted_budget_yields_nothing(self):
        self.assertEqual(_clip_to_budget("data\n", 0), ("", True))

    def test_clip_never_splits_a_multibyte_character(self):
        # Two bytes per character and no newline to fall back on, so the
        # byte-level cut lands mid-character.
        shown, clipped = _clip_to_budget("é" * 100, 5)
        self.assertTrue(clipped)
        self.assertEqual(shown, "éé")


class EmitNonSarifReportsTest(unittest.TestCase):
    """Tests for `_emit_non_sarif_reports`' job-summary budgeting."""

    def _report(self, content: str) -> _ReportTarget:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = Path(tmp) / "gitleaks-report.csv"
        path.write_text(content, encoding="utf-8")
        return _ReportTarget(fmt="csv", path=path)

    def test_report_within_budget_is_emitted_in_full(self):
        target = self._report("file,secret\na.txt,REDACTED\n")
        appended: list[str] = []
        _emit_non_sarif_reports([target], appended.append)
        (summary,) = appended
        self.assertIn("a.txt,REDACTED", summary)
        self.assertNotIn("Truncated", summary)

    def test_oversized_report_is_truncated_and_points_at_the_artifact(self):
        target = self._report("".join(f"row{i},REDACTED\n" for i in range(200)))
        appended: list[str] = []
        with mock.patch("gitleaks._STEP_SUMMARY_BUDGET_BYTES", 64):
            _emit_non_sarif_reports([target], appended.append)
        (summary,) = appended
        self.assertIn("row0,REDACTED", summary)
        self.assertNotIn("row199,REDACTED", summary)
        self.assertIn("Truncated", summary)
        self.assertIn("artifact", summary)

    def test_budget_is_shared_across_reports(self):
        first = self._report("".join(f"row{i},REDACTED\n" for i in range(50)))
        second = self._report("second,REDACTED\n")
        appended: list[str] = []
        with mock.patch("gitleaks._STEP_SUMMARY_BUDGET_BYTES", 64):
            _emit_non_sarif_reports([first, second], appended.append)
        (summary,) = appended
        # The first report consumes the budget, so the second is announced
        # but its contents are left to the artifact.
        self.assertIn("row0,REDACTED", summary)
        self.assertNotIn("second,REDACTED", summary)
        self.assertIn(str(second.path), summary)

    def test_default_budget_stays_under_githubs_limit(self):
        self.assertLess(_STEP_SUMMARY_BUDGET_BYTES, 1024 * 1024)

    def test_missing_report_is_skipped_without_a_summary(self):
        target = _ReportTarget(fmt="csv", path=Path("does-not-exist.csv"))
        appended: list[str] = []
        _emit_non_sarif_reports([target], appended.append)
        self.assertEqual(appended, [])


class RedactionRegressionTest(unittest.TestCase):
    """Regression test: a real secret's literal value must never reach any
    generated report, in any supported format, when `--redact` is passed.

    Runs the real, network-downloaded gitleaks binary end-to-end through
    this module's own `_run_gitleaks`/`_parse_report_formats` against a
    throwaway repo containing one fixture secret -- i.e. exactly the code
    path `main()` uses, not a reimplementation of it. Skips (rather than
    failing) when the binary can't be obtained, so offline/sandboxed
    environments don't get a false failure; re-run this whenever
    `_GITLEAKS_VERSION` is bumped, since redaction behavior is entirely
    upstream gitleaks' responsibility.
    """

    # Structurally matches gitleaks' built-in `slack-webhook-url` rule
    # (a fixed literal path shape, no entropy heuristic involved), so
    # detection stays reliable across gitleaks versions.
    FIXTURE_SECRET = (
        "https://hooks.slack.com/services/T00000000/B00000000/"
        "fixturefixturefixturefix"
    )

    @classmethod
    def setUpClass(cls):
        try:
            cls.binary = get_gitleaks_binary()
        except Exception as exc:  # environment-dependent: no/blocked network, etc.
            raise unittest.SkipTest(f"gitleaks binary unavailable: {exc}")

    def setUp(self):
        self._repo_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self._repo_dir, ignore_errors=True)
        self._reports_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self._reports_dir, ignore_errors=True)

        self._git("init", "-q")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "gitleaks redaction test")
        (self._repo_dir / "fixture.env").write_text(
            f"SLACK_WEBHOOK_URL={self.FIXTURE_SECRET}\n", encoding="utf-8"
        )
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "add fixture secret")

    def _git(self, *args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=self._repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )

    def test_redact_hides_secret_in_every_report_format(self):
        targets = [
            _ReportTarget(fmt=fmt, path=self._reports_dir / f"report.{ext}")
            for fmt, ext in sorted(_SUPPORTED_FORMATS.items())
        ]
        leaks_found = _run_gitleaks(
            self.binary,
            targets,
            # The fixture repo ships no config of its own, so this is the
            # default config the scanner would fall back to in CI.
            config_path=_resolve_config_path(self._repo_dir),
            log_opts="",
            source_dir=self._repo_dir,
            checkout_root=self._repo_dir,
        )
        self.assertTrue(leaks_found, "fixture secret was not detected at all")
        for target in targets:
            self.assertTrue(
                target.path.is_file(), f"no report written for {target.fmt}"
            )
            content = target.path.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn(
                self.FIXTURE_SECRET,
                content,
                f"fixture secret leaked into un-redacted {target.fmt} report",
            )


if __name__ == "__main__":
    unittest.main()
