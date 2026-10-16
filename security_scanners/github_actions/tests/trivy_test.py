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
    _trivy_scan_root,
    _trivy_subprocess_env,
    get_trivy_binary,
    main,
)
from security_scanners.utils.fork_changes import fork_only_files


class ForkOnlyFilesTest(unittest.TestCase):
    def test_all_mode_selects_only_fork_owned_audited_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "package.json"
            manifest.write_text("{}", encoding="utf-8")
            changes = root / "fork-changes.txt"
            changes.write_text("package.json\nREADME.md\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ, {"SCANNER_FORK_CHANGES_FILE": str(changes)}
            ):
                self.assertEqual(
                    fork_only_files(root, root, _is_audited_path), [manifest]
                )

    def test_new_ref_push_uses_the_fork_file_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "package.json"
            manifest.write_text("{}", encoding="utf-8")
            changes = root / "fork-changes.txt"
            changes.write_text("package.json\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ, {"SCANNER_FORK_CHANGES_FILE": str(changes)}
            ):
                files = _determine_changed_audited_files(
                    event_name="push",
                    event={"before": "0" * 40, "after": "def"},
                    scan_path=root,
                    checkout_root=root,
                )
        self.assertEqual(files, [manifest])

    def _staged_files(self, root: Path, selected: list[Path]) -> list[str]:
        with _trivy_scan_root(root, selected) as staged:
            return sorted(
                str(p.relative_to(staged)) for p in staged.rglob("*") if p.is_file()
            )

    def test_staging_copies_siblings_and_ancestor_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "checkout")
            infra = root / "infra"
            (infra / "nested").mkdir(parents=True)
            (root / "unrelated").mkdir()
            selected = infra / "main.tf"
            selected.write_text("resource {}\n", encoding="utf-8")
            (infra / "variables.tf").write_text("", encoding="utf-8")
            (infra / "nested" / "other.tf").write_text("", encoding="utf-8")
            (root / "pom.xml").write_text("<project/>", encoding="utf-8")
            (root / "unrelated" / "x.txt").write_text("", encoding="utf-8")
            self.assertEqual(
                self._staged_files(root, [selected]),
                ["infra/main.tf", "infra/variables.tf", "pom.xml"],
            )

    def test_a_repo_root_file_does_not_stage_the_whole_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "checkout")
            for directory in ("a", "b/deep", ".git"):
                (root / directory).mkdir(parents=True)
                (root / directory / "file.txt").write_text("", encoding="utf-8")
            selected = root / "Dockerfile"
            selected.write_text("FROM scratch\n", encoding="utf-8")
            self.assertEqual(self._staged_files(root, [selected]), ["Dockerfile"])

    def test_staging_follows_local_terraform_module_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "checkout")
            (root / "env").mkdir(parents=True)
            (root / "modules" / "vpc").mkdir(parents=True)
            (root / "modules" / "unused").mkdir()
            selected = root / "env" / "main.tf"
            selected.write_text(
                'module "vpc" {\n  source = "../modules/vpc"\n}\n'
                'module "remote" {\n  source = "hashicorp/consul/aws"\n}\n',
                encoding="utf-8",
            )
            (root / "modules" / "vpc" / "main.tf").write_text("", encoding="utf-8")
            (root / "modules" / "unused" / "main.tf").write_text("", encoding="utf-8")
            self.assertEqual(
                self._staged_files(root, [selected]),
                ["env/main.tf", "modules/vpc/main.tf"],
            )

    def test_module_references_cannot_escape_the_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "checkout")
            root.mkdir()
            outside = Path(tmp, "outside")
            outside.mkdir()
            (outside / "secret.tf").write_text("", encoding="utf-8")
            selected = root / "main.tf"
            selected.write_text(
                'module "x" {\n  source = "../outside"\n}\n', encoding="utf-8"
            )
            self.assertEqual(self._staged_files(root, [selected]), ["main.tf"])

    def test_symlinked_module_directory_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "checkout")
            outside = Path(tmp, "outside")
            root.mkdir()
            outside.mkdir()
            (outside / "module.tf").write_text("", encoding="utf-8")
            (root / "external").symlink_to(outside, target_is_directory=True)
            (root / "outside.tf").symlink_to(outside / "module.tf")
            selected = root / "main.tf"
            selected.write_text(
                'module "x" {\n  source = "./external"\n}\n', encoding="utf-8"
            )
            original = Path.read_text
            reads: list[Path] = []

            def track_read(path: Path, *args, **kwargs):
                reads.append(path.resolve())
                return original(path, *args, **kwargs)

            with mock.patch.object(Path, "read_text", track_read):
                self._staged_files(root, [selected])
            self.assertNotIn((outside / "module.tf").resolve(), reads)

    def test_staging_copies_internal_symlinks_and_skips_external_ones(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "checkout")
            root.mkdir()
            selected = root / "Dockerfile"
            selected.write_text("FROM scratch\n", encoding="utf-8")
            (root / "real.txt").write_text("content", encoding="utf-8")
            (root / "internal.txt").symlink_to(root / "real.txt")
            outside = Path(tmp, "outside.txt")
            outside.write_text("", encoding="utf-8")
            (root / "external.txt").symlink_to(outside)
            self.assertEqual(
                self._staged_files(root, [selected]),
                ["Dockerfile", "internal.txt", "real.txt"],
            )

    def test_staging_works_when_the_scan_path_contains_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp, "real")
            (real / "app").mkdir(parents=True)
            (real / "app" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (real / "pom.xml").write_text("<project/>", encoding="utf-8")
            link = Path(tmp, "link")
            link.symlink_to(real, target_is_directory=True)
            self.assertEqual(
                self._staged_files(link, [link / "app" / "Dockerfile"]),
                ["app/Dockerfile", "pom.xml"],
            )

    def test_a_selected_file_below_a_symlinked_directory_is_still_staged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "checkout")
            (root / "real").mkdir(parents=True)
            (root / "real" / "Dockerfile").write_text(
                "FROM scratch\n", encoding="utf-8"
            )
            (root / "alias").symlink_to(root / "real", target_is_directory=True)
            self.assertIn(
                "alias/Dockerfile",
                self._staged_files(root, [root / "alias" / "Dockerfile"]),
            )

    def test_a_selected_file_that_cannot_be_staged_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "checkout")
            root.mkdir()
            with self.assertRaises(RuntimeError):
                self._staged_files(root, [root / "missing" / "Dockerfile"])

    def test_nonfork_scan_uses_the_original_root(self):
        root = Path("/scan-target")
        with _trivy_scan_root(root, None) as staged:
            self.assertEqual(staged, root)


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

    def _run_all_mode(self, env: dict[str, str]) -> mock.Mock:
        with (
            mock.patch.dict(os.environ, env),
            mock.patch("trivy.gha_append_step_summary"),
            mock.patch("trivy.gha_set_output"),
            mock.patch("trivy._resolve_config_path", return_value="trivy.yaml"),
            mock.patch("trivy.get_trivy_binary", return_value=Path("trivy")),
            mock.patch(
                "trivy._run_trivy",
                return_value={sev: 0 for sev in _SEVERITY_ORDER},
            ) as run_trivy,
        ):
            self.assertEqual(
                main(["--scan-mode", "all", "--source-dir", self._root]), 0
            )
        return run_trivy

    def test_fork_scan_hands_trivy_only_fork_owned_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._root = tmp
            manifest = Path(tmp, "package.json")
            manifest.write_text("{}", encoding="utf-8")
            changes = Path(tmp, "fork-changes.txt")
            changes.write_text("package.json\n", encoding="utf-8")
            run_trivy = self._run_all_mode(
                {
                    "SCANNER_FORK_CHANGES_FILE": str(changes),
                    "SCANNER_CHECKOUT_ROOT": tmp,
                }
            )
        self.assertEqual(run_trivy.call_args.kwargs["scan_files"], [manifest])

    def test_nonfork_scan_hands_trivy_the_whole_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._root = tmp
            with mock.patch.dict(os.environ, {}, clear=True):
                run_trivy = self._run_all_mode({})
        self.assertIsNone(run_trivy.call_args.kwargs["scan_files"])


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
        # filtered in as though it were a manifest, so that a changed
        # .trivyignore counts too. See ConfigChangeWidensTheScanTest.
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
        # .trivyignore in particular was invisible to the manifest/IaC
        # filter, so suppressing a CVE could land without a single scan
        # confirming what it suppressed.
        for config in ("trivy.yaml", "trivy.yml", ".trivyignore"):
            with self.subTest(config=config):
                self.assertIsNone(self._changed(f"{config}\n"))

    def test_config_change_alongside_other_files_still_widens(self):
        self.assertIsNone(self._changed("README.md\n.trivyignore\n"))

    def test_config_change_on_a_fork_widens_only_to_fork_files(self):
        manifest = Path("package.json")
        manifest.write_text("{}", encoding="utf-8")
        changes = Path("fork-changes.txt")
        changes.write_text(".trivyignore\npackage.json\n", encoding="utf-8")
        with mock.patch.dict(
            os.environ, {"SCANNER_FORK_CHANGES_FILE": str(changes.resolve())}
        ):
            self.assertEqual(self._changed(".trivyignore\n"), [manifest])

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
        for config in ("trivy.yaml", ".trivyignore"):
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
    """Tests that a scanned repository's `.trivyignore` is honoured."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _run(
        self, ignore_path: Path | None, scan_files: list[Path] | None = None
    ) -> list[str]:
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
                scan_files=scan_files,
            )
        return commands[0]

    def test_ignorefile_is_passed_when_the_target_ships_one(self):
        # trivy resolves .trivyignore against its working directory, which
        # is this repo's checkout, so a scanned repository's accepted-risk
        # entries only apply if the path is explicit.
        ignore_path = self._tmp_root / ".trivyignore"
        ignore_path.write_text("CVE-2021-44228\n", encoding="utf-8")
        cmd = self._run(ignore_path)
        self.assertIn("--ignorefile", cmd)
        self.assertEqual(cmd[cmd.index("--ignorefile") + 1], str(ignore_path))

    def test_no_ignorefile_flag_when_the_target_ships_none(self):
        self.assertNotIn("--ignorefile", self._run(None))

    def _scoped_run(self, formats: list[str]):
        """Run a fork-scoped `_run_trivy` against a stub; return (commands, counts, outputs)."""
        selected = self._tmp_root / "Dockerfile"
        selected.write_text("FROM scratch\n", encoding="utf-8")
        (self._tmp_root / "upstream.Dockerfile").write_text("x\n", encoding="utf-8")
        raw_report = {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [{"Severity": "HIGH"}],
                },
                {
                    "Target": "upstream.Dockerfile",
                    "Misconfigurations": [{"Severity": "CRITICAL"}] * 3,
                },
            ]
        }
        commands: list[list[str]] = []
        converted_inputs: list[dict] = []

        def fake_run(cmd, **kwargs):
            commands.append(cmd)
            output = Path(cmd[cmd.index("--output") + 1])
            if cmd[1] == "convert":
                converted_inputs.append(json.loads(Path(cmd[-1]).read_text("utf-8")))
                output.write_text("converted", encoding="utf-8")
            else:
                output.write_text(json.dumps(raw_report), encoding="utf-8")
            return mock.Mock(returncode=0, stdout="", stderr="")

        targets = [
            _ReportTarget(fmt=fmt, path=self._tmp_root / f"report.{fmt}")
            for fmt in formats
        ]
        with mock.patch("trivy.subprocess.run", side_effect=fake_run):
            counts = _run_trivy(
                Path("trivy"),
                targets,
                config_path="trivy.yaml",
                scanners=["misconfig"],
                scan_path=self._tmp_root,
                scan_files=[selected],
            )
        return commands, counts, converted_inputs

    def test_scoped_run_scans_once_and_converts_the_filtered_report(self):
        commands, counts, converted = self._scoped_run(["sarif", "table"])
        scans = [c for c in commands if c[1] == "fs"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(
            [c[c.index("--format") + 1] for c in commands if c[1] == "convert"],
            ["sarif", "table"],
        )
        # Context files stay in the scanned tree but never reach a report.
        self.assertEqual(
            [[r["Target"] for r in report["Results"]] for report in converted],
            [["Dockerfile"], ["Dockerfile"]],
        )
        self.assertEqual(counts["HIGH"], 1)
        self.assertEqual(counts["CRITICAL"], 0)

    def test_scoped_run_never_skips_files_or_grows_with_directory_size(self):
        commands, _, _ = self._scoped_run(["sarif"])
        for cmd in commands:
            self.assertNotIn("--skip-files", cmd)

    def test_scoped_json_report_holds_only_selected_targets(self):
        self._scoped_run(["json"])
        report = json.loads((self._tmp_root / "report.json").read_text("utf-8"))
        self.assertEqual([r["Target"] for r in report["Results"]], ["Dockerfile"])

    def test_package_list_is_requested_only_for_sbom_formats(self):
        for formats, expected in (
            (["sarif"], False),
            (["sarif", "cyclonedx"], True),
            (["spdx-json"], True),
        ):
            with self.subTest(formats=formats):
                commands, _, _ = self._scoped_run(formats)
                scan = next(c for c in commands if c[1] == "fs")
                self.assertEqual("--list-all-pkgs" in scan, expected)


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
