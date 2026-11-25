# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from security_scanners.utils.codeql_scope_filter import (
    SOURCE_ROOT_FILENAME,
    FilterError,
    describe,
    filter_sarif,
    main,
    repository_path,
)

SCOPE = ("src/app",)
WRITER = "src/app/src/writer.cpp"
HEADER = "src/lib/device.hpp"


def result(rule: str, uri: str | None, line: int = 1) -> dict[str, object]:
    if uri is None:
        return {"ruleId": rule, "message": {"text": f"{rule} here"}}
    return {
        "ruleId": rule,
        "message": {"text": f"{rule} here"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def sarif(*results: dict[str, object]) -> dict[str, object]:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": list(results)}],
    }


class RepositoryPathTest(unittest.TestCase):
    def test_a_relative_uri_is_already_repository_relative(self):
        self.assertEqual(repository_path(WRITER, ""), WRITER)
        self.assertEqual(repository_path("./a//b.cpp", ""), "a/b.cpp")

    def test_a_percent_encoded_uri_is_decoded(self):
        self.assertEqual(repository_path("src/my%20file.cpp", ""), "src/my file.cpp")

    def test_an_absolute_uri_is_placed_under_the_source_root(self):
        self.assertEqual(
            repository_path(f"file:///__w/r/r/{WRITER}", "/__w/r/r"), WRITER
        )
        self.assertEqual(repository_path(f"/__w/r/r/{WRITER}", "/__w/r/r/"), WRITER)

    def test_an_absolute_uri_outside_the_source_root_is_not_in_the_repository(self):
        self.assertIsNone(repository_path("file:///usr/include/stdio.h", "/__w/r/r"))
        self.assertIsNone(repository_path("file:///__w/r/rx/a.cpp", "/__w/r/r"))

    def test_an_absolute_uri_without_a_known_root_cannot_be_placed(self):
        self.assertIsNone(repository_path("file:///__w/r/r/a.cpp", ""))

    def test_a_uri_that_climbs_out_is_not_in_the_repository(self):
        self.assertIsNone(repository_path("../x.cpp", ""))
        self.assertIsNone(repository_path("a/../../x.cpp", ""))

    def test_a_climb_that_stays_inside_is_normalised(self):
        self.assertEqual(repository_path("a/../src/app/x.cpp", ""), "src/app/x.cpp")

    def test_other_schemes_are_not_files_of_the_repository(self):
        self.assertIsNone(repository_path("https://example.com/a.cpp", ""))

    def test_a_file_uri_with_a_host_is_not_local(self):
        self.assertIsNone(repository_path("file://host/src/app/a.cpp", "/"))


class FilterSarifTest(unittest.TestCase):
    def test_results_outside_the_scope_are_dropped(self):
        headers = [
            result("cpp/a", HEADER, 10),
            result("cpp/b", "src/lib/elf.hpp", 594),
        ]
        document = sarif(*headers)
        outcome = filter_sarif(document, SCOPE)
        self.assertEqual(outcome.kept, ())
        self.assertEqual(outcome.dropped, 2)
        self.assertEqual(document["runs"][0]["results"], [])

    def test_results_in_the_scope_are_kept(self):
        kept = result("cpp/world-writable-file-creation", WRITER, 450)
        document = sarif(result("cpp/a", HEADER), kept)
        outcome = filter_sarif(document, SCOPE)
        self.assertEqual(outcome.kept, (kept,))
        self.assertEqual(outcome.dropped, 1)
        self.assertEqual(document["runs"][0]["results"], [kept])

    def test_a_directory_sharing_a_prefix_is_not_in_scope(self):
        document = sarif(
            result("cpp/x", "src/app_other/a.cpp"),
            result("cpp/x", "src/app.cpp"),
        )
        self.assertEqual(filter_sarif(document, SCOPE).kept, ())

    def test_any_of_several_scopes_will_do(self):
        document = sarif(result("cpp/x", "tools/a.cpp"), result("cpp/y", WRITER))
        outcome = filter_sarif(document, ("tools", "src/app"))
        self.assertEqual(len(outcome.kept), 2)

    def test_a_result_with_no_location_is_kept(self):
        orphan = result("cpp/x", None)
        self.assertEqual(filter_sarif(sarif(orphan), SCOPE).kept, (orphan,))

    def test_a_result_whose_location_has_no_uri_is_kept(self):
        odd = {"ruleId": "cpp/x", "locations": [{"physicalLocation": {}}]}
        self.assertEqual(filter_sarif(sarif(odd), SCOPE).kept, (odd,))

    def test_an_absolute_uri_inside_the_source_root_is_kept(self):
        inside = result("cpp/x", f"file:///__w/r/r/src/my%20app/a.cpp")
        outside = result("cpp/y", "file:///usr/include/stdio.h")
        outcome = filter_sarif(sarif(inside, outside), ("src/my app",), "/__w/r/r")
        self.assertEqual(outcome.kept, (inside,))
        artifact = inside["locations"][0]["physicalLocation"]["artifactLocation"]
        self.assertEqual(artifact["uri"], "src/my%20app/a.cpp")
        self.assertNotIn("uriBaseId", artifact)

    def test_every_run_is_filtered(self):
        kept = result("cpp/x", WRITER)
        document = {
            "runs": [{"results": [result("cpp/y", HEADER)]}, {"results": [kept]}]
        }
        outcome = filter_sarif(document, SCOPE)
        self.assertEqual(outcome.kept, (kept,))
        self.assertEqual(document["runs"][0]["results"], [])

    def test_the_rest_of_the_document_is_untouched(self):
        document = sarif(result("cpp/x", HEADER))
        filter_sarif(document, SCOPE)
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(document["runs"][0]["tool"]["driver"]["name"], "CodeQL")

    def test_a_run_without_results_is_left_alone(self):
        document = {"runs": [{"tool": {}}]}
        self.assertEqual(filter_sarif(document, SCOPE).kept, ())

    def test_a_document_without_runs_is_refused(self):
        with self.assertRaises(FilterError):
            filter_sarif({"version": "2.1.0"}, SCOPE)

    def test_a_non_array_results_value_is_refused(self):
        with self.assertRaises(FilterError):
            filter_sarif({"runs": [{"results": {}}]}, SCOPE)


class DescribeTest(unittest.TestCase):
    def test_names_file_line_rule_and_message(self):
        self.assertEqual(
            describe(result("cpp/x", WRITER, 7)), f"{WRITER}:7: cpp/x: cpp/x here"
        )

    def test_a_result_without_a_location_still_describes(self):
        self.assertEqual(
            describe(result("cpp/x", None)), "<no location>: cpp/x: cpp/x here"
        )


class MainTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self._raw = root / "raw"
        self._raw.mkdir()
        self._filtered = root / "filtered"
        self._output = root / "output"
        self._summary = root / "summary"
        self._env = {
            "GITHUB_OUTPUT": str(self._output),
            "GITHUB_STEP_SUMMARY": str(self._summary),
            "SCANNER_TARGET_NAME": "app-build",
            "SCANNER_TARGET_SCOPE": json.dumps(["src/app/"]),
            "SCANNER_SARIF_DIR": str(self._raw),
            "SCANNER_FILTERED_SARIF_DIR": str(self._filtered),
        }

    def _write(self, *results: dict[str, object], name: str = "c-cpp.sarif") -> None:
        (self._raw / name).write_text(json.dumps(sarif(*results)), encoding="utf-8")

    def _run(self) -> int:
        with mock.patch.dict(os.environ, self._env, clear=False):
            return main([])

    def _outputs(self) -> dict[str, str]:
        values: dict[str, str] = {}
        if self._output.is_file():
            for line in self._output.read_text(encoding="utf-8").splitlines():
                key, _, value = line.partition("=")
                values[key] = value
        return values

    def test_writes_the_filtered_document_and_both_outputs(self):
        kept = result("cpp/x", WRITER, 450)
        self._write(result("cpp/y", HEADER), kept)
        self.assertEqual(self._run(), 0)
        written = json.loads((self._filtered / "c-cpp.sarif").read_text("utf-8"))
        self.assertEqual(written["runs"][0]["results"], [kept])
        self.assertEqual(
            self._outputs(),
            {"sarif_path": str(self._filtered / "c-cpp.sarif"), "alerts": "1"},
        )
        self.assertIn("Results in scope: 1", self._summary.read_text("utf-8"))

    def test_zero_alerts_still_writes_a_document_to_upload(self):
        self._write(result("cpp/y", HEADER))
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._outputs()["alerts"], "0")
        self.assertTrue((self._filtered / "c-cpp.sarif").is_file())

    def test_an_absolute_uri_is_placed_with_the_recorded_source_root(self):
        (self._raw / SOURCE_ROOT_FILENAME).write_text("/__w/r/r\n", encoding="utf-8")
        self._write(result("cpp/x", f"file:///__w/r/r/{WRITER}"))
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._outputs()["alerts"], "1")
        written = json.loads((self._filtered / "c-cpp.sarif").read_text("utf-8"))
        artifact = written["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]
        self.assertEqual(artifact["uri"], WRITER)
        self.assertNotIn("uriBaseId", artifact)

    def test_exactly_one_sarif_file_is_required(self):
        self.assertEqual(self._run(), 2)
        self._write(result("cpp/x", WRITER), name="a.sarif")
        self._write(result("cpp/x", WRITER), name="b.sarif")
        self.assertEqual(self._run(), 2)
        self.assertEqual(self._outputs(), {})

    def test_unreadable_sarif_fails(self):
        (self._raw / "c-cpp.sarif").write_text("{", encoding="utf-8")
        self.assertEqual(self._run(), 2)
        (self._raw / "c-cpp.sarif").write_text("[]", encoding="utf-8")
        self.assertEqual(self._run(), 2)

    def test_a_bad_scope_fails(self):
        self._write(result("cpp/x", WRITER))
        for scope in ("", "not json", "[]", '["../x"]', "[1]", '"projects"'):
            with self.subTest(scope=scope):
                self._env["SCANNER_TARGET_SCOPE"] = scope
                self.assertEqual(self._run(), 2)

    def test_missing_directories_fail(self):
        self._env["SCANNER_SARIF_DIR"] = ""
        self.assertEqual(self._run(), 2)

    def test_takes_no_arguments(self):
        with mock.patch.dict(os.environ, self._env, clear=False):
            self.assertEqual(main(["--scope", "x"]), 2)


if __name__ == "__main__":
    unittest.main()
