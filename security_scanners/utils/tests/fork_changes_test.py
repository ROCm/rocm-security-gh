# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from security_scanners.utils.fork_changes import (
    CHANGES_FILE_ENV,
    UPSTREAM_COMMITS_ENV,
    fork_changed_paths,
    fork_only_files,
    restrict_to_fork_changes,
    select_files,
    upstream_commits,
)


class SelectFilesTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name in ("sub/a.py", "sub/b.txt", "other/c.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")

    def _is_python(self, relpath: str) -> bool:
        return relpath.endswith(".py")

    def test_keeps_existing_wanted_files_under_the_scan_path(self):
        files = select_files(
            ["sub/a.py", "sub/b.txt", "other/c.py", "sub/gone.py", ""],
            self.root / "sub",
            self.root,
            self._is_python,
        )
        self.assertEqual(files, [self.root / "sub/a.py"])

    def test_rejects_a_symlink_that_leaves_the_scan_path(self):
        (self.root / "sub" / "link.py").symlink_to(self.root / "other" / "c.py")
        files = select_files(
            ["sub/link.py"], self.root / "sub", self.root, self._is_python
        )
        self.assertEqual(files, [])

    def test_fork_only_files_is_none_outside_a_fork(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(fork_only_files(self.root, self.root, self._is_python))

    def test_fork_only_files_selects_the_fork_list(self):
        changes = self.root / "changes.json"
        changes.write_text(json.dumps(["sub/a.py", "other/c.py"]), encoding="utf-8")
        with mock.patch.dict(os.environ, {CHANGES_FILE_ENV: str(changes)}):
            files = fork_only_files(self.root / "sub", self.root, self._is_python)
        self.assertEqual(files, [self.root / "sub/a.py"])


class RestrictToForkChangesTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.changes = Path(tmp.name) / "fork-changes.txt"

    def _restrict(self, paths: list[str], **env: str) -> list[str]:
        with mock.patch.dict(os.environ, env, clear=True):
            return restrict_to_fork_changes(paths)

    def test_unset_leaves_paths_alone(self):
        self.assertEqual(self._restrict(["a.py", "b.py"]), ["a.py", "b.py"])

    def test_keeps_only_paths_the_fork_changed(self):
        self.changes.write_text("fork.py\nsub/fork.py\n", encoding="utf-8")
        result = self._restrict(
            ["fork.py", "upstream.py", "sub/fork.py"],
            **{CHANGES_FILE_ENV: str(self.changes)},
        )
        self.assertEqual(result, ["fork.py", "sub/fork.py"])

    def test_empty_fork_list_keeps_nothing(self):
        self.changes.write_text("\n", encoding="utf-8")
        result = self._restrict(["a.py"], **{CHANGES_FILE_ENV: str(self.changes)})
        self.assertEqual(result, [])

    def test_unreadable_file_does_not_filter(self):
        missing = self.changes.parent / "missing.txt"
        result = self._restrict(["a.py"], **{CHANGES_FILE_ENV: str(missing)})
        self.assertEqual(result, ["a.py"])


class ForkChangedPathsTest(unittest.TestCase):
    def test_not_a_fork_is_none(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(fork_changed_paths())

    def test_lists_paths_without_blank_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            changes = Path(tmp) / "fork-changes.txt"
            changes.write_text("a.py\n\nsub/b.py\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {CHANGES_FILE_ENV: str(changes)}):
                self.assertEqual(fork_changed_paths(), ["a.py", "sub/b.py"])

    def test_json_preserves_unicode_and_newlines_in_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            changes = Path(tmp) / "fork-changes.json"
            paths = ["café.py", "line\nbreak.py", " leading.py"]
            changes.write_text(json.dumps(paths), encoding="utf-8")
            with mock.patch.dict(os.environ, {CHANGES_FILE_ENV: str(changes)}):
                self.assertEqual(fork_changed_paths(), paths)

    def test_malformed_json_does_not_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            changes = Path(tmp) / "fork-changes.json"
            changes.write_text("[", encoding="utf-8")
            with mock.patch.dict(os.environ, {CHANGES_FILE_ENV: str(changes)}):
                self.assertIsNone(fork_changed_paths())

    def test_unreadable_file_is_none(self):
        with mock.patch.dict(os.environ, {CHANGES_FILE_ENV: "/nonexistent/x"}):
            self.assertIsNone(fork_changed_paths())


class UpstreamCommitsTest(unittest.TestCase):
    def test_splits_on_whitespace(self):
        with mock.patch.dict(os.environ, {UPSTREAM_COMMITS_ENV: "abc def"}, clear=True):
            self.assertEqual(upstream_commits(), ["abc", "def"])

    def test_unset_is_empty(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(upstream_commits(), [])


if __name__ == "__main__":
    unittest.main()
