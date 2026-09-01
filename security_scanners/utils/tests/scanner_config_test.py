# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import tempfile
import unittest
from pathlib import Path

from security_scanners.utils.scanner_config import (
    find_config_change,
    resolve_ignore_file,
    resolve_scanner_config,
)


class ResolveScannerConfigTest(unittest.TestCase):
    """Tests for `resolve_scanner_config`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self._target_root = self._tmp_root / "scan-target"
        self._target_root.mkdir()
        self._fallback = self._tmp_root / "default.toml"
        self._fallback.write_text("# org default\n", encoding="utf-8")

    def _resolve(self, candidates=("tool.toml", ".tool.toml")):
        return resolve_scanner_config(
            scanner="tool",
            checkout_root=self._target_root,
            candidates=candidates,
            fallback=self._fallback,
        )

    def test_falls_back_when_the_target_ships_no_config(self):
        resolved = self._resolve()
        self.assertEqual(resolved.path, self._fallback)
        self.assertFalse(resolved.from_scan_target)

    def test_target_config_wins_over_the_default(self):
        target_config = self._target_root / "tool.toml"
        target_config.write_text("# repo's own\n", encoding="utf-8")
        resolved = self._resolve()
        self.assertEqual(resolved.path, target_config)
        self.assertTrue(resolved.from_scan_target)

    def test_candidates_are_tried_in_order(self):
        # Both spellings present: the first candidate is the one the tool
        # itself would prefer, so it has to win regardless of which the
        # filesystem happens to list first.
        preferred = self._target_root / "tool.toml"
        preferred.write_text("# preferred\n", encoding="utf-8")
        (self._target_root / ".tool.toml").write_text("# fallback\n", encoding="utf-8")
        self.assertEqual(self._resolve().path, preferred)

    def test_later_candidate_is_used_when_the_first_is_absent(self):
        dotfile = self._target_root / ".tool.toml"
        dotfile.write_text("# dotfile\n", encoding="utf-8")
        self.assertEqual(self._resolve().path, dotfile)

    def test_a_directory_named_like_the_config_is_not_a_config(self):
        (self._target_root / "tool.toml").mkdir()
        self.assertEqual(self._resolve().path, self._fallback)

    def test_nested_candidate_paths_are_supported(self):
        # zizmor's second home is .github/zizmor.yml.
        (self._target_root / ".github").mkdir()
        nested = self._target_root / ".github" / "tool.toml"
        nested.write_text("# nested\n", encoding="utf-8")
        resolved = self._resolve(candidates=("tool.toml", ".github/tool.toml"))
        self.assertEqual(resolved.path, nested)

    def test_missing_default_is_an_error_not_an_unconfigured_scan(self):
        # No config anywhere means the tooling checkout is broken. Running
        # the scanner on tool defaults would quietly change what is being
        # enforced, so this fails instead.
        self._fallback.unlink()
        with self.assertRaises(FileNotFoundError) as ctx:
            self._resolve()
        self.assertIn(str(self._fallback), str(ctx.exception))


class FindConfigChangeTest(unittest.TestCase):
    """Tests for `find_config_change`."""

    FILENAMES = (".github/tool.yml", "tool.yml", ".toolignore")

    def _find(self, *changed: str) -> str | None:
        return find_config_change(changed, filenames=self.FILENAMES)

    def test_no_config_in_the_diff(self):
        self.assertIsNone(self._find("src/main.py", "README.md"))

    def test_finds_a_root_config(self):
        self.assertEqual(self._find("README.md", "tool.yml"), "tool.yml")

    def test_finds_a_nested_config(self):
        self.assertEqual(self._find(".github/tool.yml"), ".github/tool.yml")

    def test_finds_an_ignore_file(self):
        self.assertEqual(self._find(".toolignore"), ".toolignore")

    def test_same_name_in_a_subdirectory_does_not_count(self):
        # Only the repository root (and the exact nested paths listed)
        # hold a config the scanner will read; a fixture or doc copy
        # deeper in the tree is just another file.
        self.assertIsNone(self._find("docs/tool.yml", "tests/fixtures/.toolignore"))

    def test_trailing_whitespace_from_git_output_is_ignored(self):
        self.assertEqual(self._find("tool.yml\n"), "tool.yml")


class ResolveIgnoreFileTest(unittest.TestCase):
    """Tests for `resolve_ignore_file`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._target_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_returns_none_when_the_target_ships_no_ignore_file(self):
        self.assertIsNone(
            resolve_ignore_file(
                scanner="tool", checkout_root=self._target_root, filename=".toolignore"
            )
        )

    def test_returns_the_targets_ignore_file(self):
        ignore_file = self._target_root / ".toolignore"
        ignore_file.write_text("fingerprint-1\n", encoding="utf-8")
        self.assertEqual(
            resolve_ignore_file(
                scanner="tool", checkout_root=self._target_root, filename=".toolignore"
            ),
            ignore_file,
        )


if __name__ == "__main__":
    unittest.main()
