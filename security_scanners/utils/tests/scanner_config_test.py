# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import tempfile
import unittest
from pathlib import Path

from security_scanners.utils.scanner_config import (
    find_config_change,
    ignore_file_paths,
    resolve_ignore_file,
    resolve_scanner_config,
    scanner_config_paths,
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

    def test_explicit_nested_config_path_wins(self):
        nested = self._target_root / "security_tools" / "tool.yaml"
        nested.parent.mkdir()
        nested.write_text("# repository config\n", encoding="utf-8")
        conventional = self._target_root / "tool.toml"
        conventional.write_text("# conventional config\n", encoding="utf-8")
        resolved = resolve_scanner_config(
            scanner="tool",
            checkout_root=self._target_root,
            candidates=("tool.toml",),
            fallback=self._fallback,
            configured_path="security_tools/tool.yaml",
        )
        self.assertEqual(resolved.path, nested)

    def test_missing_explicit_config_does_not_fall_back(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            resolve_scanner_config(
                scanner="tool",
                checkout_root=self._target_root,
                candidates=("tool.toml",),
                fallback=self._fallback,
                configured_path="security_tools/missing.yaml",
            )
        self.assertIn("security_tools/missing.yaml", str(ctx.exception))

    def test_explicit_config_must_stay_inside_checkout(self):
        outside = self._tmp_root / "outside.toml"
        outside.write_text("# outside\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            resolve_scanner_config(
                scanner="tool",
                checkout_root=self._target_root,
                candidates=("tool.toml",),
                fallback=self._fallback,
                configured_path="../outside.toml",
            )

    def test_explicit_config_symlink_must_stay_inside_checkout(self):
        outside = self._tmp_root / "outside.toml"
        outside.write_text("# outside\n", encoding="utf-8")
        link = self._target_root / "tool.toml"
        link.symlink_to(outside)
        with self.assertRaises(ValueError):
            resolve_scanner_config(
                scanner="tool",
                checkout_root=self._target_root,
                candidates=("tool.toml",),
                fallback=self._fallback,
                configured_path="tool.toml",
            )

    def test_missing_default_is_an_error_not_an_unconfigured_scan(self):
        # No config anywhere means the tooling checkout is broken. Running
        # the scanner on tool defaults would quietly change what is being
        # enforced, so this fails instead.
        self._fallback.unlink()
        with self.assertRaises(FileNotFoundError) as ctx:
            self._resolve()
        self.assertIn(str(self._fallback), str(ctx.exception))


class ScannerConfigPathsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._target_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_defaults_are_preserved_when_no_override_is_set(self):
        self.assertEqual(
            scanner_config_paths(
                checkout_root=self._target_root,
                configured_path="",
                candidates=("tool.yml", ".tool.yml"),
            ),
            ("tool.yml", ".tool.yml"),
        )

    def test_explicit_path_is_normalized_for_git_diff_output(self):
        self.assertEqual(
            scanner_config_paths(
                checkout_root=self._target_root,
                configured_path="./security_tools/../security_tools/tool.yml",
                candidates=("tool.yml",),
            ),
            ("security_tools/tool.yml",),
        )

    def test_absolute_path_is_rejected(self):
        with self.assertRaises(ValueError):
            scanner_config_paths(
                checkout_root=self._target_root,
                configured_path="/tmp/tool.yml",
                candidates=("tool.yml",),
            )


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
                scanner="tool",
                checkout_root=self._target_root,
                filenames=(".toolignore",),
            )
        )

    def test_returns_the_targets_ignore_file(self):
        ignore_file = self._target_root / ".toolignore"
        ignore_file.write_text("fingerprint-1\n", encoding="utf-8")
        self.assertEqual(
            resolve_ignore_file(
                scanner="tool",
                checkout_root=self._target_root,
                filenames=(".toolignore",),
            ),
            ignore_file,
        )

    def test_ignore_file_beside_an_explicit_config_is_found(self):
        beside = self._target_root / "security_tools" / ".toolignore"
        beside.parent.mkdir()
        beside.write_text("fingerprint-1\n", encoding="utf-8")
        self.assertEqual(
            resolve_ignore_file(
                scanner="tool",
                checkout_root=self._target_root,
                filenames=(".toolignore",),
                configured_path="security_tools/tool.yml",
            ),
            beside,
        )

    def test_ignore_file_beside_the_config_wins_over_the_root_one(self):
        # Only one path is returned, never both.
        beside = self._target_root / "security_tools" / ".toolignore"
        beside.parent.mkdir()
        beside.write_text("beside\n", encoding="utf-8")
        (self._target_root / ".toolignore").write_text("root\n", encoding="utf-8")
        self.assertEqual(
            resolve_ignore_file(
                scanner="tool",
                checkout_root=self._target_root,
                filenames=(".toolignore",),
                configured_path="security_tools/tool.yml",
            ),
            beside,
        )

    def test_root_ignore_file_still_applies_to_an_explicit_config(self):
        root_ignore = self._target_root / ".toolignore"
        root_ignore.write_text("root\n", encoding="utf-8")
        (self._target_root / "security_tools").mkdir()
        self.assertEqual(
            resolve_ignore_file(
                scanner="tool",
                checkout_root=self._target_root,
                filenames=(".toolignore",),
                configured_path="security_tools/tool.yml",
            ),
            root_ignore,
        )

    def test_ignore_file_beside_an_unconfigured_config_is_not_searched(self):
        # Without an explicit path the only location is the root, so a
        # same-named file in a subdirectory is just another file.
        nested = self._target_root / "security_tools" / ".toolignore"
        nested.parent.mkdir()
        nested.write_text("nested\n", encoding="utf-8")
        self.assertIsNone(
            resolve_ignore_file(
                scanner="tool",
                checkout_root=self._target_root,
                filenames=(".toolignore",),
            )
        )

    def test_explicit_config_path_outside_the_checkout_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_ignore_file(
                scanner="tool",
                checkout_root=self._target_root,
                filenames=(".toolignore",),
                configured_path="../tool.yml",
            )

    def test_ignore_file_symlink_must_stay_inside_checkout(self):
        outside = self._target_root.parent / "outside.toolignore"
        outside.write_text("fingerprint-1\n", encoding="utf-8")
        self.addCleanup(outside.unlink)
        (self._target_root / ".toolignore").symlink_to(outside)
        with self.assertRaises(ValueError):
            resolve_ignore_file(
                scanner="tool",
                checkout_root=self._target_root,
                filenames=(".toolignore",),
            )


class IgnoreFilePathsTest(unittest.TestCase):
    """Tests for `ignore_file_paths`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._target_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _paths(self, configured_path: str) -> tuple[str, ...]:
        return ignore_file_paths(
            checkout_root=self._target_root,
            configured_path=configured_path,
            filenames=(".toolignore",),
        )

    def test_no_explicit_config_means_the_root_only(self):
        self.assertEqual(self._paths(""), (".toolignore",))

    def test_nested_config_adds_its_directory_ahead_of_the_root(self):
        self.assertEqual(
            self._paths(".github/scan_tools_configs/tool.yml"),
            (".github/scan_tools_configs/.toolignore", ".toolignore"),
        )

    def test_root_level_explicit_config_does_not_duplicate_the_root(self):
        self.assertEqual(self._paths("tool.yml"), (".toolignore",))

    def test_explicit_path_is_normalized(self):
        self.assertEqual(
            self._paths("./security_tools/../security_tools/tool.yml"),
            ("security_tools/.toolignore", ".toolignore"),
        )

    def test_multiple_names_preserve_precedence(self):
        self.assertEqual(
            ignore_file_paths(
                checkout_root=self._target_root,
                configured_path=".github/scan_tools_configs/tool.yml",
                filenames=(".toolignore.yaml", ".toolignore"),
            ),
            (
                ".github/scan_tools_configs/.toolignore.yaml",
                ".github/scan_tools_configs/.toolignore",
                ".toolignore.yaml",
                ".toolignore",
            ),
        )

    def test_absolute_path_is_rejected(self):
        with self.assertRaises(ValueError):
            self._paths("/tmp/tool.yml")


if __name__ == "__main__":
    unittest.main()
