# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, os.fspath(Path(__file__).parent.parent))
from binary_checksums import CHECKSUMS_FILENAME, expected_sha256


class ExpectedSha256Test(unittest.TestCase):
    """Tests for `expected_sha256`."""

    _VALID_DIGEST = "a" * 64

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _write_checksums(self, content: str) -> None:
        (self._tmp_root / CHECKSUMS_FILENAME).write_text(content, encoding="utf-8")

    def test_returns_digest_for_matching_filename(self):
        self._write_checksums(f"{self._VALID_DIGEST}  some_tool_1.0.0.tar.gz\n")
        self.assertEqual(
            expected_sha256(self._tmp_root, "some_tool_1.0.0.tar.gz"),
            self._VALID_DIGEST,
        )

    def test_ignores_comments_and_blank_lines(self):
        self._write_checksums(
            f"# a comment\n\n{self._VALID_DIGEST}  some_tool_1.0.0.tar.gz\n"
        )
        self.assertEqual(
            expected_sha256(self._tmp_root, "some_tool_1.0.0.tar.gz"),
            self._VALID_DIGEST,
        )

    def test_multiple_tools_coexist(self):
        self._write_checksums(
            f"{self._VALID_DIGEST}  gitleaks_8.30.1_linux_x64.tar.gz\n"
            f"{'b' * 64}  trivy_0.70.0_Linux-64bit.tar.gz\n"
        )
        self.assertEqual(
            expected_sha256(self._tmp_root, "trivy_0.70.0_Linux-64bit.tar.gz"),
            "b" * 64,
        )

    def test_strips_sha256sum_binary_mode_marker(self):
        self._write_checksums(f"{self._VALID_DIGEST} *some_tool_1.0.0.tar.gz\n")
        self.assertEqual(
            expected_sha256(self._tmp_root, "some_tool_1.0.0.tar.gz"),
            self._VALID_DIGEST,
        )

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            expected_sha256(self._tmp_root, "some_tool_1.0.0.tar.gz")
        self.assertIn(str(self._tmp_root / CHECKSUMS_FILENAME), str(ctx.exception))

    def test_no_entry_for_filename_raises(self):
        self._write_checksums(f"{self._VALID_DIGEST}  some_tool_1.0.0.tar.gz\n")
        with self.assertRaises(ValueError) as ctx:
            expected_sha256(self._tmp_root, "some_tool_2.0.0.tar.gz")
        self.assertIn("some_tool_2.0.0.tar.gz", str(ctx.exception))

    def test_malformed_line_raises(self):
        self._write_checksums("not-a-valid-line\n")
        with self.assertRaises(ValueError) as ctx:
            expected_sha256(self._tmp_root, "some_tool_1.0.0.tar.gz")
        self.assertIn("malformed line", str(ctx.exception))

    def test_invalid_digest_raises(self):
        self._write_checksums("not-hex  some_tool_1.0.0.tar.gz\n")
        with self.assertRaises(ValueError) as ctx:
            expected_sha256(self._tmp_root, "some_tool_1.0.0.tar.gz")
        self.assertIn("not a valid", str(ctx.exception))

    def test_wrong_length_digest_raises(self):
        self._write_checksums("abc123  some_tool_1.0.0.tar.gz\n")
        with self.assertRaises(ValueError):
            expected_sha256(self._tmp_root, "some_tool_1.0.0.tar.gz")


if __name__ == "__main__":
    unittest.main()
