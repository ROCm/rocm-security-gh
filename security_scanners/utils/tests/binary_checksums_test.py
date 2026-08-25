# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import hashlib
import tempfile
import tarfile
import unittest
from pathlib import Path

from security_scanners.utils.binary_checksums import (
    CHECKSUMS_FILENAME,
    download_and_verify_file,
    download_and_verify_tarball,
    expected_sha256,
    sha256_of,
)


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
            f"{'b' * 64}  bandit-1.9.4.tar.gz\n"
        )
        self.assertEqual(
            expected_sha256(self._tmp_root, "bandit-1.9.4.tar.gz"),
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


class Sha256OfTest(unittest.TestCase):
    """Tests for `sha256_of`."""

    def test_matches_hashlib(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"some binary content")
            path = Path(tmp.name)
        self.addCleanup(path.unlink, missing_ok=True)
        self.assertEqual(
            sha256_of(path), hashlib.sha256(b"some binary content").hexdigest()
        )


class DownloadAndVerifyTarballTest(unittest.TestCase):
    """Tests for `download_and_verify_tarball`, using `file://` URLs so
    these run fully offline."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _make_tarball(self, member_name: str, content: bytes) -> tuple[Path, str]:
        member_path = self._tmp_root / member_name
        member_path.write_bytes(content)
        tarball_path = self._tmp_root / "artifact.tar.gz"
        with tarfile.open(tarball_path, mode="w:gz") as tar:
            tar.add(member_path, arcname=member_name)
        return tarball_path, sha256_of(tarball_path)

    def test_extracts_member_on_matching_digest(self):
        tarball_path, digest = self._make_tarball("some-tool", b"#!/bin/sh\necho hi\n")
        install_dir = self._tmp_root / "install"
        extracted = download_and_verify_tarball(
            url=tarball_path.as_uri(),
            expected_sha256=digest,
            member_name="some-tool",
            install_dir=install_dir,
        )
        self.assertEqual(extracted, install_dir / "some-tool")
        self.assertEqual(extracted.read_bytes(), b"#!/bin/sh\necho hi\n")

    def test_mismatched_digest_raises_and_extracts_nothing(self):
        tarball_path, _ = self._make_tarball("some-tool", b"payload")
        install_dir = self._tmp_root / "install"
        with self.assertRaises(RuntimeError) as ctx:
            download_and_verify_tarball(
                url=tarball_path.as_uri(),
                expected_sha256="0" * 64,
                member_name="some-tool",
                install_dir=install_dir,
            )
        self.assertIn("SHA256 mismatch", str(ctx.exception))
        self.assertFalse((install_dir / "some-tool").exists())

    def test_missing_member_raises(self):
        tarball_path, digest = self._make_tarball("some-tool", b"payload")
        with self.assertRaises(KeyError):
            download_and_verify_tarball(
                url=tarball_path.as_uri(),
                expected_sha256=digest,
                member_name="wrong-name",
                install_dir=self._tmp_root / "install",
            )

    def test_oversized_download_raises(self):
        tarball_path, digest = self._make_tarball("some-tool", b"x" * 1000)
        with self.assertRaises(RuntimeError) as ctx:
            download_and_verify_tarball(
                url=tarball_path.as_uri(),
                expected_sha256=digest,
                member_name="some-tool",
                install_dir=self._tmp_root / "install",
                max_bytes=10,
            )
        self.assertIn("exceeds", str(ctx.exception))


class DownloadAndVerifyFileTest(unittest.TestCase):
    """Tests for `download_and_verify_file`, using `file://` URLs so
    these run fully offline."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._tmp_root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _make_source_file(self, content: bytes) -> tuple[Path, str]:
        source_path = self._tmp_root / "source" / "artifact.whl"
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(content)
        return source_path, sha256_of(source_path)

    def test_writes_dest_on_matching_digest(self):
        source_path, digest = self._make_source_file(b"wheel contents")
        dest_path = self._tmp_root / "install" / "artifact.whl"
        result = download_and_verify_file(
            url=source_path.as_uri(),
            expected_sha256=digest,
            dest_path=dest_path,
        )
        self.assertEqual(result, dest_path)
        self.assertEqual(dest_path.read_bytes(), b"wheel contents")

    def test_mismatched_digest_raises_and_writes_nothing(self):
        source_path, _ = self._make_source_file(b"payload")
        dest_path = self._tmp_root / "install" / "artifact.whl"
        with self.assertRaises(RuntimeError) as ctx:
            download_and_verify_file(
                url=source_path.as_uri(),
                expected_sha256="0" * 64,
                dest_path=dest_path,
            )
        self.assertIn("SHA256 mismatch", str(ctx.exception))
        self.assertFalse(dest_path.exists())

    def test_oversized_download_raises(self):
        source_path, digest = self._make_source_file(b"x" * 1000)
        dest_path = self._tmp_root / "install" / "artifact.whl"
        with self.assertRaises(RuntimeError) as ctx:
            download_and_verify_file(
                url=source_path.as_uri(),
                expected_sha256=digest,
                dest_path=dest_path,
                max_bytes=10,
            )
        self.assertIn("exceeds", str(ctx.exception))
        self.assertFalse(dest_path.exists())


if __name__ == "__main__":
    unittest.main()
