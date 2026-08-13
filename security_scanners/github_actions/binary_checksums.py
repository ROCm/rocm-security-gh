#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Download and verify third-party scanner artifacts.

Shared by every scanner script that downloads a release artifact at run
time (gitleaks.py, trivy.py, zizmor.py, bandit.py, ...): each resolves
its own artifact URL/filename and calls `download_and_verify_tarball()`
(for a release tarball containing a single binary) or
`download_and_verify_file()` (for a standalone file, e.g. a Python
wheel), both of which look up the expected digest recorded in this
repo's shared `checksums.sha256` and refuse to use the artifact on a
mismatch.
"""

import hashlib
import re
import tarfile
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

CHECKSUMS_FILENAME = "checksums.sha256"
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
_DEFAULT_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB guardrail
_DEFAULT_TIMEOUT_SECONDS = 60


def sha256_of(path: Path) -> str:
    """Return the SHA-256 of `path` as a lowercase hex string."""
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def expected_sha256(repo_root: Path, filename: str) -> str:
    """Return the pinned SHA-256 digest for `filename` from `repo_root/checksums.sha256`.

    Fails closed (raises) rather than falling back to any default: a
    missing file, a malformed line, or no entry for `filename` must all
    block use of the artifact, not silently skip verification.
    """
    checksums_path = repo_root / CHECKSUMS_FILENAME
    if not checksums_path.is_file():
        raise FileNotFoundError(f"checksums file not found at '{checksums_path}'")
    for lineno, raw_line in enumerate(
        checksums_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError(
                f"{checksums_path}:{lineno}: malformed line {raw_line!r} "
                "(expected '<sha256>  <filename>')"
            )
        digest, entry_name = parts
        entry_name = entry_name.lstrip("*")  # sha256sum binary-mode marker
        if entry_name != filename:
            continue
        if not _SHA256_HEX_RE.fullmatch(digest):
            raise ValueError(
                f"{checksums_path}:{lineno}: '{digest}' is not a valid "
                "64-character lowercase hex SHA-256 digest"
            )
        return digest
    raise ValueError(f"No checksum entry for '{filename}' in {checksums_path}")


def _download_to_file(
    url: str,
    dest: Path,
    *,
    max_bytes: int,
    timeout_seconds: int,
) -> None:
    """Stream `url` into `dest`, aborting once `max_bytes` is exceeded."""
    with (
        urlopen(Request(url), timeout=timeout_seconds) as resp,
        open(dest, "wb") as out,
    ):
        written = 0
        chunk = resp.read(1024 * 1024)
        while chunk:
            if written + len(chunk) > max_bytes:
                raise RuntimeError(
                    f"download exceeds {max_bytes} bytes (source: {url})"
                )
            out.write(chunk)
            written += len(chunk)
            chunk = resp.read(1024 * 1024)


def download_and_verify_file(
    *,
    url: str,
    expected_sha256: str,
    dest_path: Path,
    max_bytes: int = _DEFAULT_MAX_DOWNLOAD_BYTES,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> Path:
    """Download `url` to `dest_path`, verifying its SHA-256 before keeping it.

    Unlike `download_and_verify_tarball()`, this doesn't extract
    anything -- for artifacts that are used as-is (e.g. a Python wheel
    handed to `pip install <path>`) rather than unpacked. The digest is
    checked before `dest_path` is written; a mismatched digest or an
    oversized download leaves no file behind and raises `RuntimeError`.
    """
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=dest_path.parent, prefix=f".{dest_path.name}.", suffix=".part", delete=False
    ) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _download_to_file(
            url, tmp_path, max_bytes=max_bytes, timeout_seconds=timeout_seconds
        )
        actual_sha256 = sha256_of(tmp_path)
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                f"file SHA256 mismatch: expected {expected_sha256} (from "
                f"{CHECKSUMS_FILENAME}), got {actual_sha256} (downloaded "
                f"from {url}). Refusing to use this artifact."
            )
        tmp_path.replace(dest_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    return dest_path


def download_and_verify_tarball(
    *,
    url: str,
    expected_sha256: str,
    member_name: str,
    install_dir: Path,
    max_bytes: int = _DEFAULT_MAX_DOWNLOAD_BYTES,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> Path:
    """Download `url`, verify its SHA-256, then extract `member_name` into `install_dir`.

    The digest is checked before anything is extracted, so a mismatch
    (or an oversized download) never reaches `tarfile`. Extraction uses
    the `"data"` filter, which rejects absolute paths, `..` traversal,
    device files, and most symlink tricks. Returns the path to the
    extracted member; raises `RuntimeError` if the digest doesn't match,
    the download exceeds `max_bytes`, or the tarball doesn't contain
    `member_name`.
    """
    install_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tarball_path = Path(tmp.name)
    try:
        _download_to_file(
            url, tarball_path, max_bytes=max_bytes, timeout_seconds=timeout_seconds
        )
        actual_sha256 = sha256_of(tarball_path)
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                f"tarball SHA256 mismatch: expected {expected_sha256} (from "
                f"{CHECKSUMS_FILENAME}), got {actual_sha256} (downloaded "
                f"from {url}). Refusing to use this artifact."
            )
        with tarfile.open(tarball_path, mode="r:gz") as tar:
            member = tar.getmember(member_name)
            tar.extract(member, path=install_dir, filter="data")
    finally:
        tarball_path.unlink(missing_ok=True)

    extracted = install_dir / member_name
    if not extracted.is_file():
        raise RuntimeError(
            f"tarball from {url} did not contain a '{member_name}' file at {extracted}"
        )
    return extracted
