#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Look up pinned SHA-256 digests for downloaded scanner binaries.

Shared by every scanner script that downloads a release tarball at run
time (gitleaks.py, trivy.py, ...): each resolves its own tarball
filename and asks `expected_sha256()` for the digest recorded in this
repo's shared `checksums.sha256`, then refuses to use the binary on a
mismatch.
"""

import re
from pathlib import Path

CHECKSUMS_FILENAME = "checksums.sha256"
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")


def expected_sha256(repo_root: Path, filename: str) -> str:
    """Return the pinned SHA-256 digest for `filename` from `repo_root/checksums.sha256`."""
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
