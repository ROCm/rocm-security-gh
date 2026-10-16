# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from security_scanners.utils.compute_codeql_matrix import DiscoveryError
from security_scanners.utils.compute_fork_diff import (
    ForkDiff,
    compute_fork_diff,
    main,
)

_TIP = "b" * 40


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit(repo: Path, name: str, content: str) -> str:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", f"edit {name}")
    return _git(repo, "rev-parse", "HEAD")


class ForkDiffTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name) / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        self.merge_base = _commit(self.repo, "shared.py", "x = 1\n")
        _commit(self.repo, "fork/only.py", "y = 1\n")
        self.head = _commit(self.repo, "shared.py", "x = 2\n")

    def _compare(self, payload: object, branch: str = "main"):
        def fetcher(path: str) -> object:
            self.requested = path
            if isinstance(payload, Exception):
                raise payload
            return payload

        return compute_fork_diff(
            fetcher,
            repository="ROCm/llvm-project",
            upstream_repository="llvm/llvm-project",
            upstream_branch=branch,
            head_sha=self.head,
            checkout_root=self.repo,
        )

    def _payload(self, merge_base: str | None = None) -> dict[str, object]:
        return {
            "merge_base_commit": {"sha": merge_base or self.merge_base},
            "base_commit": {"sha": _TIP},
        }

    def test_lists_files_changed_since_the_merge_base(self):
        result = self._compare(self._payload())
        self.assertEqual(
            result,
            ForkDiff(self.merge_base, _TIP, ("fork/only.py", "shared.py")),
        )
        self.assertEqual(
            self.requested,
            f"/repos/ROCm/llvm-project/compare/llvm:main...{self.head}?per_page=1",
        )

    def test_preserves_paths_git_would_quote_in_line_delimited_output(self):
        unicode_path = "fork/café.py"
        newline_path = "fork/line\nbreak.py"
        _commit(self.repo, unicode_path, "x = 1\n")
        self.head = _commit(self.repo, newline_path, "x = 1\n")
        result = self._compare(self._payload())
        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn(unicode_path, result.paths)
        self.assertIn(newline_path, result.paths)

    def test_api_failure_means_no_filter(self):
        self.assertIsNone(self._compare(DiscoveryError("boom")))

    def test_encodes_the_upstream_branch_as_one_path_component(self):
        self._compare(self._payload(), "release/7.0#stable")
        self.assertIn("llvm:release%2F7.0%23stable...", self.requested)

    def test_missing_merge_base_means_no_filter(self):
        self.assertIsNone(self._compare({"base_commit": {"sha": _TIP}}))

    def test_unreachable_merge_base_means_no_filter(self):
        self.assertIsNone(self._compare(self._payload("c" * 40)))


class MainTest(unittest.TestCase):
    def test_unresolvable_head_sets_empty_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            env = {
                "GITHUB_OUTPUT": str(output),
                "SCANNER_CHECKOUT_ROOT": tmp,
            }
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(main([]), 0)
            text = output.read_text(encoding="utf-8")
            self.assertIn("changes_file=\n", text)
            self.assertIn("upstream_commits=\n", text)

    def test_writes_the_changes_file_and_upstream_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")
            merge_base = _commit(repo, "shared.py", "x = 1\n")
            head = _commit(repo, "fork/only.py", "y = 1\n")
            output = Path(tmp) / "output"
            env = {
                "GITHUB_OUTPUT": str(output),
                "GITHUB_REPOSITORY": "ROCm/llvm-project",
                "RUNNER_TEMP": tmp,
                "SCANNER_CHECKOUT_ROOT": str(repo),
                "SCANNER_UPSTREAM_REPOSITORY": "llvm/llvm-project",
                "SCANNER_UPSTREAM_DEFAULT_BRANCH": "main",
            }
            payload = {
                "merge_base_commit": {"sha": merge_base},
                "base_commit": {"sha": _TIP},
            }
            with (
                mock.patch.dict(os.environ, env, clear=True),
                mock.patch(
                    "security_scanners.utils.compute_fork_diff.github_get",
                    return_value=payload,
                ),
            ):
                self.assertEqual(main([]), 0)
            text = output.read_text(encoding="utf-8")
            changes = Path(tmp, "fork-changes.json")
            self.assertEqual(json.loads(changes.read_text("utf-8")), ["fork/only.py"])
            self.assertIn(f"changes_file={changes}\n", text)
            self.assertIn(f"upstream_commits={merge_base} {_TIP}\n", text)
            self.assertNotEqual(head, merge_base)

    def test_unexpected_arguments_are_rejected(self):
        self.assertEqual(main(["--nope"]), 2)


if __name__ == "__main__":
    unittest.main()
