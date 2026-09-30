# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import shutil
import tempfile
import unittest
from pathlib import Path

from security_scanners.utils.step_summary import (
    STEP_SUMMARY_BUDGET_BYTES,
    clip_to_budget,
    emit_reports,
    md_code_fence,
)


class MdCodeFenceTest(unittest.TestCase):
    """Tests for md_code_fence."""

    def test_default_three_backticks_when_no_backticks(self):
        self.assertEqual(md_code_fence("plain,csv,content"), "```")

    def test_three_backticks_when_content_has_short_runs(self):
        self.assertEqual(md_code_fence("a `b` c"), "```")

    def test_grows_beyond_triple_backtick_run(self):
        self.assertEqual(md_code_fence("before ``` after"), "````")

    def test_grows_to_longest_run(self):
        self.assertEqual(md_code_fence("x ````` y"), "``````")

    def test_fence_actually_wraps_content(self):
        content = "with ``` inside"
        fence = md_code_fence(content)
        block = f"{fence}\n{content}\n{fence}"
        # The closing fence must be on its own line and not appear within
        # the content, so the block is unambiguous.
        self.assertNotIn(fence, content)
        self.assertTrue(block.startswith(fence + "\n"))
        self.assertTrue(block.endswith("\n" + fence))


class ClipToBudgetTest(unittest.TestCase):
    """Tests for clip_to_budget."""

    def test_content_within_budget_is_untouched(self):
        self.assertEqual(clip_to_budget("a,b,c\n", 1024), ("a,b,c\n", False))

    def test_oversized_content_is_clipped_on_a_line_boundary(self):
        content = "".join(f"line{i}\n" for i in range(100))
        shown, clipped = clip_to_budget(content, 50)
        self.assertTrue(clipped)
        self.assertLessEqual(len(shown.encode("utf-8")), 50)
        # Clipping mid-record would render a partial finding in the summary.
        self.assertTrue(shown.endswith("\n"))
        self.assertTrue(content.startswith(shown))

    def test_exhausted_budget_yields_nothing(self):
        self.assertEqual(clip_to_budget("data\n", 0), ("", True))

    def test_clip_never_splits_a_multibyte_character(self):
        # Two bytes per character and no newline to fall back on, so the
        # byte-level cut lands mid-character.
        shown, clipped = clip_to_budget("é" * 100, 5)
        self.assertTrue(clipped)
        self.assertEqual(shown, "éé")


class EmitReportsTest(unittest.TestCase):
    """Tests for emit_reports' job-summary budgeting."""

    def _report(self, content: str, name: str = "report.csv") -> Path:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = Path(tmp) / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_report_within_budget_is_emitted_in_full(self):
        path = self._report("file,secret\na.txt,REDACTED\n")
        appended: list[str] = []
        emit_reports("Gitleaks", [path], appended.append)
        (summary,) = appended
        self.assertIn("### Gitleaks report:", summary)
        self.assertIn("a.txt,REDACTED", summary)
        self.assertNotIn("Truncated", summary)

    def test_oversized_report_is_truncated_and_points_at_the_artifact(self):
        path = self._report("".join(f"row{i},REDACTED\n" for i in range(200)))
        appended: list[str] = []
        emit_reports("Trivy", [path], appended.append, budget_bytes=64)
        (summary,) = appended
        self.assertIn("row0,REDACTED", summary)
        self.assertNotIn("row199,REDACTED", summary)
        self.assertIn("Truncated", summary)
        self.assertIn("artifact", summary)

    def test_budget_is_shared_across_reports(self):
        first = self._report("".join(f"row{i},REDACTED\n" for i in range(50)))
        second = self._report("second,REDACTED\n", name="second.csv")
        appended: list[str] = []
        emit_reports("Bandit", [first, second], appended.append, budget_bytes=64)
        (summary,) = appended
        # The first report consumes the budget, so the second is announced
        # but its contents are left to the artifact.
        self.assertIn("row0,REDACTED", summary)
        self.assertNotIn("second,REDACTED", summary)
        self.assertIn(str(second), summary)

    def test_default_budget_stays_under_githubs_limit(self):
        self.assertLess(STEP_SUMMARY_BUDGET_BYTES, 1024 * 1024)

    def test_missing_report_is_skipped_without_a_summary(self):
        appended: list[str] = []
        emit_reports("Zizmor", [Path("does-not-exist.csv")], appended.append)
        self.assertEqual(appended, [])


if __name__ == "__main__":
    unittest.main()
