# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import unittest

from security_scanners.utils.pr_findings import (
    COMMENT_BUDGET_CHARS,
    COMMENT_MARKER,
    MAX_COMMENT_ROWS,
    ChangedFile,
    Finding,
    LineRange,
    changed_files_from_api,
    filter_changed_findings,
    parse_bandit,
    parse_codeql_sarif,
    parse_gitleaks,
    parse_patch,
    parse_trivy,
    parse_zizmor,
    render_comment,
)


class ReportParserTest(unittest.TestCase):
    def test_parses_gitleaks(self):
        findings = parse_gitleaks(
            [
                {
                    "RuleID": "generic-api-key",
                    "Description": "API key",
                    "File": ".scan-target/src/config.py",
                    "StartLine": 12,
                    "EndLine": 13,
                    "Fingerprint": "abc",
                    "Commit": "0123456789ABCDEF0123456789abcdef01234567",
                }
            ]
        )
        self.assertEqual(
            findings[0],
            Finding(
                scanner="Gitleaks",
                severity="HIGH",
                rule_id="generic-api-key",
                path="src/config.py",
                start_line=12,
                end_line=13,
                message="API key",
                fingerprint="abc",
                commit="0123456789abcdef0123456789abcdef01234567",
                secret=True,
            ),
        )

    def test_drops_a_gitleaks_commit_that_is_not_an_object_id(self):
        findings = parse_gitleaks(
            [
                {
                    "RuleID": "generic-api-key",
                    "File": "src/config.py",
                    "StartLine": 1,
                    "Commit": "main/../../evil",
                }
            ]
        )
        self.assertEqual(findings[0].commit, "")

    def test_marks_only_trivy_secrets_as_secrets(self):
        findings = parse_trivy(
            {
                "Results": [
                    {
                        "Target": "config/.env",
                        "Secrets": [
                            {
                                "RuleID": "aws-access-key-id",
                                "Severity": "CRITICAL",
                                "Title": "AWS Access Key ID",
                                "StartLine": 3,
                                "EndLine": 3,
                            }
                        ],
                        "Vulnerabilities": [
                            {"VulnerabilityID": "CVE-2026-1", "Severity": "HIGH"}
                        ],
                    }
                ]
            }
        )
        self.assertEqual(
            {finding.rule_id: finding.secret for finding in findings},
            {"aws-access-key-id": True, "CVE-2026-1": False},
        )

    def test_parses_bandit(self):
        findings = parse_bandit(
            {
                "results": [
                    {
                        "test_id": "B602",
                        "issue_text": "shell=True",
                        "filename": "./tools/run.py",
                        "line_number": 20,
                        "line_range": [20, 21],
                        "issue_severity": "HIGH",
                    }
                ]
            }
        )
        self.assertEqual(findings[0].path, "tools/run.py")
        self.assertEqual((findings[0].start_line, findings[0].end_line), (20, 21))
        self.assertEqual(findings[0].rule_id, "B602")

    def test_parses_trivy_categories(self):
        findings = parse_trivy(
            {
                "Results": [
                    {
                        "Target": ".scan-target/requirements.txt",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-1",
                                "Severity": "CRITICAL",
                                "Title": "Unsafe dependency",
                            }
                        ],
                        "Misconfigurations": [
                            {
                                "ID": "AVD-AWS-1",
                                "Severity": "MEDIUM",
                                "Message": "Public resource",
                                "CauseMetadata": {
                                    "Path": ".scan-target/main.tf",
                                    "StartLine": 7,
                                    "EndLine": 8,
                                },
                            }
                        ],
                        "Licenses": [
                            {
                                "Name": "GPL-3.0",
                                "Severity": "HIGH",
                                "PkgName": "example",
                            }
                        ],
                    }
                ]
            }
        )
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0].rule_id, "CVE-2026-1")
        self.assertEqual(findings[1].path, "main.tf")
        self.assertEqual(findings[2].rule_id, "GPL-3.0")

    def test_parses_zizmor_primary_location(self):
        findings = parse_zizmor(
            [
                {
                    "ident": "template-injection",
                    "desc": "Template injection",
                    "url": "https://docs.zizmor.sh/audits/template-injection/",
                    "determinations": {"severity": "High"},
                    "locations": [
                        {
                            "symbolic": {
                                "kind": "Primary",
                                "key": {
                                    "Local": {
                                        "verbatim_path": "./.github/workflows/ci.yml"
                                    }
                                },
                            },
                            "concrete": {
                                "location": {
                                    "start_point": {"row": 6, "column": 2},
                                    "end_point": {"row": 7, "column": 0},
                                }
                            },
                        }
                    ],
                    "ignored": False,
                }
            ]
        )
        self.assertEqual(findings[0].path, ".github/workflows/ci.yml")
        self.assertEqual((findings[0].start_line, findings[0].end_line), (7, 7))
        self.assertEqual(findings[0].severity, "HIGH")

    def test_parses_codeql_rule_metadata(self):
        findings = parse_codeql_sarif(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "cpp/sql-injection",
                                        "properties": {"security-severity": "9.3"},
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "cpp/sql-injection",
                                "message": {"text": "Untrusted SQL"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/db.cpp"},
                                            "region": {
                                                "startLine": 30,
                                                "endLine": 31,
                                            },
                                        }
                                    }
                                ],
                                "partialFingerprints": {
                                    "primaryLocationLineHash": "hash"
                                },
                            }
                        ],
                    }
                ],
            }
        )
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(findings[0].fingerprint, "hash")

    def test_rejects_wrong_top_level_schema(self):
        with self.assertRaises(ValueError):
            parse_gitleaks({})
        with self.assertRaises(ValueError):
            parse_bandit([])
        with self.assertRaises(ValueError):
            parse_trivy([])
        with self.assertRaises(ValueError):
            parse_zizmor({})
        with self.assertRaises(ValueError):
            parse_codeql_sarif([])


class ChangedLineFilterTest(unittest.TestCase):
    def test_parses_new_side_added_lines(self):
        patch = (
            "@@ -4,3 +4,4 @@\n"
            " context\n"
            "+first\n"
            "-old\n"
            "+second\n"
            " context\n"
            "@@ -20 +22,2 @@\n"
            "+third\n"
            "+fourth\n"
        )
        self.assertEqual(
            parse_patch(patch),
            (LineRange(5, 6), LineRange(22, 23)),
        )

    def test_filters_ranges_file_level_deleted_and_missing_patch(self):
        changed = changed_files_from_api(
            [
                {
                    "filename": "src/a.py",
                    "status": "modified",
                    "patch": "@@ -9 +9,2 @@\n old\n+new\n",
                },
                {"filename": "requirements.txt", "status": "modified"},
                {"filename": "src/b.py", "status": "modified"},
                {"filename": "removed.py", "status": "removed"},
            ]
        )
        findings = [
            Finding("Bandit", "HIGH", "B1", "src/a.py", 10, 10, "match"),
            Finding("Bandit", "HIGH", "B2", "src/a.py", 9, 9, "old line"),
            Finding(
                "Trivy",
                "HIGH",
                "CVE-1",
                "requirements.txt",
                None,
                None,
                "file finding",
            ),
            Finding("Bandit", "HIGH", "B3", "src/b.py", 5, 5, "no patch"),
            Finding(
                "Trivy",
                "HIGH",
                "CVE-2",
                "removed.py",
                None,
                None,
                "deleted",
            ),
        ]
        result = filter_changed_findings(findings, changed)
        self.assertEqual(
            [finding.rule_id for finding in result.findings], ["CVE-1", "B1"]
        )
        self.assertEqual(result.unfilterable_paths, ("src/b.py",))

    def test_deduplicates_and_sorts_by_severity(self):
        changed = {
            "a.py": ChangedFile(
                path="a.py",
                status="modified",
                line_ranges=(LineRange(1, 3),),
                patch_available=True,
            )
        }
        duplicate = Finding("Bandit", "LOW", "B1", "a.py", 1, 1, "low", "same")
        result = filter_changed_findings(
            [
                duplicate,
                duplicate,
                Finding("Bandit", "CRITICAL", "B2", "a.py", 2, 2, "critical"),
            ],
            changed,
        )
        self.assertEqual(
            [finding.severity for finding in result.findings], ["CRITICAL", "LOW"]
        )

    def test_keeps_commit_scoped_findings_absent_from_the_final_diff(self):
        # The secret was added in one commit and deleted in a later one, so
        # the final diff has neither the file's line nor, here, the file.
        changed = {
            "a.py": ChangedFile(
                path="a.py",
                status="modified",
                line_ranges=(LineRange(1, 3),),
                patch_available=True,
            )
        }
        leaked = Finding(
            "Gitleaks", "HIGH", "aws", "old.env", 4, 4, "key", commit="abc1234"
        )
        self.assertEqual(filter_changed_findings([leaked], changed).findings, ())
        self.assertEqual(
            filter_changed_findings(
                [leaked], changed, commit_scoped_scanners=frozenset({"Gitleaks"})
            ).findings,
            (leaked,),
        )

    def test_sorts_secrets_ahead_of_more_severe_findings(self):
        changed = {
            "a.py": ChangedFile(
                path="a.py",
                status="modified",
                line_ranges=(LineRange(1, 3),),
                patch_available=True,
            )
        }
        result = filter_changed_findings(
            [
                Finding("Bandit", "CRITICAL", "B1", "a.py", 1, 1, "critical"),
                Finding("Trivy", "LOW", "key", "a.py", 2, 2, "key", secret=True),
            ],
            changed,
        )
        self.assertEqual(
            [finding.rule_id for finding in result.findings], ["key", "B1"]
        )

    def test_keeps_distinct_rules_sharing_a_location_fingerprint(self):
        # CodeQL's primaryLocationLineHash identifies the line, not the
        # finding, so two rules flagging one line share a fingerprint.
        changed = {
            "a.cpp": ChangedFile(
                path="a.cpp",
                status="modified",
                line_ranges=(LineRange(1, 20),),
                patch_available=True,
            )
        }
        result = filter_changed_findings(
            [
                Finding(
                    "CodeQL", "HIGH", "cpp/sql", "a.cpp", 10, 10, "sql", "linehash"
                ),
                Finding(
                    "CodeQL", "HIGH", "cpp/cmd", "a.cpp", 10, 10, "cmd", "linehash"
                ),
            ],
            changed,
        )
        self.assertEqual(
            [finding.rule_id for finding in result.findings],
            ["cpp/cmd", "cpp/sql"],
        )


class RenderCommentTest(unittest.TestCase):
    def test_escapes_untrusted_markdown_and_links_to_head(self):
        finding = Finding(
            "Bad|scanner",
            "HIGH",
            "`rule`",
            "src/a file.py",
            4,
            5,
            "<script>alert(1)</script>\n[next](https://bad) | @team",
        )
        body = render_comment(
            [finding],
            repository="ROCm/example",
            head_sha="abc123",
            run_url="https://github.com/ROCm/example/actions/runs/1",
        )
        self.assertIn(COMMENT_MARKER, body)
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)
        self.assertIn("Bad\\|scanner", body)
        self.assertNotIn("[next](https://bad)", body)
        self.assertIn("&#64;team", body)
        self.assertIn("src/a%20file.py#L4-L5", body)

    def test_warns_to_rotate_secrets_and_links_to_their_commit(self):
        findings = [
            Finding(
                "Gitleaks",
                "HIGH",
                "aws",
                "old.env",
                4,
                4,
                "AWS key",
                commit="def5678",
                secret=True,
            ),
            Finding("Trivy", "HIGH", "gh-pat", "a.py", 2, 2, "PAT", secret=True),
            Finding("Bandit", "HIGH", "B602", "a.py", 9, 9, "shell=True"),
        ]
        body = render_comment(
            findings,
            repository="ROCm/example",
            head_sha="abc123",
            run_url="https://github.com/ROCm/example/actions/runs/1",
        )
        self.assertIn("> [!CAUTION]", body)
        self.assertIn("**2 potential secret finding(s)", body)
        self.assertIn("revoke or rotate it now", body)
        self.assertLess(body.index("[!CAUTION]"), body.index("<details>"))
        self.assertIn("/blob/def5678/old.env#L4", body)
        self.assertIn("/blob/abc123/a.py#L2", body)

    def test_omits_the_rotation_warning_without_secrets(self):
        body = render_comment(
            [Finding("Bandit", "HIGH", "B602", "a.py", 9, 9, "shell=True")],
            repository="ROCm/example",
            head_sha="abc123",
            run_url="https://github.com/ROCm/example/actions/runs/1",
        )
        self.assertNotIn("[!CAUTION]", body)

    def test_caps_table_at_fifty_rows(self):
        findings = [
            Finding("Bandit", "HIGH", f"B{index}", "a.py", index, index, "finding")
            for index in range(1, 56)
        ]
        body = render_comment(
            findings,
            repository="ROCm/example",
            head_sha="abc123",
            run_url="https://github.com/ROCm/example/actions/runs/1",
        )
        self.assertEqual(body.count("\n| Bandit |"), 50)
        self.assertIn("5 additional finding(s)", body)

    def test_stays_under_github_limit_when_escaping_inflates_cells(self):
        # "@" escapes to the five-character "&#64;" and "é" percent-encodes to
        # six characters in a link, so every cell grows well past its clip
        # length; fifty such rows alone would be about twice GitHub's limit.
        findings = [
            Finding(
                "Gitleaks",
                "CRITICAL",
                "@" * 200,
                ("@" * 150 if index % 2 else "é" * 158) + f"{index}.py",
                1,
                1,
                "@" * 400,
            )
            for index in range(500)
        ]
        body = render_comment(
            findings,
            repository="ROCm/example",
            head_sha="a" * 40,
            run_url="https://github.com/ROCm/example/actions/runs/1",
            incomplete_reasons=tuple("@" * 400 for _ in range(50)),
        )
        self.assertLessEqual(len(body), COMMENT_BUDGET_CHARS)
        shown = body.count("\n| Gitleaks |")
        self.assertGreater(shown, 0)
        self.assertLess(shown, MAX_COMMENT_ROWS)
        self.assertIn(f"{500 - shown} additional finding(s)", body)
        self.assertIn("more coverage note(s) are omitted", body)

    def test_counts_every_finding_when_no_row_fits(self):
        findings = [Finding("Bandit", "HIGH", "B1", "a.py", 1, 1, "x" * 200)]
        body = render_comment(
            findings,
            repository="ROCm/example",
            head_sha="abc123",
            run_url="https://github.com/ROCm/example/actions/runs/1",
            budget_chars=600,
        )
        self.assertLessEqual(len(body), 600)
        self.assertNotIn("| Scanner |", body)
        self.assertIn("found 1 critical or high finding(s)", body)
        self.assertIn("1 additional finding(s) are omitted", body)

    def test_collapses_the_table_behind_a_one_line_summary(self):
        body = render_comment(
            [Finding("Bandit", "HIGH", "B602", "a.py", 9, 9, "shell=True")],
            repository="ROCm/example",
            head_sha="abc123",
            run_url="https://github.com/ROCm/example/actions/runs/1",
            incomplete_reasons=("CodeQL did not run",),
        )
        self.assertIn(
            "<details>\n<summary><b>Security scan found 1 critical or high "
            "finding(s) on lines changed by this pull request (coverage "
            "incomplete)</b></summary>\n\n| Scanner |",
            body,
        )
        self.assertLess(body.index("| Scanner |"), body.index("</details>"))
        self.assertLess(body.index("CodeQL did not run"), body.index("</details>"))
        self.assertTrue(body.endswith("</details>"))

    def test_lists_only_critical_high_and_secrets_and_counts_the_rest(self):
        body = render_comment(
            [
                Finding("Bandit", "CRITICAL", "B1", "a.py", 1, 1, "critical"),
                Finding("Bandit", "HIGH", "B2", "a.py", 2, 2, "high"),
                Finding("Trivy", "LOW", "gh-pat", "a.py", 3, 3, "PAT", secret=True),
                Finding("Bandit", "MEDIUM", "B3", "a.py", 4, 4, "medium"),
                Finding("Bandit", "LOW", "B4", "a.py", 5, 5, "low"),
                Finding("Trivy", "UNKNOWN", "CVE-1", "a.py", None, None, "unrated"),
            ],
            repository="ROCm/example",
            head_sha="abc123",
            run_url="https://github.com/ROCm/example/actions/runs/1",
        )
        self.assertEqual(body.count("\n| Bandit |") + body.count("\n| Trivy |"), 3)
        for rule in ("B3", "B4", "CVE-1"):
            self.assertNotIn(f"| {rule} |", body)
        self.assertIn("found 3 critical, high, or secret finding(s)", body)
        self.assertIn("3 medium, low, or unrated finding(s) are not listed", body)

    def test_reports_no_findings_when_only_lower_severities_exist(self):
        body = render_comment(
            [Finding("Bandit", "MEDIUM", "B3", "a.py", 4, 4, "medium")],
            repository="ROCm/example",
            head_sha="abc123",
            run_url="https://github.com/ROCm/example/actions/runs/1",
        )
        self.assertIn("found no critical or high findings", body)
        self.assertNotIn("| Scanner |", body)
        self.assertIn("1 medium, low, or unrated finding(s)", body)


if __name__ == "__main__":
    unittest.main()
