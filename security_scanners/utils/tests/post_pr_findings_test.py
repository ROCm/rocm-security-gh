# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import http.server
import io
import json
import os
import stat
import tempfile
import threading
import unittest
import urllib.error
import zipfile
from collections.abc import Mapping
from unittest import mock

from security_scanners.utils import post_pr_findings
from security_scanners.utils.post_pr_findings import (
    GitHubApi,
    GitHubApiError,
    PullRequestContext,
    SkipRun,
    collect_findings,
    file_list_gap_reason,
    job_coverage_reasons,
    read_artifact_reports,
    require_unchanged_head,
    resolve_pull_request,
    update_sticky_comment,
)
from security_scanners.utils.pr_findings import COMMENT_MARKER


class FakeApi:
    def __init__(self):
        self.arrays: dict[str, list[object]] = {}
        self.keyed: dict[tuple[str, str], list[object]] = {}
        self.responses: dict[tuple[str, str], object] = {}
        self.downloads: dict[str, bytes | RuntimeError] = {}
        self.requests: list[tuple[str, str, Mapping[str, object] | None]] = []

    def paginated_array(self, path: str) -> list[object]:
        return self.arrays.get(path, [])

    def paginated_key(self, path: str, key: str) -> list[object]:
        return self.keyed.get((path, key), [])

    def json(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, object] | None = None,
    ) -> object:
        self.requests.append((method, path, body))
        response = self.responses.get((method, path), {})
        if isinstance(response, Exception):
            raise response
        return response

    def bytes(self, path: str) -> bytes:
        value = self.downloads[path]
        if isinstance(value, RuntimeError):
            raise value
        return value


def make_zip(files: Mapping[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return output.getvalue()


def pull_request_event(head_repository: str = "ROCm/example") -> dict[str, object]:
    return {
        "action": "synchronize",
        "pull_request": {
            "number": 7,
            "head": {
                "sha": "abc123",
                "ref": "feature",
                "repo": {"full_name": head_repository},
            },
        },
    }


def pull_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "base": {"repo": {"full_name": "ROCm/example"}},
        "head": {
            "sha": "abc123",
            "ref": "feature",
            "repo": {"full_name": "ROCm/example"},
        },
    }
    payload.update(overrides)
    return payload


def context() -> PullRequestContext:
    return PullRequestContext(
        repository="ROCm/example",
        number=7,
        head_sha="abc123",
        run_id=42,
        run_url="https://github.com/ROCm/example/actions/runs/42",
    )


def resolve(api: "FakeApi", event: Mapping[str, object]) -> PullRequestContext:
    return resolve_pull_request(
        api,  # type: ignore[arg-type]
        event,
        repository="ROCm/example",
        run_id=42,
        run_url="https://github.com/ROCm/example/actions/runs/42",
    )


class ResolvePullRequestTest(unittest.TestCase):
    def _api(self, payload: dict[str, object]) -> "FakeApi":
        api = FakeApi()
        api.responses[("GET", "/repos/ROCm/example/pulls/7")] = payload
        return api

    def test_accepts_pull_request_from_a_branch_of_this_repository(self):
        resolved = resolve(
            self._api(pull_payload(changed_files=12)), pull_request_event()
        )
        self.assertEqual(resolved.number, 7)
        self.assertEqual(resolved.head_sha, "abc123")
        self.assertEqual(resolved.run_id, 42)
        self.assertEqual(resolved.changed_file_count, 12)

    def test_defaults_the_changed_file_count_when_absent(self):
        resolved = resolve(self._api(pull_payload()), pull_request_event())
        self.assertEqual(resolved.changed_file_count, 0)

    def test_skips_fork_without_calling_the_api(self):
        api = FakeApi()
        with self.assertRaisesRegex(SkipRun, "fork"):
            resolve(api, pull_request_event(head_repository="contributor/example"))
        self.assertEqual(api.requests, [])

    def test_skips_superseded_head(self):
        api = self._api(
            pull_payload(
                head={
                    "sha": "newer",
                    "ref": "feature",
                    "repo": {"full_name": "ROCm/example"},
                }
            )
        )
        with self.assertRaisesRegex(SkipRun, "superseded"):
            resolve(api, pull_request_event())

    def test_skips_event_without_pull_request(self):
        with self.assertRaisesRegex(SkipRun, "no pull_request object"):
            resolve(FakeApi(), {"action": "opened"})


class SafeArtifactTest(unittest.TestCase):
    def test_reads_expected_json_and_ignores_human_report(self):
        archive = make_zip(
            {
                "bandit-report.txt": b"reviewer output",
                "bandit-report.json": json.dumps({"results": []}).encode(),
            }
        )
        reports = read_artifact_reports("bandit-report", archive)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].scanner, "bandit")

    def test_reads_codeql_sarif(self):
        archive = make_zip(
            {"cpp.sarif": json.dumps({"version": "2.1.0", "runs": []}).encode()}
        )
        reports = read_artifact_reports("codeql-report-cpp", archive)
        self.assertEqual(reports[0].scanner, "codeql")

    def test_rejects_path_traversal(self):
        archive = make_zip({"../bandit-report.json": b'{"results":[]}'})
        with self.assertRaisesRegex(ValueError, "unsafe ZIP member"):
            read_artifact_reports("bandit-report", archive)

    def test_rejects_symlink(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            info = zipfile.ZipInfo("bandit-report.json")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"target")
        with self.assertRaisesRegex(ValueError, "unsafe ZIP member"):
            read_artifact_reports("bandit-report", output.getvalue())

    def test_rejects_unexpected_members(self):
        archive = make_zip(
            {
                "bandit-report.json": b'{"results":[]}',
                "payload.sh": b"echo unsafe",
            }
        )
        with self.assertRaisesRegex(ValueError, "unexpected file"):
            read_artifact_reports("bandit-report", archive)

    def test_rejects_too_many_members(self):
        archive = make_zip({f"{index}.txt": b"x" for index in range(21)})
        with self.assertRaisesRegex(ValueError, "too many files"):
            read_artifact_reports("codeql-report-cpp", archive)


class GitHubApiPaginationTest(unittest.TestCase):
    def test_reads_multiple_pages(self):
        api = mock.Mock(spec=GitHubApi)
        api.json.side_effect = [[{"id": index} for index in range(100)], [{"id": 100}]]
        result = GitHubApi.paginated_array(api, "/items")
        self.assertEqual(len(result), 101)
        self.assertEqual(api.json.call_count, 2)


class CollectionAndCoverageTest(unittest.TestCase):
    def test_records_invalid_and_missing_failed_reports(self):
        api = FakeApi()
        artifact_path = "/repos/ROCm/example/actions/runs/42/artifacts"
        api.keyed[(artifact_path, "artifacts")] = [
            {"id": 1, "name": "bandit-report", "expired": False},
            {"id": 2, "name": "trivy-report", "expired": False},
        ]
        api.downloads["/repos/ROCm/example/actions/artifacts/1/zip"] = make_zip(
            {"bandit-report.json": b'{"results":[]}'}
        )
        api.downloads["/repos/ROCm/example/actions/artifacts/2/zip"] = RuntimeError(
            "download failed"
        )
        collected = collect_findings(api, context())  # type: ignore[arg-type]
        self.assertEqual(collected.observed_scanners, frozenset({"bandit"}))
        self.assertIn(
            "Trivy report could not be processed", collected.incomplete_reasons[0]
        )

        jobs_path = "/repos/ROCm/example/actions/runs/42/jobs"
        api.keyed[(jobs_path, "jobs")] = [
            {"name": "security / Bandit", "conclusion": "failure"},
            {"name": "security / Gitleaks", "conclusion": "cancelled"},
            {"name": "security / CodeQL / cpp", "conclusion": "failure"},
            {
                "name": "security / Trivy",
                "conclusion": "success",
                "steps": [
                    {
                        "name": "Upload non-SARIF reports",
                        "conclusion": "success",
                    }
                ],
            },
        ]
        reasons = job_coverage_reasons(
            api, context(), collected.observed_scanners  # type: ignore[arg-type]
        )
        self.assertEqual(len(reasons), 3)
        self.assertIn("Gitleaks", reasons[0])
        self.assertIn("CodeQL", reasons[1])
        self.assertIn("no usable", reasons[2])


class RequireUnchangedHeadTest(unittest.TestCase):
    def _api(self, payload: object) -> "FakeApi":
        api = FakeApi()
        api.responses[("GET", "/repos/ROCm/example/pulls/7")] = payload
        return api

    def test_accepts_the_scanned_head(self):
        api = self._api(pull_payload())
        require_unchanged_head(api, context())  # type: ignore[arg-type]

    def test_skips_when_a_push_moved_the_head(self):
        api = self._api(
            pull_payload(
                head={
                    "sha": "def456789012",
                    "ref": "feature",
                    "repo": {"full_name": "contributor/example"},
                }
            )
        )
        with self.assertRaisesRegex(SkipRun, "head moved to def456789012"):
            require_unchanged_head(api, context())  # type: ignore[arg-type]

    def test_skips_when_the_pull_request_is_unreadable(self):
        api = self._api("not an object")
        with self.assertRaisesRegex(SkipRun, "no longer readable"):
            require_unchanged_head(api, context())  # type: ignore[arg-type]

    def test_skips_when_the_head_is_missing(self):
        api = self._api(pull_payload(head={"ref": "feature"}))
        with self.assertRaisesRegex(SkipRun, "no longer reports a head commit"):
            require_unchanged_head(api, context())  # type: ignore[arg-type]


class FileListGapTest(unittest.TestCase):
    def test_reports_the_files_github_never_described(self):
        reason = file_list_gap_reason(3000, 4200)
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertIn("only 3,000", reason)
        self.assertIn("4,200 changed files", reason)
        self.assertIn("remaining 1,200", reason)

    def test_stays_silent_on_a_complete_list(self):
        self.assertIsNone(file_list_gap_reason(12, 12))

    def test_stays_silent_without_a_changed_file_count(self):
        self.assertIsNone(file_list_gap_reason(12, 0))

    def test_stays_silent_when_the_list_is_longer_than_the_count(self):
        self.assertIsNone(file_list_gap_reason(13, 12))


class StickyCommentTest(unittest.TestCase):
    def test_updates_bot_owned_marker_comment(self):
        api = FakeApi()
        comments_path = "/repos/ROCm/example/issues/7/comments"
        api.arrays[comments_path] = [
            {
                "id": 10,
                "body": COMMENT_MARKER,
                "user": {"login": "contributor", "type": "User"},
            },
            {
                "id": 11,
                "body": f"{COMMENT_MARKER}\nold",
                "user": {"login": "github-actions[bot]", "type": "Bot"},
            },
        ]
        update_sticky_comment(api, context(), "new body")  # type: ignore[arg-type]
        self.assertIn(
            (
                "PATCH",
                "/repos/ROCm/example/issues/comments/11",
                {"body": "new body"},
            ),
            api.requests,
        )

    def test_creates_comment_when_marker_is_absent(self):
        api = FakeApi()
        update_sticky_comment(api, context(), "new body")  # type: ignore[arg-type]
        self.assertIn(
            (
                "POST",
                "/repos/ROCm/example/issues/7/comments",
                {"body": "new body"},
            ),
            api.requests,
        )

    def test_drops_comment_when_the_token_cannot_write(self):
        api = FakeApi()
        post_path = "/repos/ROCm/example/issues/7/comments"
        api.responses[("POST", post_path)] = GitHubApiError("denied", 403)
        with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            update_sticky_comment(api, context(), "new body")  # type: ignore[arg-type]
        self.assertIn("could not write the findings comment", stderr.getvalue())

    def test_drops_comment_when_github_is_unavailable(self):
        api = FakeApi()
        comments_path = "/repos/ROCm/example/issues/7/comments"
        api.arrays[comments_path] = [
            {
                "id": 11,
                "body": COMMENT_MARKER,
                "user": {"login": "github-actions[bot]", "type": "Bot"},
            }
        ]
        patch_path = "/repos/ROCm/example/issues/comments/11"
        api.responses[("PATCH", patch_path)] = GitHubApiError("bad gateway", 502)
        with mock.patch("sys.stderr", new_callable=io.StringIO):
            update_sticky_comment(api, context(), "new body")  # type: ignore[arg-type]

    def test_raises_when_the_body_is_rejected(self):
        api = FakeApi()
        post_path = "/repos/ROCm/example/issues/7/comments"
        api.responses[("POST", post_path)] = GitHubApiError("unprocessable", 422)
        with self.assertRaises(GitHubApiError):
            update_sticky_comment(api, context(), "new body")  # type: ignore[arg-type]

    def test_raises_when_the_request_never_reached_github(self):
        api = FakeApi()
        post_path = "/repos/ROCm/example/issues/7/comments"
        api.responses[("POST", post_path)] = GitHubApiError("connection reset")
        with self.assertRaises(GitHubApiError):
            update_sticky_comment(api, context(), "new body")  # type: ignore[arg-type]


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    """Answers every GET with `status`, recording the Authorization it saw."""

    status = 200
    location = ""
    seen_authorization: list[str | None]

    def do_GET(self):
        self.seen_authorization.append(self.headers.get("Authorization"))
        self.send_response(self.status)
        if self.location:
            self.send_header("Location", self.location)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"PK")

    def log_message(self, *args: object) -> None:
        pass


def _serve(handler: type[_RecordingHandler]) -> http.server.ThreadingHTTPServer:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class GitHubApiRedirectTest(unittest.TestCase):
    def test_token_is_not_sent_to_the_redirect_target(self):
        # The artifact endpoint answers with a redirect to a storage host;
        # only the API host may receive the token.
        storage_seen: list[str | None] = []
        storage_handler = type(
            "Storage", (_RecordingHandler,), {"seen_authorization": storage_seen}
        )
        storage = _serve(storage_handler)
        self.addCleanup(storage.shutdown)
        api_seen: list[str | None] = []
        api_handler = type(
            "Api",
            (_RecordingHandler,),
            {
                "seen_authorization": api_seen,
                "status": 302,
                "location": f"http://127.0.0.1:{storage.server_port}/blob",
            },
        )
        api_server = _serve(api_handler)
        self.addCleanup(api_server.shutdown)

        api = GitHubApi("secret-token", f"http://127.0.0.1:{api_server.server_port}")
        self.assertEqual(
            api.bytes("/repos/ROCm/example/actions/artifacts/1/zip"), b"PK"
        )
        self.assertEqual(api_seen, ["Bearer secret-token"])
        self.assertEqual(storage_seen, [None])

    def test_rejects_paths_outside_the_api_root(self):
        api = GitHubApi("token")
        with self.assertRaisesRegex(ValueError, "must start with '/'"):
            api.json("GET", "https://attacker.example/steal")


class GitHubApiErrorTest(unittest.TestCase):
    def test_carries_the_response_status(self):
        api = GitHubApi("token")
        error = urllib.error.HTTPError("https://api", 403, "Forbidden", {}, None)  # type: ignore[arg-type]
        with mock.patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(GitHubApiError) as caught:
                api.json("POST", "/repos/ROCm/example/issues/7/comments", body={})
        self.assertEqual(caught.exception.status, 403)

    def test_has_no_status_without_a_response(self):
        api = GitHubApi("token")
        error = urllib.error.URLError("connection reset")
        with mock.patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(GitHubApiError) as caught:
                api.json("GET", "/repos/ROCm/example/pulls/7")
        self.assertIsNone(caught.exception.status)


class MainTest(unittest.TestCase):
    def _run(
        self,
        api: "FakeApi",
        event_name: str = "pull_request",
        scan_mode: str = "changed",
    ) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            event_path = os.path.join(directory, "event.json")
            with open(event_path, "w", encoding="utf-8") as event_file:
                json.dump(pull_request_event(), event_file)
            environment = {
                "GITHUB_EVENT_NAME": event_name,
                "GITHUB_EVENT_PATH": event_path,
                "GITHUB_REPOSITORY": "ROCm/example",
                "GITHUB_RUN_ID": "42",
                "GITHUB_TOKEN": "token",
                "SCANNER_SCAN_MODE": scan_mode,
            }
            with (
                mock.patch.dict(os.environ, environment),
                mock.patch.object(post_pr_findings, "GitHubApi", return_value=api),
                mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                return post_pr_findings.main(), stderr.getvalue()

    def test_warns_instead_of_failing_when_the_caller_granted_no_permission(self):
        api = FakeApi()
        api.responses[("GET", "/repos/ROCm/example/pulls/7")] = GitHubApiError(
            "forbidden", 403
        )
        status, stderr = self._run(api)
        self.assertEqual(status, 0)
        self.assertIn("pull-requests: write", stderr)
        self.assertIn("actions: read", stderr)

    def test_fails_on_other_api_errors(self):
        api = FakeApi()
        api.responses[("GET", "/repos/ROCm/example/pulls/7")] = GitHubApiError(
            "not found", 404
        )
        with self.assertRaises(SystemExit) as caught:
            self._run(api)
        self.assertEqual(caught.exception.code, 1)

    def test_skips_other_events(self):
        api = FakeApi()
        status, _ = self._run(api, event_name="push")
        self.assertEqual(status, 0)
        self.assertEqual(api.requests, [])

    def test_posts_a_comment_for_a_same_repository_pull_request(self):
        api = FakeApi()
        api.responses[("GET", "/repos/ROCm/example/pulls/7")] = pull_payload()
        status, _ = self._run(api)
        self.assertEqual(status, 0)
        posts = [request for request in api.requests if request[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][1], "/repos/ROCm/example/issues/7/comments")
        body = posts[0][2]
        assert body is not None
        self.assertIn(
            "https://github.com/ROCm/example/actions/runs/42", str(body["body"])
        )

    def test_scopes_gitleaks_to_pull_request_commits_only_in_changed_mode(self):
        for scan_mode, expected in (
            ("changed", frozenset({"Gitleaks"})),
            ("all", frozenset()),
            ("", frozenset()),
        ):
            with self.subTest(scan_mode=scan_mode):
                api = FakeApi()
                api.responses[("GET", "/repos/ROCm/example/pulls/7")] = pull_payload()
                with mock.patch.object(
                    post_pr_findings,
                    "filter_changed_findings",
                    wraps=post_pr_findings.filter_changed_findings,
                ) as spy:
                    self._run(api, scan_mode=scan_mode)
                self.assertEqual(
                    spy.call_args.kwargs["commit_scoped_scanners"], expected
                )


if __name__ == "__main__":
    unittest.main()
