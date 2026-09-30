#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Post a pull request scan's findings on changed lines as one comment."""

from __future__ import annotations

import io
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.request
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import NoReturn
from urllib.parse import urlencode

from security_scanners.utils.pr_findings import (
    COMMENT_MARKER,
    Finding,
    changed_files_from_api,
    filter_changed_findings,
    parse_report,
    render_comment,
)

_API_VERSION = "2022-11-28"
_EXPECTED_SCANNERS = ("bandit", "gitleaks", "trivy", "zizmor")
_MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
_MAX_MEMBER_BYTES = 10 * 1024 * 1024
_MAX_TOTAL_BYTES = 20 * 1024 * 1024
_MAX_MEMBERS = 20
_MAX_PAGES = 100
_CODEQL_ARTIFACT_RE = re.compile(r"^codeql-report-[A-Za-z0-9_.+-]+$")


class SkipRun(RuntimeError):
    """A run that must not create or update a pull request comment."""


class GitHubApiError(RuntimeError):
    """A failed GitHub REST call. `status` is the HTTP code, or None if the
    request never got a response (DNS failure, connection reset, timeout)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class PullRequestContext:
    """The pull request this run scanned, and the run that scanned it."""

    repository: str
    number: int
    head_sha: str
    run_id: int
    run_url: str
    # GitHub's own count of files in the diff, which the file-list endpoint
    # caps at 3,000. `file_list_gap_reason` compares the two to detect a
    # truncated list. Zero when the pull request payload omitted the field.
    changed_file_count: int = 0


@dataclass(frozen=True)
class Artifact:
    """An expected Actions artifact uploaded by this run's scan jobs."""

    artifact_id: int
    name: str
    expired: bool


@dataclass(frozen=True)
class ArtifactReport:
    """One validated machine-readable report from an Actions artifact."""

    scanner: str
    member_name: str
    data: object


@dataclass(frozen=True)
class CollectionResult:
    """Normalized artifact findings and coverage limitations."""

    findings: tuple[Finding, ...]
    incomplete_reasons: tuple[str, ...]
    observed_scanners: frozenset[str]


class GitHubApi:
    """Small authenticated GitHub REST client with bounded pagination."""

    def __init__(self, token: str, api_url: str = "https://api.github.com"):
        if not token:
            raise ValueError("GITHUB_TOKEN is required")
        self._token = token
        self._api_url = api_url.rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, object] | None = None,
    ) -> bytes:
        # Only paths under the API root are accepted, so the token is never
        # sent to a URL assembled from response data.
        if not path.startswith("/"):
            raise ValueError(f"GitHub API path must start with '/': {path!r}")
        encoded = (
            json.dumps(body, separators=(",", ":")).encode("utf-8")
            if body is not None
            else None
        )
        request = urllib.request.Request(
            f"{self._api_url}{path}",
            data=encoded,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": _API_VERSION,
                "User-Agent": "rocm-security-gh-pr-findings",
                **({"Content-Type": "application/json"} if encoded is not None else {}),
            },
        )
        # Artifact downloads redirect to a signed URL on a storage host, and
        # urllib copies ordinary headers onto the redirected request. An
        # unredirected header is sent to the API host only.
        request.add_unredirected_header("Authorization", f"Bearer {self._token}")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read(_MAX_ARCHIVE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise GitHubApiError(
                f"GitHub API {method} {path} returned HTTP {exc.code}", exc.code
            ) from exc
        except urllib.error.URLError as exc:
            raise GitHubApiError(
                f"GitHub API {method} {path} failed: {exc.reason}"
            ) from exc

    def json(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, object] | None = None,
    ) -> object:
        """Request and decode a JSON response."""

        raw = self._request(method, path, body=body)
        if len(raw) > _MAX_ARCHIVE_BYTES:
            raise RuntimeError(f"GitHub API response for {path} exceeds the size limit")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise RuntimeError(
                f"GitHub API response for {path} is not valid JSON"
            ) from exc

    def bytes(self, path: str) -> bytes:
        """Download a bounded binary response."""

        raw = self._request("GET", path)
        if len(raw) > _MAX_ARCHIVE_BYTES:
            raise ValueError("Artifact archive exceeds the compressed size limit")
        return raw

    def paginated_array(self, path: str) -> list[object]:
        """Read every page from an endpoint whose response is a JSON array."""

        values: list[object] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, _MAX_PAGES + 1):
            page_data = self.json(
                "GET", f"{path}{separator}{urlencode({'per_page': 100, 'page': page})}"
            )
            if not isinstance(page_data, list):
                raise RuntimeError(
                    f"GitHub API pagination response for {path} is not an array"
                )
            values.extend(page_data)
            if len(page_data) < 100:
                return values
        raise RuntimeError(
            f"GitHub API pagination for {path} exceeded {_MAX_PAGES} pages"
        )

    def paginated_key(self, path: str, key: str) -> list[object]:
        """Read every page from an endpoint whose array is nested under `key`."""

        values: list[object] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, _MAX_PAGES + 1):
            page_data = self.json(
                "GET", f"{path}{separator}{urlencode({'per_page': 100, 'page': page})}"
            )
            if not isinstance(page_data, Mapping):
                raise RuntimeError(
                    f"GitHub API pagination response for {path} is not an object"
                )
            batch = page_data.get(key)
            if not isinstance(batch, list):
                raise RuntimeError(f"GitHub API response for {path} has no {key} array")
            values.extend(batch)
            if len(batch) < 100:
                return values
        raise RuntimeError(
            f"GitHub API pagination for {path} exceeded {_MAX_PAGES} pages"
        )


def _object(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def _string(value: object, *, limit: int = 2_000) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) and value > 0 else None


def _nested_string(value: object, *keys: str) -> str:
    current = value
    for key in keys:
        mapping = _object(current)
        if mapping is None:
            return ""
        current = mapping.get(key)
    return _string(current)


def resolve_pull_request(
    api: GitHubApi,
    event: Mapping[str, object],
    *,
    repository: str,
    run_id: int,
    run_url: str,
) -> PullRequestContext:
    """Identify the pull request this run scanned, from the run's own event.

    `event` is the `pull_request` payload GitHub wrote for this run. A pull
    request opened from a fork is skipped: its token is read-only and no
    workflow can raise it, so a comment could never be written. The head
    commit named in the event is what the scan checked out; if the API already
    reports a different head, a push has superseded this run and it skips
    rather than pairing its findings with a newer diff.
    """

    pull_event = _object(event.get("pull_request"))
    if pull_event is None:
        raise SkipRun("Event has no pull_request object")
    number = _positive_int(pull_event.get("number"))
    head_sha = _nested_string(pull_event, "head", "sha")
    if number is None or not head_sha:
        raise SkipRun("Pull request event has no number or head commit")
    if _nested_string(pull_event, "head", "repo", "full_name") != repository:
        raise SkipRun("Pull request comes from a fork, whose token cannot comment")

    pull = _object(api.json("GET", f"/repos/{repository}/pulls/{number}"))
    if pull is None:
        raise SkipRun("Pull request is not readable")
    if _nested_string(pull, "head", "sha") != head_sha:
        raise SkipRun("A push superseded the head commit this run scanned")

    return PullRequestContext(
        repository=repository,
        number=number,
        head_sha=head_sha,
        run_id=run_id,
        run_url=run_url,
        changed_file_count=_positive_int(pull.get("changed_files")) or 0,
    )


def require_unchanged_head(api: GitHubApi, context: PullRequestContext) -> None:
    """Skip the run unless the pull request head is still the scanned commit.

    `resolve_pull_request` establishes the head once, but reading the diff,
    downloading artifacts, and writing the comment each take time during which
    a push can land. Afterwards the findings describe one commit while the diff
    describes another, and a run for the newer commit may already have
    commented, so this is called both after the diff is read and immediately
    before the write. GitHub offers no conditional write for issue comments, so
    the second call narrows the race to a single round trip rather than
    closing it.
    """

    pull = _object(
        api.json("GET", f"/repos/{context.repository}/pulls/{context.number}")
    )
    if pull is None:
        raise SkipRun("Pull request is no longer readable")
    head_sha = _nested_string(pull, "head", "sha")
    if not head_sha:
        raise SkipRun("Pull request no longer reports a head commit")
    if head_sha != context.head_sha:
        raise SkipRun(
            f"Pull request head moved to {head_sha[:12]} while this run was "
            f"reporting on {context.head_sha[:12]}"
        )


def _run_artifacts(api: GitHubApi, repository: str, run_id: int) -> list[Artifact]:
    """Return every named artifact attached to a run."""

    payloads = api.paginated_key(
        f"/repos/{repository}/actions/runs/{run_id}/artifacts", "artifacts"
    )
    artifacts: list[Artifact] = []
    for payload in payloads:
        item = _object(payload)
        if item is None:
            continue
        artifact_id = _positive_int(item.get("id"))
        name = _string(item.get("name"), limit=200)
        if artifact_id is None or not name:
            continue
        artifacts.append(
            Artifact(
                artifact_id=artifact_id,
                name=name,
                expired=item.get("expired") is True,
            )
        )
    return artifacts


def list_artifacts(api: GitHubApi, context: PullRequestContext) -> list[Artifact]:
    """Return expected scanner and CodeQL artifacts from this run."""

    expected = {f"{scanner}-report" for scanner in _EXPECTED_SCANNERS}
    return [
        artifact
        for artifact in _run_artifacts(api, context.repository, context.run_id)
        if artifact.name in expected or _CODEQL_ARTIFACT_RE.fullmatch(artifact.name)
    ]


def _validate_member(info: zipfile.ZipInfo) -> None:
    name = info.filename.replace("\\", "/")
    path = PurePosixPath(name)
    mode = info.external_attr >> 16
    if (
        not name
        or name.startswith("/")
        or "\x00" in name
        or any(part in ("", ".", "..") for part in path.parts)
        or stat.S_ISLNK(mode)
        or info.flag_bits & 0x1
    ):
        raise ValueError(f"Artifact contains an unsafe ZIP member: {name!r}")
    if info.file_size > _MAX_MEMBER_BYTES:
        raise ValueError(f"Artifact member {name!r} exceeds the size limit")
    if info.compress_size and info.file_size > info.compress_size * 200:
        raise ValueError(
            f"Artifact member {name!r} exceeds the compression ratio limit"
        )


def _allowed_member(artifact_name: str, member_name: str) -> tuple[bool, str]:
    normalized_name = PurePosixPath(member_name).as_posix()
    basename = PurePosixPath(normalized_name).name
    if artifact_name.startswith("codeql-report-"):
        return basename.endswith(".sarif"), "codeql"
    scanner = artifact_name.removesuffix("-report")
    allowed = {
        "bandit": {"bandit-report.json", "bandit-report.txt"},
        "gitleaks": {"gitleaks-report.csv", "gitleaks-report.json"},
        "trivy": {"trivy-report.json", "trivy-report.txt"},
        "zizmor": {"zizmor-report.json", "zizmor-report.txt"},
    }
    return normalized_name in allowed.get(scanner, set()), scanner


def read_artifact_reports(artifact_name: str, archive: bytes) -> list[ArtifactReport]:
    """Validate an artifact ZIP in memory and return its JSON or SARIF reports."""

    if len(archive) > _MAX_ARCHIVE_BYTES:
        raise ValueError("Artifact archive exceeds the compressed size limit")
    try:
        zip_file = zipfile.ZipFile(io.BytesIO(archive))
    except zipfile.BadZipFile as exc:
        raise ValueError("Artifact is not a valid ZIP archive") from exc
    with zip_file:
        all_members = zip_file.infolist()
        if len(all_members) > _MAX_MEMBERS:
            raise ValueError("Artifact contains too many files")
        for info in all_members:
            _validate_member(info)
        members = [info for info in all_members if not info.is_dir()]
        total_size = 0
        reports: list[ArtifactReport] = []
        machine_reports = 0
        for info in members:
            total_size += info.file_size
            if total_size > _MAX_TOTAL_BYTES:
                raise ValueError("Artifact uncompressed contents exceed the size limit")
            allowed, scanner = _allowed_member(artifact_name, info.filename)
            if not allowed:
                raise ValueError(
                    f"Artifact {artifact_name!r} contains unexpected file {info.filename!r}"
                )
            basename = PurePosixPath(info.filename).name
            if not (basename.endswith(".json") or basename.endswith(".sarif")):
                continue
            machine_reports += 1
            try:
                data = json.loads(zip_file.read(info))
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                RecursionError,
                zipfile.BadZipFile,
            ) as exc:
                raise ValueError(
                    f"Artifact member {info.filename!r} is invalid JSON"
                ) from exc
            reports.append(
                ArtifactReport(
                    scanner=scanner,
                    member_name=info.filename,
                    data=data,
                )
            )
        if machine_reports == 0:
            raise ValueError(
                f"Artifact {artifact_name!r} has no machine-readable report"
            )
        if not artifact_name.startswith("codeql-report-") and machine_reports != 1:
            raise ValueError(
                f"Artifact {artifact_name!r} must contain exactly one JSON report"
            )
        return reports


def _artifact_label(name: str) -> str:
    if name.startswith("codeql-report-"):
        return "CodeQL"
    return name.removesuffix("-report").capitalize()


def collect_findings(
    api: GitHubApi,
    context: PullRequestContext,
) -> CollectionResult:
    """Download, validate, and parse expected artifacts from this run."""

    artifacts = list_artifacts(api, context)
    findings: list[Finding] = []
    reasons: list[str] = []
    observed: set[str] = set()
    seen_names: set[str] = set()
    for artifact in artifacts:
        if artifact.name in seen_names:
            reasons.append(f"Duplicate {artifact.name} artifact was ignored.")
            continue
        seen_names.add(artifact.name)
        label = _artifact_label(artifact.name)
        if artifact.expired:
            reasons.append(f"{label} artifact expired before it could be processed.")
            continue
        try:
            archive = api.bytes(
                f"/repos/{context.repository}/actions/artifacts/"
                f"{artifact.artifact_id}/zip"
            )
            reports = read_artifact_reports(artifact.name, archive)
            for report in reports:
                findings.extend(parse_report(report.scanner, report.data))
                observed.add(report.scanner)
        except (RuntimeError, ValueError) as exc:
            reasons.append(f"{label} report could not be processed: {exc}")
    return CollectionResult(
        findings=tuple(findings),
        incomplete_reasons=tuple(reasons),
        observed_scanners=frozenset(observed),
    )


def _job_scanner(name: str) -> str:
    lowered = name.lower()
    for scanner in _EXPECTED_SCANNERS:
        if lowered == scanner or lowered.endswith(f" / {scanner}"):
            return scanner
    if "codeql" in lowered:
        return "codeql"
    return ""


def job_coverage_reasons(
    api: GitHubApi,
    context: PullRequestContext,
    observed_scanners: frozenset[str],
) -> list[str]:
    """Describe failed source jobs that produced no complete report."""

    jobs = api.paginated_key(
        f"/repos/{context.repository}/actions/runs/{context.run_id}/jobs", "jobs"
    )
    reasons: list[str] = []
    for payload in jobs:
        job = _object(payload)
        if job is None:
            continue
        name = _string(job.get("name"), limit=200)
        conclusion = _string(job.get("conclusion"), limit=40).lower()
        scanner = _job_scanner(name)
        steps = job.get("steps")
        upload_succeeded = False
        if isinstance(steps, list):
            for step_payload in steps:
                step = _object(step_payload)
                if step is None:
                    continue
                step_name = _string(step.get("name"), limit=200)
                step_conclusion = _string(step.get("conclusion"), limit=40).lower()
                if (
                    step_name
                    in (
                        "Upload non-SARIF reports",
                        "Upload CodeQL findings",
                    )
                    and step_conclusion == "success"
                ):
                    upload_succeeded = True
        if upload_succeeded and scanner and scanner not in observed_scanners:
            reasons.append(f"{name} uploaded no usable machine-readable report.")
            continue
        if conclusion in ("success", "skipped", "neutral", ""):
            continue
        if scanner in observed_scanners and scanner != "codeql":
            continue
        reasons.append(f"{name or 'A scan job'} concluded with {conclusion}.")
    return reasons


def file_list_gap_reason(listed_files: int, changed_file_count: int) -> str | None:
    """Describe a pull request file list that is shorter than the diff.

    The file-list endpoint returns at most 3,000 files, while the pull request
    payload's `changed_files` counts the whole diff, so a shorter list means
    some changed files were never described. A finding in one of those files is
    indistinguishable from a finding in an untouched file and is therefore
    dropped, so the shortfall is reported rather than silently narrowing what
    the comment claims to cover. Returns None when the list is complete, or
    when `changed_file_count` is 0 because the payload omitted the field.
    """

    if changed_file_count <= listed_files:
        return None
    return (
        f"GitHub described only {listed_files:,} of this pull request's "
        f"{changed_file_count:,} changed files, so findings in the remaining "
        f"{changed_file_count - listed_files:,} are missing from this comment."
    )


def _write_comment(api: GitHubApi, method: str, path: str, body: str) -> None:
    """Create or replace a comment, tolerating failures nothing here can fix.

    A repository whose organization caps the default token at read-only, or
    which forbids Actions from writing pull request content, answers every
    write with 403; rate limiting answers 403 or 429, and GitHub outages answer
    5xx. None of those mean the findings are wrong or that this code
    misbehaved, and the scan workflow reports findings through SARIF and its
    own job summary regardless, so the comment is dropped with a warning rather
    than failing a run that has nothing to retry. Every other status still
    raises, because it points at a defect here -- a malformed body (422) or a
    pull request that vanished mid-run (404).
    """

    try:
        api.json(method, path, body={"body": body})
    except GitHubApiError as exc:
        if exc.status is None or not (
            exc.status in (403, 429) or 500 <= exc.status < 600
        ):
            raise
        print(f"warning: could not write the findings comment: {exc}", file=sys.stderr)


def update_sticky_comment(
    api: GitHubApi,
    context: PullRequestContext,
    body: str,
) -> None:
    """Update the github-actions bot marker comment, or create it."""

    comments = api.paginated_array(
        f"/repos/{context.repository}/issues/{context.number}/comments"
    )
    matches: list[int] = []
    for payload in comments:
        comment = _object(payload)
        if comment is None or COMMENT_MARKER not in _string(
            comment.get("body"), limit=100_000
        ):
            continue
        login = _nested_string(comment, "user", "login")
        user_type = _nested_string(comment, "user", "type")
        comment_id = _positive_int(comment.get("id"))
        if (
            login == "github-actions[bot]"
            and user_type == "Bot"
            and comment_id is not None
        ):
            matches.append(comment_id)
    if matches:
        _write_comment(
            api,
            "PATCH",
            f"/repos/{context.repository}/issues/comments/{min(matches)}",
            body,
        )
    else:
        _write_comment(
            api,
            "POST",
            f"/repos/{context.repository}/issues/{context.number}/comments",
            body,
        )


def _load_event(path: Path) -> Mapping[str, object]:
    try:
        data = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RuntimeError(f"Cannot read the workflow event at {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise RuntimeError("The workflow event must be a JSON object")
    return data


def _fatal(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _run_id(value: str) -> int:
    run_id = _positive_int(int(value)) if value.isdigit() else None
    if run_id is None:
        raise RuntimeError(f"GITHUB_RUN_ID is not a run ID: {value!r}")
    return run_id


def main() -> int:
    """Report this run's findings on the pull request it scanned."""

    try:
        if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
            raise SkipRun("Run was not triggered by pull_request")
        repository = os.environ["GITHUB_REPOSITORY"]
        run_id = _run_id(os.environ["GITHUB_RUN_ID"])
        server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        api = GitHubApi(
            os.environ["GITHUB_TOKEN"],
            os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
        context = resolve_pull_request(
            api,
            _load_event(Path(os.environ["GITHUB_EVENT_PATH"])),
            repository=repository,
            run_id=run_id,
            run_url=f"{server_url}/{repository}/actions/runs/{run_id}",
        )
        file_payloads = api.paginated_array(
            f"/repos/{context.repository}/pulls/{context.number}/files"
        )
        # The diff is only usable with these findings while it describes the
        # commit they came from.
        require_unchanged_head(api, context)
        changed_files = changed_files_from_api(file_payloads)
        collection = collect_findings(api, context)
        filtered = filter_changed_findings(collection.findings, changed_files)
        reasons = list(collection.incomplete_reasons)
        reasons.extend(job_coverage_reasons(api, context, collection.observed_scanners))
        gap = file_list_gap_reason(len(file_payloads), context.changed_file_count)
        if gap is not None:
            reasons.append(gap)
        if filtered.unfilterable_paths:
            paths = ", ".join(filtered.unfilterable_paths[:5])
            suffix = (
                f" and {len(filtered.unfilterable_paths) - 5} more"
                if len(filtered.unfilterable_paths) > 5
                else ""
            )
            reasons.append(
                f"GitHub did not provide a patch for {paths}{suffix}; "
                "line-located findings in those files could not be classified."
            )
        body = render_comment(
            filtered.findings,
            repository=context.repository,
            head_sha=context.head_sha,
            run_url=context.run_url,
            incomplete_reasons=tuple(dict.fromkeys(reasons)),
        )
        require_unchanged_head(api, context)
        update_sticky_comment(api, context, body)
    except SkipRun as exc:
        print(f"Skipping PR findings comment: {exc}")
        return 0
    except GitHubApiError as exc:
        if exc.status != 403:
            _fatal(str(exc))
        # The job inherits the caller's token, and a caller that has not
        # granted these permissions has not enabled the comment.
        print(
            f"warning: skipping PR findings comment: {exc}. Grant "
            "`pull-requests: write` and `actions: read` to the job that calls "
            "security-baseline to enable it.",
            file=sys.stderr,
        )
        return 0
    except (KeyError, RuntimeError, ValueError) as exc:
        _fatal(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
