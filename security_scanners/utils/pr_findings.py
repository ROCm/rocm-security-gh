#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Normalize scanner reports and render findings on pull request lines."""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import quote, unquote, urlparse

COMMENT_MARKER = "<!-- rocm-security-gh:pr-findings:v1 -->"
MAX_COMMENT_ROWS = 50
# GitHub rejects comment bodies over 65,536 characters; the difference is
# headroom so a body at the budget is never the one that fails.
COMMENT_BUDGET_CHARS = 60_000
_REASONS_BUDGET_CHARS = 10_000
# Room for the "N additional finding(s) are omitted" line and its blank line.
_OMITTED_LINE_RESERVE_CHARS = 100

# A full or abbreviated git object ID, e.g. Gitleaks's "Commit" field.
_COMMIT_RE = re.compile(r"[0-9a-f]{7,64}")
# The new-side start line of a unified-diff hunk header, e.g. the "9" in
# "@@ -4,3 +9,2 @@ def example():". A trailing section heading is ignored.
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,\d+)? @@")
_SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFORMATIONAL": 4,
    "UNKNOWN": 5,
}


@dataclass(frozen=True)
class Finding:
    """One repository-relative finding emitted by a security scanner."""

    scanner: str
    severity: str
    rule_id: str
    path: str
    start_line: int | None
    end_line: int | None
    message: str
    fingerprint: str = ""
    commit: str = ""
    # A credential or other secret, which must be rotated rather than fixed.
    secret: bool = False


@dataclass(frozen=True)
class LineRange:
    """An inclusive range of new-side pull request lines."""

    start: int
    end: int


@dataclass(frozen=True)
class ChangedFile:
    """A pull request file and its added or modified new-side lines."""

    path: str
    status: str
    line_ranges: tuple[LineRange, ...]
    patch_available: bool


@dataclass(frozen=True)
class FilterResult:
    """Findings on changed lines plus files whose patches were unavailable."""

    findings: tuple[Finding, ...]
    unfilterable_paths: tuple[str, ...]


def _object(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def _objects(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _string(value: object, *, limit: int = 4_000) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()[:limit]


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    return None


def _line_range(start: object, end: object = None) -> tuple[int | None, int | None]:
    start_line = _integer(start)
    if start_line is None:
        return None, None
    end_line = _integer(end) or start_line
    return start_line, max(start_line, end_line)


def normalize_path(raw_path: object) -> str:
    """Return a repository-relative POSIX path, or an empty string."""

    path = _string(raw_path, limit=2_000).replace("\\", "/")
    if not path:
        return ""
    if path.startswith("file:"):
        path = unquote(urlparse(path).path)
    path = path.replace("%SRCROOT%/", "").replace("$SRCROOT/", "")
    marker = "/.scan-target/"
    if marker in path:
        path = path.split(marker, 1)[1]
    while path.startswith("./"):
        path = path[2:]
    if path.startswith(".scan-target/"):
        path = path[len(".scan-target/") :]
    if path.startswith("/") or "\x00" in path:
        return ""
    candidate = PurePosixPath(path)
    if not path or any(part in ("", ".", "..") for part in candidate.parts):
        return ""
    return candidate.as_posix()


def normalize_severity(value: object, *, fallback: str = "UNKNOWN") -> str:
    """Return a scanner-independent severity name."""

    raw = _string(value, limit=40).upper()
    aliases = {
        "INFO": "INFORMATIONAL",
        "INFORMATION": "INFORMATIONAL",
        "NOTE": "LOW",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "ERROR": "HIGH",
    }
    normalized = aliases.get(raw, raw)
    return normalized if normalized in _SEVERITY_RANK else fallback


def _score_severity(value: object) -> str:
    raw = _string(value, limit=40)
    try:
        score = float(raw)
    except ValueError:
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFORMATIONAL"


def parse_gitleaks(data: object) -> list[Finding]:
    """Parse a Gitleaks JSON array."""

    if not isinstance(data, list):
        raise ValueError("Gitleaks report must be a JSON array")
    findings: list[Finding] = []
    for item in _objects(data):
        path = normalize_path(item.get("File"))
        rule_id = _string(item.get("RuleID")) or "gitleaks"
        message = _string(item.get("Description")) or "Potential secret"
        start, end = _line_range(item.get("StartLine"), item.get("EndLine"))
        commit = _string(item.get("Commit"), limit=64).lower()
        if path:
            findings.append(
                Finding(
                    scanner="Gitleaks",
                    severity="HIGH",
                    rule_id=rule_id,
                    path=path,
                    start_line=start,
                    end_line=end,
                    message=message,
                    fingerprint=_string(item.get("Fingerprint")),
                    commit=commit if _COMMIT_RE.fullmatch(commit) else "",
                    secret=True,
                )
            )
    return findings


def parse_bandit(data: object) -> list[Finding]:
    """Parse a Bandit JSON object."""

    root = _object(data)
    if root is None or not isinstance(root.get("results"), list):
        raise ValueError("Bandit report must contain a results array")
    findings: list[Finding] = []
    for item in _objects(root.get("results")):
        path = normalize_path(item.get("filename"))
        start, end = _line_range(item.get("line_number"))
        line_range = item.get("line_range")
        if isinstance(line_range, list):
            lines = [line for line in line_range if _integer(line) is not None]
            if lines:
                start, end = min(lines), max(lines)
        if path:
            findings.append(
                Finding(
                    scanner="Bandit",
                    severity=normalize_severity(item.get("issue_severity")),
                    rule_id=_string(item.get("test_id")) or "bandit",
                    path=path,
                    start_line=start,
                    end_line=end,
                    message=_string(item.get("issue_text")) or "Bandit finding",
                )
            )
    return findings


def _trivy_message(item: Mapping[str, object], kind: str) -> str:
    for key in ("Title", "Message", "Description"):
        text = _string(item.get(key))
        if text:
            return text
    package = _string(item.get("PkgName"))
    version = _string(item.get("InstalledVersion"))
    if package:
        return f"{kind} in {package}{f' {version}' if version else ''}"
    return f"Trivy {kind.lower()} finding"


def parse_trivy(data: object) -> list[Finding]:
    """Parse a Trivy filesystem JSON object."""

    root = _object(data)
    if root is None or not isinstance(root.get("Results"), list):
        raise ValueError("Trivy report must contain a Results array")
    findings: list[Finding] = []
    categories = (
        ("Vulnerabilities", "Vulnerability", ("VulnerabilityID", "ID")),
        ("Misconfigurations", "Misconfiguration", ("ID", "AVDID")),
        ("Secrets", "Secret", ("RuleID", "Category")),
        ("Licenses", "License", ("Name", "Category")),
    )
    for result in _objects(root.get("Results")):
        target = normalize_path(result.get("Target"))
        for key, kind, id_keys in categories:
            for item in _objects(result.get(key)):
                cause = _object(item.get("CauseMetadata")) or {}
                path = (
                    normalize_path(item.get("Path"))
                    or normalize_path(cause.get("Path"))
                    or target
                )
                start, end = _line_range(
                    item.get("StartLine") or cause.get("StartLine"),
                    item.get("EndLine") or cause.get("EndLine"),
                )
                rule_id = next(
                    (
                        _string(item.get(id_key))
                        for id_key in id_keys
                        if item.get(id_key)
                    ),
                    "",
                )
                if path:
                    findings.append(
                        Finding(
                            scanner="Trivy",
                            severity=normalize_severity(item.get("Severity")),
                            rule_id=rule_id or f"trivy-{kind.lower()}",
                            path=path,
                            start_line=start,
                            end_line=end,
                            message=_trivy_message(item, kind),
                            secret=kind == "Secret",
                        )
                    )
    return findings


def _zizmor_location(
    locations: object,
) -> tuple[str, int | None, int | None]:
    candidates = _objects(locations)
    primary = next(
        (
            location
            for location in candidates
            if _string((_object(location.get("symbolic")) or {}).get("kind")).lower()
            == "primary"
        ),
        candidates[0] if candidates else None,
    )
    if primary is None:
        return "", None, None
    symbolic = _object(primary.get("symbolic")) or {}
    key = _object(symbolic.get("key")) or {}
    local = _object(key.get("Local")) or {}
    path = normalize_path(local.get("verbatim_path"))
    concrete = _object(primary.get("concrete")) or {}
    location = _object(concrete.get("location")) or {}
    start_point = _object(location.get("start_point")) or {}
    end_point = _object(location.get("end_point")) or {}
    start_row = start_point.get("row")
    end_row = end_point.get("row")
    if not isinstance(start_row, int) or start_row < 0:
        return path, None, None
    start_line = start_row + 1
    end_line = (
        end_row if isinstance(end_row, int) and end_row > start_row else start_line
    )
    return path, start_line, end_line


def parse_zizmor(data: object) -> list[Finding]:
    """Parse a zizmor JSON v1 array."""

    if not isinstance(data, list):
        raise ValueError("Zizmor report must be a JSON array")
    findings: list[Finding] = []
    for item in _objects(data):
        if item.get("ignored") is True:
            continue
        path, start, end = _zizmor_location(item.get("locations"))
        determinations = _object(item.get("determinations")) or {}
        if path:
            findings.append(
                Finding(
                    scanner="Zizmor",
                    severity=normalize_severity(determinations.get("severity")),
                    rule_id=_string(item.get("ident")) or "zizmor",
                    path=path,
                    start_line=start,
                    end_line=end,
                    message=_string(item.get("desc")) or "Zizmor finding",
                )
            )
    return findings


def _sarif_rule_severities(run: Mapping[str, object]) -> dict[str, str]:
    tool = _object(run.get("tool")) or {}
    driver = _object(tool.get("driver")) or {}
    severities: dict[str, str] = {}
    for rule in _objects(driver.get("rules")):
        rule_id = _string(rule.get("id"))
        properties = _object(rule.get("properties")) or {}
        severity = _score_severity(properties.get("security-severity"))
        if not severity:
            severity = normalize_severity(properties.get("problem.severity"))
        if rule_id:
            severities[rule_id] = severity
    return severities


def _sarif_location(result: Mapping[str, object]) -> tuple[str, int | None, int | None]:
    locations = _objects(result.get("locations"))
    if not locations:
        return "", None, None
    physical = _object(locations[0].get("physicalLocation")) or {}
    artifact = _object(physical.get("artifactLocation")) or {}
    region = _object(physical.get("region")) or {}
    path = normalize_path(artifact.get("uri"))
    start, end = _line_range(region.get("startLine"), region.get("endLine"))
    return path, start, end


def parse_codeql_sarif(data: object) -> list[Finding]:
    """Parse CodeQL SARIF 2.1.0 output."""

    root = _object(data)
    if root is None or not isinstance(root.get("runs"), list):
        raise ValueError("CodeQL SARIF must contain a runs array")
    findings: list[Finding] = []
    for run in _objects(root.get("runs")):
        rule_severities = _sarif_rule_severities(run)
        for result in _objects(run.get("results")):
            path, start, end = _sarif_location(result)
            rule_id = _string(result.get("ruleId")) or "codeql"
            properties = _object(result.get("properties")) or {}
            severity = (
                _score_severity(properties.get("security-severity"))
                or rule_severities.get(rule_id)
                or normalize_severity(result.get("level"))
            )
            message_data = _object(result.get("message")) or {}
            message = _string(message_data.get("text")) or _string(
                message_data.get("markdown")
            )
            fingerprints = _object(result.get("partialFingerprints")) or {}
            fingerprint = next(
                (_string(value) for value in fingerprints.values() if _string(value)),
                "",
            )
            if path:
                findings.append(
                    Finding(
                        scanner="CodeQL",
                        severity=severity,
                        rule_id=rule_id,
                        path=path,
                        start_line=start,
                        end_line=end,
                        message=message or "CodeQL finding",
                        fingerprint=fingerprint,
                    )
                )
    return findings


def parse_report(scanner: str, data: object) -> list[Finding]:
    """Parse one supported scanner report."""

    parsers = {
        "bandit": parse_bandit,
        "codeql": parse_codeql_sarif,
        "gitleaks": parse_gitleaks,
        "trivy": parse_trivy,
        "zizmor": parse_zizmor,
    }
    parser = parsers.get(scanner.lower())
    if parser is None:
        raise ValueError(f"Unsupported scanner report: {scanner}")
    return parser(data)


def parse_patch(patch: str) -> tuple[LineRange, ...]:
    """Return inclusive ranges of lines added on the new side of a patch."""

    lines: list[int] = []
    new_line: int | None = None
    for patch_line in patch.splitlines():
        hunk = _HUNK_RE.match(patch_line)
        if hunk:
            new_line = int(hunk.group("start"))
            continue
        if new_line is None or patch_line.startswith("\\"):
            continue
        if patch_line.startswith("+"):
            lines.append(new_line)
            new_line += 1
        elif patch_line.startswith("-"):
            continue
        else:
            new_line += 1
    if not lines:
        return ()
    ranges: list[LineRange] = []
    start = previous = lines[0]
    for line in lines[1:]:
        if line != previous + 1:
            ranges.append(LineRange(start, previous))
            start = line
        previous = line
    ranges.append(LineRange(start, previous))
    return tuple(ranges)


def changed_files_from_api(data: object) -> dict[str, ChangedFile]:
    """Convert GitHub pull request file objects into changed-line ranges."""

    if not isinstance(data, list):
        raise ValueError("Pull request files response must be a JSON array")
    changed: dict[str, ChangedFile] = {}
    for item in _objects(data):
        path = normalize_path(item.get("filename"))
        status = _string(item.get("status"), limit=20).lower()
        patch = item.get("patch")
        if path:
            changed[path] = ChangedFile(
                path=path,
                status=status,
                line_ranges=parse_patch(patch) if isinstance(patch, str) else (),
                patch_available=isinstance(patch, str),
            )
    return changed


def _overlaps(finding: Finding, ranges: Sequence[LineRange]) -> bool:
    if finding.start_line is None:
        return False
    end = finding.end_line or finding.start_line
    return any(
        finding.start_line <= line_range.end and end >= line_range.start
        for line_range in ranges
    )


def _deduplicate(findings: Sequence[Finding]) -> list[Finding]:
    unique: dict[tuple[object, ...], Finding] = {}
    for finding in findings:
        identity: tuple[object, ...]
        if finding.fingerprint:
            # The rule is part of the identity because a fingerprint can be
            # scoped to a location rather than a finding: CodeQL's
            # `primaryLocationLineHash` is shared by every result on a line,
            # so two rules flagging one line would otherwise collapse to one.
            identity = (
                finding.scanner,
                finding.rule_id,
                finding.fingerprint,
                finding.path,
            )
        else:
            identity = (
                finding.scanner,
                finding.rule_id,
                finding.path,
                finding.start_line,
                finding.end_line,
                finding.message,
            )
        unique.setdefault(identity, finding)
    return list(unique.values())


def filter_changed_findings(
    findings: Sequence[Finding],
    changed_files: Mapping[str, ChangedFile],
    *,
    commit_scoped_scanners: frozenset[str] = frozenset(),
) -> FilterResult:
    """Keep findings that overlap added or modified pull request lines.

    A scanner in `commit_scoped_scanners` already limited itself to the pull
    request's own commits, so every finding it reports was introduced by the
    pull request and is kept as is. Gitleaks in `changed` mode scans
    `base..head` that way, and a secret added in one commit and deleted in a
    later one is still in the history even though no line of the final diff
    shows it.

    Secrets sort first, then by severity, so they are never the rows a size
    or row limit drops.
    """

    matched: list[Finding] = []
    unfilterable: set[str] = set()
    for finding in findings:
        if finding.scanner in commit_scoped_scanners:
            matched.append(finding)
            continue
        changed = changed_files.get(finding.path)
        if changed is None or changed.status == "removed":
            continue
        if finding.start_line is None:
            matched.append(finding)
        elif not changed.patch_available:
            unfilterable.add(finding.path)
        elif _overlaps(finding, changed.line_ranges):
            matched.append(finding)
    ordered = sorted(
        _deduplicate(matched),
        key=lambda item: (
            not item.secret,
            _SEVERITY_RANK.get(item.severity, _SEVERITY_RANK["UNKNOWN"]),
            item.path,
            item.start_line or 0,
            item.scanner,
            item.rule_id,
        ),
    )
    return FilterResult(tuple(ordered), tuple(sorted(unfilterable)))


def _escape_cell(value: str, max_length: int = 240) -> str:
    # Truncation happens before escaping so a cut can never land inside an
    # HTML entity or split a backslash from the character it escapes.
    clipped = value if len(value) <= max_length else f"{value[: max_length - 1]}…"
    escaped = html.escape(clipped, quote=False)
    return (
        escaped.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "&#96;")
        .replace("@", "&#64;")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("!", "\\!")
        .replace("~", "\\~")
        .replace("\r\n", "<br>")
        .replace("\n", "<br>")
        .replace("\r", "<br>")
    )


def _location_link(repository: str, head_sha: str, finding: Finding) -> str:
    path_label = _escape_cell(finding.path, 200)
    if finding.start_line is None:
        label = path_label
        fragment = ""
    elif finding.end_line and finding.end_line != finding.start_line:
        label = f"{path_label}:{finding.start_line}-{finding.end_line}"
        fragment = f"#L{finding.start_line}-L{finding.end_line}"
    else:
        label = f"{path_label}:{finding.start_line}"
        fragment = f"#L{finding.start_line}"
    if len(finding.path) > 160:
        return label
    path_url = quote(finding.path, safe="/")
    # A finding from history links to the commit that contains it; the head
    # may no longer have the file or the line.
    ref = finding.commit or head_sha
    url = f"https://github.com/{repository}/blob/{ref}/{path_url}{fragment}"
    return f"[{label}]({url})"


def _render_row(repository: str, head_sha: str, finding: Finding) -> str:
    cells = (
        _escape_cell(finding.scanner),
        _escape_cell(finding.severity, 20),
        _escape_cell(finding.rule_id, 100),
        _location_link(repository, head_sha, finding),
        _escape_cell(finding.message),
    )
    return f"| {' | '.join(cells)} |"


def _take_within(lines: Sequence[str], budget_chars: int) -> list[str]:
    """Return the longest prefix of `lines` whose newline-joined size fits."""

    kept: list[str] = []
    used = 0
    for line in lines:
        cost = len(line) + 1
        if used + cost > budget_chars:
            break
        kept.append(line)
        used += cost
    return kept


def render_comment(
    findings: Sequence[Finding],
    *,
    repository: str,
    head_sha: str,
    run_url: str,
    incomplete_reasons: Sequence[str] = (),
    max_rows: int = MAX_COMMENT_ROWS,
    budget_chars: int = COMMENT_BUDGET_CHARS,
) -> str:
    """Render a sticky pull request findings comment of bounded size."""

    header = [
        COMMENT_MARKER,
        "## Security findings on changed lines",
        "",
        (
            f"Found **{len(findings)}** finding(s) located on lines added or "
            "modified by this pull request."
            if findings
            else "No security findings were reported on added or modified lines."
        ),
        "",
    ]
    secret_count = sum(finding.secret for finding in findings)
    if secret_count:
        header.extend(
            [
                "> [!CAUTION]",
                f"> **{secret_count} potential secret finding(s) were committed "
                "in this pull request.** Treat each credential as compromised "
                "and revoke or rotate it now, even if a later commit removed "
                "it. Deleting the line or force-pushing does not undo the "
                "leak: the commits stay reachable from this pull request and "
                "from every clone or fork, and automated scanners harvest "
                "secrets pushed to public repositories within minutes.",
                ">",
                "> If a finding is a test fixture or a false positive, "
                "allowlist it in the configuration of the scanner that "
                "reported it.",
                "",
            ]
        )

    footer: list[str] = []
    if incomplete_reasons:
        notes = [f"- {_escape_cell(reason)}" for reason in incomplete_reasons]
        kept_notes = _take_within(notes, _REASONS_BUDGET_CHARS)
        footer.extend(["Coverage was incomplete:", ""])
        footer.extend(kept_notes)
        if len(kept_notes) < len(notes):
            footer.append(
                f"- {len(notes) - len(kept_notes)} more coverage note(s) are "
                "omitted from this comment."
            )
        footer.append("")
    footer.append(f"[View the security scan run]({run_url}) for complete reports.")
    footer.extend(
        [
            "",
            (
                "_“New” means the finding is located in a changed file on an "
                "added or modified line; it is not a base-versus-head findings delta._"
            ),
        ]
    )

    table_header = [
        "| Scanner | Severity | Rule | Location | Finding |",
        "|---|---|---|---|---|",
    ]
    fixed_chars = sum(len(line) + 1 for line in (*header, *table_header, *footer))
    rows = _take_within(
        [_render_row(repository, head_sha, finding) for finding in findings[:max_rows]],
        budget_chars - fixed_chars - _OMITTED_LINE_RESERVE_CHARS,
    )

    lines = list(header)
    if rows:
        lines.extend(table_header)
        lines.extend(rows)
        lines.append("")
    omitted = len(findings) - len(rows)
    if omitted:
        lines.extend(
            [
                f"{omitted} additional finding(s) are omitted from this comment.",
                "",
            ]
        )
    lines.extend(footer)
    return "\n".join(lines)
