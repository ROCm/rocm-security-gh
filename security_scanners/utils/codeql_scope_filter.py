#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Keep the results of a scoped CodeQL target that lie in its scope.

A build includes code from outside the target's scope, and CodeQL reports on
it too. A result is kept only when its primary location is under a scope
directory. A result with no usable location is kept, since it can't be shown
to be outside.

Locations are normally relative ("src/app/a.cpp"). An absolute `file://` URI
under the directory recorded in `source-root.txt` is rewritten relative to
the repository; one outside it is out of scope.

Reads the environment:
    SCANNER_TARGET_NAME         target name, for the summary.
    SCANNER_TARGET_SCOPE        JSON list of scope directories.
    SCANNER_SARIF_DIR           directory with one .sarif file and
                                `source-root.txt`.
    SCANNER_FILTERED_SARIF_DIR  directory to write the filtered SARIF to.

Sets the outputs `sarif_path` (the filtered file) and `alerts` (its result
count).
"""

import json
import os
import posixpath
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import quote, unquote, urlsplit

from security_scanners.utils.codeql_targets import (
    TargetsError,
    minimal_scopes,
    normalize_repo_path,
    path_in_scope,
)
from security_scanners.utils.github_actions_api import (
    gha_append_step_summary,
    gha_set_output,
)

# Written by the analysis job: the directory it ran in.
SOURCE_ROOT_FILENAME = "source-root.txt"


class FilterError(RuntimeError):
    """The analysis output is missing or isn't what the filter expects."""


@dataclass(frozen=True)
class FilterResult:
    """What filtering a SARIF document kept and dropped."""

    kept: tuple[Mapping[str, object], ...]
    dropped: int


def _primary_artifact(result: Mapping[str, object]) -> dict[str, object] | None:
    """Return the `artifactLocation` of a result's primary location."""
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    first = locations[0]
    if not isinstance(first, dict):
        return None
    physical = first.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    return artifact if isinstance(artifact, dict) else None


def primary_uri(result: Mapping[str, object]) -> str | None:
    """Return the URI of a result's primary location, if it has one."""
    artifact = _primary_artifact(result)
    uri = artifact.get("uri") if artifact is not None else None
    return uri if isinstance(uri, str) and uri else None


def repository_path(uri: str, source_root: str) -> str | None:
    """Return `uri` as a repository-relative path, or None if it is outside.

    Outside means a scheme other than `file`, an absolute path not under
    `source_root`, or a relative path that climbs out.
    """
    parts = urlsplit(uri)
    if parts.scheme not in ("", "file") or parts.netloc:
        return None
    path = unquote(parts.path)
    if path.startswith("/"):
        if not source_root:
            return None
        try:
            path = (
                PurePosixPath(posixpath.normpath(path))
                .relative_to(source_root)
                .as_posix()
            )
        except ValueError:
            return None
    normalized = posixpath.normpath(path)
    if normalized == ".." or normalized.startswith("../"):
        return None
    return normalized


def in_scope(
    result: Mapping[str, object], scope: Sequence[str], source_root: str
) -> bool:
    """Whether `result` is located under one of the `scope` directories."""
    uri = primary_uri(result)
    if uri is None:
        return True
    path = repository_path(uri, source_root)
    if path is None:
        return False
    return any(path_in_scope(path, directory) for directory in scope)


def _rewrite_absolute_primary_uri(
    result: Mapping[str, object], uri: str, path: str
) -> None:
    """Make an absolute primary location relative to the repository root."""
    artifact = _primary_artifact(result)
    if artifact is None or not urlsplit(uri).path.startswith("/"):
        return
    artifact["uri"] = quote(path, safe="/")
    artifact.pop("uriBaseId", None)


def filter_sarif(
    sarif: dict[str, object], scope: Sequence[str], source_root: str = ""
) -> FilterResult:
    """Remove the out-of-scope results of every run in `sarif`, in place."""
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        raise FilterError("SARIF has no runs array")
    kept: list[Mapping[str, object]] = []
    dropped = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            raise FilterError("SARIF run has a results value that is not an array")
        in_run: list[Mapping[str, object]] = []
        for result in results:
            if not isinstance(result, dict):
                continue
            uri = primary_uri(result)
            if uri is None:
                in_run.append(result)
                continue
            path = repository_path(uri, source_root)
            if path is None or not any(
                path_in_scope(path, directory) for directory in scope
            ):
                continue
            _rewrite_absolute_primary_uri(result, uri, path)
            in_run.append(result)
        dropped += len(results) - len(in_run)
        run["results"] = in_run
        kept.extend(in_run)
    return FilterResult(kept=tuple(kept), dropped=dropped)


def _start_line(result: Mapping[str, object]) -> int | None:
    """Return the line of a result's primary location, if it has one."""
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    first = locations[0]
    physical = first.get("physicalLocation") if isinstance(first, dict) else None
    region = physical.get("region") if isinstance(physical, dict) else None
    line = region.get("startLine") if isinstance(region, dict) else None
    return line if isinstance(line, int) else None


def describe(result: Mapping[str, object]) -> str:
    """Render a result as `<file>:<line>: <rule>: <message>`."""
    location = primary_uri(result) or "<no location>"
    line = _start_line(result)
    if line is not None:
        location = f"{location}:{line}"
    message = result.get("message")
    text = message.get("text", "") if isinstance(message, dict) else ""
    return f"{location}: {result.get('ruleId', '?')}: {text}"


def _load_scope(raw: str) -> tuple[str, ...]:
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FilterError(f"SCANNER_TARGET_SCOPE is not JSON: {exc}") from exc
    if (
        not isinstance(values, list)
        or not values
        or not all(isinstance(value, str) for value in values)
    ):
        raise FilterError("SCANNER_TARGET_SCOPE must be a non-empty JSON list of paths")
    try:
        return minimal_scopes(
            normalize_repo_path(value, what="scope entry") for value in values
        )
    except TargetsError as exc:
        raise FilterError(str(exc)) from exc


def _find_sarif(directory: Path) -> Path:
    found = sorted(directory.glob("*.sarif"))
    if len(found) != 1:
        raise FilterError(f"expected one SARIF file in {directory}, found {len(found)}")
    return found[0]


def _read_source_root(directory: Path) -> str:
    path = directory / SOURCE_ROOT_FILENAME
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def main(argv: Sequence[str]) -> int:
    if argv:
        print(f"unexpected arguments: {' '.join(argv)}", file=sys.stderr)
        return 2

    name = os.environ.get("SCANNER_TARGET_NAME", "")
    source_env = os.environ.get("SCANNER_SARIF_DIR", "")
    output_env = os.environ.get("SCANNER_FILTERED_SARIF_DIR", "")
    try:
        if not source_env or not output_env:
            raise FilterError(
                "SCANNER_SARIF_DIR and SCANNER_FILTERED_SARIF_DIR must be set"
            )
        scope = _load_scope(os.environ.get("SCANNER_TARGET_SCOPE", ""))
        source_dir = Path(source_env)
        source = _find_sarif(source_dir)
        try:
            sarif = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, RecursionError) as exc:
            raise FilterError(f"cannot read {source.name}: {exc}") from exc
        if not isinstance(sarif, dict):
            raise FilterError(f"{source.name} is not a SARIF document")
        result = filter_sarif(sarif, scope, _read_source_root(source_dir))
    except FilterError as exc:
        print(f"CodeQL scope filter failed: {exc}", file=sys.stderr)
        gha_append_step_summary(
            f"### CodeQL target `{name}`\n\nFailed to filter the results: {exc}"
        )
        return 2

    output_dir = Path(output_env)
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / source.name
    destination.write_text(json.dumps(sarif), encoding="utf-8")

    for kept in result.kept:
        print(describe(kept))
    print(
        f"{len(result.kept)} result(s) under {', '.join(scope)}; "
        f"{result.dropped} outside it were dropped"
    )
    gha_set_output({"sarif_path": destination, "alerts": str(len(result.kept))})
    gha_append_step_summary(
        f"### CodeQL target `{name}`\n\n"
        f"- Scope: {', '.join(f'`{directory}`' for directory in scope)}\n"
        f"- Results in scope: {len(result.kept)}\n"
        f"- Results outside the scope, dropped: {result.dropped}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
