#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Decide which CodeQL languages to analyse in the repository being scanned.

Two API sources, because neither alone is enough:

* `GET /repos/{owner}/{repo}/languages` is Linguist's view of the
  default branch. It is the same signal GitHub's own default setup uses,
  but it lags: a pull request that introduces a language isn't in it
  yet, and Linguist stops counting past 100,000 files.
* `GET /repos/{owner}/{repo}/git/trees/{sha}?recursive=1` is the exact
  tree of the commit under scan. It answers "what is in *this* commit",
  but GitHub truncates it past 100,000 entries or 7 MB, and reports that
  in `truncated`. On a truncated tree, a pull request falls back to its
  changed files, which is at least the part of the repository the run is
  about.
"""

import json
import os
import posixpath
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from security_scanners.utils.compute_scan_matrix import MAX_TIMEOUT_MINUTES
from security_scanners.utils.github_actions_api import (
    gha_append_step_summary,
    gha_load_github_event,
    gha_set_output,
)

# CodeQL walks every source file it recognises, and the C/C++ extractor.
DEFAULT_TIMEOUT_MINUTES = 120

# GitHub truncates a recursive tree past 100,000 entries or 7 MB and says
# so in `truncated`, which is the only size threshold worth honouring --
# inventing our own repository-size cutoff would just disagree with it.
# https://docs.github.com/en/rest/git/trees#get-a-tree
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_TIMEOUT_SECONDS = 30
_ATTEMPTS = 3
_RETRY_STATUSES = frozenset({500, 502, 503, 504})
# GitHub caps a pull request's file list at 3,000 files, i.e. 30 pages.
_MAX_FILE_PAGES = 30
# temp workaround
MAX_BUILDLESS_CPP_FILES = 1_000

# Linguist language name -> CodeQL language, for the languages CodeQL can
# analyse from source alone.
BUILDLESS_LANGUAGES: Mapping[str, str] = {
    "C": "c-cpp",
    "C++": "c-cpp",
    "C#": "csharp",
    "Java": "java-kotlin",
    "JavaScript": "javascript-typescript",
    "TypeScript": "javascript-typescript",
    "Python": "python",
    "Ruby": "ruby",
    "Rust": "rust",
}

# Languages CodeQL supports only by observing a compiler, which this
# workflow never runs. Reported, never analysed.
# https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/codeql-code-scanning-for-compiled-languages
BUILD_REQUIRED_LANGUAGES: Mapping[str, str] = {
    "Go": "needs a build",
    "Swift": "needs a build",
    "Kotlin": "needs a build (Java is still analysed)",
}

# ROCm repositories are full of these, and CodeQL has no extractor for
# either, so saying nothing would read as "clean" rather than "unread".
# The C/C++ sources and headers alongside them are analysed as usual.
UNSUPPORTED_LANGUAGES: Mapping[str, str] = {
    "Cuda": "no CodeQL extractor",
    "HIP": "no CodeQL extractor",
}

# File extensions that count as evidence of a language in an exact tree
# or a pull request's changed files. Deliberately narrower than
# Linguist: this decides whether a CodeQL job has anything to read.
_EXTENSION_LANGUAGES: Mapping[str, str] = {
    ".c": "c-cpp",
    ".cc": "c-cpp",
    ".cpp": "c-cpp",
    ".cxx": "c-cpp",
    ".c++": "c-cpp",
    ".h": "c-cpp",
    ".hh": "c-cpp",
    ".hpp": "c-cpp",
    ".hxx": "c-cpp",
    ".h++": "c-cpp",
    ".cs": "csharp",
    ".java": "java-kotlin",
    ".js": "javascript-typescript",
    ".jsx": "javascript-typescript",
    ".mjs": "javascript-typescript",
    ".cjs": "javascript-typescript",
    ".ts": "javascript-typescript",
    ".tsx": "javascript-typescript",
    ".mts": "javascript-typescript",
    ".cts": "javascript-typescript",
    ".py": "python",
    ".pyw": "python",
    ".rb": "ruby",
    ".rs": "rust",
}

# CodeQL's Rust support reads a Cargo project rather than loose files, so
# a stray .rs file is not something it can analyse.
_RUST_MANIFESTS = frozenset({"Cargo.toml", "rust-project.json"})

# What the `actions` extractor reads. Linguist calls these YAML, so they
# never show up as a language of their own.
_WORKFLOW_DIRECTORY = "workflows"
_ACTION_FILENAMES = frozenset({"action.yml", "action.yaml"})
_WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})

# Languages that are only selected on file-level evidence, never on
# Linguist alone when file evidence is available: initialising CodeQL for
# a language whose files it can't find fails the run, and Linguist counts
# things the extractors don't read (`.cu` and `.hip` as C++, for one).
_NEEDS_FILE_EVIDENCE = frozenset({"c-cpp", "rust"})

# GitHub Actions is not a Linguist language (workflows count as YAML), and
# a repository calling this workflow necessarily has a workflow file in
# the commit being scanned, so this needs no discovery.
ACTIONS_LANGUAGE = "actions"

DETECTION_LANGUAGES_AND_TREE = "github-languages+exact-tree"
DETECTION_LANGUAGES_AND_CHANGED_FILES = "github-languages+changed-files"
DETECTION_LANGUAGES_ONLY = "github-languages-only"
DETECTION_TREE_ONLY = "exact-tree-fallback"
DETECTION_PRIVATE_REPOSITORY_POLICY = "private-repository-policy"


class JsonFetcher(Protocol):
    """Fetches a parsed JSON document from a GitHub REST path."""

    def __call__(self, path: str) -> object: ...


class DiscoveryError(RuntimeError):
    """Discovery produced nothing trustworthy to build a matrix from."""


@dataclass(frozen=True)
class ChangedFiles:
    """A pull request's file list, and whether it is all of it.

    GitHub stops at 3,000 files. An incomplete list is still usable as
    evidence that a language is present, but it can't be used to decide
    a language is *absent*.
    """

    paths: tuple[str, ...] = ()
    complete: bool = True


@dataclass(frozen=True)
class Discovery:
    """What the API said about the repository under scan.

    `paths` is file-level evidence: the exact tree when GitHub returned
    all of it, otherwise a pull request's changed files, otherwise
    nothing. `path_source` names which, so the summary can admit how
    complete the answer is.
    """

    linguist_languages: tuple[str, ...] = ()
    linguist_available: bool = False
    paths: tuple[str, ...] = ()
    path_source: str = ""
    tree_truncated: bool = False
    warnings: tuple[str, ...] = ()
    # Kept so a changed-mode run doesn't ask for the same file list twice.
    changed_files: ChangedFiles | None = None

    @property
    def has_exact_tree(self) -> bool:
        """Whether `paths` is every file in the commit, not just some."""
        return self.path_source == "exact-tree"


@dataclass(frozen=True)
class CodeqlPlan:
    """The languages to analyse, and everything the run should say out loud."""

    selected: tuple[str, ...]
    skipped: tuple[str, ...]
    detection_source: str
    tree_truncated: bool
    warnings: tuple[str, ...]
    restricted_to_changes: bool = False

    def matrix(self, timeout_minutes: int) -> str:
        """Render `strategy.matrix` for the CodeQL job."""
        return json.dumps(
            {
                "include": [
                    {"language": language, "timeout_minutes": timeout_minutes}
                    for language in self.selected
                ]
            }
        )


def languages_from_paths(
    paths: Iterable[str], *, require_rust_manifest: bool = True
) -> set[str]:
    """Return the CodeQL languages evidenced by `paths`.

    `require_rust_manifest` asks whether a Cargo project has to be among
    `paths` for Rust to count. It does when `paths` is the repository,
    since CodeQL can't analyse Rust without one; it doesn't when `paths`
    is a pull request's diff, where the manifest is usually untouched.
    """
    found: set[str] = set()
    manifests_seen = False
    for raw in paths:
        path = PurePosixPath(raw.strip())
        if path.name in _RUST_MANIFESTS:
            manifests_seen = True
        language = _EXTENSION_LANGUAGES.get(path.suffix.lower())
        if language is not None:
            found.add(language)
    if require_rust_manifest and not manifests_seen:
        found.discard("rust")
    return found


def count_cpp_files(paths: Iterable[str]) -> int:
    """Count C/C++ sources and headers recognised by the CodeQL planner."""
    return sum(
        _EXTENSION_LANGUAGES.get(PurePosixPath(raw.strip()).suffix.lower()) == "c-cpp"
        for raw in paths
    )


def touches_actions(paths: Iterable[str]) -> bool:
    """Whether `paths` includes anything CodeQL's `actions` extractor reads."""
    for raw in paths:
        path = PurePosixPath(raw.strip())
        if path.suffix.lower() not in _WORKFLOW_SUFFIXES:
            continue
        if path.name in _ACTION_FILENAMES:
            return True
        if path.parent.name == _WORKFLOW_DIRECTORY and ".github" in path.parts:
            return True
    return False


def languages_from_linguist(names: Iterable[str]) -> tuple[set[str], list[str]]:
    """Map Linguist names to CodeQL languages, plus notes on what was dropped."""
    selected: set[str] = set()
    notes: list[str] = []
    for name in names:
        language = BUILDLESS_LANGUAGES.get(name)
        if language is not None:
            selected.add(language)
            continue
        reason = BUILD_REQUIRED_LANGUAGES.get(name) or UNSUPPORTED_LANGUAGES.get(name)
        if reason is not None:
            notes.append(f"{name} ({reason})")
        else:
            # Shell, CMake, Markdown and friends: nothing CodeQL analyses,
            # and nothing worth reporting as a gap.
            print(f"Ignoring language CodeQL does not analyse: {name}")
    return selected, notes


def build_plan(
    discovery: Discovery, *, restrict_to: ChangedFiles | None = None
) -> CodeqlPlan:
    """Decide the language matrix from what discovery managed to establish.

    Raises:
        DiscoveryError: neither source produced a usable answer, so the
            run can't tell an empty matrix from a broken lookup.
    """
    linguist_selected, skipped = languages_from_linguist(discovery.linguist_languages)
    path_selected = languages_from_paths(discovery.paths)

    if discovery.linguist_available and discovery.has_exact_tree:
        detection_source = DETECTION_LANGUAGES_AND_TREE
    elif discovery.has_exact_tree:
        detection_source = DETECTION_TREE_ONLY
    elif not discovery.linguist_available:
        raise DiscoveryError(
            "Cannot determine which languages to analyse: the repository "
            "language API failed and the commit's tree was unavailable or "
            "truncated. Refusing to run an empty CodeQL matrix, which "
            "would report as a clean scan."
        )
    elif discovery.path_source == "changed-files":
        detection_source = DETECTION_LANGUAGES_AND_CHANGED_FILES
    else:
        detection_source = DETECTION_LANGUAGES_ONLY

    if not discovery.linguist_languages and not discovery.has_exact_tree:
        raise DiscoveryError(
            "The repository language API reported no languages and the "
            "commit's tree was unavailable or truncated, so 'no code' and "
            "'discovery failed' are indistinguishable. Refusing to run an "
            "empty CodeQL matrix."
        )

    selected = set(linguist_selected) | path_selected
    if discovery.has_exact_tree:
        # The tree is authoritative about what exists, so a language
        # Linguist claims but the tree doesn't show would fail the run.
        selected -= _NEEDS_FILE_EVIDENCE - path_selected
    selected.add(ACTIONS_LANGUAGE)

    warnings = list(discovery.warnings)
    restricted = False
    if restrict_to is not None:
        if restrict_to.complete:
            touched = languages_from_paths(
                restrict_to.paths, require_rust_manifest=False
            )
            if touches_actions(restrict_to.paths):
                touched.add(ACTIONS_LANGUAGE)
            skipped.extend(
                f"{language} (not touched by this pull request)"
                for language in selected - touched
            )
            selected &= touched
            restricted = True
        else:
            warnings.append(
                "the pull request's file list was incomplete, so every "
                "discovered language is analysed rather than only the "
                "languages the pull request touches"
            )

    if "c-cpp" in selected:
        if discovery.has_exact_tree:
            cpp_files = count_cpp_files(discovery.paths)
            if cpp_files > MAX_BUILDLESS_CPP_FILES:
                selected.remove("c-cpp")
                skipped.append(
                    f"c-cpp ({cpp_files:,} C/C++ files exceeds the "
                    f"{MAX_BUILDLESS_CPP_FILES:,}-file standard-runner limit)"
                )
        else:
            selected.remove("c-cpp")
            skipped.append(
                "c-cpp (the complete C/C++ file count is unavailable, "
                f"so the {MAX_BUILDLESS_CPP_FILES:,}-file standard-runner "
                "limit cannot be verified)"
            )

    return CodeqlPlan(
        selected=tuple(sorted(selected)),
        skipped=tuple(sorted(skipped)),
        detection_source=detection_source,
        tree_truncated=discovery.tree_truncated,
        warnings=tuple(warnings),
        restricted_to_changes=restricted,
    )


def _github_get(path: str, *, token: str, api_root: str) -> object:
    """GET a GitHub REST path and parse the JSON body.

    Retries the statuses GitHub returns while a request is merely
    unlucky; anything else (404, 403, a malformed body) is the caller's
    problem to interpret.
    """
    url = f"{api_root.rstrip('/')}{path}"
    if urlsplit(url).scheme != "https":
        raise DiscoveryError(f"refusing to call a non-HTTPS GitHub API URL: {url}")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "rocm-security-gh",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_error: Exception | None = None
    for attempt in range(1, _ATTEMPTS + 1):
        try:
            # The scheme is checked above, so this can only speak HTTPS.
            with urlopen(  # nosec B310
                Request(url, headers=headers), timeout=_TIMEOUT_SECONDS
            ) as response:
                return json.loads(response.read(_MAX_RESPONSE_BYTES))
        except HTTPError as exc:
            if exc.code not in _RETRY_STATUSES:
                raise
            last_error = exc
        except (URLError, json.JSONDecodeError, TimeoutError) as exc:
            last_error = exc
        if attempt < _ATTEMPTS:
            print(f"GET {path} failed ({last_error}); retrying")
            time.sleep(attempt)
    raise DiscoveryError(f"GET {path} failed after {_ATTEMPTS} attempts: {last_error}")


def _fetch_linguist_languages(fetcher: JsonFetcher, repo: str) -> tuple[str, ...]:
    """Return Linguist's languages for `repo`, newest statistics first."""
    payload = fetcher(f"/repos/{repo}/languages")
    if not isinstance(payload, dict):
        raise DiscoveryError(f"/repos/{repo}/languages did not return an object")
    return tuple(str(name) for name in payload)


def _fetch_tree_paths(
    fetcher: JsonFetcher, repo: str, sha: str
) -> tuple[tuple[str, ...], bool]:
    """Return the blob paths of `sha`'s tree, and whether GitHub truncated it."""
    payload = fetcher(f"/repos/{repo}/git/trees/{quote(sha, safe='')}?recursive=1")
    if not isinstance(payload, dict):
        raise DiscoveryError(f"tree for {sha} did not return an object")
    entries = payload.get("tree")
    if not isinstance(entries, list):
        raise DiscoveryError(f"tree for {sha} has no 'tree' array")
    paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if isinstance(path, str):
            paths.append(path)
    return tuple(paths), bool(payload.get("truncated"))


def fetch_changed_files(fetcher: JsonFetcher, repo: str, number: int) -> ChangedFiles:
    """Return every changed path in a pull request, following pagination."""
    paths: list[str] = []
    complete = False
    for page in range(1, _MAX_FILE_PAGES + 1):
        payload = fetcher(
            f"/repos/{repo}/pulls/{number}/files?per_page=100&page={page}"
        )
        if not isinstance(payload, list):
            raise DiscoveryError(f"pull request {number} file list is not an array")
        for entry in payload:
            if isinstance(entry, dict):
                filename = entry.get("filename")
                if isinstance(filename, str):
                    paths.append(filename)
        if len(payload) < 100:
            complete = True
            break
    return ChangedFiles(paths=tuple(paths), complete=complete)


def pull_request_number(event: Mapping[str, object]) -> int | None:
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return None
    number = pull_request.get("number")
    return number if isinstance(number, int) else None


def discover(
    fetcher: JsonFetcher,
    *,
    repo: str,
    sha: str,
    event: Mapping[str, object],
) -> Discovery:
    """Ask the API what `repo` is written in at `sha`.

    Each source is allowed to fail on its own; `build_plan` decides
    whether what survived is enough to run on.
    """
    warnings: list[str] = []

    linguist: tuple[str, ...] = ()
    linguist_available = False
    try:
        linguist = _fetch_linguist_languages(fetcher, repo)
        linguist_available = True
        print(f"Repository languages (Linguist): {', '.join(linguist) or '<none>'}")
    except (DiscoveryError, OSError) as exc:
        warnings.append(f"the repository language API failed ({exc})")

    paths: tuple[str, ...] = ()
    path_source = ""
    truncated = False
    try:
        paths, truncated = _fetch_tree_paths(fetcher, repo, sha)
        if truncated:
            warnings.append(
                "GitHub truncated the commit's file tree (over 100,000 "
                "entries or 7 MB), so detection can't see the whole "
                "repository"
            )
            paths = ()
        else:
            path_source = "exact-tree"
            print(f"Exact tree at {sha}: {len(paths)} files")
    except (DiscoveryError, OSError) as exc:
        warnings.append(f"the commit tree API failed ({exc})")

    changed_files: ChangedFiles | None = None
    if not path_source:
        number = pull_request_number(event)
        if number is not None:
            try:
                changed_files = fetch_changed_files(fetcher, repo, number)
                paths = changed_files.paths
                path_source = "changed-files"
                print(f"Changed files in PR #{number}: {len(paths)} files")
            except (DiscoveryError, OSError) as exc:
                warnings.append(f"the pull request file API failed ({exc})")

    return Discovery(
        linguist_languages=linguist,
        linguist_available=linguist_available,
        paths=paths,
        path_source=path_source,
        tree_truncated=truncated,
        warnings=tuple(warnings),
        changed_files=changed_files,
    )


def render_summary(plan: CodeqlPlan) -> str:
    """Render the job summary a reviewer reads to judge the run's coverage."""
    lines = [
        "### CodeQL language discovery",
        "",
        f"- Detection source: `{plan.detection_source}`",
        f"- Selected: {', '.join(f'`{lang}`' for lang in plan.selected) or 'nothing'}",
    ]
    if plan.restricted_to_changes:
        lines.append("- Narrowed to the languages this pull request touches")
    if plan.skipped:
        lines.append(f"- Skipped: {', '.join(plan.skipped)}")
    if plan.tree_truncated:
        lines.append(
            "- Recursive tree: truncated, so a language present only in "
            "unscanned parts of the repository may be missing"
        )
    for warning in plan.warnings:
        lines.append(f"- Warning: {warning}")
    return "\n".join(lines)


def resolve_timeout(requested_minutes: int) -> int:
    """Return the CodeQL job budget, honouring a caller's raise."""
    return max(DEFAULT_TIMEOUT_MINUTES, requested_minutes)


def _normalize_config_path(config_path: str) -> str:
    """Return a normalized repository-relative CodeQL config path."""
    raw = config_path.strip()
    if not raw:
        return ""

    normalized = posixpath.normpath(raw)
    path = PurePosixPath(normalized)
    if path.is_absolute():
        raise DiscoveryError(
            f"CodeQL config path {config_path!r} must be relative to the repository"
        )
    if normalized == ".." or normalized.startswith("../"):
        raise DiscoveryError(
            f"CodeQL config path {config_path!r} resolves outside the repository"
        )
    if normalized == ".":
        raise DiscoveryError(f"CodeQL config path {config_path!r} does not name a file")
    return path.as_posix()


def validate_config_path(config_path: str, checkout_root: Path) -> str:
    """Validate and return a CodeQL config path relative to the scan target."""
    normalized = _normalize_config_path(config_path)
    if not normalized:
        return ""

    try:
        root = checkout_root.resolve(strict=True)
        resolved = (root / config_path.strip()).resolve(strict=True)
    except OSError as exc:
        raise DiscoveryError(
            f"CodeQL config file {config_path!r} does not exist"
        ) from exc

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise DiscoveryError(
            f"CodeQL config path {config_path!r} resolves outside the repository"
        ) from exc
    if not resolved.is_file():
        raise DiscoveryError(
            f"CodeQL config path {config_path!r} does not resolve to a file"
        )
    return normalized


def _changed_files_to_restrict_to(
    fetcher: JsonFetcher,
    *,
    repo: str,
    event: Mapping[str, object],
    scan_mode: str,
    already_fetched: ChangedFiles | None,
    config_path: str,
) -> ChangedFiles | None:
    """Return the file list to narrow the matrix with, or None to analyse everything.

    Only a `changed`-mode pull request narrows anything. A file list
    that couldn't be read narrows nothing -- an API failure has to widen
    the scan, never shrink it. A CodeQL config change also widens the
    scan because its paths and query settings apply repository-wide.
    """
    normalized_config_path = _normalize_config_path(config_path)
    number = pull_request_number(event)
    if scan_mode != "changed" or number is None:
        return None
    if already_fetched is not None:
        changed_files = already_fetched
    else:
        try:
            changed_files = fetch_changed_files(fetcher, repo, number)
        except (DiscoveryError, OSError) as exc:
            print(f"Could not list the pull request's files ({exc})")
            return ChangedFiles(paths=(), complete=False)

    if normalized_config_path and normalized_config_path in changed_files.paths:
        print("CodeQL config changed; analysing every discovered language")
        return None
    return changed_files


def main(argv: Sequence[str]) -> int:
    if argv:
        print(f"unexpected arguments: {' '.join(argv)}", file=sys.stderr)
        return 2

    if os.environ.get("SCANNER_REPOSITORY_PRIVATE", "").lower() == "true":
        matrix = json.dumps({"include": []})
        message = "CodeQL is disabled for private repositories by baseline policy"
        print(message)
        gha_set_output(
            {
                "matrix": matrix,
                "enabled": "false",
                "selected_languages": "",
                "config_path": "",
                "skipped_languages": message,
                "detection_source": DETECTION_PRIVATE_REPOSITORY_POLICY,
                "tree_truncated": "false",
            }
        )
        gha_append_step_summary(
            "### CodeQL language discovery\n\n"
            "- Disabled by policy: this is a private repository.\n"
            "- The other security scanners are unaffected."
        )
        return 0

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    if not repo or not sha:
        print(
            "GITHUB_REPOSITORY and GITHUB_SHA must be set to discover "
            "languages; refusing to guess.",
            file=sys.stderr,
        )
        return 2

    requested = os.environ.get("SCANNER_TIMEOUT_MINUTES") or "0"
    try:
        requested_minutes = int(requested)
    except ValueError:
        print(f"SCANNER_TIMEOUT_MINUTES must be an integer, got {requested!r}")
        return 2
    if requested_minutes < 0 or requested_minutes > MAX_TIMEOUT_MINUTES:
        print(
            f"SCANNER_TIMEOUT_MINUTES must be between 0 and "
            f"{MAX_TIMEOUT_MINUTES}, got {requested_minutes}"
        )
        return 2

    token = os.environ.get("GITHUB_TOKEN", "")
    # GITHUB_API_URL rather than a hard-coded host, for Enterprise Server.
    api_root = os.environ.get("GITHUB_API_URL") or "https://api.github.com"

    def fetcher(path: str) -> object:
        return _github_get(path, token=token, api_root=api_root)

    event: Mapping[str, object] = {}
    if os.environ.get("GITHUB_EVENT_PATH"):
        try:
            event = gha_load_github_event()
        except (KeyError, FileNotFoundError, ValueError, RuntimeError) as exc:
            print(f"Ignoring unreadable event payload: {exc}")

    try:
        config_path = validate_config_path(
            os.environ.get("SCANNER_CODEQL_CONFIG_PATH", ""),
            Path(os.environ.get("SCANNER_CHECKOUT_ROOT", ".scan-target")),
        )
        discovery = discover(fetcher, repo=repo, sha=sha, event=event)
        plan = build_plan(
            discovery,
            restrict_to=_changed_files_to_restrict_to(
                fetcher,
                repo=repo,
                event=event,
                scan_mode=os.environ.get("SCANNER_SCAN_MODE", "changed"),
                already_fetched=discovery.changed_files,
                config_path=config_path,
            ),
        )
    except DiscoveryError as exc:
        print(f"CodeQL language discovery failed: {exc}", file=sys.stderr)
        gha_append_step_summary(
            "### CodeQL language discovery\n\n"
            f"Failed: {exc}\n\nNo CodeQL analysis ran for this commit."
        )
        return 2

    timeout_minutes = resolve_timeout(requested_minutes)
    matrix = plan.matrix(timeout_minutes)
    print(f"CodeQL detection source: {plan.detection_source}")
    if plan.selected:
        print(
            f"CodeQL languages: {', '.join(plan.selected)} "
            f"({timeout_minutes}m each)"
        )
    else:
        print("No CodeQL language selected; nothing to analyse")
    if plan.skipped:
        print(f"CodeQL skipped: {', '.join(plan.skipped)}")
    for warning in plan.warnings:
        print(f"Warning: {warning}")
    print(f"matrix = {matrix}")

    gha_set_output(
        {
            "matrix": matrix,
            "enabled": "true" if plan.selected else "false",
            "selected_languages": ",".join(plan.selected),
            "config_path": config_path,
            "skipped_languages": ",".join(plan.skipped),
            "detection_source": plan.detection_source,
            "tree_truncated": "true" if plan.tree_truncated else "false",
        }
    )
    gha_append_step_summary(render_summary(plan))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
