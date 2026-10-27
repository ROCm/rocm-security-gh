#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Scoped CodeQL targets declared by the repository being scanned.

A target is a CodeQL analysis with its own build, limited to part of the
repository. The repository lists targets in a TOML file:

    [[target]]
    name = "native-tool"
    language = "c-cpp"
    scope = ["tools/native/"]
    container = "example/builder:1.0@sha256:<64 hex digits>"
    build_command = "cmake -S tools/native -B build && cmake --build build"
    trigger_paths = ["scripts/build_native.sh"]
    sparse_checkout = ["third_party/headers"]
    timeout_minutes = 180
    fail_on_findings = true

`name`, `language`, `scope` and `build_command` are required. Unknown keys
are rejected.
"""

import posixpath
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from security_scanners.utils.compute_scan_matrix import MAX_TIMEOUT_MINUTES

# Languages a target can analyse.
TARGET_LANGUAGES = frozenset({"c-cpp"})

# The name is used in check names, categories and artifact names.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$")

# Images are pinned by digest; a tag can be moved.
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$")

# Paths are literal prefixes, so a glob is refused rather than matching nothing.
_GLOB_CHARACTERS = frozenset("*?[]{}")

# Bounds the jobs a single change to the file can start.
MAX_TARGETS = 32

_TARGET_KEYS = frozenset(
    {
        "name",
        "language",
        "scope",
        "build_command",
        "container",
        "trigger_paths",
        "sparse_checkout",
        "timeout_minutes",
        "fail_on_findings",
    }
)
_REQUIRED_KEYS = ("name", "language", "scope", "build_command")


class TargetsError(ValueError):
    """The targets file is unreadable or declares something unusable."""


@dataclass(frozen=True)
class CodeqlTarget:
    """One scoped CodeQL analysis.

    `scope` holds normalised repository-relative directories ("." is the
    whole repository); only results under them are reported.
    `trigger_paths` are further files or directories whose change runs the
    target on a pull request. A non-empty `sparse_checkout` limits the
    checkout to `scope`, these directories and the files at the repository
    root; empty means a full checkout.
    """

    name: str
    language: str
    scope: tuple[str, ...]
    build_command: str
    container: str = ""
    trigger_paths: tuple[str, ...] = ()
    sparse_checkout: tuple[str, ...] = ()
    timeout_minutes: int = 0
    fail_on_findings: bool = False


def normalize_repo_path(raw: str, *, what: str) -> str:
    """Return `raw` as a normalised repository-relative path.

    "src/app/" and "./src//app" both become "src/app"; "." stays ".".

    Raises:
        TargetsError: `raw` is empty, absolute, outside the repository, or
            contains glob characters.
    """
    stripped = raw.strip()
    if not stripped:
        raise TargetsError(f"{what} must not be empty")
    if "\\" in stripped or "\x00" in stripped or "\n" in stripped:
        raise TargetsError(f"{what} {raw!r} must be a '/'-separated path")
    if _GLOB_CHARACTERS & set(stripped):
        raise TargetsError(
            f"{what} {raw!r} is matched literally and can't contain glob "
            "characters; name a directory"
        )
    if stripped.startswith("/"):
        raise TargetsError(f"{what} {raw!r} must be relative to the repository")
    normalized = posixpath.normpath(stripped)
    if normalized == ".." or normalized.startswith("../"):
        raise TargetsError(f"{what} {raw!r} resolves outside the repository")
    return normalized


def path_in_scope(path: str, scope: str) -> bool:
    """Whether `path` is `scope` or lies under it, by whole path segment.

    "src/app" holds "src/app/a.cpp" but not "src/app_other/a.cpp"; "."
    holds every path.
    """
    return scope == "." or path == scope or path.startswith(f"{scope}/")


def minimal_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    """Drop every scope that another one already contains, and duplicates."""
    unique = sorted(set(scopes))
    return tuple(
        scope
        for scope in unique
        if not any(other != scope and path_in_scope(scope, other) for other in unique)
    )


def _require_str(raw: Mapping[str, object], key: str, *, where: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TargetsError(f"{where}: '{key}' must be a non-empty string")
    return value


def _path_list(raw: Mapping[str, object], key: str, *, where: str) -> tuple[str, ...]:
    value = raw.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TargetsError(f"{where}: '{key}' must be a list of strings")
    paths = tuple(
        normalize_repo_path(item, what=f"{where}: '{key}' entry") for item in value
    )
    return tuple(dict.fromkeys(paths))


def parse_target(raw: object, where: str) -> CodeqlTarget:
    """Build a target from one table of the targets file.

    `where` names the table in errors.

    Raises:
        TargetsError: the table is not a valid target.
    """
    if not isinstance(raw, dict):
        raise TargetsError(f"{where} must be a table")
    unknown = sorted(set(raw) - _TARGET_KEYS)
    if unknown:
        raise TargetsError(
            f"{where}: unknown key(s) {', '.join(unknown)}; "
            f"expected {', '.join(sorted(_TARGET_KEYS))}"
        )
    missing = [key for key in _REQUIRED_KEYS if key not in raw]
    if missing:
        raise TargetsError(f"{where}: missing {', '.join(missing)}")

    name = _require_str(raw, "name", where=where).strip()
    where = f"target {name!r}"
    if not _NAME_RE.fullmatch(name):
        raise TargetsError(
            f"{where}: name must be 1-48 characters from letters, digits, "
            "'.', '_' and '-', starting with a letter or digit"
        )

    language = _require_str(raw, "language", where=where).strip()
    if language not in TARGET_LANGUAGES:
        raise TargetsError(
            f"{where}: language {language!r} is not supported; "
            f"supported: {', '.join(sorted(TARGET_LANGUAGES))}"
        )

    scope = _path_list(raw, "scope", where=where)
    if not scope:
        raise TargetsError(f"{where}: 'scope' must list at least one directory")

    container = ""
    if "container" in raw:
        container = _require_str(raw, "container", where=where).strip()
        if not _IMAGE_RE.fullmatch(container):
            raise TargetsError(
                f"{where}: container must be pinned by digest, as "
                "'image@sha256:<64 hex digits>'"
            )

    trigger_paths: tuple[str, ...] = ()
    if "trigger_paths" in raw:
        trigger_paths = _path_list(raw, "trigger_paths", where=where)

    sparse_checkout: tuple[str, ...] = ()
    if "sparse_checkout" in raw:
        sparse_checkout = _path_list(raw, "sparse_checkout", where=where)
        if sparse_checkout and "." in scope + sparse_checkout:
            raise TargetsError(
                f"{where}: sparse_checkout can't be combined with the whole "
                "repository ('.')"
            )

    timeout_minutes = 0
    if "timeout_minutes" in raw:
        value = raw["timeout_minutes"]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= MAX_TIMEOUT_MINUTES
        ):
            raise TargetsError(
                f"{where}: timeout_minutes must be an integer from 0 to "
                f"{MAX_TIMEOUT_MINUTES}"
            )
        timeout_minutes = value

    fail_on_findings = False
    if "fail_on_findings" in raw:
        value = raw["fail_on_findings"]
        if not isinstance(value, bool):
            raise TargetsError(f"{where}: fail_on_findings must be true or false")
        fail_on_findings = value

    return CodeqlTarget(
        name=name,
        language=language,
        scope=scope,
        build_command=_require_str(raw, "build_command", where=where).strip(),
        container=container,
        trigger_paths=trigger_paths,
        sparse_checkout=sparse_checkout,
        timeout_minutes=timeout_minutes,
        fail_on_findings=fail_on_findings,
    )


def parse_targets(text: str) -> tuple[CodeqlTarget, ...]:
    """Parse the contents of a targets file.

    Raises:
        TargetsError: the text is not valid TOML in the documented shape.
    """
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise TargetsError(f"not valid TOML: {exc}") from exc

    unknown = sorted(set(document) - {"target"})
    if unknown:
        raise TargetsError(
            f"unknown top-level key(s) {', '.join(unknown)}; "
            "targets are declared as [[target]] tables"
        )
    entries = document.get("target")
    if not isinstance(entries, list) or not entries:
        raise TargetsError("declares no targets; add at least one [[target]] table")
    if len(entries) > MAX_TARGETS:
        raise TargetsError(f"declares {len(entries)} targets; at most {MAX_TARGETS}")

    targets = tuple(
        parse_target(entry, f"target #{i}") for i, entry in enumerate(entries, 1)
    )
    names = [target.name for target in targets]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise TargetsError(f"duplicate target name(s): {', '.join(duplicates)}")
    return targets


def load_targets(path: Path) -> tuple[CodeqlTarget, ...]:
    """Read and parse the targets file at `path`.

    Raises:
        TargetsError: the file can't be read or is not a valid targets file.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise TargetsError(f"cannot read the targets file: {exc}") from exc
    return parse_targets(text)


# How the baseline analyses C/C++: `none` reads the sources without a build,
# `manual` runs a build command while CodeQL watches.
BUILD_MODES = ("none", "manual")

# The target a `manual` build mode describes.
BUILD_INPUT_TARGET_NAME = "c-cpp"


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def target_from_build_inputs(
    *,
    build_mode: str,
    build_command: str = "",
    container: str = "",
    scope: str = "",
    sparse_checkout: str = "",
    trigger_paths: str = "",
    fail_on_findings: bool = False,
) -> CodeqlTarget | None:
    """Return the C/C++ target a caller's build inputs describe, if any.

    `scope`, `sparse_checkout` and `trigger_paths` are newline-separated
    paths; an empty `scope` means the whole repository. Mode `none` (or
    empty) describes no target.

    Raises:
        TargetsError: the mode is unknown, a build input is set without
            `manual`, or `manual` has no build command or an invalid input.
    """
    mode = build_mode.strip() or "none"
    if mode not in BUILD_MODES:
        raise TargetsError(
            f"build mode {build_mode!r} is not one of {', '.join(BUILD_MODES)}"
        )
    inputs = (build_command, container, scope, sparse_checkout, trigger_paths)
    if mode == "none":
        if any(value.strip() for value in inputs) or fail_on_findings:
            raise TargetsError("the CodeQL build inputs need build mode 'manual'")
        return None
    if not build_command.strip():
        raise TargetsError("build mode 'manual' needs a build command")

    raw: dict[str, object] = {
        "name": BUILD_INPUT_TARGET_NAME,
        "language": "c-cpp",
        "scope": _lines(scope) or ["."],
        "build_command": build_command,
        "sparse_checkout": _lines(sparse_checkout),
        "trigger_paths": _lines(trigger_paths),
        "fail_on_findings": fail_on_findings,
    }
    if container.strip():
        raw["container"] = container
    return parse_target(raw, "build inputs")
