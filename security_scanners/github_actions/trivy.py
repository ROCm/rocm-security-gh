#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Run trivy against a repository filesystem or container image.

- Download and SHA256-verify the pinned `trivy` release binary.
- Require the baseline Trivy config (hard error if missing).
- Derive change sets from the GitHub event for changed/all scans; in
  'changed' mode short-circuit to a no-op unless a dependency
  manifest / IaC / container file changed under `--source-dir` (trivy's
  filesystem scanner needs the whole subtree to resolve transitive
  deps and cross-file IaC references, so -- unlike bandit/zizmor --
  individual changed files are never fed to it directly: we either
  scan the whole subtree or nothing). Run per requested format and
  emit SARIF/non-SARIF paths plus a severity tally.

In image mode (`--scan-type image`) one invocation builds and scans one
image: `--dockerfile` names its Dockerfile and `--image` the local tag.
The image is built with `docker build` from the checkout root, or by
`--build-commands` when given, which must produce `--image`. In 'changed'
mode the build and scan run only when the calling event changed one of
the image's inputs or the Trivy config/ignore file.

Default scanners are `misconfig,vuln,license`; `secret` is omitted
because gitleaks already covers secret detection.

Exit codes:

* `0` - clean run, or an empty changed-file set.
* `1` - findings at/above `--severity-threshold`, or `--report-formats`
  / `--scanners` was empty/unknown.
* `2` - input error: scan path or Dockerfile missing, invalid image
  reference, baseline config missing, `GITHUB_EVENT_PATH` malformed, the
  image build failed, or trivy itself errored.

Inputs come from CLI flags or matching `SCANNER_*` env vars set by
`security-baseline.yml`. That prefix is shared by every scanner, so one
workflow step body drives all of them; each script ignores the variables
that don't apply to it. Any ambient `TRIVY_*` vars are stripped from the
trivy subprocess environment, so nothing in the runner's environment can
override the flags this script passes via trivy's own env-driven CLI
(e.g. `TRIVY_SEVERITY`, `TRIVY_SCANNERS`).
"""

import argparse
import fnmatch
import json
import logging
import os
import posixpath
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from security_scanners.utils.binary_checksums import (
    download_and_verify_tarball,
    expected_sha256,
)
from security_scanners.utils.github_actions_api import (
    gha_append_step_summary,
    gha_load_github_event,
    gha_set_output,
)
from security_scanners.utils.step_summary import emit_reports
from security_scanners.utils.scanner_config import (
    find_config_change,
    ignore_file_paths,
    resolve_ignore_file,
    resolve_scanner_config,
    scanner_config_paths,
)
from security_scanners.utils.trivy_targets import (
    SCAN_TYPE_FILESYSTEM,
    SCAN_TYPE_IMAGE,
    SCAN_TYPES,
    TrivyTargetError,
    validate_image_reference,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

log = logging.getLogger(__name__)


# Keep in sync with the `report_formats` input in
# `.github/workflows/security-baseline.yml`.
_SUPPORTED_FORMATS: dict[str, str] = {
    "sarif": "sarif",
    "json": "json",
    "table": "txt",
    "cyclonedx": "cdx.json",
    "spdx-json": "spdx.json",
    "github": "github.json",
}
# Tool-independent aliases, so a caller can ask every scanner for "the
# report a reviewer reads" without knowing that trivy spells it 'table',
# gitleaks 'csv', zizmor 'plain' and bandit 'txt'.
_FORMAT_ALIASES: dict[str, str] = {"human": "table"}
_TRIVY_VERSION = "0.71.0"
_TRIVY_TARBALL_FILENAME = f"trivy_{_TRIVY_VERSION}_Linux-64bit.tar.gz"
_TRIVY_TARBALL_URL = f"https://rocm-third-party-deps.s3.us-east-2.amazonaws.com/{_TRIVY_TARBALL_FILENAME}"
_CONFIG_PATH = ".github/scan_tools_configs/trivy.yml"
# Where a scanned repository is allowed to keep its own config, in the
# order trivy itself would look for one.
_CONFIG_CANDIDATES: tuple[str, ...] = ("trivy.yaml", "trivy.yml")
# Suppressions for findings a repository has already triaged. The YAML
# format supports path-scoped entries and statements; the plain format is
# retained as a fallback for repositories that have not adopted it.
_IGNORE_FILENAMES: tuple[str, ...] = (".trivyignore.yaml", ".trivyignore")
# Ascending severity order; threshold comparisons rely on it. Trivy has a
# CRITICAL tier (unlike bandit/zizmor); UNKNOWN never satisfies a threshold.
_SEVERITY_ORDER: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_SEVERITY_CHOICES: tuple[str, ...] = tuple(s.lower() for s in _SEVERITY_ORDER)
_DEFAULT_SEVERITY_THRESHOLD = "high"
# Trivy scanners: vuln (CVEs), misconfig (IaC), secret, license.
_SUPPORTED_SCANNERS: tuple[str, ...] = ("vuln", "misconfig", "secret", "license")
# Omits 'secret': gitleaks already covers secret detection in this repo.
_DEFAULT_SCANNERS = "misconfig,vuln,license"
# Internal JSON tally pass output; cleaned up before returning.
_INTERNAL_TALLY_PATH = "trivy-tally.json"
# Diff filter for 'changed' mode: dependency manifests/lockfiles (drive
# vuln) plus container/IaC sources (drive misconfig). Broad globs like
# **/*.yaml are excluded so unrelated YAML changes don't defeat the
# no-op fast path; callers that want full coverage use scan_mode=all.
_AUDITED_PATTERNS: tuple[str, ...] = (
    # Python
    "**/pyproject.toml",
    "pyproject.toml",
    "**/requirements*.txt",
    "requirements*.txt",
    "**/Pipfile",
    "**/Pipfile.lock",
    "**/poetry.lock",
    "**/setup.py",
    "**/setup.cfg",
    # JavaScript / Node
    "**/package.json",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/npm-shrinkwrap.json",
    # Rust
    "**/Cargo.toml",
    "**/Cargo.lock",
    # Go
    "**/go.mod",
    "**/go.sum",
    # Java / Kotlin
    "**/pom.xml",
    "**/build.gradle",
    "**/build.gradle.kts",
    "**/gradle.lockfile",
    # .NET
    "**/*.csproj",
    "**/packages.config",
    "**/packages.lock.json",
    # Ruby
    "**/Gemfile",
    "**/Gemfile.lock",
    "**/*.gemspec",
    # PHP
    "**/composer.json",
    "**/composer.lock",
    # Container manifests
    "**/Dockerfile",
    "**/Dockerfile.*",
    "**/*.dockerfile",
    "**/Containerfile",
    "**/Containerfile.*",
    # Terraform
    "**/*.tf",
    "**/*.tfvars",
    "**/*.tf.json",
)
# Config-only PRs widen the run to a full scan instead (see
# _determine_changed_audited_files), so a new config or suppression is
# exercised by the PR that introduces it.
_CONFIG_TRIGGERS: tuple[str, ...] = (*_CONFIG_CANDIDATES, *_IGNORE_FILENAMES)


@dataclass(frozen=True)
class _ReportTarget:
    """A single `(format, on-disk path)` pair the runner will produce."""

    fmt: str
    path: Path


def _emit_non_sarif_reports(
    non_sarif: list[_ReportTarget],
    append_step_summary: Callable[[str], None],
) -> None:
    """Surface non-SARIF reports in logs and a size-bounded step summary."""
    emit_reports("Trivy", [t.path for t in non_sarif], append_step_summary)


def get_trivy_binary() -> Path:
    """Download, verify, and extract the pinned trivy binary, and return its path."""
    install_dir = (
        Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
        / f"trivy-{_TRIVY_VERSION}"
    )
    binary = install_dir / "trivy"
    expected_sha = expected_sha256(REPO_ROOT, _TRIVY_TARBALL_FILENAME)
    log.info("Downloading trivy v%s from %s", _TRIVY_VERSION, _TRIVY_TARBALL_URL)
    download_and_verify_tarball(
        url=_TRIVY_TARBALL_URL,
        expected_sha256=expected_sha,
        member_name="trivy",
        install_dir=install_dir,
    )
    binary.chmod(0o755)

    try:
        result = subprocess.run(
            [str(binary), "--version"],
            check=True,
            capture_output=True,
            text=True,
            env=_trivy_subprocess_env(),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            f"trivy at {binary} failed to execute after install: {exc}"
        ) from exc
    log.info(
        "Installed %s at %s",
        result.stdout.strip().splitlines()[0] if result.stdout.strip() else "trivy",
        binary,
    )
    return binary


def _trivy_subprocess_env() -> dict[str, str]:
    """Return a subprocess env with any ambient `TRIVY_*` vars stripped.

    Trivy natively reads `TRIVY_*` env vars as defaults for its own CLI
    flags (e.g. `TRIVY_SEVERITY`, `TRIVY_SCANNERS`), so anything set in
    the runner's environment could silently override the flags this
    script passes -- which are org policy, not suggestions. Our own
    inputs arrive under `SCANNER_*` and so survive this stripping.
    """
    env = dict(os.environ)
    for key in list(env.keys()):
        if key.startswith("TRIVY_"):
            del env[key]
    return env


def _parse_report_formats(raw: str) -> list[_ReportTarget]:
    """Parse a comma-separated `report_formats` value into report targets."""
    targets: list[_ReportTarget] = []
    seen: set[str] = set()
    for raw_fmt in raw.split(","):
        fmt = _FORMAT_ALIASES.get(raw_fmt.strip(), raw_fmt.strip())
        if not fmt or fmt in seen:
            continue
        seen.add(fmt)
        ext = _SUPPORTED_FORMATS.get(fmt)
        if ext is None:
            raise ValueError(
                f"Invalid report_formats entry '{fmt}' "
                f"(expected one of: "
                f"{', '.join(sorted({*_SUPPORTED_FORMATS, *_FORMAT_ALIASES}))})"
            )
        targets.append(_ReportTarget(fmt=fmt, path=Path(f"trivy-report.{ext}")))
    if not targets:
        raise ValueError(
            "report_formats is empty (expected one or more of: "
            f"{', '.join(sorted(_SUPPORTED_FORMATS))})"
        )
    return targets


def _parse_scanners(raw: str) -> list[str]:
    """Parse a comma-separated `scanners` value into a canonical list."""
    scanners: list[str] = []
    seen: set[str] = set()
    for raw_s in raw.split(","):
        s = raw_s.strip().lower()
        if not s or s in seen:
            continue
        if s not in _SUPPORTED_SCANNERS:
            raise ValueError(
                f"Invalid scanner '{s}' "
                f"(expected one or more of: {', '.join(_SUPPORTED_SCANNERS)})"
            )
        seen.add(s)
        scanners.append(s)
    if not scanners:
        raise ValueError(
            "scanners is empty (expected one or more of: "
            f"{', '.join(_SUPPORTED_SCANNERS)})"
        )
    return scanners


def _resolve_dockerfile_path(checkout_root: Path, raw: str) -> Path:
    """Resolve a Dockerfile path and keep it inside the checkout."""
    dockerfile = raw.strip()
    if not dockerfile:
        raise ValueError("Dockerfile path is empty")

    checkout = checkout_root.resolve()
    path = Path(dockerfile)
    if path.is_absolute():
        raise ValueError("Dockerfile path must be relative to the checkout root")

    resolved = (checkout / path).resolve()
    try:
        resolved.relative_to(checkout)
    except ValueError as exc:
        raise ValueError(
            "Dockerfile path must remain inside the checkout root"
        ) from exc
    if not resolved.is_file():
        raise ValueError(f"Dockerfile not found: {dockerfile}")
    return resolved


def _build_trivy_image(
    *,
    checkout_root: Path,
    dockerfile: Path,
    image: str,
    build_commands: str = "",
) -> None:
    """Build `image` with `docker build`, or with `build_commands` instead."""
    if build_commands:
        dockerfile_relpath = dockerfile.relative_to(checkout_root.resolve())
        command = ["bash", "-euo", "pipefail", "-c", build_commands]
        env: dict[str, str] | None = {
            **os.environ,
            "SCANNER_TRIVY_IMAGE": image,
            "SCANNER_TRIVY_DOCKERFILE": dockerfile_relpath.as_posix(),
        }
        log.info("Running build commands for %s:\n%s", image, build_commands)
    else:
        command = [
            "docker",
            "build",
            "--file",
            str(dockerfile),
            "--tag",
            image,
            ".",
        ]
        env = None
        log.info("Running: %s", " ".join(command))
    try:
        subprocess.run(command, check=True, cwd=checkout_root, env=env)
    except OSError as exc:
        raise RuntimeError(f"image build failed to start: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"image build failed with exit code {exc.returncode}"
        ) from exc

    try:
        subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            f"the image build did not produce a local image named {image}"
        ) from exc


def _resolve_config_path(checkout_root: Path, configured_path: str = "") -> str:
    # The fallback is anchored on REPO_ROOT (this script's own checkout),
    # not the cwd: when this workflow is called from another repo, the cwd
    # holds *that* repo's checkout (the scan target), not
    # rocm-security-gh's.
    return str(
        resolve_scanner_config(
            scanner="trivy",
            checkout_root=checkout_root,
            candidates=_CONFIG_CANDIDATES,
            fallback=REPO_ROOT / _CONFIG_PATH,
            configured_path=configured_path,
        ).path
    )


def _event_str(event: Mapping[str, object], *keys: str) -> str:
    """Return the nested string at `event[keys[0]][keys[1]]...`, or `""`."""
    current: object = event
    for key in keys:
        if not isinstance(current, Mapping):
            return ""
        current = current.get(key)
    return current if isinstance(current, str) else ""


def _diff_range(event_name: str, event: Mapping[str, object]) -> tuple[str, str] | None:
    """Return `(base_sha, head_sha)` for the calling event, or `None`.

    `None` means "no diff range applicable" (workflow_dispatch,
    schedule, new ref push, missing SHAs, etc.) and instructs callers
    to fall back to a full scan.
    """
    if event_name in ("pull_request", "pull_request_target"):
        base = _event_str(event, "pull_request", "base", "sha")
        head = _event_str(event, "pull_request", "head", "sha")
        if not base or not head:
            log.warning("PR event missing base/head SHA; using the full scan scope")
            return None
        return (base, head)
    if event_name == "push":
        before = _event_str(event, "before")
        after = _event_str(event, "after")
        if not before or not after:
            log.warning(
                "Push event missing before/after SHA; using the full scan scope"
            )
            return None
        # All-zero SHA means a new ref: nothing to diff against.
        if set(before) <= {"0"}:
            log.info("Push created a new ref; using the full scan scope")
            return None
        return (before, after)
    log.info(
        "Event '%s' has no diff range; using the full scan scope",
        event_name or "<unset>",
    )
    return None


def _is_audited_path(relpath: str) -> bool:
    """Return True if `relpath` matches an audited file pattern.

    `**/` patterns are matched both with and without the prefix so
    top-level files hit the same rules as nested ones.
    """
    norm = relpath.replace(os.sep, "/")
    for pattern in _AUDITED_PATTERNS:
        if fnmatch.fnmatchcase(norm, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatchcase(
            norm, pattern[len("**/") :]
        ):
            return True
    return False


def _determine_changed_audited_files(
    event_name: str,
    event: Mapping[str, object],
    scan_path: Path,
    checkout_root: Path = Path("."),
    config_paths: tuple[str, ...] = _CONFIG_TRIGGERS,
) -> list[Path] | None:
    """Return the changed audited files inside `scan_path`, or `None`.

    Filters the git diff to `_AUDITED_PATTERNS`. The result drives the
    'changed' mode short-circuit but, unlike bandit/zizmor, the files
    themselves are NOT fed to trivy: its filesystem scanner needs the
    whole subtree to resolve transitive deps and cross-file IaC
    references, so we either scan everything under `scan_path` or
    nothing.

    `checkout_root` is the scan target's git checkout (its repo root),
    which this function runs `git` in explicitly: `scan_path` may point
    at a subdirectory of the checkout, but `git diff --name-only`
    always prints paths relative to the repo *root*, not to the
    process's cwd or to whatever subdirectory `git` was invoked from.

    Semantics:

    * `None` — no usable diff range; caller should fall back to a full
      recursive scan of `scan_path`.
    * `[]` — diff range was usable but contained no audited files under
      `scan_path`; caller should treat this as a clean no-op.
    * `[paths…]` — at least one audited file changed; caller should run
      trivy against `scan_path` and log the trigger files.
    """
    changed = _changed_paths(event_name, event, checkout_root, config_paths)
    if changed is None:
        return None

    scan_root = scan_path.resolve()
    files: list[Path] = []
    for raw in changed:
        relpath = raw.strip()
        if not relpath or not _is_audited_path(relpath):
            continue
        # `relpath` is relative to the repo root (`checkout_root`), not
        # to this process's cwd, so it must be re-anchored there before
        # any further path operations.
        candidate = checkout_root / relpath
        try:
            candidate.resolve().relative_to(scan_root)
        except ValueError:
            continue
        if not candidate.is_file():
            continue
        files.append(candidate)
    return files


def _dockerfile_changed(
    event_name: str,
    event: Mapping[str, object],
    dockerfile: Path,
    checkout_root: Path = Path("."),
    config_paths: tuple[str, ...] = _CONFIG_TRIGGERS,
    build_commands: str = "",
) -> bool:
    """Return whether the event changed an input of `dockerfile`'s image.

    With `build_commands` any change counts, since they pick their own
    build context.
    """
    changed = _changed_paths(event_name, event, checkout_root, config_paths)
    if changed is None:
        return True
    relpaths = [relpath.strip() for relpath in changed if relpath.strip()]
    build_files = {
        dockerfile,
        dockerfile.with_name(f"{dockerfile.name}.dockerignore"),
        (checkout_root / ".dockerignore").resolve(),
    }
    if any((checkout_root / relpath).resolve() in build_files for relpath in relpaths):
        return True
    if build_commands:
        return bool(relpaths)
    sources = _dockerfile_sources(dockerfile)
    return any(sources.matches(relpath) for relpath in relpaths)


@dataclass(frozen=True)
class DockerfileSources:
    """Build-context paths a Dockerfile reads.

    `whole_context` is set when any path may be read, including sources
    the parser cannot map to paths.
    """

    whole_context: bool = False
    paths: frozenset[str] = frozenset()
    patterns: frozenset[str] = frozenset()

    def matches(self, relpath: str) -> bool:
        if self.whole_context:
            return True
        if any(
            relpath == path or relpath.startswith(f"{path}/") for path in self.paths
        ):
            return True
        # fnmatch's '*' matches '/', so 'pattern/*' covers a matched directory.
        return any(
            fnmatch.fnmatchcase(relpath, pattern)
            or fnmatch.fnmatchcase(relpath, f"{pattern}/*")
            for pattern in self.patterns
        )


_WHOLE_CONTEXT = DockerfileSources(whole_context=True)
_GLOB_CHARS = frozenset("*?[")
# '<<EOF', '<<-EOF', "<<'EOF'", '<<"EOF"', but not the here-string '<<<'.
_HEREDOC_RE = re.compile(r"(?<!<)<<(?!<)-?([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1")
_DIRECTIVE_RE = re.compile(r"#\s*([A-Za-z]+)\s*=\s*(\S+)\s*")
_FLAG_RE = re.compile(r"(--\S+)\s+")


def _dockerfile_sources(dockerfile: Path) -> DockerfileSources:
    """Return the paths `COPY`, `ADD` and `RUN --mount` read from the context."""
    try:
        text = dockerfile.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        log.warning(
            "cannot read %s (%s); treating every change as an input", dockerfile, exc
        )
        return _WHOLE_CONTEXT
    instructions = _dockerfile_instructions(text)
    if instructions is None:
        return _WHOLE_CONTEXT
    paths: set[str] = set()
    patterns: set[str] = set()
    for instruction in instructions:
        sources = _instruction_sources(instruction)
        if sources is None:
            return _WHOLE_CONTEXT
        for source in sources:
            path = _context_path(source)
            if path is None:
                return _WHOLE_CONTEXT
            if _GLOB_CHARS.intersection(path):
                patterns.add(path)
            else:
                paths.add(path)
    return DockerfileSources(paths=frozenset(paths), patterns=frozenset(patterns))


def _dockerfile_instructions(text: str) -> list[str] | None:
    """Return logical instructions, or `None` for an unterminated heredoc."""
    lines = text.splitlines()
    escape = "\\"
    # Parser directives are only honoured at the very top of the file.
    for line in lines:
        directive = _DIRECTIVE_RE.fullmatch(line.strip())
        if directive is None:
            break
        if directive.group(1).lower() == "escape":
            escape = directive.group(2)
    instructions: list[str] = []
    current = ""
    heredoc_terminators: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if heredoc_terminators:
            if line == heredoc_terminators[0]:
                heredoc_terminators.pop(0)
            continue
        if not line or line.startswith("#"):
            continue
        current = f"{current} {line}" if current else line
        if current.endswith(escape):
            current = current[: -len(escape)].rstrip()
            continue
        instructions.append(current)
        heredoc_terminators = [
            match.group(2) for match in _HEREDOC_RE.finditer(current)
        ]
        current = ""
    if heredoc_terminators:
        return None
    if current:
        instructions.append(current)
    return instructions


def _instruction_sources(instruction: str) -> list[str] | None:
    """Return the context sources an instruction reads, or `None` if unparsable."""
    opcode, _, rest = instruction.partition(" ")
    opcode = opcode.lower()
    flags, rest = _split_flags(rest.strip())
    if opcode == "run":
        return _run_mount_sources(flags)
    if opcode not in {"copy", "add"}:
        return []
    if any(flag.startswith("--from=") for flag in flags):
        return []
    operands = _copy_operands(rest)
    if operands is None or len(operands) < 2:
        return None
    sources = operands[:-1]
    return [
        source
        for source in sources
        if not source.startswith("<<")
        and not (opcode == "add" and ("://" in source or source.startswith("git@")))
    ]


def _split_flags(rest: str) -> tuple[list[str], str]:
    flags: list[str] = []
    while (match := _FLAG_RE.match(rest)) is not None:
        flags.append(match.group(1))
        rest = rest[match.end() :]
    return flags, rest


def _copy_operands(rest: str) -> list[str] | None:
    if rest.startswith("["):
        try:
            values = json.loads(rest)
        except json.JSONDecodeError:
            # Docker falls back to the shell form.
            values = None
        if isinstance(values, list):
            if not all(isinstance(value, str) for value in values):
                return None
            return [value for value in values if value.strip()]
    try:
        return shlex.split(rest)
    except ValueError:
        return None


def _run_mount_sources(flags: list[str]) -> list[str]:
    """Return the sources of bind mounts that read the build context."""
    sources: list[str] = []
    for flag in flags:
        if not flag.startswith("--mount="):
            continue
        options: dict[str, str] = {}
        for field in flag.removeprefix("--mount=").strip("\"'").split(","):
            key, _, value = field.partition("=")
            options[key.strip().lower()] = value.strip()
        if options.get("type", "bind") != "bind" or "from" in options:
            continue
        sources.append(options.get("source", options.get("src", ".")))
    return sources


def _context_path(source: str) -> str | None:
    """Return `source` relative to the context root, as Docker resolves it.

    '/src', './src/' and '../src' all give 'src'. `None` means the source
    could be any path: the context root or a variable.
    """
    if "$" in source:
        return None
    path = posixpath.normpath(f"/{source}").lstrip("/")
    return path or None


def _changed_paths(
    event_name: str,
    event: Mapping[str, object],
    checkout_root: Path,
    config_paths: tuple[str, ...],
) -> list[str] | None:
    """Return the repo-root-relative paths the calling event changed.

    `None` means the caller must scan its whole scope: the event has no
    usable diff range, `git diff` failed, or a Trivy config or ignore file
    changed (which applies to every file).
    """
    diff = _diff_range(event_name, event)
    if diff is None:
        return None
    base_sha, head_sha = diff

    # Best-effort fetch so the base SHA is reachable for the diff.
    subprocess.run(
        ["git", "fetch", "--no-tags", "--depth=1", "origin", base_sha],
        cwd=checkout_root,
        check=False,
        capture_output=True,
    )

    try:
        result = subprocess.run(
            [
                "git",
                "diff",
                "--name-only",
                # D is here for the config check below: deleting a config
                # or ignore file switches the whole repository back to the
                # default one, which is as much a config change as editing
                # it. Deleted manifests reaching the filter is harmless,
                # since the is_file() check below drops paths that no
                # longer exist.
                "--diff-filter=ACDMR",
                f"{base_sha}..{head_sha}",
            ],
            cwd=checkout_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        log.warning(
            "git diff %s..%s failed (rc=%s, stderr=%r); using the full scan scope",
            base_sha,
            head_sha,
            exc.returncode,
            exc.stderr.strip() if exc.stderr else "",
        )
        return None

    changed = result.stdout.splitlines()
    config_change = find_config_change(changed, filenames=config_paths)
    if config_change is not None:
        log.info(
            "Changed config (%s) applies to every file, so this run scans "
            "every file in scope instead of the changed files alone",
            config_change,
        )
        return None
    return changed


def _run_trivy(
    binary: Path,
    user_targets: list[_ReportTarget],
    *,
    config_path: str,
    scanners: list[str],
    scan_path: Path | None = None,
    ignore_path: Path | None = None,
    scan_type: str = SCAN_TYPE_FILESYSTEM,
    image: str = "",
) -> dict[str, int]:
    """Run trivy for each user-requested format plus an internal JSON
    tally pass if the user didn't already request one, and return a
    severity tally.
    """
    if scan_type == SCAN_TYPE_FILESYSTEM:
        if scan_path is None:
            raise RuntimeError("filesystem scan requires a scan path")
        scan_command = ["fs", str(scan_path)]
    elif scan_type == SCAN_TYPE_IMAGE:
        try:
            image_reference = validate_image_reference(image)
        except TrivyTargetError as exc:
            raise RuntimeError(f"invalid image reference: {exc}") from exc
        scan_command = ["image", image_reference]
    else:
        raise RuntimeError(
            f"unsupported Trivy scan type '{scan_type}' "
            f"(expected one of: {', '.join(SCAN_TYPES)})"
        )

    severity_csv = ",".join(_SEVERITY_ORDER)
    scanners_csv = ",".join(scanners)
    base_args: list[str] = [
        str(binary),
        *scan_command,
        "--severity",
        severity_csv,
        "--scanners",
        scanners_csv,
        "--exit-code",
        "0",
        "--config",
        config_path,
        # Quiet the progress bar; the wrapper logs its own summary.
        "--quiet",
    ]
    if ignore_path is not None:
        # trivy resolves this relative to its working directory, which is
        # this repo's checkout rather than the scanned one.
        base_args.extend(["--ignorefile", str(ignore_path)])

    # Reuse a user-requested JSON report for the tally, else add one.
    user_json = next((t for t in user_targets if t.fmt == "json"), None)
    if user_json is not None:
        tally_target = user_json
        runs: list[_ReportTarget] = list(user_targets)
    else:
        tally_target = _ReportTarget(fmt="json", path=Path(_INTERNAL_TALLY_PATH))
        runs = [*user_targets, tally_target]

    subprocess_env = _trivy_subprocess_env()
    try:
        # NOTE: trivy emits a single report per invocation, so a
        # multi-format request re-runs the full scan once per format.
        for tgt in runs:
            cmd = [
                *base_args,
                "--format",
                tgt.fmt,
                "--output",
                str(tgt.path),
            ]
            log.info("Running: %s", " ".join(cmd))
            try:
                completed = subprocess.run(
                    cmd,
                    check=False,
                    capture_output=True,
                    text=True,
                    env=subprocess_env,
                )
            except OSError as exc:
                raise RuntimeError(
                    f"trivy invocation for format '{tgt.fmt}' failed to start: {exc}"
                ) from exc
            if completed.returncode != 0:
                raise RuntimeError(
                    f"trivy exited unexpectedly with code {completed.returncode} "
                    f"for format '{tgt.fmt}'; stderr: "
                    f"{completed.stderr.strip() if completed.stderr else '<empty>'}"
                )

        return _tally_findings_by_severity(tally_target.path)
    finally:
        # Safe even if the loop above raised before writing the tally
        # file (unlink(missing_ok=True) is a no-op then).
        if tally_target.path == Path(_INTERNAL_TALLY_PATH):
            tally_target.path.unlink(missing_ok=True)


def _tally_findings_by_severity(json_path: Path) -> dict[str, int]:
    """Read trivy's JSON output and tally findings by severity."""
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Failed to read trivy JSON tally at {json_path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            f"trivy JSON tally at {json_path} is not an object "
            f"(got {type(data).__name__})"
        )
    counts: dict[str, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    finding_keys = ("Vulnerabilities", "Misconfigurations", "Secrets", "Licenses")
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for key in finding_keys:
            for finding in result.get(key) or []:
                if not isinstance(finding, dict):
                    continue
                sev = str(finding.get("Severity") or "UNKNOWN").upper()
                counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--scan-type",
        default=os.environ.get("SCANNER_TRIVY_SCAN_TYPE") or SCAN_TYPE_FILESYSTEM,
        choices=SCAN_TYPES,
        help=(
            "Trivy target type. 'filesystem' (the default) scans "
            "--source-dir; 'image' builds --image from --dockerfile and "
            "scans it."
        ),
    )
    p.add_argument(
        "--image",
        default=os.environ.get("SCANNER_TRIVY_IMAGE", ""),
        help="Local image reference to build and scan with --scan-type image.",
    )
    p.add_argument(
        "--dockerfile",
        default=os.environ.get("SCANNER_TRIVY_DOCKERFILE", ""),
        help=(
            "Dockerfile path relative to --checkout-root for --scan-type "
            "image. In 'changed' mode the image is built and scanned only "
            "when this file, or the Trivy config/ignore file, changed."
        ),
    )
    p.add_argument(
        "--build-commands",
        default=os.environ.get("SCANNER_TRIVY_BUILD_COMMANDS", ""),
        help=(
            "Bash commands that build --image in place of `docker build "
            "--file <dockerfile> --tag <image> .`, run from --checkout-root "
            "with SCANNER_TRIVY_IMAGE and SCANNER_TRIVY_DOCKERFILE set."
        ),
    )
    p.add_argument(
        "--scan-mode",
        default=os.environ.get("SCANNER_SCAN_MODE", "changed"),
        choices=("changed", "all"),
        help=(
            "'changed' (default) short-circuits with a no-op when no "
            "dependency-manifest / IaC / container file changed in the "
            "calling event, and otherwise scans the entire --source-dir "
            "(trivy's filesystem scanner needs the whole subtree to "
            "resolve transitive deps and cross-file IaC references, so "
            "we don't try to feed individual changed files). 'all' "
            "always scans --source-dir recursively."
        ),
    )
    p.add_argument(
        "--report-formats",
        default=os.environ.get("SCANNER_REPORT_FORMATS", "sarif"),
        help=(
            "Comma-separated list of trivy report formats. Allowed "
            f"values: {', '.join(sorted({*_SUPPORTED_FORMATS, *_FORMAT_ALIASES}))}. "
            f"'human' is an alias for '{_FORMAT_ALIASES['human']}', so a "
            "caller can request a reviewer-readable report from every "
            "scanner without knowing each tool's format names."
        ),
    )
    p.add_argument(
        "--scanners",
        default=os.environ.get("SCANNER_TRIVY_SCANNERS", _DEFAULT_SCANNERS),
        help=(
            "Comma-separated list of trivy scanners to enable. Allowed "
            f"values: {', '.join(_SUPPORTED_SCANNERS)}. Default "
            f"'%(default)s' intentionally omits 'secret' because "
            "gitleaks already covers secret detection in this "
            "repository; enable it explicitly if you want both."
        ),
    )
    p.add_argument(
        "--source-dir",
        default=os.environ.get("SCANNER_SOURCE_DIR", "."),
        help=(
            "Path to scan (default %(default)s). Set to a subdirectory of "
            "the checkout to restrict the scan to that subtree; the "
            "'changed' scan mode further restricts the no-op check to "
            "only audited files modified inside this path. The path "
            "must exist."
        ),
    )
    p.add_argument(
        "--checkout-root",
        default=os.environ.get("SCANNER_CHECKOUT_ROOT", "."),
        help=(
            "Git checkout root of the repository being scanned (default "
            "%(default)s). Used to run `git fetch`/`git diff` and to "
            "re-anchor the paths they report; only matters when this "
            "differs from --source-dir (e.g. --source-dir restricts to a "
            "subtree, or the scan target isn't checked out at this "
            "process's cwd)."
        ),
    )
    p.add_argument(
        "--config-path",
        default=os.environ.get("SCANNER_TRIVY_CONFIG_PATH", ""),
        help=(
            "Optional trivy config path relative to --checkout-root. "
            "When omitted, conventional root-level names are discovered "
            "before falling back to the baseline default. "
            f"One of {', '.join(_IGNORE_FILENAMES)} is read from the same "
            "directory as an explicit config, else from --checkout-root."
        ),
    )
    p.add_argument(
        "--severity-threshold",
        default=os.environ.get(
            "SCANNER_SEVERITY_THRESHOLD", _DEFAULT_SEVERITY_THRESHOLD
        ),
        choices=_SEVERITY_CHOICES,
        help=(
            "Minimum trivy severity that fails the job. Trivy reports "
            "every finding regardless of threshold so the uploaded "
            "reports keep the full picture; after the scan the script "
            "tallies findings by severity and exits 1 only if any are "
            "at or above this threshold. Trivy categorises findings as "
            "LOW / MEDIUM / HIGH / CRITICAL. Default '%(default)s' "
            "fails on HIGH or CRITICAL findings; set 'low' to fail on "
            "any finding."
        ),
    )
    return p


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(message)s")
    args = build_parser().parse_args(argv)

    try:
        targets = _parse_report_formats(args.report_formats)
        scanners = _parse_scanners(args.scanners)
    except ValueError as exc:
        log.error("%s", exc)
        return 1

    image_mode = args.scan_type == SCAN_TYPE_IMAGE
    build_commands = args.build_commands.strip()
    try:
        if image_mode:
            image = validate_image_reference(args.image)
            if not args.dockerfile.strip():
                raise ValueError("--dockerfile is required when --scan-type is image")
        else:
            image = ""
            image_only = {
                "--image": args.image,
                "--dockerfile": args.dockerfile,
                "--build-commands": build_commands,
            }
            for flag, value in image_only.items():
                if value.strip():
                    raise ValueError(f"{flag} requires --scan-type image")
    except ValueError as exc:
        log.error("%s", exc)
        return 2

    source_dir = Path(args.source_dir)
    if not image_mode and not source_dir.is_dir():
        log.error(
            "scan path '%s' does not exist or is not a directory "
            "(did the checkout step fetch it?)",
            source_dir,
        )
        return 2
    checkout_root = Path(args.checkout_root)

    try:
        config_paths = (
            *scanner_config_paths(
                checkout_root=checkout_root,
                configured_path=args.config_path,
                candidates=_CONFIG_CANDIDATES,
            ),
            *ignore_file_paths(
                checkout_root=checkout_root,
                configured_path=args.config_path,
                filenames=_IGNORE_FILENAMES,
            ),
        )
        config_path = _resolve_config_path(checkout_root, args.config_path)
        ignore_path = resolve_ignore_file(
            scanner="trivy",
            checkout_root=checkout_root,
            filenames=_IGNORE_FILENAMES,
            configured_path=args.config_path,
        )
        dockerfile_path = (
            _resolve_dockerfile_path(checkout_root, args.dockerfile)
            if image_mode
            else None
        )
        # Only 'changed' mode needs the event payload, to work out the
        # diff range. Loading it unconditionally would make 'all' mode
        # fail on events that have no payload we can parse, even though
        # it never looks at one.
        files: list[Path] | None = None
        image_changed = True
        if args.scan_mode == "changed" and dockerfile_path is not None:
            image_changed = _dockerfile_changed(
                event_name=os.environ.get("GITHUB_EVENT_NAME", ""),
                event=gha_load_github_event(),
                dockerfile=dockerfile_path,
                checkout_root=checkout_root,
                config_paths=config_paths,
                build_commands=build_commands,
            )
        elif args.scan_mode == "changed":
            files = _determine_changed_audited_files(
                event_name=os.environ.get("GITHUB_EVENT_NAME", ""),
                event=gha_load_github_event(),
                scan_path=source_dir,
                checkout_root=checkout_root,
                config_paths=config_paths,
            )
    except (FileNotFoundError, KeyError, ValueError, RuntimeError) as exc:
        log.error("%s", exc)
        return 2

    nothing_to_scan = not image_changed or (files is not None and not files)
    if image_mode and image_changed:
        log.info("Trivy scope: Docker image %s built from %s", image, args.dockerfile)
    elif image_mode:
        log.info(
            "Trivy scope: %s and the Trivy config are unchanged in the event; "
            "nothing to build or scan",
            args.dockerfile,
        )
    elif files is None:
        log.info(
            "Trivy scope: recursive scan of %s (no usable diff range)",
            source_dir,
        )
    elif files:
        log.info(
            "Trivy scope: recursive scan of %s "
            "(%d audited file(s) changed in the event)",
            source_dir,
            len(files),
        )
        for f in files:
            log.info("  - %s", f)
    else:
        log.info(
            "Trivy scope: no audited files changed under %s; nothing to scan",
            source_dir,
        )

    log.info(
        "Trivy formats: %s",
        ", ".join(f"{t.fmt}->{t.path}" for t in targets),
    )
    log.info("Trivy scanners: %s", ", ".join(scanners))
    log.info(
        "Trivy fail threshold: severity >= %s (lower-severity findings "
        "still appear in reports)",
        args.severity_threshold.upper(),
    )

    sarif_target = next((t for t in targets if t.fmt == "sarif"), None)
    non_sarif = [t for t in targets if t.fmt != "sarif"]

    # 'changed' mode with nothing to scan: emit empty paths so uploads skip.
    if nothing_to_scan:
        gha_set_output({"sarif_path": "", "non_sarif_paths": ""})
        return 0

    try:
        if dockerfile_path is not None:
            _build_trivy_image(
                checkout_root=checkout_root,
                dockerfile=dockerfile_path,
                image=image,
                build_commands=build_commands,
            )
        binary = get_trivy_binary()
        counts = _run_trivy(
            binary,
            targets,
            config_path=config_path,
            scanners=scanners,
            scan_path=source_dir,
            ignore_path=ignore_path,
            scan_type=args.scan_type,
            image=image,
        )
        # Set outputs only after a successful run, gated on the report
        # actually existing on disk: the workflow's upload steps run with
        # `if: always() && steps.scan.outputs.sarif_path != ''`, so a
        # non-empty path reported despite a failed/incomplete run would
        # make the SARIF upload step fire against a missing file and
        # fail with a confusing second error.
        gha_set_output(
            {
                "sarif_path": (
                    str(sarif_target.path)
                    if sarif_target is not None and sarif_target.path.is_file()
                    else ""
                ),
                "non_sarif_paths": "\n".join(
                    str(t.path) for t in non_sarif if t.path.is_file()
                ),
            }
        )
    except RuntimeError as exc:
        log.error("%s", exc)
        _emit_non_sarif_reports(non_sarif, gha_append_step_summary)
        return 2
    except Exception:
        log.exception("trivy install or scan failed unexpectedly")
        _emit_non_sarif_reports(non_sarif, gha_append_step_summary)
        return 2

    threshold = args.severity_threshold.upper()
    threshold_idx = _SEVERITY_ORDER.index(threshold)
    failing = sum(counts[sev] for sev in _SEVERITY_ORDER[threshold_idx:])
    summary = ", ".join(f"{sev}={counts[sev]}" for sev in _SEVERITY_ORDER)
    extra = {sev: n for sev, n in counts.items() if sev not in _SEVERITY_ORDER and n}
    if extra:
        summary += ", " + ", ".join(f"{sev}={n}" for sev, n in extra.items())
    log.info("Trivy findings: %s", summary)

    _emit_non_sarif_reports(non_sarif, gha_append_step_summary)

    if failing:
        log.error(
            "trivy reported %d finding(s) at severity >= %s; failing the job "
            "(see report artifacts for the full set, including lower-severity "
            "findings that didn't trigger the threshold)",
            failing,
            threshold,
        )
        return 1
    log.info(
        "All findings below threshold '%s'; passing (lower-severity findings "
        "are still listed in the uploaded reports)",
        threshold,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
