#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Run trivy against the current repository checkout.

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

Default scanners are `misconfig,vuln,license`; `secret` is omitted
because gitleaks already covers secret detection.

Exit codes:

* `0` - clean run, or an empty changed-file set.
* `1` - findings at/above `--severity-threshold`, or `--report-formats`
  / `--scanners` was empty/unknown.
* `2` - input error: scan path missing, baseline config missing,
  `GITHUB_EVENT_PATH` malformed, or trivy itself errored.

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
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
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
from security_scanners.utils.fork_changes import (
    fork_changed_paths,
    fork_only_files,
    restrict_to_fork_changes,
    select_files,
    split_git_paths,
)
from security_scanners.utils.step_summary import emit_reports
from security_scanners.utils.scanner_config import (
    find_config_change,
    ignore_file_paths,
    resolve_ignore_file,
    resolve_scanner_config,
    scanner_config_paths,
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
    """Return the audited files (manifests, IaC, Dockerfiles) in scope, or `None`.

    `checkout_root` is the scan target's repo root, where `git` runs and
    against which the repo-relative paths in `git diff --name-only` are
    resolved; `scan_path` may be a subdirectory of it.

    * `None` -- scan `scan_path` recursively: no usable diff range, or a
      trivy config or ignore file changed, and the repository isn't a fork.
    * `[]` -- the scope held no audited files under `scan_path`; a clean no-op.
    * `[paths...]` -- audited files exist. Outside a fork they only decide
      that trivy runs over the whole `scan_path`; on a fork they are every
      audited file the fork changed relative to its upstream (limited to the
      event's files in `changed` mode), and trivy scans just their context.
    """
    diff = _diff_range(event_name, event)
    if diff is None:
        return fork_only_files(scan_path, checkout_root, _is_audited_path)
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
                "-z",
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
            errors="surrogateescape",
        )
    except subprocess.CalledProcessError as exc:
        log.warning(
            "git diff %s..%s failed (rc=%s, stderr=%r); using the full scan scope",
            base_sha,
            head_sha,
            exc.returncode,
            exc.stderr.strip() if exc.stderr else "",
        )
        return fork_only_files(scan_path, checkout_root, _is_audited_path)

    changed = split_git_paths(result.stdout)
    # On a fork, files that only came in from upstream aren't ours to scan.
    changed = restrict_to_fork_changes(changed)
    config_change = find_config_change(changed, filenames=config_paths)
    if config_change is not None:
        log.info(
            "Changed config (%s) applies to every file, so this run scans "
            "every file in scope instead of the changed files alone",
            config_change,
        )
        return fork_only_files(scan_path, checkout_root, _is_audited_path)

    return select_files(changed, scan_path, checkout_root, _is_audited_path)


def _run_trivy(
    binary: Path,
    user_targets: list[_ReportTarget],
    *,
    config_path: str,
    scanners: list[str],
    scan_path: Path,
    ignore_path: Path | None = None,
    scan_files: list[Path] | None = None,
) -> dict[str, int]:
    """Run trivy for each user-requested format plus an internal JSON
    tally pass if the user didn't already request one, and return a
    severity tally.
    """
    severity_csv = ",".join(_SEVERITY_ORDER)
    scanners_csv = ",".join(scanners)
    base_args: list[str] = [
        str(binary),
        "fs",
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

    def execute(cmd: list[str], label: str) -> None:
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
                f"trivy invocation for format '{label}' failed to start: {exc}"
            ) from exc
        if completed.returncode != 0:
            raise RuntimeError(
                f"trivy exited unexpectedly with code {completed.returncode} "
                f"for format '{label}'; stderr: "
                f"{completed.stderr.strip() if completed.stderr else '<empty>'}"
            )

    try:
        with _trivy_scan_root(scan_path, scan_files) as target:
            if scan_files is None:
                # Trivy emits one report per invocation, so each format reruns it.
                for tgt in runs:
                    execute(
                        [
                            *base_args,
                            "--format",
                            tgt.fmt,
                            "--output",
                            str(tgt.path),
                            str(target),
                        ],
                        tgt.fmt,
                    )
                return _tally_findings_by_severity(tally_target.path)

            selected = {
                path.as_posix() for path in _relative_to_root(scan_path, scan_files)
            }
            with tempfile.TemporaryDirectory(prefix="trivy-scoped-") as work:
                raw, filtered = Path(work, "raw.json"), Path(work, "filtered.json")
                list_pkgs = ["--list-all-pkgs"] if _needs_packages(runs) else []
                execute(
                    [
                        *base_args,
                        *list_pkgs,
                        "--format",
                        "json",
                        "--output",
                        str(raw),
                        str(target),
                    ],
                    "json",
                )
                _filter_report_to_files(raw, filtered, selected)
                for tgt in runs:
                    if tgt.fmt == "json":
                        shutil.copyfile(filtered, tgt.path)
                        continue
                    execute(
                        [
                            str(binary),
                            "convert",
                            "--quiet",
                            "--severity",
                            severity_csv,
                            "--scanners",
                            scanners_csv,
                            "--format",
                            tgt.fmt,
                            "--output",
                            str(tgt.path),
                            str(filtered),
                        ],
                        tgt.fmt,
                    )
                return _tally_findings_by_severity(filtered)
    finally:
        # Safe even if the loop above raised before writing the tally
        # file (unlink(missing_ok=True) is a no-op then).
        if tally_target.path == Path(_INTERNAL_TALLY_PATH):
            tally_target.path.unlink(missing_ok=True)


# Formats built from a report's package list rather than its findings.
_SBOM_FORMATS = frozenset({"cyclonedx", "spdx-json", "github"})


def _needs_packages(runs: list[_ReportTarget]) -> bool:
    return any(target.fmt in _SBOM_FORMATS for target in runs)


def _relative_to_root(scan_path: Path, files: list[Path]) -> list[Path]:
    """Return `files` as paths relative to `scan_path`, dropping any outside it."""
    scan_root = Path(os.path.abspath(scan_path))
    relative: list[Path] = []
    for source in files:
        try:
            relative.append(Path(os.path.abspath(source)).relative_to(scan_root))
        except ValueError:
            continue
    return relative


def _filter_report_to_files(raw: Path, filtered: Path, selected: set[str]) -> None:
    """Write `raw` to `filtered`, keeping only results for `selected` targets.

    Targets are posix paths relative to the scanned root, e.g. "infra/main.tf".
    """
    try:
        data = json.loads(raw.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Failed to read trivy JSON report at {raw}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"trivy JSON report at {raw} is not an object")
    results = data.get("Results") or []
    data["Results"] = [
        result
        for result in results
        if isinstance(result, dict) and result.get("Target") in selected
    ]
    filtered.write_text(json.dumps(data), encoding="utf-8")


# A local Terraform module reference, e.g. `source = "../modules/vpc"`.
_TF_MODULE_SOURCE = re.compile(r'^\s*source\s*=\s*"(\.{1,2}/[^"]*)"', re.MULTILINE)


@contextmanager
def _trivy_scan_root(scan_path: Path, scan_files: list[Path] | None) -> Iterator[Path]:
    """Stage a bounded copy of the context Trivy needs for `scan_files`.

    Each file's own directory and the regular files of its ancestors are
    copied, plus the directories its Terraform files reference as local
    modules. Nothing else is copied, so a file at the repo root can't pull
    in the whole tree. Every selected file is staged itself, even when it
    sits below a symlinked directory, and a file that can't be staged is an
    error rather than a silent omission.
    """
    if scan_files is None:
        yield scan_path
        return

    real_root = Path(os.path.abspath(scan_path)).resolve()
    selected = _relative_to_root(scan_path, scan_files)

    # Directories are tracked relative to the root so a symlink in the scan
    # path itself doesn't change what they mean.
    directories: set[Path] = set()
    pending = [path.parent for path in selected]
    while pending:
        relative = pending.pop()
        directory = real_root / relative
        try:
            resolved = directory.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        # A symlinked directory has no safe staged location of its own.
        if resolved != directory or relative in directories:
            continue
        directories.add(relative)
        pending.extend(_local_terraform_modules(directory, real_root))

    with tempfile.TemporaryDirectory(prefix="trivy-fork-scope-") as temp:
        staged_root = Path(temp)
        copy_from = set(directories)
        for relative in directories:
            copy_from.update(relative.parents)
        for relative in copy_from:
            _copy_directory_files(
                real_root / relative, staged_root / relative, real_root
            )
        for relative in selected:
            destination = staged_root / relative
            if not destination.is_file():
                _copy_file(real_root / relative, destination, real_root)
            if not destination.is_file():
                raise RuntimeError(f"Could not stage {relative} for trivy")
        yield staged_root


def _local_terraform_modules(directory: Path, real_root: Path) -> list[Path]:
    """Return the in-tree directories (relative to `real_root`) that
    `directory`'s .tf files reference as local modules."""
    modules: list[Path] = []
    for tf_file in directory.glob("*.tf"):
        try:
            resolved = tf_file.resolve(strict=True)
            resolved.relative_to(real_root)
            text = resolved.read_text(encoding="utf-8")
        except (OSError, RuntimeError, UnicodeDecodeError, ValueError):
            continue
        for match in _TF_MODULE_SOURCE.findall(text):
            module = Path(os.path.normpath(directory / match))
            if module.is_relative_to(real_root) and module.is_dir():
                modules.append(module.relative_to(real_root))
    return modules


def _copy_file(source: Path, destination: Path, real_root: Path) -> None:
    """Copy `source` when it is a regular file whose target stays in the checkout."""
    try:
        resolved = source.resolve(strict=True)
        resolved.relative_to(real_root)
    except (OSError, RuntimeError, ValueError):
        return
    if resolved.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(resolved, destination)


def _copy_directory_files(directory: Path, destination: Path, real_root: Path) -> None:
    """Copy the files directly in `directory` that stay in the checkout."""
    try:
        children = list(directory.iterdir())
    except OSError:
        return
    for source in children:
        if source.name != ".git":
            _copy_file(source, destination / source.name, real_root)


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
        "--scan-mode",
        default=os.environ.get("SCANNER_SCAN_MODE", "changed"),
        choices=("changed", "all"),
        help=(
            "'changed' (default) short-circuits with a no-op when no "
            "dependency-manifest / IaC / container file changed in the "
            "calling event. Forks scan only their own matching files; "
            "non-forks scan the entire --source-dir. 'all' scans every "
            "matching fork-owned file on a fork, otherwise --source-dir."
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

    source_dir = Path(args.source_dir)
    if not source_dir.is_dir():
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
        # Only 'changed' mode needs the event payload, to work out the
        # diff range. Loading it unconditionally would make 'all' mode
        # fail on events that have no payload we can parse, even though
        # it never looks at one.
        if args.scan_mode == "all":
            files: list[Path] | None = fork_only_files(
                source_dir, checkout_root, _is_audited_path
            )
        else:
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

    fork_scoped = fork_changed_paths() is not None
    if files is None:
        log.info(
            "Trivy scope: recursive scan of %s (no usable diff range)",
            source_dir,
        )
    elif files:
        if fork_scoped:
            log.info(
                "Trivy scope: %d fork-owned audited file(s) under %s",
                len(files),
                source_dir,
            )
        else:
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

    if files is not None and not files:
        gha_set_output({"sarif_path": "", "non_sarif_paths": ""})
        return 0

    try:
        binary = get_trivy_binary()
        counts = _run_trivy(
            binary,
            targets,
            config_path=config_path,
            scanners=scanners,
            scan_path=source_dir,
            ignore_path=ignore_path,
            scan_files=files if fork_scoped else None,
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
