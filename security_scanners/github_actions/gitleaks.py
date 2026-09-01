#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Run gitleaks against the current repository checkout.

Exit codes:

* `0` - no leaks, clean run.
* `1` - gitleaks found leaks, or `--report-formats` was empty/unknown.
* `2` - input error: scan path missing, `gitleaks.toml` missing,
  `GITHUB_EVENT_PATH` malformed, or gitleaks itself errored.

Inputs come from CLI flags or the matching `SCANNER_*` env vars set by
`.github/workflows/security-baseline.yml`.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast

from security_scanners.utils.binary_checksums import (
    CHECKSUMS_FILENAME,
    download_and_verify_tarball,
    expected_sha256,
)
from security_scanners.utils.scanner_config import (
    resolve_ignore_file,
    resolve_scanner_config,
)
from security_scanners.utils.github_actions_api import (
    gha_append_step_summary,
    gha_load_github_event,
    gha_set_output,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

log = logging.getLogger(__name__)


# Keep in sync with the `report_formats` input in
# `.github/workflows/security-baseline.yml`.
_SUPPORTED_FORMATS: dict[str, str] = {
    "sarif": "sarif",
    "json": "json",
    "csv": "csv",
    "junit": "xml",
}
# Tool-independent aliases, so a caller can ask every scanner for "the
# report a reviewer reads" without knowing that gitleaks spells it 'csv',
# zizmor 'plain' and trivy 'table'.
_FORMAT_ALIASES: dict[str, str] = {"human": "csv"}
# Mirrored to the rocm-third-party-deps S3 bucket so CI doesn't depend on
# github.com. When bumping the version, add the new tarball's digest to
# `checksums.sha256` (see that file's header for the required provenance
# comment) and drop the entry for the version being replaced.
_GITLEAKS_VERSION = "8.30.1"
_GITLEAKS_TARBALL_FILENAME = f"gitleaks_{_GITLEAKS_VERSION}_linux_x64.tar.gz"
_GITLEAKS_TARBALL_URL = f"https://rocm-third-party-deps.s3.us-east-2.amazonaws.com/{_GITLEAKS_TARBALL_FILENAME}"
_CONFIG_PATH = "gitleaks.toml"
# Where a scanned repository is allowed to keep its own config, in the
# order gitleaks itself would look for one.
#
# Unlike the other scanners, a config-only change needs no special
# handling here: gitleaks always runs over the commit range rather than
# a filtered file list, so a new config is always parsed and exercised,
# and a malformed one always fails the PR that introduced it. Only a
# suppression aimed at a finding older than the range goes unverified
# until the next full-history run.
_CONFIG_CANDIDATES: tuple[str, ...] = ("gitleaks.toml", ".gitleaks.toml")
# Fingerprint suppressions for findings a repository has already triaged.
_IGNORE_FILENAME = ".gitleaksignore"
# Pin --exit-code to 1 so we can tell clean (0) from leaks (1) from a
# gitleaks error (>1).
_LEAK_EXIT_CODE = 1
_LEAK_SECURITY_SEVERITY_HIGH = "8.5"
# GitHub renders at most 1 MiB of job summary per step and drops anything
# beyond it, so leave headroom for the headings and fences we wrap reports in.
_STEP_SUMMARY_BUDGET_BYTES = 900 * 1024

# Null SHA-1 git uses for "no previous commit" (a newly created ref).
Z40 = "0" * 40


class _PullRequestRef(TypedDict):
    sha: str


class _PullRequestPayload(TypedDict):
    base: _PullRequestRef
    head: _PullRequestRef


class _PullRequestEvent(TypedDict):
    pull_request: _PullRequestPayload


class _PushEvent(TypedDict):
    before: str
    after: str


# The real GitHub event payload is a large, event-type-dependent JSON object
# (see gha_load_github_event); only the shapes this module actually reads are
# modeled here. Other event types (schedule, workflow_dispatch, release, ...)
# only ever reach the `Mapping[str, object]` branch below, which is never
# indexed into directly.
GitHubEventPayload = _PullRequestEvent | _PushEvent | Mapping[str, object]


@dataclass(frozen=True)
class _ReportTarget:
    """A single `(format, on-disk path)` pair the runner will produce."""

    fmt: str
    path: Path


def get_gitleaks_binary() -> Path:
    """Return a verified gitleaks binary in RUNNER_TEMP/gitleaks-<ver>.

    Downloads and validates it if missing.
    """
    install_root = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
    install_dir = install_root / f"gitleaks-{_GITLEAKS_VERSION}"
    binary = install_dir / "gitleaks"
    if binary.is_file() and os.access(binary, os.X_OK):
        log.info("Found gitleaks binary at %s", binary)
        return binary

    expected_sha = expected_sha256(REPO_ROOT, _GITLEAKS_TARBALL_FILENAME)
    log.info(
        "Downloading gitleaks v%s from %s",
        _GITLEAKS_VERSION,
        _GITLEAKS_TARBALL_URL,
    )
    binary = download_and_verify_tarball(
        url=_GITLEAKS_TARBALL_URL,
        expected_sha256=expected_sha,
        member_name="gitleaks",
        install_dir=install_dir,
    )
    binary.chmod(0o755)

    try:
        result = subprocess.run(
            [str(binary), "version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            f"gitleaks at {binary} failed to execute after install: {exc}"
        ) from exc
    installed_version = result.stdout.strip().lstrip("v")
    if installed_version != _GITLEAKS_VERSION:
        raise RuntimeError(
            f"gitleaks at {binary} reports version {installed_version!r}, "
            f"expected {_GITLEAKS_VERSION!r}"
        )
    log.info("Installed gitleaks %s at %s", installed_version, binary)
    return binary


def _parse_report_formats(raw: str) -> list[_ReportTarget]:
    """Parse comma-separated report formats into unique report targets."""
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
        targets.append(_ReportTarget(fmt=fmt, path=Path(f"gitleaks-report.{ext}")))
    if not targets:
        raise ValueError(
            "report_formats is empty (expected one or more of: "
            f"{', '.join(sorted(_SUPPORTED_FORMATS))})"
        )
    return targets


def _resolve_config_path(checkout_root: Path) -> str:
    # The fallback is anchored on REPO_ROOT (this script's own checkout),
    # not the cwd: when this workflow is called from another repo, the cwd
    # holds *that* repo's checkout (the scan target), not
    # rocm-security-gh's.
    return str(
        resolve_scanner_config(
            scanner="gitleaks",
            checkout_root=checkout_root,
            candidates=_CONFIG_CANDIDATES,
            fallback=REPO_ROOT / _CONFIG_PATH,
        ).path
    )


def _determine_log_opts(
    scan_mode: str,
    event_name: str,
    event: GitHubEventPayload,
    source_dir: Path = Path("."),
) -> str:
    """Build the `--log-opts` value for `gitleaks detect`.

    Returns '' to scan the full history; otherwise returns a git range
    derived from the triggering event or raises when unavailable.

    `source_dir` is the scan target's git checkout; the `pull_request`
    branch below runs `git` there explicitly (rather than relying on this
    process's cwd) since the scan target isn't always checked out at cwd
    (e.g. when this script's own repo is checked out at cwd instead).
    """
    if scan_mode == "all":
        return ""

    if event_name == "pull_request_target":
        raise ValueError(
            "pull_request_target is not supported for scan_mode=changed. "
            "Use pull_request for untrusted PRs, or set scan_mode='all' "
            "for trusted post-merge/manual scans."
        )

    if event_name == "pull_request":
        # Safe: GitHub guarantees this shape for `pull_request` events.
        pr_event = cast(_PullRequestEvent, event)
        pr = pr_event["pull_request"]
        base_sha = pr["base"]["sha"]
        head_sha = pr["head"]["sha"]
        fetch_result = subprocess.run(
            ["git", "fetch", "--no-tags", "--depth=1", "origin", base_sha],
            cwd=source_dir,
            check=False,
            capture_output=True,
            text=True,
        )
        if fetch_result.returncode != 0:
            log.warning(
                "git fetch of PR base %s exited %d: %s",
                base_sha,
                fetch_result.returncode,
                (fetch_result.stderr or "").strip() or "(no stderr)",
            )
        rev_parse = subprocess.run(
            ["git", "rev-parse", "--verify", f"{base_sha}^{{commit}}"],
            cwd=source_dir,
            check=False,
            capture_output=True,
            text=True,
        )
        if rev_parse.returncode != 0:
            raise RuntimeError(
                f"PR base commit {base_sha} is not reachable in the local "
                "checkout (fetch failed and the commit isn't in the pack). "
                "Increase the checkout `fetch-depth` or ensure the base ref "
                "is fetchable."
            )
        return f"{base_sha}..{head_sha}"

    if event_name == "push":
        # Safe: GitHub guarantees `before` and `after` on push events.
        push_event = cast(_PushEvent, event)
        before = push_event["before"]
        after = push_event["after"]
        if before == Z40:
            log.info("Push created a new ref; falling back to full history scan")
            return ""
        return f"{before}..{after}"

    raise ValueError(
        f"Cannot derive a diff range for event "
        f"'{event_name or '<unset>'}'. Pass --scan-mode all "
        f"(or set scan_mode='all' in the workflow input) to scan the "
        f"full repository history."
    )


def _enrich_sarif_with_security_severity(sarif_path: Path) -> None:
    """Mark every gitleaks SARIF result as High severity for code scanning.

    Gitleaks leaves `level` and `security-severity` unset; we backfill to
    match GitHub's severity tiers. Pre-existing values are preserved.
    """
    try:
        with open(sarif_path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"SARIF file '{sarif_path}' is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"SARIF file '{sarif_path}' top-level must be a JSON object, "
            f"got {type(data).__name__}"
        )
    runs = data.get("runs", [])
    if not isinstance(runs, list):
        raise ValueError(
            f"SARIF file '{sarif_path}' field 'runs' must be a list, "
            f"got {type(runs).__name__}"
        )
    if not runs:
        raise ValueError(
            f"SARIF file '{sarif_path}' has an empty 'runs' array; "
            "gitleaks should always emit at least one run. This usually "
            "indicates the scanner aborted before writing a real report."
        )

    levels_set_count = 0
    levels_kept_count = 0
    scores_set_count = 0
    scores_kept_count = 0
    for run_idx, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(
                f"SARIF file '{sarif_path}' runs[{run_idx}] must be an "
                f"object, got {type(run).__name__}"
            )
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError(
                f"SARIF file '{sarif_path}' runs[{run_idx}].results must "
                f"be a list, got {type(results).__name__}"
            )
        for res_idx, result in enumerate(results):
            if not isinstance(result, dict):
                raise ValueError(
                    f"SARIF file '{sarif_path}' "
                    f"runs[{run_idx}].results[{res_idx}] must be an "
                    f"object, got {type(result).__name__}"
                )
            if result.get("level") is None:
                result["level"] = "error"
                levels_set_count += 1
            else:
                levels_kept_count += 1
            props = result.setdefault("properties", {})
            if not isinstance(props, dict):
                raise ValueError(
                    f"SARIF file '{sarif_path}' "
                    f"runs[{run_idx}].results[{res_idx}].properties must "
                    f"be an object, got {type(props).__name__}"
                )
            if props.get("security-severity") is None:
                props["security-severity"] = _LEAK_SECURITY_SEVERITY_HIGH
                scores_set_count += 1
            else:
                scores_kept_count += 1

    if levels_set_count == 0 and scores_set_count == 0:
        log.debug(
            "SARIF severity enrichment: nothing to add (%d level preserved, "
            "%d score preserved) in %s",
            levels_kept_count,
            scores_kept_count,
            sarif_path,
        )
        return

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=sarif_path.parent,
            prefix=f"{sarif_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp_path = Path(tmp.name)
            json.dump(data, tmp, indent=2)
        os.replace(tmp_path, sarif_path)
    except OSError as exc:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"Failed to write enriched SARIF to '{sarif_path}': {exc}"
        ) from exc

    log.info(
        "SARIF severity enrichment: set level=error on %d result(s) and "
        "security-severity=%s on %d result(s) in %s",
        levels_set_count,
        _LEAK_SECURITY_SEVERITY_HIGH,
        scores_set_count,
        sarif_path,
    )


def _run_gitleaks(
    binary: Path,
    targets: list[_ReportTarget],
    *,
    config_path: str,
    log_opts: str,
    source_dir: Path,
    ignore_path: Path | None = None,
) -> bool:
    """Run gitleaks once per target. Return `True` if any leaks were found.

    Raises :class:`RuntimeError` for unexpected gitleaks exit codes.
    """
    base_args: list[str] = [
        str(binary),
        "detect",
        "--source",
        str(source_dir),
        "--redact",
        "--verbose",
        "--no-banner",
        "--exit-code",
        str(_LEAK_EXIT_CODE),
    ]
    base_args.extend(["--config", config_path])
    if ignore_path is not None:
        # gitleaks resolves this relative to its working directory, which
        # is this repo's checkout rather than the scanned one.
        base_args.extend(["--gitleaks-ignore-path", str(ignore_path)])
    if log_opts:
        base_args.append(f"--log-opts={log_opts}")

    leaks_found = False
    # NOTE: gitleaks emits a single report per invocation, so we re-run
    # per format. Revisit when https://github.com/gitleaks/gitleaks/pull/1232
    # is merged.
    for tgt in targets:
        cmd = [*base_args, "--report-format", tgt.fmt, "--report-path", str(tgt.path)]
        log.info("Running: %s", " ".join(cmd))
        rc = subprocess.run(cmd, check=False).returncode
        if rc == 0 or rc == _LEAK_EXIT_CODE:
            if rc == _LEAK_EXIT_CODE:
                leaks_found = True
            if not tgt.path.is_file():
                raise RuntimeError(
                    f"gitleaks exited {rc} but did not write the expected "
                    f"{tgt.fmt} report at '{tgt.path}'."
                )
            # Align SARIF with the GitHub Security tab's severity tiers
            # (gitleaks leaves `level` and `security-severity` unset).
            if tgt.fmt == "sarif":
                _enrich_sarif_with_security_severity(tgt.path)
            continue
        raise RuntimeError(
            f"gitleaks exited unexpectedly with code {rc} for format '{tgt.fmt}'"
        )
    return leaks_found


def _md_code_fence(content: str) -> str:
    """Return a backtick fence longer than any backtick run in `content`.

    Ensures markdown summaries stay intact even when reports contain backticks.
    """
    longest = max((len(m) for m in re.findall(r"`+", content)), default=0)
    return "`" * max(3, longest + 1)


def _clip_to_budget(content: str, budget_bytes: int) -> tuple[str, bool]:
    """Return `content` clipped to `budget_bytes`, and whether it was clipped.

    Clips on a line boundary so a report never ends mid-record.
    """
    encoded = content.encode("utf-8")
    if len(encoded) <= budget_bytes:
        return content, False
    if budget_bytes <= 0:
        return "", True
    clipped = encoded[:budget_bytes].decode("utf-8", errors="ignore")
    last_newline = clipped.rfind("\n")
    return (clipped[: last_newline + 1] if last_newline != -1 else clipped), True


def _emit_non_sarif_reports(
    non_sarif: list[_ReportTarget],
    append_step_summary: Callable[[str], None],
) -> None:
    """Surface each non-SARIF report in the workflow run.

    Every report reaches the job log in full and is uploaded as an artifact by
    the workflow; only the job summary is budgeted, since GitHub discards
    summaries that run past its size limit.
    """
    summary_chunks: list[str] = []
    remaining = _STEP_SUMMARY_BUDGET_BYTES
    for target in non_sarif:
        path = target.path
        if not path.is_file():
            log.warning(
                "non-SARIF report '%s' missing; skipping log + summary emission",
                path,
            )
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        print(f"::group::Gitleaks report: {path}")
        print(content)
        print("::endgroup::")

        shown, clipped = _clip_to_budget(content, remaining)
        remaining -= len(shown.encode("utf-8"))
        chunk = f"### Gitleaks report: `{path}`"
        if shown:
            fence = _md_code_fence(shown)
            chunk += f"\n\n{fence}\n{shown}\n{fence}"
        if clipped:
            log.warning(
                "report '%s' exceeds the job-summary budget; summary truncated",
                path,
            )
            chunk += (
                "\n\n_Truncated to stay under GitHub's job-summary limit. "
                "The full report is in the uploaded artifact._"
            )
        summary_chunks.append(chunk)
    if summary_chunks:
        append_step_summary("\n\n".join(summary_chunks))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--scan-mode",
        default=os.environ.get("SCANNER_SCAN_MODE", "changed"),
        choices=("changed", "all"),
        help=(
            "'changed' (default) scans only commits introduced by the calling "
            "event; requires a pull_request or push "
            "event payload at $GITHUB_EVENT_PATH and hard-fails otherwise. "
            "'all' scans the full repository history and is required for "
            "schedule, workflow_dispatch, release, and any other event."
        ),
    )
    p.add_argument(
        "--report-formats",
        default=os.environ.get("SCANNER_REPORT_FORMATS", "sarif"),
        help=(
            "Comma-separated list of gitleaks report formats. Allowed "
            f"values: {', '.join(sorted({*_SUPPORTED_FORMATS, *_FORMAT_ALIASES}))}. "
            f"'human' is an alias for '{_FORMAT_ALIASES['human']}', so a "
            "caller can request a reviewer-readable report from every "
            "scanner without knowing each tool's format names."
        ),
    )
    p.add_argument(
        "--source-dir",
        default=os.environ.get("SCANNER_SOURCE_DIR", "."),
        help=(
            "Path to scan (default %(default)s). Set to a subdirectory of the "
            "checkout to restrict the scan to that subtree; gitleaks's "
            "--source flag combines naturally with --log-opts so the "
            "'changed' scan mode still works for partial-tree scans. The "
            "path must exist."
        ),
    )
    p.add_argument(
        "--checkout-root",
        default=os.environ.get("SCANNER_CHECKOUT_ROOT", "."),
        help=(
            "Git checkout root of the repository being scanned (default "
            "%(default)s). Where this script looks for the repository's own "
            f"gitleaks config and its {_IGNORE_FILENAME}; only matters when "
            "this differs from --source-dir (e.g. --source-dir restricts to "
            "a subtree, or the scan target isn't checked out at this "
            "process's cwd)."
        ),
    )
    return p


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(message)s")
    args = build_parser().parse_args(argv)

    try:
        targets = _parse_report_formats(args.report_formats)
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
        config_path = _resolve_config_path(checkout_root)
        ignore_path = resolve_ignore_file(
            scanner="gitleaks",
            checkout_root=checkout_root,
            filename=_IGNORE_FILENAME,
        )
        # Only 'changed' mode derives a git range from the event, so 'all'
        # mode is handed no payload at all rather than one it ignores:
        # loading it unconditionally would make a scheduled or dispatch
        # run fail on a payload it was never going to read.
        event = {} if args.scan_mode == "all" else gha_load_github_event()
        log_opts = _determine_log_opts(
            scan_mode=args.scan_mode,
            event_name=os.environ.get("GITHUB_EVENT_NAME", ""),
            event=event,
            source_dir=source_dir,
        )
    except (FileNotFoundError, KeyError, ValueError, RuntimeError) as exc:
        log.error("%s", exc)
        return 2
    log.info("Gitleaks scope: %s", log_opts or "<full repository history>")
    log.info("Gitleaks source: %s", source_dir)
    log.info(
        "Gitleaks formats: %s",
        ", ".join(f"{t.fmt}->{t.path}" for t in targets),
    )

    sarif_target = next((t for t in targets if t.fmt == "sarif"), None)
    non_sarif = [t for t in targets if t.fmt != "sarif"]

    try:
        binary = get_gitleaks_binary()
        leaks_found = _run_gitleaks(
            binary,
            targets,
            config_path=config_path,
            log_opts=log_opts,
            source_dir=source_dir,
            ignore_path=ignore_path,
        )
        # Set outputs only after a successful run, gated on the report
        # actually existing on disk: the workflow's upload steps run with
        # `if: always() && steps.scan.outputs.sarif_path != ''`, so a
        # non-empty path set *before* gitleaks runs (or on a path that
        # never got written) would make the SARIF upload step fire
        # against a missing file and fail with a confusing second error.
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
        # get_gitleaks_binary() can also fail with e.g. KeyError (tarball
        # missing the 'gitleaks' member) or OSError (download/network
        # errors) rather than RuntimeError; the documented contract maps
        # every scanner failure to exit code 2, so this is a deliberately
        # broad catch-all at main()'s top-level error boundary.
        log.exception("gitleaks install or scan failed unexpectedly")
        _emit_non_sarif_reports(non_sarif, gha_append_step_summary)
        return 2

    _emit_non_sarif_reports(non_sarif, gha_append_step_summary)

    if leaks_found:
        log.error("gitleaks found one or more potential secrets; see report artifacts")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
