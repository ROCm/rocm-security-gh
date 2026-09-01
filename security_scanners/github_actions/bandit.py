#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Run bandit against the current repository checkout.

- Install the pinned `bandit[sarif]` release and verify it.
- Require `bandit.yaml` at the repo root (hard error if missing).
- Derive change sets from the GitHub event for changed/all scans; run per
  requested format and emit SARIF/non-SARIF paths plus a severity tally.

Exit codes:

* `0` - clean run, or an empty changed-file set.
* `1` - findings at/above `--severity-threshold`, or `--report-formats`
  was empty/unknown.
* `2` - input error: scan path missing, `bandit.yaml` missing,
  `GITHUB_EVENT_PATH` malformed, or bandit itself errored.

Inputs come from CLI flags or matching `SCANNER_*` env vars set by
`security-baseline.yml`. That prefix is shared by every scanner, so one
workflow step body drives all of them; each script ignores the variables
that don't apply to it.
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

from security_scanners.utils.binary_checksums import (
    CHECKSUMS_FILENAME,
    download_and_verify_file,
    expected_sha256,
    sha256_of,
)
from security_scanners.utils.github_actions_api import (
    gha_append_step_summary,
    gha_load_github_event,
    gha_set_output,
)
from security_scanners.utils.scanner_config import (
    find_config_change,
    resolve_scanner_config,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

log = logging.getLogger(__name__)


# Keep in sync with the `report_formats` input in
# `.github/workflows/security-baseline.yml`. Every one of bandit's format
# names is also the right file extension for what it writes, so the
# report path is derived from the format name; scanners where that isn't
# true (e.g. gitleaks' `junit`, which writes XML) need an explicit
# mapping instead.
_SUPPORTED_FORMATS: tuple[str, ...] = (
    "sarif",
    "json",
    "csv",
    "html",
    "xml",
    "yaml",
    "txt",
)
# Tool-independent aliases, so a caller can ask every scanner for "the
# report a reviewer reads" without knowing that bandit spells it 'txt',
# gitleaks 'csv', zizmor 'plain' and trivy 'table'.
_FORMAT_ALIASES: dict[str, str] = {"human": "txt"}
_BANDIT_VERSION = "1.9.4"
_BANDIT_EXTRAS = "sarif"
# PyPI sdist filenames are always version-qualified, unlike some other
# scanners' release assets, so bumping _BANDIT_VERSION naturally points
# this at a distinct checksums.sha256 entry -- no risk of an old digest
# silently matching a new binary under a reused, unversioned filename.
_BANDIT_SDIST_FILENAME = f"bandit-{_BANDIT_VERSION}.tar.gz"
_BANDIT_SDIST_URL = (
    f"https://rocm-third-party-deps.s3.us-east-2.amazonaws.com/{_BANDIT_SDIST_FILENAME}"
)
_CONFIG_PATH = "bandit.yaml"
# Where a scanned repository is allowed to keep its own config. Only the
# YAML form bandit's `-c` accepts: a `.bandit` file is INI-formatted CLI
# defaults, which `-c` can't read.
_CONFIG_CANDIDATES: tuple[str, ...] = ("bandit.yaml", "bandit.yml")
# Bandit exits with this code when it finds any issue at/above the
# --severity-level; we always scan at low, so it just means "any finding".
_FINDING_EXIT_CODE = 1
# Ascending severity order; threshold comparisons rely on it.
_SEVERITY_ORDER: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH")
_SEVERITY_CHOICES: tuple[str, ...] = tuple(s.lower() for s in _SEVERITY_ORDER)
_DEFAULT_SEVERITY_THRESHOLD = "high"
# Internal JSON tally pass output; cleaned up before returning.
_INTERNAL_TALLY_PATH = "bandit-tally.json"
# Extensions bandit treats as Python source; mirrors its --recursive walker.
_PYTHON_EXTENSIONS: tuple[str, ...] = (".py", ".pyw")
# Map bandit severities to GitHub security-severity values.
_BANDIT_SECURITY_SEVERITY: dict[str, str] = {
    "HIGH": "8.5",
    "MEDIUM": "5.0",
    "LOW": "1.0",
}


@dataclass(frozen=True)
class _ReportTarget:
    """A single `(format, on-disk path)` pair the runner will produce."""

    fmt: str
    path: Path


def _md_code_fence(content: str) -> str:
    """Return a fence longer than any backtick run in `content`."""
    longest = max((len(m) for m in re.findall(r"`+", content)), default=0)
    return "`" * max(3, longest + 1)


def _emit_non_sarif_reports(
    non_sarif: list[_ReportTarget],
    append_step_summary: Callable[[str], None],
) -> None:
    """Surface non-SARIF reports in logs and step summary."""
    summary_chunks: list[str] = []
    for target in non_sarif:
        path = target.path
        if not path.is_file():
            log.warning("Non-SARIF report '%s' missing; skipping", path)
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        print(f"::group::Bandit report: {path}")
        print(content)
        print("::endgroup::")
        fence = _md_code_fence(content)
        summary_chunks.append(
            f"### Bandit report: `{path}`\n\n{fence}\n{content}\n{fence}"
        )
    if summary_chunks:
        append_step_summary("\n\n".join(summary_chunks))


def get_bandit_binary() -> Path:
    """Download, verify, install the pinned bandit release, and return its CLI path.

    Unlike gitleaks/zizmor (statically-linked release binaries), bandit
    ships as a pure-Python package with its own runtime dependencies
    (PyYAML, stevedore, rich, pbr, plus sarif-om/jschema-to-python for
    the `sarif` extra). Rather than letting `pip install bandit[sarif]==...`
    resolve and fetch the bandit sdist itself straight from PyPI on
    pip's own (unaudited-by-us) TLS chain, this downloads that exact
    source tarball from a pinned S3 mirror, verifies it against this
    repo's `checksums.sha256` (see `security_scanners/utils/binary_checksums.py`),
    and only then
    hands the verified local file to pip, which builds and installs it
    (bandit has no compiled extensions, so a pure-Python sdist build is
    a normal, fast `pip install`). pip still resolves bandit's
    *dependencies* from PyPI as before -- only the security-critical
    bandit code itself gets an independent integrity check here.

    Pinned to an exact release rather than a floating range; no
    `--upgrade` since a fresh runner never has a stale bandit to
    replace. Smoke-tests the binary afterwards so we fail fast if the
    install left a half-broken state.
    """
    install_root = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
    sdist_path = install_root / _BANDIT_SDIST_FILENAME
    expected_sha = expected_sha256(REPO_ROOT, _BANDIT_SDIST_FILENAME)
    if sdist_path.is_file():
        # Verify the cached sdist as well, not just freshly downloaded
        # ones. A file already sitting at this path (job re-run, reused
        # RUNNER_TEMP, self-hosted runner) would otherwise reach pip
        # without any integrity check, which is not what
        # `checksums.sha256` promises. Fails closed rather than
        # re-downloading over it: the filename pins an exact release, so
        # a digest mismatch there is tampering or corruption, not
        # staleness, and silently replacing the evidence would hide it.
        actual_sha = sha256_of(sdist_path)
        if actual_sha != expected_sha:
            raise RuntimeError(
                f"cached bandit sdist at {sdist_path} has SHA256 "
                f"{actual_sha}, expected {expected_sha} (from "
                f"{CHECKSUMS_FILENAME}). Refusing to use this artifact; "
                "delete the file to force a fresh download."
            )
        log.info("Reusing verified bandit sdist at %s", sdist_path)
    else:
        log.info("Downloading bandit v%s from %s", _BANDIT_VERSION, _BANDIT_SDIST_URL)
        download_and_verify_file(
            url=_BANDIT_SDIST_URL,
            expected_sha256=expected_sha,
            dest_path=sdist_path,
        )

    spec = f"{sdist_path}[{_BANDIT_EXTRAS}]"
    log.info("Installing %s", spec)
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", spec],
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Failed to install {spec}: {exc}") from exc

    # Console scripts land next to sys.executable, even for an unactivated venv.
    binary_path = Path(sys.executable).parent / "bandit"
    if not binary_path.is_file():
        found = shutil.which("bandit")
        if found is None:
            raise RuntimeError(
                f"bandit CLI not found at {binary_path} or on PATH after "
                f"installing {spec}; is the active Python environment writable?"
            )
        binary_path = Path(found)

    try:
        result = subprocess.run(
            [str(binary_path), "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            f"bandit at {binary_path} failed to execute after install: {exc}"
        ) from exc
    # `bandit --version` prints "bandit <version>" as its first line,
    # followed by extra lines (python version, etc).
    first_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    installed_version = first_line.rsplit(maxsplit=1)[-1] if first_line else ""
    if installed_version != _BANDIT_VERSION:
        raise RuntimeError(
            f"bandit at {binary_path} reports version {installed_version!r}, "
            f"expected {_BANDIT_VERSION!r}"
        )
    log.info("Installed bandit %s at %s", installed_version, binary_path)
    return binary_path


def _parse_report_formats(raw: str) -> list[_ReportTarget]:
    """Parse a comma-separated `report_formats` value into report targets.

    Whitespace is trimmed, duplicates collapse to the first occurrence,
    and unknown formats raise :class:`ValueError`.
    """
    targets: list[_ReportTarget] = []
    seen: set[str] = set()
    for raw_fmt in raw.split(","):
        fmt = _FORMAT_ALIASES.get(raw_fmt.strip(), raw_fmt.strip())
        if not fmt or fmt in seen:
            continue
        seen.add(fmt)
        if fmt not in _SUPPORTED_FORMATS:
            raise ValueError(
                f"Invalid report_formats entry '{fmt}' "
                f"(expected one of: "
                f"{', '.join(sorted({*_SUPPORTED_FORMATS, *_FORMAT_ALIASES}))})"
            )
        targets.append(_ReportTarget(fmt=fmt, path=Path(f"bandit-report.{fmt}")))
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
            scanner="bandit",
            checkout_root=checkout_root,
            candidates=_CONFIG_CANDIDATES,
            fallback=REPO_ROOT / _CONFIG_PATH,
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

    `pull_request_target` carries the same payload shape as
    `pull_request` and is accepted for callers that trigger on it, even
    though nothing in this repo does. Its default checkout is the base
    commit, so if such a caller doesn't fetch the PR head, the diff
    downstream simply fails and the scan widens to the whole tree --
    the failure mode is scanning more than asked, never less.
    """
    if event_name in ("pull_request", "pull_request_target"):
        base = _event_str(event, "pull_request", "base", "sha")
        head = _event_str(event, "pull_request", "head", "sha")
        if not base or not head:
            log.warning("PR event missing base/head SHA; falling back to full scan")
            return None
        return (base, head)
    if event_name == "push":
        before = _event_str(event, "before")
        after = _event_str(event, "after")
        if not before or not after:
            log.warning(
                "Push event missing before/after SHA; falling back to full scan"
            )
            return None
        # All-zero SHA means a new ref: nothing to diff against.
        if set(before) <= {"0"}:
            log.info("Push created a new ref; falling back to full scan")
            return None
        return (before, after)
    log.info(
        "Event '%s' has no diff range; falling back to full scan",
        event_name or "<unset>",
    )
    return None


def _determine_changed_python_files(
    event_name: str,
    event: Mapping[str, object],
    scan_path: Path,
    checkout_root: Path = Path("."),
) -> list[Path] | None:
    """Return the changed Python source files inside `scan_path`, or `None`.

    Semantics:

    * `None` — no usable diff range, or the bandit config itself changed;
      caller should fall back to a full recursive scan of `scan_path`.
    * `[]` — diff range was usable but contained no Python files under
      `scan_path`; caller should treat this as a clean no-op.
    * `[paths…]` — exact set of files for bandit to scan.
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
                "--diff-filter=ACMR",
                f"{base_sha}..{head_sha}",
            ],
            cwd=checkout_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        log.warning(
            "git diff %s..%s failed (rc=%s, stderr=%r); falling back to full scan",
            base_sha,
            head_sha,
            exc.returncode,
            exc.stderr.strip() if exc.stderr else "",
        )
        return None

    changed = result.stdout.splitlines()
    config_change = find_config_change(changed, filenames=_CONFIG_CANDIDATES)
    if config_change is not None:
        log.info(
            "Changed config (%s) applies to every file, so this run scans "
            "the whole tree instead of the changed files alone",
            config_change,
        )
        return None

    scan_root = scan_path.resolve()
    files: list[Path] = []
    for raw in changed:
        relpath = raw.strip()
        if not relpath.endswith(_PYTHON_EXTENSIONS):
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


def _run_bandit(
    binary: Path,
    user_targets: list[_ReportTarget],
    *,
    config_path: str,
    files: list[Path] | None,
    scan_path: Path,
) -> dict[str, int]:
    """Run bandit at `--severity-level low` for each user-requested format
    plus an internal JSON tally pass if the user didn't already request
    one, and return a severity tally.

    Bandit always scans at LOW so the uploaded reports keep every
    finding regardless of `--severity-threshold`; the threshold-based
    job-fail decision is taken separately in `main()` from the returned
    tally.

    Raises :class:`RuntimeError` for unexpected bandit exit codes
    (anything outside `{0, _FINDING_EXIT_CODE}`).
    """
    base_args: list[str] = [str(binary), "--severity-level", "low"]
    base_args.extend(["--configfile", config_path])
    if files is None:
        base_args.extend(["--recursive", str(scan_path)])
    else:
        base_args.extend(str(p) for p in files)

    # Reuse a user-requested JSON report for the tally, else add one.
    user_json = next((t for t in user_targets if t.fmt == "json"), None)
    if user_json is not None:
        tally_target = user_json
        runs: list[_ReportTarget] = list(user_targets)
    else:
        tally_target = _ReportTarget(fmt="json", path=Path(_INTERNAL_TALLY_PATH))
        runs = [*user_targets, tally_target]

    try:
        for tgt in runs:
            cmd = [*base_args, "--format", tgt.fmt, "--output", str(tgt.path)]
            log.info("Running: %s", " ".join(cmd))
            rc = subprocess.run(cmd, check=False).returncode
            if rc not in (0, _FINDING_EXIT_CODE):
                raise RuntimeError(
                    f"bandit exited unexpectedly with code {rc} for format '{tgt.fmt}'"
                )

        # Enrich SARIF severity for the Security tab (tally pass is never SARIF).
        user_sarif = next((t for t in user_targets if t.fmt == "sarif"), None)
        if user_sarif is not None and user_sarif.path.is_file():
            _enrich_sarif_with_security_severity(user_sarif.path)

        return _tally_findings_by_severity(tally_target.path)
    finally:
        # Safe even if the loop above raised before writing the tally
        # file (unlink(missing_ok=True) is a no-op then).
        if tally_target.path == Path(_INTERNAL_TALLY_PATH):
            tally_target.path.unlink(missing_ok=True)


def _enrich_sarif_with_security_severity(sarif_path: Path) -> None:
    """Inject `security-severity` into each SARIF result so the GitHub
    Security tab tiers bandit findings the same way it tiers CodeQL.

    Maps bandit's per-result `properties.issue_severity` through
    `_BANDIT_SECURITY_SEVERITY`. Pre-existing values are preserved.
    Enrichment failures are logged at WARNING and don't propagate:
    `level` still drives the Security tab tier on its own.
    """
    try:
        with open(sarif_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("SARIF severity enrichment skipped (%s): %s", sarif_path, exc)
        return
    if not isinstance(data, dict):
        log.warning(
            "SARIF severity enrichment skipped: %s is not a JSON object",
            sarif_path,
        )
        return

    enriched = 0
    preserved = 0
    unknown = 0
    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            props = result.get("properties")
            if not isinstance(props, dict):
                props = {}
                result["properties"] = props
            if props.get("security-severity") is not None:
                preserved += 1
                continue
            sev = str(props.get("issue_severity") or "").upper()
            score = _BANDIT_SECURITY_SEVERITY.get(sev)
            if score is None:
                unknown += 1
                continue
            props["security-severity"] = score
            enriched += 1

    if enriched == 0:
        if unknown:
            # Loud rather than silent: bandit's SARIF formatter is the
            # only source of `properties.issue_severity`, so results
            # arriving without one mean the pinned release changed shape
            # and every finding is now tiered by `level` alone.
            log.warning(
                "SARIF severity enrichment added nothing: %d result(s) in %s carry "
                "no recognised properties.issue_severity. bandit %s emits it; a "
                "release that renames or drops the field leaves the Security tab "
                "tiering findings by 'level' alone.",
                unknown,
                sarif_path,
                _BANDIT_VERSION,
            )
        else:
            log.debug(
                "SARIF severity enrichment: nothing to add (%d preserved) in %s",
                preserved,
                sarif_path,
            )
        return

    try:
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError as exc:
        log.warning("Failed to write enriched SARIF to %s: %s", sarif_path, exc)
        return

    log.info(
        "SARIF severity enrichment: %d result(s) given security-severity "
        "(%d already had it, %d had unknown severity) in %s",
        enriched,
        preserved,
        unknown,
        sarif_path,
    )


def _tally_findings_by_severity(json_path: Path) -> dict[str, int]:
    """Returns a dict with at minimum `LOW`/`MEDIUM`/`HIGH` keys (each
    `int >= 0`); any other `issue_severity` value bandit emits (e.g.
    `UNDEFINED`) is preserved verbatim but doesn't participate in the
    threshold decision.
    """
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Failed to read bandit JSON tally at {json_path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            f"bandit JSON tally at {json_path} is not an object "
            f"(got {type(data).__name__})"
        )
    counts: dict[str, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    for issue in data.get("results") or []:
        sev = str(issue.get("issue_severity") or "UNDEFINED").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--scan-mode",
        default=os.environ.get("SCANNER_SCAN_MODE", "changed"),
        choices=("changed", "all"),
        help=(
            "'changed' (default) scans only Python source files modified "
            "by the calling event (PR commits or push range). 'all' "
            "recursively scans every Python source file under "
            "--source-dir; bandit's own --recursive walker filters to "
            ".py / .pyw automatically so non-Python files are skipped "
            "regardless of mode."
        ),
    )
    p.add_argument(
        "--report-formats",
        default=os.environ.get("SCANNER_REPORT_FORMATS", "sarif"),
        help=(
            "Comma-separated list of bandit report formats. Allowed "
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
            "Path to scan (default %(default)s). Set to a subdirectory of "
            "the checkout to restrict the scan to that subtree; the "
            "'changed' scan mode further restricts to only the Python "
            "source files modified inside this path. The path must exist."
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
        "--severity-threshold",
        default=os.environ.get(
            "SCANNER_SEVERITY_THRESHOLD", _DEFAULT_SEVERITY_THRESHOLD
        ),
        choices=_SEVERITY_CHOICES,
        help=(
            "Minimum bandit severity that fails the job. Bandit always "
            "scans at LOW so the uploaded reports keep every finding; "
            "after the scan the script tallies findings by severity and "
            "exits 1 only if any are at or above this threshold. Bandit "
            "categorises findings as LOW / MEDIUM / HIGH (no 'critical' "
            "tier). Default '%(default)s' fails only on HIGH findings; "
            "set 'low' to fail on any finding (the legacy behaviour)."
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
        # Only 'changed' mode needs the event payload, to work out the
        # diff range. Loading it unconditionally would make 'all' mode
        # fail on events that have no payload we can parse, even though
        # it never looks at one.
        if args.scan_mode == "all":
            files: list[Path] | None = None
        else:
            files = _determine_changed_python_files(
                event_name=os.environ.get("GITHUB_EVENT_NAME", ""),
                event=gha_load_github_event(),
                scan_path=source_dir,
                checkout_root=checkout_root,
            )
    except (FileNotFoundError, KeyError, ValueError, RuntimeError) as exc:
        log.error("%s", exc)
        return 2

    if files is None:
        log.info(
            "Bandit scope: recursive scan of %s (bandit filters to %s itself)",
            source_dir,
            "/".join(_PYTHON_EXTENSIONS),
        )
    elif files:
        log.info(
            "Bandit scope: %d changed Python source file(s) under %s",
            len(files),
            source_dir,
        )
        for f in files:
            log.info("  - %s", f)
    else:
        log.info(
            "Bandit scope: no Python source files changed under %s; nothing to scan",
            source_dir,
        )

    log.info(
        "Bandit formats: %s",
        ", ".join(f"{t.fmt}->{t.path}" for t in targets),
    )
    log.info(
        "Bandit fail threshold: severity >= %s (lower-severity findings "
        "still appear in reports)",
        args.severity_threshold.upper(),
    )

    sarif_target = next((t for t in targets if t.fmt == "sarif"), None)
    non_sarif = [t for t in targets if t.fmt != "sarif"]

    # 'changed' mode with nothing to scan: emit empty paths so uploads skip.
    if files is not None and not files:
        gha_set_output({"sarif_path": "", "non_sarif_paths": ""})
        return 0

    try:
        binary = get_bandit_binary()
        counts = _run_bandit(
            binary,
            targets,
            config_path=config_path,
            files=files,
            scan_path=source_dir,
        )
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
        # get_bandit_binary()/_run_bandit() can also fail with exception
        # types other than RuntimeError (e.g. OSError from a pip/network
        # failure); the documented contract maps every scanner failure
        # to exit code 2, so this is a deliberately broad catch-all at
        # main()'s top-level error boundary.
        log.exception("bandit install or scan failed unexpectedly")
        _emit_non_sarif_reports(non_sarif, gha_append_step_summary)
        return 2

    threshold = args.severity_threshold.upper()
    threshold_idx = _SEVERITY_ORDER.index(threshold)
    failing = sum(counts[sev] for sev in _SEVERITY_ORDER[threshold_idx:])
    summary = ", ".join(f"{sev}={counts[sev]}" for sev in _SEVERITY_ORDER)
    extra = {sev: n for sev, n in counts.items() if sev not in _SEVERITY_ORDER and n}
    if extra:
        summary += ", " + ", ".join(f"{sev}={n}" for sev, n in extra.items())
    log.info("Bandit findings: %s", summary)

    _emit_non_sarif_reports(non_sarif, gha_append_step_summary)

    if failing:
        log.error(
            "bandit reported %d finding(s) at severity >= %s; failing the job "
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
