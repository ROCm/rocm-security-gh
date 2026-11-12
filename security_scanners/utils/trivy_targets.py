#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Turn a caller's `trivy_scan_type` and `trivy_images` inputs into Trivy targets.

`trivy_scan_type` is a comma-separated subset of `filesystem` and `image`,
e.g. `filesystem,image`. `trivy_images` is a YAML list with one entry per
image to build and scan, each on its own runner:

    - dockerfile: docker/Dockerfile        # required, repository-relative
      name: rocm-dev                       # optional, see below
      image: rocm-dev:security-scan        # optional local tag
      build_commands: |                    # optional, replaces docker build
        ./tools/build-image.sh "$SCANNER_TRIVY_IMAGE"

`name` identifies the matrix leg, its check run, SARIF category and report
artifact as `trivy-image-<name>`; it defaults to a slug of the Dockerfile
path, so two entries need distinct names only when they share a Dockerfile.
`image` defaults to `security-scan/<name>:ci`.
"""

import posixpath
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

SCAN_TYPE_FILESYSTEM = "filesystem"
SCAN_TYPE_IMAGE = "image"
SCAN_TYPES: tuple[str, ...] = (SCAN_TYPE_FILESYSTEM, SCAN_TYPE_IMAGE)
DEFAULT_SCAN_TYPES = SCAN_TYPE_FILESYSTEM
IMAGE_LEG_PREFIX = "trivy-image-"

_IMAGE_KEYS = frozenset({"dockerfile", "name", "image", "build_commands"})
# Lowercase alphanumerics and inner hyphens: valid in a check-run name, a
# SARIF category, an artifact name and a Docker repository name alike.
_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_SLUG_SEPARATOR_RE = re.compile(r"[^a-z0-9]+")
# Registry host, path, tag and digest characters. The leading character
# keeps the reference from ever being read as a docker or trivy flag.
_IMAGE_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")


class TrivyTargetError(ValueError):
    """A `trivy_scan_type` or `trivy_images` value the workflow cannot run."""


@dataclass(frozen=True)
class TrivyImageTarget:
    """One image to build and scan on its own runner.

    Attributes:
        name: Matrix leg name, also its check run, SARIF category and
            report artifact stem (`trivy-image-<name>`).
        dockerfile: Normalized repository-relative Dockerfile path.
        image: Local image reference the build produces and trivy scans.
        build_commands: Shell commands that replace `docker build`, or
            empty to build `dockerfile` with the repository root as context.
    """

    name: str
    dockerfile: str
    image: str
    build_commands: str = ""


@dataclass(frozen=True)
class TrivyPlan:
    """Which Trivy legs the matrix runs."""

    filesystem: bool = True
    images: tuple[TrivyImageTarget, ...] = ()


def validate_image_reference(raw: str) -> str:
    """Return `raw` stripped, if it is safe to pass as one docker/trivy argument."""
    image = raw.strip()
    if not image:
        raise TrivyTargetError("image reference is empty")
    if not _IMAGE_REFERENCE_RE.fullmatch(image):
        raise TrivyTargetError(
            f"image reference {image!r} must start with a letter or digit "
            "and contain only letters, digits and . _ / : @ -"
        )
    return image


def parse_scan_types(raw: str) -> frozenset[str]:
    """Parse a comma-separated `trivy_scan_type` value."""
    scan_types: set[str] = set()
    for item in raw.split(","):
        scan_type = item.strip().lower()
        if not scan_type:
            continue
        if scan_type not in SCAN_TYPES:
            raise TrivyTargetError(
                f"Invalid trivy_scan_type entry '{scan_type}' "
                f"(expected one or more of: {', '.join(SCAN_TYPES)})"
            )
        scan_types.add(scan_type)
    if not scan_types:
        raise TrivyTargetError(
            f"trivy_scan_type is empty (expected one or more of: "
            f"{', '.join(SCAN_TYPES)})"
        )
    return frozenset(scan_types)


def _normalize_dockerfile(raw: object, index: int) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise TrivyTargetError(f"trivy_images[{index}].dockerfile must be a path")
    normalized = posixpath.normpath(raw.strip())
    if PurePosixPath(normalized).is_absolute():
        raise TrivyTargetError(
            f"trivy_images[{index}].dockerfile {raw!r} must be relative to "
            "the repository root"
        )
    if normalized in (".", "..") or normalized.startswith("../"):
        raise TrivyTargetError(
            f"trivy_images[{index}].dockerfile {raw!r} must name a file "
            "inside the repository"
        )
    return normalized


def _leg_name(raw: object, dockerfile: str, index: int) -> str:
    if raw is None:
        slug = _SLUG_SEPARATOR_RE.sub("-", dockerfile.lower()).strip("-")
        name = slug[:64].rstrip("-")
    elif isinstance(raw, str):
        name = raw.strip()
    else:
        raise TrivyTargetError(f"trivy_images[{index}].name must be a string")
    if not _NAME_RE.fullmatch(name):
        raise TrivyTargetError(
            f"trivy_images[{index}].name {name!r} must be 1-64 lowercase "
            "letters, digits or inner hyphens"
        )
    return name


def _optional_string(entry: dict[str, object], key: str, index: int) -> str:
    value = entry.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise TrivyTargetError(f"trivy_images[{index}].{key} must be a string")
    return value.strip()


def _parse_image_entry(entry: object, index: int) -> TrivyImageTarget:
    if not isinstance(entry, dict):
        raise TrivyTargetError(f"trivy_images[{index}] must be a mapping")
    unknown = sorted(str(key) for key in entry if key not in _IMAGE_KEYS)
    if unknown:
        raise TrivyTargetError(
            f"trivy_images[{index}] has unknown key(s) {', '.join(unknown)} "
            f"(expected: {', '.join(sorted(_IMAGE_KEYS))})"
        )
    dockerfile = _normalize_dockerfile(entry.get("dockerfile"), index)
    name = _leg_name(entry.get("name"), dockerfile, index)
    image = _optional_string(entry, "image", index) or f"security-scan/{name}:ci"
    return TrivyImageTarget(
        name=f"{IMAGE_LEG_PREFIX}{name}",
        dockerfile=dockerfile,
        image=validate_image_reference(image),
        build_commands=_optional_string(entry, "build_commands", index),
    )


def parse_image_targets(raw: str) -> tuple[TrivyImageTarget, ...]:
    """Parse the `trivy_images` YAML list."""
    if not raw.strip():
        return ()
    # PyYAML is installed only in the plan job; the scanner jobs import
    # this module for `validate_image_reference` and never parse YAML.
    import yaml

    try:
        entries = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise TrivyTargetError(f"trivy_images is not valid YAML: {exc}") from exc
    if entries is None:
        return ()
    if not isinstance(entries, list):
        raise TrivyTargetError("trivy_images must be a YAML list")

    targets = tuple(
        _parse_image_entry(entry, index) for index, entry in enumerate(entries)
    )
    names = [target.name for target in targets]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise TrivyTargetError(
            f"trivy_images has duplicate leg name(s) {', '.join(duplicates)}; "
            "give entries that share a Dockerfile distinct 'name' values"
        )
    return targets


def plan_trivy(scan_types_raw: str, images_raw: str) -> TrivyPlan:
    """Return the Trivy legs for a caller's inputs."""
    scan_types = parse_scan_types(scan_types_raw)
    images = parse_image_targets(images_raw)
    if SCAN_TYPE_IMAGE in scan_types and not images:
        raise TrivyTargetError(
            "trivy_scan_type includes 'image' but trivy_images lists no images"
        )
    if images and SCAN_TYPE_IMAGE not in scan_types:
        raise TrivyTargetError(
            "trivy_images is set but trivy_scan_type does not include 'image'"
        )
    return TrivyPlan(filesystem=SCAN_TYPE_FILESYSTEM in scan_types, images=images)
