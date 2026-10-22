#!/usr/bin/env python3
# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT
"""Install Bash and Git in a CodeQL build container when they are absent.

The container provides POSIX sh and a CA certificate bundle so checkout and
`actions/setup-python` can run before this module. When Bash or Git is absent,
the module installs Bash, Git and the certificate package with the container's
supported package manager. It runs under the Python that setup-python provides,
which has no builds for musl, so the image must be glibc-based; Alpine is not
supported.

Package commands run non-interactively: `sudo -n` fails instead of prompting
for a password, and apt never asks a question.
"""

import os
import shutil
import subprocess  # nosec B404 # fixed package-manager commands only
import sys
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Sequence


@dataclass(frozen=True)
class PackageManager:
    """Commands that update package metadata and install prerequisites."""

    executable: str
    update: tuple[str, ...]
    install: tuple[str, ...]


PACKAGE_MANAGERS = (
    PackageManager(
        "apt-get",
        ("apt-get", "update", "-qq"),
        (
            "apt-get",
            "install",
            "-y",
            "-qq",
            "--no-install-recommends",
            "bash",
            "git",
            "ca-certificates",
        ),
    ),
    PackageManager(
        "dnf",
        (),
        ("dnf", "install", "-y", "bash", "git", "ca-certificates"),
    ),
    PackageManager(
        "microdnf",
        (),
        ("microdnf", "install", "-y", "bash", "git", "ca-certificates"),
    ),
    PackageManager(
        "yum",
        (),
        ("yum", "install", "-y", "bash", "git", "ca-certificates"),
    ),
    PackageManager(
        "zypper",
        (),
        (
            "zypper",
            "--non-interactive",
            "install",
            "--no-recommends",
            "bash",
            "git",
            "ca-certificates",
        ),
    ),
    PackageManager(
        "pacman",
        (),
        (
            "pacman",
            "-Sy",
            "--noconfirm",
            "--needed",
            "bash",
            "git",
            "ca-certificates",
        ),
    ),
)

CA_BUNDLES = (
    Path("/etc/ssl/certs/ca-certificates.crt"),
    Path("/etc/pki/tls/certs/ca-bundle.crt"),
    Path("/etc/ssl/ca-bundle.pem"),
    Path("/etc/ca-certificates/extracted/tls-ca-bundle.pem"),
)


class BootstrapError(RuntimeError):
    """The container cannot supply the required build tools."""


def prerequisites_available(ca_bundles: Sequence[Path] = CA_BUNDLES) -> bool:
    """Whether Bash, Git and a non-empty CA bundle are available."""
    return (
        shutil.which("bash") is not None
        and shutil.which("git") is not None
        and any(path.is_file() and path.stat().st_size > 0 for path in ca_bundles)
    )


def select_package_manager() -> PackageManager:
    """Return the first supported package manager available in the container."""
    for manager in PACKAGE_MANAGERS:
        if shutil.which(manager.executable) is not None:
            return manager
    raise BootstrapError(
        "the build container needs Bash, Git and CA certificates and has no "
        "supported package manager"
    )


def privilege_prefix() -> tuple[str, ...]:
    """Return the command prefix that grants package-install privileges."""
    if os.geteuid() == 0:
        return ()
    if shutil.which("sudo") is not None:
        return ("sudo", "-n")
    raise BootstrapError(
        "the build container needs Bash, Git and CA certificates, but its "
        "user cannot install packages"
    )


def install_prerequisites(manager: PackageManager) -> None:
    """Install the prerequisites with `manager`, raising on command failure."""
    prefix = privilege_prefix()
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    if manager.update:
        subprocess.run(  # nosec B603 # argv is a constant table
            (*prefix, *manager.update), check=True, env=env
        )
    subprocess.run(  # nosec B603 # argv is a constant table
        (*prefix, *manager.install), check=True, env=env
    )


def _fail(message: str) -> int:
    print(f"::error::{message}", file=sys.stderr)
    return 1


def main(argv: Sequence[str]) -> int:
    if argv:
        print(f"unexpected arguments: {' '.join(argv)}", file=sys.stderr)
        return 2
    if prerequisites_available():
        return 0
    try:
        install_prerequisites(select_package_manager())
    except BootstrapError as exc:
        return _fail(str(exc))
    except subprocess.CalledProcessError as exc:
        return _fail(f"package installation failed with exit code {exc.returncode}")
    if not prerequisites_available():
        return _fail(
            "package installation did not provide Bash, Git and CA certificates"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
