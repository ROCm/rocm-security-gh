# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from security_scanners.utils.codeql_container_bootstrap import (
    BootstrapError,
    PACKAGE_MANAGERS,
    install_prerequisites,
    main,
    prerequisites_available,
    privilege_prefix,
    select_package_manager,
)


class PrerequisitesTest(unittest.TestCase):
    def test_bash_git_and_a_nonempty_ca_bundle_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "ca-bundle.crt"
            bundle.write_text("certificate", encoding="utf-8")
            with mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.shutil.which",
                side_effect=lambda command: f"/usr/bin/{command}",
            ):
                self.assertTrue(prerequisites_available((bundle,)))

            bundle.write_text("", encoding="utf-8")
            with mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.shutil.which",
                return_value="/usr/bin/tool",
            ):
                self.assertFalse(prerequisites_available((bundle,)))


class PackageManagerTest(unittest.TestCase):
    def test_selects_the_first_available_supported_manager(self):
        with mock.patch(
            "security_scanners.utils.codeql_container_bootstrap.shutil.which",
            side_effect=lambda command: "/usr/bin/dnf" if command == "dnf" else None,
        ):
            self.assertEqual(select_package_manager().executable, "dnf")

    def test_refuses_a_container_without_a_supported_manager(self):
        with (
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.shutil.which",
                return_value=None,
            ),
            self.assertRaises(BootstrapError),
        ):
            select_package_manager()

    def test_root_runs_package_commands_directly(self):
        manager = PACKAGE_MANAGERS[0]
        with (
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.os.geteuid",
                return_value=0,
            ),
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.subprocess.run"
            ) as run,
        ):
            install_prerequisites(manager)
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [manager.update, manager.install],
        )
        for call in run.call_args_list:
            self.assertTrue(call.kwargs["check"])
            self.assertEqual(call.kwargs["env"]["DEBIAN_FRONTEND"], "noninteractive")

    def test_a_nonroot_user_runs_package_commands_with_sudo(self):
        manager = PACKAGE_MANAGERS[1]
        with (
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.os.geteuid",
                return_value=1000,
            ),
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.shutil.which",
                return_value="/usr/bin/sudo",
            ),
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.subprocess.run"
            ) as run,
        ):
            install_prerequisites(manager)
        (call,) = run.call_args_list
        self.assertEqual(call.args[0], ("sudo", "-n", *manager.install))

    def test_a_nonroot_user_without_sudo_cannot_install(self):
        with (
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.os.geteuid",
                return_value=1000,
            ),
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.shutil.which",
                return_value=None,
            ),
            self.assertRaises(BootstrapError),
        ):
            privilege_prefix()


class MainTest(unittest.TestCase):
    def test_an_already_prepared_container_needs_no_package_manager(self):
        with (
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.prerequisites_available",
                return_value=True,
            ),
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.select_package_manager"
            ) as select,
        ):
            self.assertEqual(main([]), 0)
        select.assert_not_called()

    def test_failed_package_command_fails_the_step(self):
        with (
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.prerequisites_available",
                return_value=False,
            ),
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.select_package_manager",
                return_value=PACKAGE_MANAGERS[1],
            ),
            mock.patch(
                "security_scanners.utils.codeql_container_bootstrap.install_prerequisites",
                side_effect=subprocess.CalledProcessError(7, ("dnf",)),
            ),
        ):
            self.assertEqual(main([]), 1)

    def test_arguments_are_rejected(self):
        self.assertEqual(main(["--install"]), 2)


if __name__ == "__main__":
    unittest.main()
