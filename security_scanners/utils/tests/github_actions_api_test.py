# Copyright Advanced Micro Devices, Inc.
# SPDX-License-Identifier: MIT

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from security_scanners.utils.github_actions_api import import_github_actions_api


class ImportGithubActionsApiTest(unittest.TestCase):
    """Tests for import_github_actions_api."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("THEROCK_BUILD_TOOLS_DIR", None)

    def test_raises_when_env_var_unset(self):
        with self.assertRaises(RuntimeError) as ctx:
            import_github_actions_api()
        self.assertIn("THEROCK_BUILD_TOOLS_DIR", str(ctx.exception))

    def test_imports_from_env_var_path(self):
        # Isolate this test's sys.path/sys.modules mutations: importing a
        # real `github_actions.github_actions_api` module (even a stub)
        # caches it in sys.modules, which must not leak into other tests.
        self.addCleanup(sys.modules.pop, "github_actions.github_actions_api", None)
        self.addCleanup(sys.modules.pop, "github_actions", None)
        with tempfile.TemporaryDirectory() as tmp:
            build_tools = Path(tmp) / "build_tools"
            (build_tools / "github_actions").mkdir(parents=True)
            (build_tools / "github_actions" / "github_actions_api.py").write_text(
                "def gha_append_step_summary(summary):\n"
                "    return 'summary:' + summary\n"
                "def gha_load_github_event():\n"
                "    return {'stub': True}\n"
                "def gha_set_output(vars):\n"
                "    return dict(vars)\n",
                encoding="utf-8",
            )
            os.environ["THEROCK_BUILD_TOOLS_DIR"] = str(build_tools)
            self.addCleanup(sys.path.remove, str(build_tools))
            gha = import_github_actions_api()

        self.assertEqual(gha.append_step_summary("x"), "summary:x")
        self.assertEqual(gha.load_github_event(), {"stub": True})
        self.assertEqual(gha.set_output({"a": "b"}), {"a": "b"})


if __name__ == "__main__":
    unittest.main()
