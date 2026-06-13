"""Deep tests for TrustGate — symlink hijack, perms, SARIF, demo runner."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustgate.core import scan_repo, to_sarif

REPO_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk(base, rel, content):
    p = Path(base) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _can_symlink(tmp):
    try:
        t = Path(tmp) / "_t"
        l = Path(tmp) / "_l"
        t.mkdir()
        os.symlink(t, l, target_is_directory=True)
        os.remove(l)
        t.rmdir()
        return True
    except (OSError, NotImplementedError):
        return False


class TestSymlink(unittest.TestCase):
    def test_out_of_repo_symlink_is_critical(self):
        with tempfile.TemporaryDirectory() as outer:
            if not _can_symlink(outer):
                self.skipTest("symlinks not permitted on this platform")
            repo = Path(outer) / "repo"
            repo.mkdir()
            outside = Path(outer) / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("x", encoding="utf-8")
            os.symlink(outside, repo / "link", target_is_directory=True)
            rules = {f.rule for f in scan_repo(str(repo)).findings}
            self.assertIn("symlink.escapes_repo", rules)

    def test_in_repo_symlink_ok(self):
        with tempfile.TemporaryDirectory() as outer:
            if not _can_symlink(outer):
                self.skipTest("symlinks not permitted on this platform")
            repo = Path(outer) / "repo"
            (repo / "a").mkdir(parents=True)
            (repo / "a" / "f.txt").write_text("x", encoding="utf-8")
            os.symlink(repo / "a", repo / "b", target_is_directory=True)
            rules = {f.rule for f in scan_repo(str(repo)).findings}
            self.assertNotIn("symlink.escapes_repo", rules)

    def test_sensitive_target(self):
        with tempfile.TemporaryDirectory() as outer:
            if not _can_symlink(outer):
                self.skipTest("symlinks not permitted on this platform")
            repo = Path(outer) / "repo"
            repo.mkdir()
            try:
                os.symlink("/etc/passwd", repo / "pw")
            except OSError:
                self.skipTest("cannot create file symlink")
            rules = {f.rule for f in scan_repo(str(repo)).findings}
            self.assertIn("symlink.sensitive_target", rules)


class TestPermissions(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX mode bits not meaningful on Windows")
    def test_world_writable_config_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _mk(tmp, ".cursor/mcp.json", json.dumps({"x": 1}))
            os.chmod(p, 0o666)
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("perms.world_writable", rules)


class TestGitHooks(unittest.TestCase):
    def test_custom_hookspath(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, ".git/config",
                "[core]\n\thooksPath = .githooks\n")
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("autorun.custom_hookspath", rules)

    def test_repo_git_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, ".githooks/pre-commit", "#!/bin/sh\necho hi\n")
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("autorun.repo_git_hook", rules)


class TestJsonc(unittest.TestCase):
    def test_jsonc_with_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, ".vscode/settings.json",
                "{\n  // trust everything\n  \"autoApprove\": true,\n}\n")
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("trust.auto_approve", rules)


class TestSarif(unittest.TestCase):
    def test_sarif_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json", json.dumps({"autoApprove": True}))
            rep = scan_repo(tmp)
            sarif = to_sarif(rep)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"],
                             "trustgate")
            self.assertTrue(sarif["runs"][0]["results"])
            for r in sarif["runs"][0]["results"]:
                self.assertIn(r["level"], ("error", "warning", "note"))


class TestFailOn(unittest.TestCase):
    def test_fail_on_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            # only a medium-severity finding (devcontainer hook)
            _mk(tmp, ".devcontainer/devcontainer.json",
                json.dumps({"postCreateCommand": "./x.sh"}))
            rep = scan_repo(tmp)
            self.assertTrue(rep.failed("medium"))
            self.assertFalse(rep.failed("high"))


class TestDemoRunner(unittest.TestCase):
    def test_demo_runs(self):
        demo = REPO_ROOT / "demos" / "01-basic" / "run_demo.py"
        proc = subprocess.run(
            [sys.executable, str(demo), "--format", "json"],
            cwd=str(REPO_ROOT), capture_output=True, text=True)
        # Non-zero exit means risky findings were detected (expected).
        self.assertEqual(proc.returncode, 1, proc.stderr)
        data = json.loads(proc.stdout)
        rules = {f["rule"] for f in data["findings"]}
        # These are platform-independent (no symlink needed):
        self.assertIn("trust.auto_approve", rules)
        self.assertIn("autorun.task_on_open", rules)


if __name__ == "__main__":
    unittest.main()
