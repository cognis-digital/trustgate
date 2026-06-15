"""Hardening tests: error paths, edge cases, and new guards added in this pass.

Standard library only, no network.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustgate.cli import main, _emit
from trustgate.core import (
    scan_repo,
    merge_ai_findings,
    Finding,
    ai_finding_to_finding,
)

REPO_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk(base, rel, content):
    p = Path(base) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# CLI error path: unwritable output file → exit 2 (not a traceback)
# ---------------------------------------------------------------------------

class TestEmitBadPath(unittest.TestCase):
    def test_unwritable_out_path_raises_oserror(self):
        """_emit to a nonexistent directory should raise OSError, not crash silently."""
        with self.assertRaises(OSError):
            _emit("hello", "/no/such/dir/report.html")


class TestScanOutWriteFailure(unittest.TestCase):
    def test_scan_bad_out_exits_2(self):
        """scan --out to an unwritable path must return 2, not traceback."""
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "src/x.py", "print(1)\n")
            rc = main(["scan", tmp, "--out", "/no/such/dir/out.json"])
            self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# CLI: missing / nonexistent path → exit 2
# ---------------------------------------------------------------------------

class TestMissingPath(unittest.TestCase):
    def test_nonexistent_dir_exits_2(self):
        rc = main(["scan", "/totally/nonexistent/path/xyz"])
        self.assertEqual(rc, 2)

    def test_path_is_file_not_dir_exits_2(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            fname = f.name
        try:
            rc = main(["scan", fname])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(fname)


# ---------------------------------------------------------------------------
# Edge case: empty directory → no findings, score 100, exit 0
# ---------------------------------------------------------------------------

class TestEmptyRepo(unittest.TestCase):
    def test_empty_dir_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            rep = scan_repo(tmp)
            self.assertEqual(rep.findings, [])
            self.assertEqual(rep.score, 100)
            self.assertFalse(rep.failed("info"))

    def test_empty_dir_cli_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = main(["scan", tmp])
            self.assertEqual(rc, 0)


# ---------------------------------------------------------------------------
# Edge case: malformed / unparseable config file → no crash, no false findings
# ---------------------------------------------------------------------------

class TestMalformedConfig(unittest.TestCase):
    def test_invalid_json_no_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json", "{ this is NOT valid json !!!")
            # Should not raise; findings may be empty or have non-trust rules
            rep = scan_repo(tmp)
            rules = {f.rule for f in rep.findings}
            # malformed JSON must not produce a trust.auto_approve false positive
            self.assertNotIn("trust.auto_approve", rules)

    def test_empty_json_file_no_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, ".cursor/mcp.json", "")
            rep = scan_repo(tmp)
            # empty file → no trust findings
            rules = {f.rule for f in rep.findings}
            self.assertNotIn("trust.auto_approve", rules)

    def test_null_json_no_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json", "null")
            rep = scan_repo(tmp)
            rules = {f.rule for f in rep.findings}
            self.assertNotIn("trust.auto_approve", rules)


# ---------------------------------------------------------------------------
# merge_ai_findings: O(n) dedup set built once (regression for the F841 fix)
# ---------------------------------------------------------------------------

class TestMergeAiDedup(unittest.TestCase):
    def test_exact_collision_deduped(self):
        rule_f = Finding("trust.auto_approve", "critical", "msg",
                         "mcp.json::autoApprove", evidence="autoApprove=true")
        ai_f = ai_finding_to_finding(
            {"title": "auto-approve", "severity": "critical",
             "evidence": "autoApprove=true"}, "mcp.json")
        merged = merge_ai_findings([rule_f], [ai_f])
        self.assertEqual(len(merged), 1)

    def test_different_evidence_kept(self):
        rule_f = Finding("trust.auto_approve", "critical", "msg",
                         "mcp.json::autoApprove", evidence="autoApprove=true")
        ai_f = ai_finding_to_finding(
            {"title": "novel flaw", "severity": "high",
             "evidence": "completely different", "novel": True}, "cfg.toml")
        merged = merge_ai_findings([rule_f], [ai_f])
        self.assertEqual(len(merged), 2)

    def test_empty_inputs(self):
        self.assertEqual(merge_ai_findings([], []), [])

    def test_only_ai_findings_all_kept(self):
        ai_findings = [
            ai_finding_to_finding({"title": f"f{i}", "severity": "low",
                                   "evidence": f"ev{i}"}, f"f{i}.json")
            for i in range(5)
        ]
        merged = merge_ai_findings([], ai_findings)
        self.assertEqual(len(merged), 5)


# ---------------------------------------------------------------------------
# MCP server: malformed / oversized lines do not crash
# ---------------------------------------------------------------------------

class TestMcpServerEdgeCases(unittest.TestCase):
    def test_oversized_line_skipped(self):
        """run_stdio_server must not crash on a line exceeding _MAX_LINE_BYTES."""
        from trustgate.mcp_server import _MAX_LINE_BYTES, run_stdio_server
        import io

        big_line = "x" * (_MAX_LINE_BYTES + 1) + "\n"
        normal = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}) + "\n"
        fake_stdin = io.StringIO(big_line + normal)
        orig = sys.stdin
        capture = io.StringIO()
        orig_stdout = sys.stdout
        try:
            sys.stdin = fake_stdin
            sys.stdout = capture
            rc = run_stdio_server()
        finally:
            sys.stdin = orig
            sys.stdout = orig_stdout
        self.assertEqual(rc, 0)
        # The ping reply must still have been emitted (after the big line was skipped)
        output = capture.getvalue()
        self.assertTrue(any("result" in line for line in output.splitlines()),
                        f"expected a result reply but got: {output!r}")


if __name__ == "__main__":
    unittest.main()
