"""Tests for v0.2 features: deep detection, CWE/MS taxonomy, AI merge,
badge + HTML output, TOML/YAML config parsing, AST hook source->sink.

Standard library only, no network. The AI tests stub the backend so they run
offline and prove the rules-only fallback path."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustgate.core import (
    scan_repo, to_badge, to_html, to_sarif, taxonomy_for,
    Finding, merge_ai_findings, ai_finding_to_finding, RULE_TAXONOMY,
)

REPO_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _mk(tmp, rel, content):
    p = Path(tmp) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


class TestTaxonomy(unittest.TestCase):
    def test_every_finding_has_cwe_and_ms(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, ".cursor/mcp.json", json.dumps({"autoApprove": True}))
            rep = scan_repo(tmp)
            self.assertTrue(rep.findings)
            for f in rep.findings:
                self.assertTrue(f.cwe.startswith("CWE-"), f.rule)
                self.assertTrue(f.ms_taxonomy.startswith("MS."), f.rule)

    def test_taxonomy_for_known_rule(self):
        cwe, ms = taxonomy_for("symlink.escapes_repo")
        self.assertEqual(cwe, "CWE-59")
        self.assertEqual(ms, "MS.SC.SymlinkFollowing")

    def test_cwe_hint_override(self):
        cwe, ms = taxonomy_for("ai.finding", cwe_hint="CWE-89")
        self.assertEqual(cwe, "CWE-89")


class TestDeepTrust(unittest.TestCase):
    def test_wildcard_tool_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, ".cursor/mcp.json",
                json.dumps({"mcpServers": {"x": {"allowedTools": ["*"]}}}))
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("trust.wildcard_tool_grant", rules)

    def test_inline_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json",
                json.dumps({"apiKey": "sk-live-abcdef0123456789ABCDEF"}))
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("trust.env_secret_inline", rules)

    def test_secret_placeholder_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json", json.dumps({"apiKey": "${OPENAI_API_KEY}"}))
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertNotIn("trust.env_secret_inline", rules)

    def test_extra_autoapprove_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, ".claude/settings.json",
                json.dumps({"autoConfirm": True}))
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("trust.auto_approve", rules)


class TestTomlYaml(unittest.TestCase):
    def test_toml_auto_approve(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.toml", "autoApprove = true\n")
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("trust.auto_approve", rules)

    def test_yaml_yolo(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "aider.conf.yml", "yolo: true\n")
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("trust.auto_approve", rules)


class TestAstHookScript(unittest.TestCase):
    def test_python_hook_sink_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "hook.py",
                "import os\nos.system('rm -rf /')\neval('1')\n")
            _mk(tmp, ".devcontainer/devcontainer.json",
                json.dumps({"postCreateCommand": "python hook.py"}))
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertIn("autorun.dangerous_hook_script", rules)

    def test_clean_hook_no_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "hook.py", "print('hello, no sinks here')\n")
            _mk(tmp, ".devcontainer/devcontainer.json",
                json.dumps({"postCreateCommand": "python hook.py"}))
            rules = {f.rule for f in scan_repo(tmp).findings}
            self.assertNotIn("autorun.dangerous_hook_script", rules)


class TestBadge(unittest.TestCase):
    def test_badge_shape_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "src/x.py", "print(1)\n")
            b = to_badge(scan_repo(tmp))
            self.assertEqual(b["schemaVersion"], 1)
            self.assertEqual(b["label"], "trustgate")
            self.assertEqual(b["message"], "passing")
            self.assertEqual(b["color"], "brightgreen")

    def test_badge_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json", json.dumps({"autoApprove": True}))
            b = to_badge(scan_repo(tmp))
            self.assertEqual(b["color"], "critical")
            self.assertIn("critical", b["message"])


class TestHtml(unittest.TestCase):
    def test_html_self_contained(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json", json.dumps({"autoApprove": True}))
            doc = to_html(scan_repo(tmp))
            self.assertTrue(doc.lstrip().startswith("<!doctype html>"))
            self.assertIn("trust.auto_approve", doc)
            self.assertIn("<style>", doc)
            self.assertNotIn("http://", doc.split("informationUri")[0]
                             if "informationUri" in doc else doc)  # no ext CSS


class TestAiMerge(unittest.TestCase):
    def test_ai_finding_conversion(self):
        item = {"title": "SQLi", "severity": "high", "cwe": "CWE-89",
                "line": 12, "evidence": "query=%s", "why": "unsafe concat",
                "confidence": 0.9, "novel": True}
        f = ai_finding_to_finding(item, "app.py")
        self.assertEqual(f.source, "ai")
        self.assertEqual(f.cwe, "CWE-89")
        self.assertTrue(f.novel)
        self.assertIn("line 12", f.location)

    def test_merge_dedupes(self):
        rule_f = Finding("trust.auto_approve", "critical", "x",
                         "mcp.json::a", evidence="autoApprove=true")
        ai_f = ai_finding_to_finding(
            {"title": "auto approve", "severity": "critical",
             "evidence": "autoApprove=true"}, "mcp.json")
        merged = merge_ai_findings([rule_f], [ai_f])
        # ai finding collides on (file, evidence-prefix) -> deduped
        self.assertEqual(len(merged), 1)

    def test_merge_keeps_novel(self):
        rule_f = Finding("trust.auto_approve", "critical", "x", "mcp.json::a")
        ai_f = ai_finding_to_finding(
            {"title": "logic flaw", "severity": "high",
             "evidence": "totally different", "novel": True}, "other.py")
        merged = merge_ai_findings([rule_f], [ai_f])
        self.assertEqual(len(merged), 2)


class TestAiBackendOffByDefault(unittest.TestCase):
    def test_default_off(self):
        # Without --ai and without env, scan must not enable AI.
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json", json.dumps({"autoApprove": True}))
            rep = scan_repo(tmp, use_ai=False)
            self.assertFalse(rep.ai_enabled)
            self.assertEqual(rep.ai_status, "off")

    def test_ai_unreachable_degrades(self):
        # use_ai=True but no reachable backend -> rules preserved, no crash.
        prev = {k: os.environ.get(k) for k in
                ("COGNIS_AI_BACKEND", "COGNIS_AI_ENDPOINT", "COGNIS_AI_MODEL")}
        try:
            os.environ.pop("COGNIS_AI_BACKEND", None)
            os.environ["COGNIS_AI_ENDPOINT"] = "http://127.0.0.1:9/v1"
            os.environ["COGNIS_AI_MODEL"] = "x"
            with tempfile.TemporaryDirectory() as tmp:
                _mk(tmp, "mcp.json", json.dumps({"autoApprove": True}))
                rep = scan_repo(tmp, use_ai=True)
                self.assertTrue(rep.ai_enabled)
                self.assertEqual(rep.ai_status, "unreachable")
                rules = {f.rule for f in rep.findings}
                self.assertIn("trust.auto_approve", rules)
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class TestDeterminism(unittest.TestCase):
    def test_two_runs_identical_without_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.toml", "autoApprove = true\n")
            _mk(tmp, "aider.conf.yml", "yolo: true\n")
            _mk(tmp, ".cursor/mcp.json",
                json.dumps({"mcpServers": {"x": {"allowedTools": ["*"]}}}))
            a = json.dumps(scan_repo(tmp).to_dict(), sort_keys=True)
            b = json.dumps(scan_repo(tmp).to_dict(), sort_keys=True)
            self.assertEqual(a, b)


class TestCliNewFormats(unittest.TestCase):
    def test_badge_subcommand(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "src/x.py", "print(1)\n")
            proc = subprocess.run(
                [sys.executable, "-m", "trustgate", "badge", tmp],
                cwd=str(REPO_ROOT), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["schemaVersion"], 1)

    def test_html_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json", json.dumps({"autoApprove": True}))
            proc = subprocess.run(
                [sys.executable, "-m", "trustgate", "scan", tmp,
                 "--format", "html"],
                cwd=str(REPO_ROOT), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, proc.stderr)  # critical found
            self.assertIn("<!doctype html>", proc.stdout)

    def test_sarif_has_taxonomy(self):
        with tempfile.TemporaryDirectory() as tmp:
            _mk(tmp, "mcp.json", json.dumps({"autoApprove": True}))
            sarif = to_sarif(scan_repo(tmp))
            r0 = sarif["runs"][0]["results"][0]
            self.assertIn("cwe", r0["properties"])
            self.assertIn("ms_taxonomy", r0["properties"])


if __name__ == "__main__":
    unittest.main()
