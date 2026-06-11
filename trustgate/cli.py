"""Command-line interface for TrustGate."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Report,
    ScanError,
    SEVERITY_ORDER,
    RULE_TAXONOMY,
    scan_repo,
    to_sarif,
    to_badge,
    to_html,
    taxonomy_for,
)

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _ai_requested(args: argparse.Namespace) -> bool:
    """--ai flag OR an env opt-in (COGNIS_AI_BACKEND/COGNIS_AI_ENDPOINT)."""
    if getattr(args, "ai", False):
        return True
    return bool(os.environ.get("COGNIS_AI_BACKEND")
                or os.environ.get("COGNIS_AI_ENDPOINT"))


def _render_table(report: Report, fail_on: str) -> str:
    lines: List[str] = []
    lines.append(f"TrustGate scan — {report.root}")
    lines.append(f"(source: {report.source})")
    if report.ai_enabled:
        lines.append(f"AI layer: {report.ai_status}")
    lines.append("=" * 72)
    if not report.findings:
        lines.append("No findings. No symlink-hijack / one-click-RCE / unsafe-trust "
                     "issues detected.")
    else:
        for f in report.findings:
            label = _SEV_LABEL.get(f.severity, f.severity.upper())
            tag = f"[{f.domain}]" if f.domain else ""
            src = " (AI)" if f.source == "ai" else ""
            novel = " *NOVEL*" if f.novel else ""
            lines.append(f"[{label}] {f.rule} {tag}{src}{novel}")
            lines.append(f"        {f.message}")
            if f.cwe or f.ms_taxonomy:
                lines.append(f"        tax: {f.cwe}  {f.ms_taxonomy}")
            if f.location:
                lines.append(f"        at:  {f.location}")
            if f.evidence:
                lines.append(f"        evi: {f.evidence}")
            if f.remediation:
                lines.append(f"        fix: {f.remediation}")
    c = report.counts
    lines.append("-" * 72)
    lines.append(
        f"files={report.files_scanned} symlinks={report.symlinks_scanned}  "
        f"score={report.score}/100  "
        f"critical={c['critical']} high={c['high']} medium={c['medium']} "
        f"low={c['low']} info={c['info']}"
    )
    failed = report.failed(fail_on)
    lines.append(f"RESULT: {'FAIL' if failed else 'PASS'} (fail-on={fail_on})")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Detect symlink-hijack / one-click-RCE / unsafe-trust "
                    "settings in AI coding-agent projects.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan", help="Scan a project / agent-workspace directory for risks.")
    scan.add_argument("path", help="Path to the project directory to scan.")
    scan.add_argument("--format", choices=("table", "json", "sarif", "html",
                                           "badge"),
                      default="table", help="Output format (default: table).")
    scan.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER),
                      default="info",
                      help="Only report findings at or above this severity.")
    scan.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER),
                      default="high",
                      help="Exit non-zero if a finding at or above this "
                           "severity is present (default: high).")
    scan.add_argument("--ai", action="store_true",
                      help="Enable the opt-in Cognis AI layer (off by "
                           "default). Honors COGNIS_AI_* env. Degrades to "
                           "rules-only if the backend is unreachable.")
    scan.add_argument("--out", metavar="FILE",
                      help="Write the rendered report to FILE instead of "
                           "stdout (useful for --format html).")

    rules = sub.add_parser("rules", help="List the detection rules / domains.")
    rules.add_argument("--format", choices=("table", "json"), default="table")

    badge = sub.add_parser(
        "badge", help="Print a shields.io endpoint JSON for a status badge.")
    badge.add_argument("path", help="Path to the project directory to scan.")
    badge.add_argument("--ai", action="store_true",
                       help="Enable the opt-in AI layer for the badge scan.")
    return p


def _emit(text: str, out_path: Optional[str]) -> None:
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {out_path}", file=sys.stderr)
    else:
        print(text)


def _run_scan(args: argparse.Namespace) -> int:
    use_ai = _ai_requested(args)
    try:
        report = scan_repo(args.path, use_ai=use_ai)
    except (OSError, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if use_ai and report.ai_status != "ok":
        print(f"note: --ai requested but backend is '{report.ai_status}'; "
              f"continuing with rule findings only.", file=sys.stderr)

    threshold = SEVERITY_ORDER[args.min_severity]
    report.findings = [
        f for f in report.findings
        if SEVERITY_ORDER.get(f.severity, 99) <= threshold
    ]

    if args.format == "json":
        _emit(json.dumps(report.to_dict(), indent=2), args.out)
    elif args.format == "sarif":
        _emit(json.dumps(to_sarif(report), indent=2), args.out)
    elif args.format == "badge":
        _emit(json.dumps(to_badge(report), indent=2), args.out)
    elif args.format == "html":
        _emit(to_html(report, args.fail_on), args.out)
    else:
        _emit(_render_table(report, args.fail_on), args.out)

    return 1 if report.failed(args.fail_on) else 0


def _run_badge(args: argparse.Namespace) -> int:
    use_ai = _ai_requested(args)
    try:
        report = scan_repo(args.path, use_ai=use_ai)
    except (OSError, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(to_badge(report), indent=2))
    return 0


_RULES = [
    ("symlink", "symlink.escapes_repo", "critical",
     "Symlink target resolves outside the repository root."),
    ("symlink", "symlink.sensitive_target", "critical",
     "Symlink points at a sensitive host location (/etc, .ssh, .env, ...)."),
    ("symlink", "symlink.absolute_target", "high",
     "Symlink uses an absolute target path."),
    ("symlink", "symlink.dangling", "low",
     "Dangling symlink whose target does not exist."),
    ("trust", "trust.auto_approve", "critical",
     "Agent config enables auto-approve / auto-run / trusted-without-prompt."),
    ("trust", "trust.curl_pipe_shell", "critical",
     "Config runs curl|sh style remote-fetch-piped-to-shell."),
    ("trust", "trust.mcp_shell_command", "medium",
     "MCP/agent config launches an interpreter or chained shell command."),
    ("trust", "trust.wildcard_tool_grant", "high",
     "Agent config grants ALL tools/permissions via a wildcard."),
    ("trust", "trust.env_secret_inline", "high",
     "Agent config contains an inline hard-coded credential."),
    ("autorun", "autorun.task_on_open", "critical",
     "VS Code task runs automatically on folder open."),
    ("autorun", "autorun.devcontainer_hook", "medium",
     "devcontainer lifecycle command auto-executes on create/open."),
    ("autorun", "autorun.repo_git_hook", "high",
     "Repository ships an executable git hook."),
    ("autorun", "autorun.custom_hookspath", "high",
     "git core.hooksPath redirects hooks to a repo-controlled directory."),
    ("autorun", "autorun.agent_hooks", "medium",
     "Config defines agent lifecycle hooks."),
    ("autorun", "autorun.dangerous_hook_script", "high",
     "Auto-run hook/task script reaches a dangerous exec/shell sink (AST)."),
    ("perms", "perms.world_writable", "critical/high",
     "File (config) is world-writable and can be replaced by any local user."),
    ("perms", "perms.group_writable_config", "medium",
     "Agent config is group-writable."),
    ("perms", "perms.untrusted_location", "high",
     "Agent config lives in a world-writable system location (Windows)."),
]


def _run_rules(args: argparse.Namespace) -> int:
    if args.format == "json":
        print(json.dumps([
            {"domain": d, "rule": r, "severity": s, "description": desc,
             "cwe": taxonomy_for(r)[0], "ms_taxonomy": taxonomy_for(r)[1]}
            for d, r, s, desc in _RULES
        ], indent=2))
    else:
        print(f"{TOOL_NAME} detection rules:")
        cur = None
        for d, r, s, desc in _RULES:
            if d != cur:
                print(f"\n[{d}]")
                cur = d
            cwe, ms = taxonomy_for(r)
            print(f"  {r:<32} ({s})")
            print(f"      {desc}")
            print(f"      {cwe} · {ms}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)
    if args.command == "badge":
        return _run_badge(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
