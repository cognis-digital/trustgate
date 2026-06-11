"""Command-line interface for TrustGate."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Report,
    ScanError,
    SEVERITY_ORDER,
    scan_repo,
    to_sarif,
)

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _render_table(report: Report, fail_on: str) -> str:
    lines: List[str] = []
    lines.append(f"TrustGate scan — {report.root}")
    lines.append(f"(source: {report.source})")
    lines.append("=" * 72)
    if not report.findings:
        lines.append("No findings. No symlink-hijack / one-click-RCE / unsafe-trust "
                     "issues detected.")
    else:
        for f in report.findings:
            label = _SEV_LABEL.get(f.severity, f.severity.upper())
            tag = f"[{f.domain}]" if f.domain else ""
            lines.append(f"[{label}] {f.rule} {tag}")
            lines.append(f"        {f.message}")
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
    scan.add_argument("--format", choices=("table", "json", "sarif"),
                      default="table", help="Output format (default: table).")
    scan.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER),
                      default="info",
                      help="Only report findings at or above this severity.")
    scan.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER),
                      default="high",
                      help="Exit non-zero if a finding at or above this "
                           "severity is present (default: high).")

    rules = sub.add_parser("rules", help="List the detection rules / domains.")
    rules.add_argument("--format", choices=("table", "json"), default="table")
    return p


def _run_scan(args: argparse.Namespace) -> int:
    try:
        report = scan_repo(args.path)
    except (OSError, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    threshold = SEVERITY_ORDER[args.min_severity]
    report.findings = [
        f for f in report.findings
        if SEVERITY_ORDER.get(f.severity, 99) <= threshold
    ]

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(report), indent=2))
    else:
        print(_render_table(report, args.fail_on))

    return 1 if report.failed(args.fail_on) else 0


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
            {"domain": d, "rule": r, "severity": s, "description": desc}
            for d, r, s, desc in _RULES
        ], indent=2))
    else:
        print(f"{TOOL_NAME} detection rules:")
        cur = None
        for d, r, s, desc in _RULES:
            if d != cur:
                print(f"\n[{d}]")
                cur = d
            print(f"  {r:<32} ({s})")
            print(f"      {desc}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
