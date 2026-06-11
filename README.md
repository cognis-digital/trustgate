# trustgate

> Part of the **Cognis Neural Suite** · AI-Security tools

**Detect symlink-hijack / one-click-RCE / unsafe-trust settings in AI coding-agent projects.**

When you (or your AI coding agent) open an untrusted repository, *opening it*
can be enough to get code execution: a `.vscode` task that runs on folder
open, a `.cursor/mcp.json` that auto-approves every tool call, a
`devcontainer.json` lifecycle hook, or a symlink that quietly points at your
`~/.ssh`. This is the **SymJack / TrustFall** class of risks. TrustGate scans
a project for them before your agent ever touches it.

Standard-library Python only. No network access. No third-party dependencies.

## What it detects

| Domain    | Examples |
|-----------|----------|
| **symlink** | Symlinks whose target resolves **outside** the repo (hijack), absolute targets, links to sensitive host paths (`/etc`, `.ssh`, `.env`, `id_rsa`, `system32`), dangling links. |
| **trust**   | Agent configs (`.cursor/`, `.vscode/`, `.claude/`, `mcp.json`, devcontainer) with `autoApprove` / `alwaysAllow` / `dangerouslySkipPermissions` / `yolo` / `trustedWithoutPrompt`; MCP commands that launch shells or `curl … \| bash`. |
| **perms**   | World-writable / group-writable config files; configs living in world-writable system locations (Windows `C:\Temp`, `C:\Users\Public`). |
| **autorun** | VS Code tasks with `runOn: folderOpen` (zero-click), devcontainer lifecycle commands, repo-shipped git hooks, custom `core.hooksPath`, agent lifecycle hooks. |

## Install

```bash
pip install -e .
# or run straight from a checkout — stdlib only, no install needed:
python -m trustgate --help
```

## Usage

```bash
# Scan a project directory (human-readable table)
python -m trustgate scan /path/to/project

# Machine-readable JSON
python -m trustgate scan /path/to/project --format json

# SARIF (for GitHub code-scanning / CI dashboards)
python -m trustgate scan /path/to/project --format sarif

# Only show high+ findings, and gate CI on critical only
python -m trustgate scan /path/to/project --min-severity high --fail-on critical

# List the detection rules
python -m trustgate rules
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No finding at or above `--fail-on` (default `high`). |
| `1`  | One or more findings at/above the `--fail-on` threshold. |
| `2`  | Usage / path error. |

`--fail-on` accepts `critical`, `high`, `medium`, `low`, `info`.

## Demo

```bash
python demos/01-basic/run_demo.py
```

The demo builds a throwaway copy of a deliberately-unsafe sample project,
plants an out-of-repo symlink at runtime, and scans it — flagging an
auto-approve MCP config, a `curl | bash` server command, a folder-open task,
a devcontainer hook, and the symlink hijack. See
[`demos/01-basic/SCENARIO.md`](demos/01-basic/SCENARIO.md).

## MCP server

TrustGate exposes itself as an MCP tool (`trustgate_scan(path)`), so an agent
runtime can scan a workspace before trusting it:

```bash
python -m trustgate.mcp_server
```

It uses the Cognis suite's shared MCP helper when available and otherwise
falls back to a self-contained, stdlib-only JSON-RPC-over-stdio server.

## Library API

```python
from trustgate import scan_repo, to_sarif

report = scan_repo("/path/to/project")
print(report.score, report.counts)
for f in report.findings:
    print(f.severity, f.rule, f.location)
```

## License

Cognis Open Collaboration License (COCL) 1.0 — see [LICENSE](LICENSE).
