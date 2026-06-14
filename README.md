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

## Usage — step by step

`trustgate` scans a project / agent-workspace directory for symlink-hijack,
one-click-RCE, and unsafe-trust settings in AI coding-agent projects.

1. **Install** (editable from a clone, or from the wheel):
   ```bash
   pip install -e .
   # provides the `trustgate` console script
   ```
2. **Scan a project directory** (the `scan` subcommand takes a path):
   ```bash
   trustgate scan ./my-agent-project
   ```
3. **List the detection rules / domains**, or produce a status badge:
   ```bash
   trustgate rules
   trustgate badge ./my-agent-project    # shields.io endpoint JSON
   ```
4. **Read / use the output.** Default `--format table` prints findings, taxonomy
   (CWE / MS), locations, and a 0–100 score; switch to `json`, `sarif`, `html`,
   or `badge`, and `--out FILE` to write a report. `--min-severity` filters the
   list; the opt-in `--ai` flag (env `COGNIS_AI_*`) adds novel findings and
   degrades to rules-only if the backend is down:
   ```bash
   trustgate scan ./my-agent-project --format html --out trustgate.html
   ```
5. **Gate CI** with `--fail-on` (`critical|high|medium|low|info`, default `high`);
   the process exits non-zero when a finding at/above that severity is present:
   ```bash
   trustgate scan ./my-agent-project --format sarif --fail-on high --out trustgate.sarif
   ```

## What it detects

| Domain    | Examples |
|-----------|----------|
| **symlink** | Symlinks whose target resolves **outside** the repo (hijack), absolute targets, links to sensitive host paths (`/etc`, `.ssh`, `.aws`, `.kube`, `.npmrc`, `.git-credentials`, `id_rsa`, `system32`), dangling links. |
| **trust**   | Agent configs — now JSON **and** JSONC / TOML / YAML — across `.cursor/`, `.vscode/`, `.claude/`, `.continue/`, `.cline/`, `.windsurf/`, `.aider/`, `mcp.json`, devcontainer — with `autoApprove` / `alwaysAllow` / `dangerouslySkipPermissions` / `yolo` / `autoConfirm` / `bypassPermissions` / `trustedWithoutPrompt`; **wildcard tool/permission grants** (`"*"`); **inline hard-coded secrets**; MCP commands that launch shells or `curl … \| bash`. |
| **perms**   | World-writable / group-writable config files; configs living in world-writable system locations (Windows `C:\Temp`, `C:\Users\Public`). |
| **autorun** | VS Code tasks with `runOn: folderOpen` (zero-click), devcontainer lifecycle commands, repo-shipped git hooks, custom `core.hooksPath`, agent lifecycle hooks — **plus AST-level source→sink analysis** of the Python/shell/JS scripts those hooks invoke (`os.system`, `subprocess(..., shell=True)`, `eval`/`exec`, `curl\|bash`, …). |

Every finding is mapped to a **CWE** id and a **Microsoft AI-agent / supply-chain trust taxonomy** class (e.g. `MS.AGENT.HumanInTheLoopBypass`, `MS.SC.SymlinkFollowing`), surfaced in `rules`, `--format json`, SARIF, and the HTML report.

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

# Self-contained HTML report
python -m trustgate scan /path/to/project --format html --out trustgate.html

# shields.io status-badge endpoint JSON
python -m trustgate badge /path/to/project

# List the detection rules (with CWE + MS taxonomy)
python -m trustgate rules
```

## Pluggable AI mode (opt-in, off by default)

TrustGate is **byte-for-byte deterministic by default**. With `--ai` (or the
`COGNIS_AI_*` env), it additionally runs the Cognis shared AI backend over the
same config/script sources, merges the model's findings (`source="ai"`, novel
candidates flagged), and dedupes them against the rule findings. Nothing leaves
the box — the backend points at a **local** OpenAI-compatible endpoint:

```bash
# Point at a local fleet endpoint, then opt in with --ai
export COGNIS_AI_BACKEND=uncensored-fleet   # or COGNIS_AI_ENDPOINT=http://127.0.0.1:8774/v1
python -m trustgate scan /path/to/project --ai
```

If `--ai` is given but the backend is unreachable, TrustGate prints a clear
note and **continues with rule findings only** (it never crashes, and the scan
without `--ai` is unchanged).

## GitHub Action (viral CI)

TrustGate ships a reusable composite Action. Drop this into any repo's
`.github/workflows/`:

```yaml
name: trustgate
on: [push, pull_request]
permissions:
  contents: read
  pull-requests: write   # for the PR comment
jobs:
  trustgate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cognis-digital/trustgate@main
        with:
          path: "."
          fail-on: "high"
          comment: "true"
```

It scans the repo, **comments the findings table on the PR** (via `gh api`),
and **fails the job** on `--fail-on` severity. Outputs `score` and `result`.

## Status badge

`trustgate badge <path>` (or `scan --format badge`) prints a
[shields.io endpoint](https://shields.io/endpoint) object
(`{schemaVersion,label,message,color}`). Publish it as `trustgate-badge.json`
and embed:

```markdown
![trustgate](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/main/trustgate-badge.json)
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

## Interoperability

`trustgate` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `trustgate`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.

## License

Cognis Open Collaboration License (COCL) 1.0 — see [LICENSE](LICENSE).
