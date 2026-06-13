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

<!-- cognis:layman:start -->
## What is this?

TrustGate is a security scanner for software projects that use AI coding assistants. It checks a project folder before you or your AI agent starts working in it, looking for hidden traps that could let malicious code run on your computer just by opening a repository. It detects things like suspicious file links that escape the project, AI agent settings that skip safety prompts, and scripts that run automatically on folder open. Developers and teams using tools like Cursor, VS Code, or Claude Code will find it useful for catching supply-chain and one-click attack risks before they strike.
<!-- cognis:layman:end -->

## What it detects

| Domain    | Examples |
|-----------|----------|
| **symlink** | Symlinks whose target resolves **outside** the repo (hijack), absolute targets, links to sensitive host paths (`/etc`, `.ssh`, `.aws`, `.kube`, `.npmrc`, `.git-credentials`, `id_rsa`, `system32`), dangling links. |
| **trust**   | Agent configs — now JSON **and** JSONC / TOML / YAML — across `.cursor/`, `.vscode/`, `.claude/`, `.continue/`, `.cline/`, `.windsurf/`, `.aider/`, `mcp.json`, devcontainer — with `autoApprove` / `alwaysAllow` / `dangerouslySkipPermissions` / `yolo` / `autoConfirm` / `bypassPermissions` / `trustedWithoutPrompt`; **wildcard tool/permission grants** (`"*"`); **inline hard-coded secrets**; MCP commands that launch shells or `curl … \| bash`. |
| **perms**   | World-writable / group-writable config files; configs living in world-writable system locations (Windows `C:\Temp`, `C:\Users\Public`). |
| **autorun** | VS Code tasks with `runOn: folderOpen` (zero-click), devcontainer lifecycle commands, repo-shipped git hooks, custom `core.hooksPath`, agent lifecycle hooks — **plus AST-level source→sink analysis** of the Python/shell/JS scripts those hooks invoke (`os.system`, `subprocess(..., shell=True)`, `eval`/`exec`, `curl\|bash`, …). |

Every finding is mapped to a **CWE** id and a **Microsoft AI-agent / supply-chain trust taxonomy** class (e.g. `MS.AGENT.HumanInTheLoopBypass`, `MS.SC.SymlinkFollowing`), surfaced in `rules`, `--format json`, SARIF, and the HTML report.

<!-- cognis:domains:start -->
## Domains

**Primary domain:** AI & ML  ·  **JTF MERIDIAN division:** ATHENA-PRIME · SAGE

**Topics:** `cognis` `ai` `llm` `machine-learning` `agent-security` `cli`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

<!-- cognis:install:start -->
## Install

`trustgate` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/trustgate/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/trustgate/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/trustgate.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/trustgate.git"  # uv
pip install "git+https://github.com/cognis-digital/trustgate.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/trustgate.git
cd trustgate && pip install .
```

Then run:
```sh
trustgate --help
```
<!-- cognis:install:end -->

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

<a name="verification"></a>
## Verification

[![tests](https://img.shields.io/badge/tests-45%20passing-2ea44f.svg)](AUDIT.md)

Every push is verified end-to-end. Latest audit (2026-06-13):

```text
tests        : 45 passed, 0 failed, 0 errored
compile      : all modules parse
cli          : C:\Python314\python.exe: No module named https
package      : https
```

<details><summary>CLI surface (<code>--help</code>)</summary>

```text
C:\Python314\python.exe: No module named https
```
</details>

Full machine-readable results: [`AUDIT.md`](AUDIT.md) · regenerate with `python -m https --help` + `pytest -q`.

<div align="right"><a href="#top">↑ back to top</a></div>


## License

Cognis Open Collaboration License (COCL) 1.0 — see [LICENSE](LICENSE).
