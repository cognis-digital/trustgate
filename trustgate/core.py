"""Core detection engine for TrustGate.

TrustGate scans a project / AI-coding-agent workspace for the
SymJack / TrustFall class of risks, where an attacker (or a malicious
repo you cloned) can turn *opening the project in an agent* into code
execution or trust escalation. It covers four detection domains:

  * symlink   — symlinks inside the repo whose target escapes the repo
                root (symlink hijack), plus dangling / absolute-target links
                and links pointing at sensitive host locations.
  * trust     — agent config files (.cursor/, .vscode/, mcp.json,
                .claude settings, etc.) carrying auto-approve / auto-run /
                trusted-without-prompt flags that enable one-click RCE. Now
                parses JSON, JSONC, TOML and YAML configs.
  * perms     — world-writable or otherwise attacker-writable config files
                (POSIX mode bits / Windows ACL heuristics).
  * autorun   — hooks / tasks / lifecycle scripts that auto-execute on
                folder open (VS Code runOptions.runOn, tasks, devcontainer
                lifecycle commands, git hooks, agent hooks), plus AST-level
                source->sink analysis of the scripts those hooks invoke.

Every finding is mapped to a CWE id and a Microsoft "AI agent / supply-chain
trust" taxonomy class so downstream dashboards can roll findings up.

Everything is computed locally from the filesystem; no network access (the
optional ``--ai`` layer is a separate, opt-in module). Standard library only.
"""

from __future__ import annotations

import ast
import html
import json
import os
import re
import stat
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL_NAME = "trustgate"
TOOL_VERSION = "0.2.0"

# Severity ordering, highest first. Drives sorting + --fail-on policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Directories we never descend into — scanning them is noise and slow.
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".idea", ".tox",
}

# Config file globs that an AI coding agent reads to decide trust / autorun.
# (lower-cased basename or relative-path suffix match)
_AGENT_CONFIG_NAMES = {
    "mcp.json", ".mcp.json", "mcp_config.json", "settings.json",
    "tasks.json", "launch.json", "extensions.json", "devcontainer.json",
    ".cursorrules", "environment.json", "claude_desktop_config.json",
    # broader agent ecosystem
    ".clinerules", ".windsurfrules", "continue.json", ".continuerc",
    "aider.conf.yml", ".aider.conf.yml", "copilot-instructions.md",
    "mcp.toml", "mcp.yaml", "mcp.yml", "config.toml", "agent.toml",
    "cline_mcp_settings.json", "amazonq.json", "zed-settings.json",
}
_AGENT_CONFIG_DIRS = {
    ".cursor", ".vscode", ".claude", ".devcontainer", ".aider",
    ".continue", ".cline", ".windsurf", ".github",
}

# Keys/flags that, when truthy, disable the human-in-the-loop prompt and
# enable one-click / zero-click RCE. Matched case-insensitively against
# both JSON keys and the raw text. (normalized: lowercase, alnum only)
_AUTO_APPROVE_KEYS = (
    "autoapprove", "autoapprovetools", "alwaysallow",
    "autorun", "autoexecute",
    "yolomode", "yolo", "skipconfirmation",
    "disableconfirmation", "trustedwithoutprompt",
    "allowunsignedtools", "dangerouslyskippermissions",
    "bypasspermissions", "neverask",
    "autoacceptedits", "trustall", "allowall",
    # broader agent-config trust flags
    "autoapprovecommands", "autoexecutetools", "autoexecutecommands",
    "autoconfirm", "noconfirm", "autoaccept", "autoacceptall",
    "trustlevel", "fulltrust", "trustworkspace", "trustedfolders",
    "disablesafemode", "unsafe", "unrestricted", "allowdangerous",
    "enableallcommands", "skippermissioncheck", "skipprompt",
    "approveall", "permitall", "runwithoutconfirmation",
    "acceptalledits", "autoallowtools", "donotask",
)

# Truthy-key normalization shares the underscore/dash stripper.
_AUTO_APPROVE_SET = set(_AUTO_APPROVE_KEYS)

# VS Code task "run on folder open" markers (zero-click on open).
_RUNON_FOLDER_OPEN = "folderopen"

# Sensitive host-path needles for symlink targets (and write sinks).
_SENSITIVE_NEEDLES = (
    "/etc/", "/.ssh", "/.aws", "/.gnupg", "/.config", "id_rsa", "id_ed25519",
    "/proc/", "/sys/", "system32", "/.env", ".env", "/root/",
    "authorized_keys", "/.docker", "/.kube", "/.npmrc", "/.pypirc",
    "/.git-credentials", "/.netrc", "credentials", "/boot/", "/.bash_history",
    "windows\\system32", "%userprofile%", "$home", "~/.ssh",
)

# Interpreters / network tools that signal "this command runs arbitrary code".
_INTERP_RE = re.compile(
    r"(?i)\b(sh|bash|zsh|fish|cmd|powershell|pwsh|python[0-9.]*|node|npx|deno|"
    r"bun|ruby|perl|php|osascript|curl|wget|iwr|invoke-webrequest|eval|exec|"
    r"certutil|bitsadmin|rundll32|regsvr32|mshta|wscript|cscript)\b"
)
_CURL_PIPE_RE = re.compile(
    r"(?i)(curl|wget|iwr|invoke-webrequest)[^\n|]*\|\s*(sh|bash|zsh|pwsh|"
    r"powershell|python|node|perl|ruby)"
)


# --------------------------------------------------------------------------
# CWE + Microsoft taxonomy mapping
# --------------------------------------------------------------------------
# Each rule id -> (CWE id, MS AI-agent/supply-chain trust taxonomy class).
# The MS taxonomy strings mirror Microsoft's "AI agent threats" + SCITT/SLSA
# supply-chain framing used in their secure-agent guidance.
RULE_TAXONOMY: Dict[str, Tuple[str, str]] = {
    "symlink.escapes_repo": ("CWE-59", "MS.SC.SymlinkFollowing"),
    "symlink.sensitive_target": ("CWE-61", "MS.SC.SymlinkFollowing"),
    "symlink.absolute_target": ("CWE-59", "MS.SC.SymlinkFollowing"),
    "symlink.dangling": ("CWE-59", "MS.SC.SymlinkFollowing"),
    "trust.auto_approve": ("CWE-862", "MS.AGENT.HumanInTheLoopBypass"),
    "trust.curl_pipe_shell": ("CWE-494", "MS.SC.UntrustedCodeExecution"),
    "trust.mcp_shell_command": ("CWE-78", "MS.AGENT.ToolPoisoning"),
    "trust.wildcard_tool_grant": ("CWE-732", "MS.AGENT.ExcessiveAgency"),
    "trust.env_secret_inline": ("CWE-798", "MS.SC.SecretExposure"),
    "autorun.task_on_open": ("CWE-829", "MS.SC.AutomaticCodeExecution"),
    "autorun.devcontainer_hook": ("CWE-829", "MS.SC.AutomaticCodeExecution"),
    "autorun.repo_git_hook": ("CWE-829", "MS.SC.AutomaticCodeExecution"),
    "autorun.custom_hookspath": ("CWE-426", "MS.SC.AutomaticCodeExecution"),
    "autorun.agent_hooks": ("CWE-829", "MS.AGENT.ToolPoisoning"),
    "autorun.dangerous_hook_script": ("CWE-94", "MS.SC.UntrustedCodeExecution"),
    "perms.world_writable": ("CWE-732", "MS.SC.TamperableConfig"),
    "perms.group_writable_config": ("CWE-732", "MS.SC.TamperableConfig"),
    "perms.untrusted_location": ("CWE-427", "MS.SC.TamperableConfig"),
    # AI-sourced findings get a generic mapping unless the model supplies one.
    "ai.finding": ("CWE-1039", "MS.AGENT.AIAssistedReview"),
}


def taxonomy_for(rule: str, cwe_hint: str = "") -> Tuple[str, str]:
    """Return (cwe, ms_class) for a rule, honoring a model-supplied CWE hint."""
    cwe, ms = RULE_TAXONOMY.get(rule, ("", "MS.SC.Uncategorized"))
    if cwe_hint:
        cwe = cwe_hint
    return cwe, ms


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    location: str = ""
    remediation: str = ""
    domain: str = ""
    evidence: str = ""
    cwe: str = ""
    ms_taxonomy: str = ""
    source: str = "rule"          # "rule" | "ai"
    novel: bool = False           # AI-flagged novel / logic flaw
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not self.cwe or not self.ms_taxonomy:
            cwe, ms = taxonomy_for(self.rule, self.cwe)
            self.cwe = self.cwe or cwe
            self.ms_taxonomy = self.ms_taxonomy or ms

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def dedupe_key(self) -> Tuple[str, str, str]:
        """Identity used to dedupe AI findings against rule findings."""
        loc = (self.location or "").split("::", 1)[0]
        return (self.rule, loc, self.severity)


@dataclass
class Report:
    source: str
    root: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    symlinks_scanned: int = 0
    ai_enabled: bool = False
    ai_status: str = "off"        # off | ok | unreachable | error

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def score(self) -> int:
        """0-100 trust-hygiene score; critical/high dominate the penalty."""
        weights = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
        penalty = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    def failed(self, fail_on: str = "high") -> bool:
        thr = SEVERITY_ORDER.get(fail_on, 1)
        return any(SEVERITY_ORDER.get(f.severity, 99) <= thr for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "source": self.source,
            "root": self.root,
            "files_scanned": self.files_scanned,
            "symlinks_scanned": self.symlinks_scanned,
            "score": self.score,
            "counts": self.counts,
            "ai_enabled": self.ai_enabled,
            "ai_status": self.ai_status,
            "findings": [f.to_dict() for f in self.findings],
        }


class ScanError(ValueError):
    """Raised when a target path cannot be scanned."""


# --------------------------------------------------------------------------
# Filesystem walk
# --------------------------------------------------------------------------

def _iter_entries(root: Path) -> Iterable[Path]:
    """Yield every file & symlink under root, skipping noise dirs.

    Does NOT follow symlinked directories (avoids loops / escaping the walk).
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # prune skip dirs in place
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        base = Path(dirpath)
        # symlinked subdirectories show up in dirnames; surface them too
        for name in list(dirnames):
            p = base / name
            if p.is_symlink():
                yield p
        for name in filenames:
            yield base / name


def _is_inside(child: Path, parent: Path) -> bool:
    """True if resolved `child` is at or under resolved `parent`."""
    try:
        c = os.path.normcase(os.path.realpath(str(child)))
        pa = os.path.normcase(os.path.realpath(str(parent)))
    except (OSError, ValueError, RuntimeError):
        return False
    try:
        return os.path.commonpath([c, pa]) == pa
    except ValueError:
        return False


# --------------------------------------------------------------------------
# (a) symlink-hijack detection
# --------------------------------------------------------------------------

def _check_symlinks(root: Path, entries: List[Path], out: List[Finding]) -> int:
    count = 0
    for p in entries:
        if not p.is_symlink():
            continue
        count += 1
        rel = _rel(root, p)
        try:
            raw_target = os.readlink(p)
        except OSError:
            raw_target = "<unreadable>"

        clean_target = raw_target
        if clean_target.startswith("\\\\?\\"):
            clean_target = clean_target[4:]
        try:
            if os.path.isabs(clean_target):
                resolved = Path(os.path.realpath(clean_target))
            else:
                resolved = Path(os.path.realpath(str(p.parent / clean_target)))
        except (OSError, ValueError, RuntimeError):
            resolved = None

        target_exists = False
        try:
            target_exists = p.exists()
        except OSError:
            target_exists = False

        inside = resolved is not None and _is_inside(resolved, root)

        if os.path.isabs(clean_target):
            out.append(Finding(
                "symlink.absolute_target",
                "high" if not inside else "medium",
                f"Symlink uses an absolute target '{raw_target}'.",
                rel, "Use a relative, in-repo target or remove the symlink.",
                "symlink", evidence=raw_target,
            ))

        if resolved is not None and not inside:
            out.append(Finding(
                "symlink.escapes_repo", "critical",
                f"Symlink points OUTSIDE the repository (target resolves to "
                f"'{resolved}'). A malicious repo can use this to read or "
                f"clobber host files when an agent follows it.",
                rel,
                "Delete the symlink or repoint it inside the repo. Never trust "
                "out-of-repo symlinks from a cloned project.",
                "symlink", evidence=raw_target,
            ))
        elif not target_exists and resolved is not None:
            out.append(Finding(
                "symlink.dangling", "low",
                f"Dangling symlink (target '{raw_target}' does not exist).",
                rel, "Remove dangling symlinks; they can be pre-positioned to "
                "capture a later-created path.", "symlink", evidence=raw_target,
            ))

        # Symlinks to sensitive host locations even if 'inside' a mount.
        low = raw_target.lower().replace("\\", "/")
        for needle in _SENSITIVE_NEEDLES:
            if needle.replace("\\", "/") in low:
                out.append(Finding(
                    "symlink.sensitive_target", "critical",
                    f"Symlink target references a sensitive location "
                    f"('{raw_target}').",
                    rel, "Remove; this is a classic credential / secret "
                    "exfiltration primitive.", "symlink", evidence=raw_target,
                ))
                break
    return count


# --------------------------------------------------------------------------
# (b) auto-approve / one-click-RCE trust settings
# --------------------------------------------------------------------------

def _is_agent_config(root: Path, p: Path) -> bool:
    name = p.name.lower()
    if name in _AGENT_CONFIG_NAMES:
        return True
    rel_parts = {part.lower() for part in _rel(root, p).replace("\\", "/").split("/")}
    if rel_parts & _AGENT_CONFIG_DIRS:
        return True
    if name.endswith(".mcp.json") or name == "mcp.json":
        return True
    # any *.toml/*.yaml/*.yml whose basename mentions mcp/agent/cursor/claude
    if name.endswith((".toml", ".yaml", ".yml")) and re.search(
            r"(mcp|agent|cursor|claude|cline|windsurf|continue|aider|copilot)",
            name):
        return True
    return False


def _walk_json(obj: Any, path: str = "") -> Iterable[Tuple[str, str, Any]]:
    """Yield (json_path, key, value) for every key in a nested JSON object."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            jp = f"{path}.{k}" if path else str(k)
            yield jp, str(k), v
            yield from _walk_json(v, jp)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            jp = f"{path}[{i}]"
            yield from _walk_json(v, jp)


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in (
            "true", "1", "yes", "on", "all", "*", "always", "full",
            "unrestricted", "high", "danger", "dangerous", "auto",
        )
    if isinstance(v, (list, dict)):
        return len(v) > 0
    if isinstance(v, (int, float)):
        return v != 0
    return False


def _norm_key(k: str) -> str:
    return re.sub(r"[^a-z0-9]", "", k.lower())


def _looks_like_secret(key: str, val: Any) -> bool:
    if not isinstance(val, str) or len(val) < 12:
        return False
    nk = _norm_key(key)
    if not any(t in nk for t in ("token", "key", "secret", "password",
                                 "passwd", "apikey", "auth", "credential",
                                 "bearer", "pat")):
        return False
    # ignore obvious placeholders / env interpolation
    if re.search(r"\$\{?\w+\}?|<[^>]+>|xxxx|placeholder|example|changeme",
                 val, re.IGNORECASE):
        return False
    return bool(re.search(r"[A-Za-z0-9_\-]{16,}", val))


def _check_trust_config(root: Path, p: Path, raw: str,
                        data: Optional[Any], out: List[Finding]) -> None:
    rel = _rel(root, p)

    if data is not None:
        for jp, key, val in _walk_json(data):
            nk = _norm_key(key)
            if nk in _AUTO_APPROVE_SET and _truthy(val):
                out.append(Finding(
                    "trust.auto_approve", "critical",
                    f"Agent config enables auto-approval / auto-run via "
                    f"'{key}' = {json.dumps(val)[:80]}. An agent opening this "
                    f"project can run tools/commands WITHOUT a human prompt "
                    f"(one-click RCE).",
                    f"{rel}::{jp}",
                    "Remove the flag or set it false; require explicit "
                    "per-action confirmation.",
                    "trust", evidence=f"{key}={json.dumps(val)[:120]}",
                ))
            # Wildcard tool/permission grants ("*", ["*"], "all").
            if nk in ("allowedtools", "tools", "permissions", "allow",
                      "allowedcommands", "scopes") and _is_wildcard_grant(val):
                out.append(Finding(
                    "trust.wildcard_tool_grant", "high",
                    f"Agent config grants ALL tools/permissions via "
                    f"'{key}' = {json.dumps(val)[:80]} (wildcard). This gives "
                    f"the agent excessive agency over the host.",
                    f"{rel}::{jp}",
                    "Enumerate the minimum set of tools/permissions instead of "
                    "a wildcard '*'.",
                    "trust", evidence=f"{key}={json.dumps(val)[:120]}",
                ))
            # Inline secrets in agent config (often committed by mistake).
            if _looks_like_secret(key, val):
                out.append(Finding(
                    "trust.env_secret_inline", "high",
                    f"Agent config contains an inline credential ('{key}'). "
                    f"Committed secrets in agent configs leak to anyone who "
                    f"clones the repo.",
                    f"{rel}::{jp}",
                    "Move secrets to a non-committed env/secret store; never "
                    "hard-code tokens in agent configs.",
                    "trust", evidence=f"{key}=<redacted len={len(str(val))}>",
                ))
            # MCP server entries that launch a shell/interpreter command.
            if nk in ("command", "cmd", "run", "exec", "script", "entrypoint") \
                    and isinstance(val, str):
                _flag_command_string(rel, jp, val, out)

    # Raw-text fallback (catches comments, JSONC, non-standard shapes).
    if _CURL_PIPE_RE.search(raw):
        out.append(Finding(
            "trust.curl_pipe_shell", "critical",
            "Config text contains a remote-fetch-piped-to-shell pattern.",
            rel, "Never pipe network downloads into a shell.",
            "trust", evidence="curl ... | sh",
        ))


def _is_wildcard_grant(val: Any) -> bool:
    if isinstance(val, str):
        return val.strip() in ("*", "all", "ALL", "Allow(*)")
    if isinstance(val, list):
        return any(isinstance(x, str) and x.strip() in ("*", "all", "ALL")
                   for x in val)
    if isinstance(val, dict):
        return any(k == "*" for k in val.keys())
    return False


def _flag_command_string(rel: str, jp: str, val: str,
                         out: List[Finding]) -> None:
    if _CURL_PIPE_RE.search(val):
        out.append(Finding(
            "trust.curl_pipe_shell", "critical",
            f"Config runs a remote-fetch-piped-to-shell command "
            f"('{val[:90]}') — classic supply-chain RCE.",
            f"{rel}::{jp}",
            "Never pipe network downloads into a shell.",
            "trust", evidence=val[:160],
        ))
        return
    if _INTERP_RE.search(val) or "|" in val or "&&" in val or ";" in val \
            or "$(" in val or "`" in val:
        out.append(Finding(
            "trust.mcp_shell_command", "medium",
            f"MCP/agent config launches an interpreter or chained "
            f"shell command: '{val[:90]}'. Combined with "
            f"auto-approval this is direct code execution.",
            f"{rel}::{jp}",
            "Pin the command to a known binary + reviewed args; "
            "avoid shell metacharacters and curl|sh patterns.",
            "trust", evidence=val[:160],
        ))


# --------------------------------------------------------------------------
# (d) auto-execute-on-open hooks / tasks  (+ source->sink AST analysis)
# --------------------------------------------------------------------------

def _check_autorun(root: Path, p: Path, data: Optional[Any],
                   out: List[Finding]) -> None:
    rel = _rel(root, p)
    name = p.name.lower()

    if data is None:
        return

    # VS Code tasks.json: runOptions.runOn == "folderOpen"  → zero-click.
    if name == "tasks.json" and isinstance(data, dict):
        for task in (data.get("tasks") or []):
            if not isinstance(task, dict):
                continue
            ro = task.get("runOptions") or {}
            run_on = _norm_key(str(ro.get("runOn", "")))
            if run_on == _RUNON_FOLDER_OPEN:
                cmd = task.get("command", "")
                args = task.get("args", "")
                out.append(Finding(
                    "autorun.task_on_open", "critical",
                    f"VS Code task '{task.get('label','?')}' is configured to "
                    f"run automatically on folder open (runOn=folderOpen) and "
                    f"executes '{cmd} {args}'. Opening the project runs code "
                    f"with no prompt.",
                    f"{rel}::task:{task.get('label','?')}",
                    "Remove runOn=folderOpen for any task that executes "
                    "commands; require manual task invocation.",
                    "autorun", evidence=f"{cmd} {args}".strip()[:160],
                ))
                _maybe_analyze_referenced_script(root, p, str(cmd), out)

    # devcontainer lifecycle hooks run automatically when the container builds.
    if name == "devcontainer.json" and isinstance(data, dict):
        for hook in ("onCreateCommand", "postCreateCommand",
                     "updateContentCommand", "postStartCommand",
                     "postAttachCommand", "initializeCommand"):
            if data.get(hook):
                sev = "high" if hook == "initializeCommand" else "medium"
                out.append(Finding(
                    "autorun.devcontainer_hook", sev,
                    f"devcontainer '{hook}' auto-executes "
                    f"'{str(data[hook])[:90]}' when the dev container is "
                    f"created/opened.",
                    f"{rel}::{hook}",
                    "Review lifecycle commands; treat them as untrusted code "
                    "from the repo author.",
                    "autorun", evidence=str(data[hook])[:160],
                ))
                _maybe_analyze_referenced_script(root, p, str(data[hook]), out)

    # Agent hooks block (.claude settings / generic "hooks").
    if isinstance(data, dict) and isinstance(data.get("hooks"), (list, dict)):
        out.append(Finding(
            "autorun.agent_hooks", "medium",
            "Config defines agent hooks that fire on lifecycle events; verify "
            "none execute attacker-controlled commands automatically.",
            f"{rel}::hooks",
            "Audit each hook's command; disable hooks you did not author.",
            "autorun", evidence="hooks present",
        ))
        for cmd in _iter_hook_commands(data.get("hooks")):
            _flag_command_string(rel, "hooks", cmd, out)
            _maybe_analyze_referenced_script(root, p, cmd, out)


def _iter_hook_commands(hooks: Any) -> Iterable[str]:
    for _, key, val in _walk_json(hooks):
        if _norm_key(key) in ("command", "cmd", "run", "exec", "script") \
                and isinstance(val, str):
            yield val


def _maybe_analyze_referenced_script(root: Path, cfg: Path, cmd: str,
                                     out: List[Finding]) -> None:
    """If `cmd` references an in-repo script file, AST-scan it for sinks."""
    if not cmd:
        return
    # pull the first token that looks like a path to a repo file
    for tok in re.split(r"[\s;&|]+", cmd):
        tok = tok.strip("'\"")
        if not tok or tok.startswith("-"):
            continue
        if not re.search(r"\.(py|sh|bash|js|cjs|mjs|ps1)$", tok, re.IGNORECASE):
            continue
        cand = (cfg.parent / tok)
        if not cand.exists():
            cand = (root / tok.lstrip("./"))
        if cand.exists() and cand.is_file() and _is_inside(cand, root):
            _analyze_script_file(root, cand, out)


def _analyze_script_file(root: Path, path: Path, out: List[Finding]) -> None:
    """Source->sink scan of a hook/task script. AST for Python, regex else."""
    rel = _rel(root, path)
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if len(src) > 500_000:
        return

    suffix = path.suffix.lower()
    sinks: List[str] = []

    if suffix == ".py":
        sinks = _python_ast_sinks(src)
    else:
        sinks = _regex_script_sinks(src)

    for sink in sinks[:5]:
        out.append(Finding(
            "autorun.dangerous_hook_script", "high",
            f"Auto-run hook/task invokes script '{rel}' which reaches a "
            f"dangerous sink: {sink}. Opening the project can execute this.",
            rel,
            "Review the script; remove dynamic exec / shell-out from anything "
            "that runs automatically on open.",
            "autorun", evidence=sink[:160],
        ))


def _python_ast_sinks(src: str) -> List[str]:
    """Return human-readable descriptions of dangerous sinks in Python src."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return _regex_script_sinks(src)

    sinks: List[str] = []
    DANGEROUS = {
        ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
        ("os", "execl"), ("os", "execlp"), ("os", "spawnl"),
        ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "Popen"),
        ("subprocess", "check_call"), ("subprocess", "check_output"),
        ("subprocess", "getoutput"),
        ("pty", "spawn"), ("shutil", "rmtree"),
    }
    BARE = {"eval", "exec", "compile", "__import__"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        # bare eval/exec/compile/__import__
        if isinstance(fn, ast.Name) and fn.id in BARE:
            sinks.append(f"{fn.id}() at line {getattr(node, 'lineno', 0)}")
            continue
        # module.attr style
        if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
            pair = (fn.value.id, fn.attr)
            if pair in DANGEROUS:
                shell = _has_shell_true(node)
                tag = " (shell=True)" if shell else ""
                sinks.append(
                    f"{fn.value.id}.{fn.attr}(){tag} at line "
                    f"{getattr(node, 'lineno', 0)}")
    return sinks


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell":
            v = kw.value
            if isinstance(v, ast.Constant) and v.value is True:
                return True
    return False


_SHELL_SINK_RE = re.compile(
    r"^\s*(eval|exec|source|\.\s)\b"
    r"|\b(curl|wget)\b[^\n|]*\|\s*(sh|bash)"
    r"|\$\(([^)]+)\)"
    r"|\b(rm\s+-rf|chmod\s+\+x|base64\s+-d|powershell\s+-enc)",
    re.IGNORECASE | re.MULTILINE,
)


def _regex_script_sinks(src: str) -> List[str]:
    sinks: List[str] = []
    for i, line in enumerate(src.splitlines(), 1):
        if _SHELL_SINK_RE.search(line):
            sinks.append(f"'{line.strip()[:80]}' at line {i}")
    # JS-style dynamic exec
    for m in re.finditer(r"(?i)\b(child_process|execSync|exec|spawn|"
                         r"eval|Function)\s*\(", src):
        sinks.append(f"{m.group(0).strip()} (dynamic exec)")
    # de-dup, keep order
    seen = set()
    uniq = []
    for s in sinks:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def _check_git_hooks(root: Path, out: List[Finding]) -> None:
    """Repo-supplied git hooks (or core.hooksPath) auto-run on git ops."""
    for cand in (root / ".githooks", root / "githooks"):
        if cand.is_dir():
            for h in cand.iterdir():
                if h.is_file():
                    out.append(Finding(
                        "autorun.repo_git_hook", "high",
                        f"Repository ships an executable git hook "
                        f"('{_rel(root, h)}'). If core.hooksPath points here, "
                        f"it runs on commit/checkout/merge automatically.",
                        _rel(root, h),
                        "Review every checked-in hook before enabling "
                        "core.hooksPath; never run unreviewed repo hooks.",
                        "autorun", evidence=h.name,
                    ))
                    _analyze_script_file(root, h, out)
    cfg = root / ".git" / "config"
    if cfg.is_file():
        try:
            txt = cfg.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"(?im)^\s*hooksPath\s*=\s*(.+)$", txt)
            if m:
                out.append(Finding(
                    "autorun.custom_hookspath", "high",
                    f"git core.hooksPath is set to '{m.group(1).strip()}', "
                    f"redirecting hooks to a repo-controlled directory.",
                    ".git/config::core.hooksPath",
                    "Unset core.hooksPath unless you have reviewed every hook.",
                    "autorun", evidence=m.group(1).strip(),
                ))
        except OSError:
            pass


# --------------------------------------------------------------------------
# (c) attacker-writable config
# --------------------------------------------------------------------------

def _check_permissions(root: Path, p: Path, is_config: bool,
                       out: List[Finding]) -> None:
    try:
        st = p.lstat()
    except OSError:
        return
    mode = st.st_mode

    if os.name != "nt":
        _check_posix_perms(root, p, mode, is_config, out)

    if os.name == "nt" and is_config:
        try:
            parent = str(p.resolve().parent).lower()
        except OSError:
            parent = ""
        if any(parent.startswith(d) for d in (
                "c:\\temp", "c:\\windows\\temp", "c:\\users\\public")):
            out.append(Finding(
                "perms.untrusted_location", "high",
                f"Agent config lives in a world-writable system location "
                f"('{parent}'); other users may overwrite it.",
                _rel(root, p),
                "Move agent configs into a per-user, ACL-restricted directory.",
                "perms", evidence=parent,
            ))


def _check_posix_perms(root: Path, p: Path, mode: int, is_config: bool,
                       out: List[Finding]) -> None:
    if mode & stat.S_IWOTH:
        sev = "critical" if is_config else "high"
        out.append(Finding(
            "perms.world_writable", sev,
            f"File is world-writable (mode {stat.filemode(mode)}). Any local "
            f"user can replace its contents; if it is an agent config this is "
            f"a trust-escalation primitive.",
            _rel(root, p),
            "Restrict to owner-write (chmod o-w / 0644).",
            "perms", evidence=oct(mode & 0o777),
        ))
    elif (mode & stat.S_IWGRP) and is_config:
        out.append(Finding(
            "perms.group_writable_config", "medium",
            f"Agent config is group-writable (mode {stat.filemode(mode)}); a "
            f"non-owner in the group can tamper with trust settings.",
            _rel(root, p),
            "Restrict to owner-write (chmod g-w).",
            "perms", evidence=oct(mode & 0o777),
        ))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(p).replace("\\", "/")


def _load_jsonish(text: str) -> Optional[Any]:
    """Parse JSON, tolerating // and /* */ comments + trailing commas (JSONC)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    no_block = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    no_line = re.sub(r"(?m)^\s*//.*$", "", no_block)
    no_trailing = re.sub(r",(\s*[}\]])", r"\1", no_line)
    try:
        return json.loads(no_trailing)
    except json.JSONDecodeError:
        return None


def _load_config(path: Path, raw: str) -> Optional[Any]:
    """Parse a config file by extension: JSON/JSONC, TOML, or YAML (stdlib)."""
    suffix = path.suffix.lower()
    if suffix == ".toml":
        try:
            import tomllib  # py3.11+
            return tomllib.loads(raw)
        except Exception:
            return _toml_fallback(raw)
    if suffix in (".yaml", ".yml"):
        return _yaml_fallback(raw)
    return _load_jsonish(raw)


def _coerce_scalar(s: str) -> Any:
    s = s.strip()
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none", "~", ""):
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    # inline list  [a, b]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_coerce_scalar(x) for x in inner.split(",")]
    return s


def _toml_fallback(raw: str) -> Optional[Any]:
    """Minimal best-effort TOML reader (key=value + [tables]) for old Pythons."""
    root: Dict[str, Any] = {}
    cur = root
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^\[+([^\]]+)\]+$", line)
        if m:
            cur = root
            for part in m.group(1).split("."):
                cur = cur.setdefault(part.strip(), {})
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            cur[k.strip()] = _coerce_scalar(v)
    return root or None


def _yaml_fallback(raw: str) -> Optional[Any]:
    """Minimal indentation-based YAML reader (mappings + simple lists)."""
    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Any]] = [(-1, root)]
    for line in raw.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            stack = [(-1, root)]
        parent = stack[-1][1]
        if content.startswith("- "):
            item = _coerce_scalar(content[2:])
            if isinstance(parent, list):
                parent.append(item)
            continue
        if ":" in content:
            k, _, v = content.partition(":")
            k = k.strip()
            v = v.strip()
            if v == "":
                # could be a nested map or a list; default to dict, may flip
                child: Any = {}
                if isinstance(parent, dict):
                    parent[k] = child
                stack.append((indent, child))
            else:
                val = _coerce_scalar(v)
                if isinstance(parent, dict):
                    parent[k] = val
    return root or None


# --------------------------------------------------------------------------
# AI merge
# --------------------------------------------------------------------------

def ai_finding_to_finding(item: Dict[str, Any], location: str) -> Finding:
    """Convert a normalized ai_backend finding dict into a Finding."""
    sev = str(item.get("severity", "info")).lower()
    if sev not in SEVERITY_ORDER:
        sev = "info"
    cwe = str(item.get("cwe", "")).strip()
    title = str(item.get("title", "AI finding")).strip() or "AI finding"
    why = str(item.get("why", "")).strip()
    line = item.get("line", 0)
    loc = location
    try:
        if int(line) > 0:
            loc = f"{location}::line {int(line)}"
    except (TypeError, ValueError):
        pass
    return Finding(
        rule="ai.finding",
        severity=sev,
        message=f"{title}: {why}" if why else title,
        location=loc,
        remediation="Triage this AI-suggested issue; confirm before acting.",
        domain="ai",
        evidence=str(item.get("evidence", ""))[:200],
        cwe=cwe,
        source="ai",
        novel=bool(item.get("novel", False)),
        confidence=float(item.get("confidence", 0.0) or 0.0),
    )


def merge_ai_findings(rule_findings: List[Finding],
                      ai_findings: List[Finding]) -> List[Finding]:
    """Append AI findings, deduping any that collide with a rule finding."""
    seen = {f.dedupe_key() for f in rule_findings}
    merged = list(rule_findings)
    for f in ai_findings:
        # dedupe by (location-file, evidence) since ai.rule differs from rules
        key = (f.location.split("::", 1)[0], (f.evidence or "")[:60].lower())
        rule_locs = {(rf.location.split("::", 1)[0],
                      (rf.evidence or "")[:60].lower()) for rf in rule_findings}
        if key in rule_locs:
            continue
        merged.append(f)
    return merged


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def scan(path: str) -> Dict[str, Any]:
    """Convenience wrapper returning a dict report (used by the MCP server)."""
    return scan_repo(path).to_dict()


def scan_repo(path: str, use_ai: bool = False) -> Report:
    """Scan a project directory and return a Report of trust/RCE risks.

    When ``use_ai`` is True, run the opt-in ai_backend over the same config /
    script sources and merge its findings (tagged source="ai"). The scan is
    byte-for-byte deterministic when ``use_ai`` is False.
    """
    root = Path(path)
    if not root.exists():
        raise ScanError(f"path does not exist: {path}")
    if not root.is_dir():
        raise ScanError(f"path is not a directory: {path}")
    root = root.resolve()

    findings: List[Finding] = []
    entries = list(_iter_entries(root))

    sym_count = _check_symlinks(root, entries, findings)

    files_scanned = 0
    ai_targets: List[Tuple[str, str]] = []   # (rel_location, source_text)
    for p in entries:
        if p.is_symlink():
            continue
        try:
            if not p.is_file():
                continue
        except OSError:
            continue
        files_scanned += 1

        is_config = _is_agent_config(root, p)
        _check_permissions(root, p, is_config, findings)

        if not is_config:
            continue
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(raw) > 2_000_000:
            continue
        data = _load_config(p, raw)
        _check_trust_config(root, p, raw, data, findings)
        _check_autorun(root, p, data, findings)
        if use_ai and raw.strip():
            ai_targets.append((_rel(root, p), raw))

    _check_git_hooks(root, findings)

    report = Report(source=path, root=str(root), findings=findings,
                    files_scanned=files_scanned, symlinks_scanned=sym_count)

    if use_ai:
        _run_ai_layer(report, ai_targets)

    report.findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.source, f.rule,
                       f.location))
    return report


def _run_ai_layer(report: Report, targets: List[Tuple[str, str]]) -> None:
    """Run the opt-in ai_backend; degrade gracefully if unreachable."""
    report.ai_enabled = True
    try:
        from trustgate import ai_backend
    except Exception:
        report.ai_status = "error"
        return

    backend = ai_backend.CognisAIBackend()
    if not backend.is_enabled():
        report.ai_status = "unreachable"
        return
    if not backend.health():
        report.ai_status = "unreachable"
        return

    report.ai_status = "ok"
    ai_findings: List[Finding] = []
    for loc, src in targets:
        try:
            raw_findings = backend.analyze_code(
                src,
                context=f"Agent/MCP config file: {loc}. Look for trust-boundary "
                        f"bypass, auto-approval, command injection, and "
                        f"supply-chain RCE primitives.",
                focus="AI coding-agent trust escalation and one-click RCE.",
            )
        except Exception:
            continue
        for item in raw_findings:
            ai_findings.append(ai_finding_to_finding(item, loc))

    report.findings = merge_ai_findings(report.findings, ai_findings)


# --------------------------------------------------------------------------
# SARIF rendering
# --------------------------------------------------------------------------

_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}


def to_sarif(report: Report) -> Dict[str, Any]:
    rule_ids = sorted({f.rule for f in report.findings})
    rules = []
    for rid in rule_ids:
        cwe, ms = taxonomy_for(rid)
        rules.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": rid},
            "properties": {"cwe": cwe, "ms_taxonomy": ms},
        })

    results = []
    for f in report.findings:
        loc_uri = (f.location.split("::", 1)[0] or report.root)
        results.append({
            "ruleId": f.rule,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "properties": {"severity": f.severity, "domain": f.domain,
                           "remediation": f.remediation, "evidence": f.evidence,
                           "cwe": f.cwe, "ms_taxonomy": f.ms_taxonomy,
                           "source": f.source, "novel": f.novel,
                           "confidence": f.confidence},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc_uri}
                }
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/trustgate",
                "rules": rules,
            }},
            "results": results,
        }],
    }


# --------------------------------------------------------------------------
# Badge (shields.io endpoint) + HTML report rendering
# --------------------------------------------------------------------------

def to_badge(report: Report) -> Dict[str, Any]:
    """shields.io 'endpoint' JSON so users can show a status badge.

    Render with:  https://img.shields.io/endpoint?url=<raw-json-url>
    """
    c = report.counts
    if c["critical"]:
        color, msg = "critical", f"{c['critical']} critical"
    elif c["high"]:
        color, msg = "red", f"{c['high']} high"
    elif c["medium"]:
        color, msg = "orange", f"{c['medium']} medium"
    elif c["low"] or c["info"]:
        color, msg = "yellow", f"score {report.score}"
    else:
        color, msg = "brightgreen", "passing"
    return {
        "schemaVersion": 1,
        "label": "trustgate",
        "message": msg,
        "color": color,
    }


_HTML_SEV_COLOR = {
    "critical": "#b30000", "high": "#d9480f", "medium": "#e8590c",
    "low": "#f08c00", "info": "#868e96",
}


def to_html(report: Report, fail_on: str = "high") -> str:
    """Self-contained HTML report (no external CSS/JS)."""
    c = report.counts
    failed = report.failed(fail_on)
    e = html.escape
    rows = []
    for f in report.findings:
        color = _HTML_SEV_COLOR.get(f.severity, "#868e96")
        src_tag = ('<span class="ai">AI</span>' if f.source == "ai" else "")
        novel = ('<span class="novel">novel</span>' if f.novel else "")
        rows.append(f"""
      <tr>
        <td><span class="sev" style="background:{color}">{e(f.severity.upper())}</span> {src_tag}{novel}</td>
        <td><code>{e(f.rule)}</code><br><small>{e(f.cwe)} · {e(f.ms_taxonomy)}</small></td>
        <td>{e(f.message)}<br><small class="loc">{e(f.location)}</small>
            {('<br><small class="evi">'+e(f.evidence)+'</small>') if f.evidence else ''}
            {('<br><small class="fix">fix: '+e(f.remediation)+'</small>') if f.remediation else ''}
        </td>
      </tr>""")
    body = "\n".join(rows) if rows else (
        '<tr><td colspan="3">No findings. Clean trust hygiene.</td></tr>')
    result_color = "#b30000" if failed else "#2b8a3e"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TrustGate report — {e(report.root)}</title>
<style>
  body {{ font: 15px/1.5 -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; color: #212529; background: #f8f9fa; }}
  header {{ background: #11181c; color: #fff; padding: 20px 28px; }}
  header h1 {{ margin: 0 0 4px; font-size: 20px; }}
  header .sub {{ color: #adb5bd; font-size: 13px; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; padding: 24px 16px; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }}
  .card {{ background: #fff; border: 1px solid #dee2e6; border-radius: 10px;
          padding: 14px 18px; min-width: 90px; }}
  .card .n {{ font-size: 26px; font-weight: 700; }}
  .card .l {{ font-size: 12px; color: #868e96; text-transform: uppercase; }}
  .score {{ font-size: 26px; font-weight: 700; }}
  .result {{ display:inline-block; padding:6px 14px; border-radius:8px;
            color:#fff; font-weight:700; background:{result_color}; }}
  table {{ width: 100%; border-collapse: collapse; background:#fff;
          border:1px solid #dee2e6; border-radius:10px; overflow:hidden; }}
  th, td {{ text-align: left; padding: 10px 14px; vertical-align: top;
           border-bottom: 1px solid #f1f3f5; }}
  th {{ background:#f1f3f5; font-size:12px; text-transform:uppercase;
       color:#495057; }}
  .sev {{ color:#fff; padding:2px 8px; border-radius:6px; font-size:11px;
         font-weight:700; }}
  .ai {{ background:#5f3dc4; color:#fff; padding:2px 6px; border-radius:6px;
        font-size:10px; }}
  .novel {{ background:#0c8599; color:#fff; padding:2px 6px; border-radius:6px;
           font-size:10px; }}
  code {{ background:#f1f3f5; padding:1px 5px; border-radius:4px; }}
  small.loc {{ color:#1971c2; }} small.evi {{ color:#868e96; }}
  small.fix {{ color:#2b8a3e; }}
  footer {{ text-align:center; color:#adb5bd; font-size:12px; padding:20px; }}
</style></head>
<body>
<header>
  <h1>TrustGate report</h1>
  <div class="sub">{e(report.root)} · {TOOL_NAME} {TOOL_VERSION}
    · AI: {e(report.ai_status)}</div>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="n score">{report.score}<small>/100</small></div>
      <div class="l">trust score</div></div>
    <div class="card"><div class="n" style="color:#b30000">{c['critical']}</div>
      <div class="l">critical</div></div>
    <div class="card"><div class="n" style="color:#d9480f">{c['high']}</div>
      <div class="l">high</div></div>
    <div class="card"><div class="n" style="color:#e8590c">{c['medium']}</div>
      <div class="l">medium</div></div>
    <div class="card"><div class="n">{c['low']}</div><div class="l">low</div></div>
    <div class="card"><div class="n">{report.files_scanned}</div>
      <div class="l">files</div></div>
  </div>
  <p><span class="result">{'FAIL' if failed else 'PASS'}</span>
     &nbsp;<small>fail-on = {e(fail_on)}</small></p>
  <table>
    <thead><tr><th>Severity</th><th>Rule / taxonomy</th><th>Detail</th></tr></thead>
    <tbody>{body}
    </tbody>
  </table>
</div>
<footer>Generated by TrustGate (Cognis Neural Suite). Local, deterministic
unless --ai was used.</footer>
</body></html>"""
