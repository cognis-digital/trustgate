"""Core detection engine for TrustGate.

TrustGate scans a project / AI-coding-agent workspace for the
SymJack / TrustFall class of risks, where an attacker (or a malicious
repo you cloned) can turn *opening the project in an agent* into code
execution or trust escalation. It covers four detection domains:

  * symlink   — symlinks inside the repo whose target escapes the repo
                root (symlink hijack), plus dangling / absolute-target links.
  * trust     — agent config files (.cursor/, .vscode/, mcp.json,
                .claude settings, etc.) carrying auto-approve / auto-run /
                trusted-without-prompt flags that enable one-click RCE.
  * perms     — world-writable or otherwise attacker-writable config files
                (POSIX mode bits / Windows ACL heuristics).
  * autorun   — hooks / tasks / lifecycle scripts that auto-execute on
                folder open (VS Code runOptions.runOn, tasks, devcontainer
                lifecycle commands, git hooks, agent hooks).

Everything is computed locally from the filesystem; no network access.
Standard library only.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL_NAME = "trustgate"
TOOL_VERSION = "0.1.0"

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
}
_AGENT_CONFIG_DIRS = {".cursor", ".vscode", ".claude", ".devcontainer", ".aider"}

# Keys/flags that, when truthy, disable the human-in-the-loop prompt and
# enable one-click / zero-click RCE. Matched case-insensitively against
# both JSON keys and the raw text.
_AUTO_APPROVE_KEYS = (
    "autoapprove", "auto_approve", "autoapprovetools", "alwaysallow",
    "always_allow", "autorun", "auto_run", "autoexecute", "auto_execute",
    "yolomode", "yolo", "skipconfirmation", "skip_confirmation",
    "disableconfirmation", "disable_confirmation", "trustedwithoutprompt",
    "trusted_without_prompt", "allowunsignedtools", "dangerouslyskippermissions",
    "dangerously_skip_permissions", "bypasspermissions", "neverask",
    "never_ask", "autoacceptedits", "auto_accept_edits", "trust_all",
    "trustall", "allow_all", "allowall",
)

# VS Code task "run on folder open" markers (zero-click on open).
_RUNON_FOLDER_OPEN = "folderopen"


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    location: str = ""
    remediation: str = ""
    domain: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    source: str
    root: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    symlinks_scanned: int = 0

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
    """True if resolved `child` is at or under resolved `parent`.

    Uses os.path.realpath + commonpath so Windows extended-length prefixes
    and case differences don't cause false 'escapes'.
    """
    try:
        c = os.path.normcase(os.path.realpath(str(child)))
        pa = os.path.normcase(os.path.realpath(str(parent)))
    except (OSError, ValueError, RuntimeError):
        return False
    try:
        return os.path.commonpath([c, pa]) == pa
    except ValueError:
        # Different drives / mounts -> not inside.
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

        # Resolve the link target. If the link's parent + target escapes root,
        # it's a hijack vector: writes/reads through it touch files outside.
        # Normalize away any Windows extended-length prefix (\\?\) from the
        # readlink result before joining/resolving.
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
        for needle in ("/etc/", "/.ssh", "/.aws", "id_rsa", "/proc/",
                       "system32", ".env", "/root/", "authorized_keys"):
            if needle in low:
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
    # mcp.json anywhere, plus *.mcp.json
    if name.endswith(".mcp.json") or name == "mcp.json":
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
        return v.strip().lower() in ("true", "1", "yes", "on", "all", "*", "always")
    if isinstance(v, (list, dict)):
        return len(v) > 0
    if isinstance(v, (int, float)):
        return v != 0
    return False


def _norm_key(k: str) -> str:
    return re.sub(r"[^a-z0-9]", "", k.lower())


def _check_trust_config(root: Path, p: Path, raw: str,
                        data: Optional[Any], out: List[Finding]) -> None:
    rel = _rel(root, p)

    if data is not None:
        for jp, key, val in _walk_json(data):
            nk = _norm_key(key)
            if nk in _AUTO_APPROVE_KEYS and _truthy(val):
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
            # MCP server entries that launch a shell/interpreter command.
            if nk == "command" and isinstance(val, str):
                if re.search(r"(?i)\b(sh|bash|zsh|cmd|powershell|pwsh|python|"
                             r"node|npx|deno|ruby|perl|curl|wget|eval)\b", val) \
                        or "|" in val or "&&" in val or ";" in val:
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
                if re.search(r"(?i)(curl|wget)[^|]*\|\s*(sh|bash)", val):
                    out.append(Finding(
                        "trust.curl_pipe_shell", "critical",
                        f"Config runs a remote-fetch-piped-to-shell command "
                        f"('{val[:90]}') — classic supply-chain RCE.",
                        f"{rel}::{jp}",
                        "Never pipe network downloads into a shell.",
                        "trust", evidence=val[:160],
                    ))

    # Raw-text fallback (catches comments, JSONC, non-standard shapes).
    low = raw.lower()
    if re.search(r"(?i)curl[^\n|]*\|\s*(sh|bash)", raw):
        out.append(Finding(
            "trust.curl_pipe_shell", "critical",
            "Config text contains a curl|sh remote-execution pattern.",
            rel, "Never pipe network downloads into a shell.",
            "trust", evidence="curl ... | sh",
        ))


# --------------------------------------------------------------------------
# (d) auto-execute-on-open hooks / tasks
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


def _check_git_hooks(root: Path, out: List[Finding]) -> None:
    """Repo-supplied git hooks (or core.hooksPath) auto-run on git ops."""
    hooks_dir = root / ".git" / "hooks"
    # A checked-in hooks dir (not under .git) is the real supply-chain risk.
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

    # POSIX mode bits only carry meaning on POSIX systems. On Windows, Python
    # reports a synthetic 0o666/0o777 for ordinary files, so the world/group
    # writable checks would false-positive on every file — skip them and rely
    # on the location-based ACL heuristic below instead.
    if os.name != "nt":
        _check_posix_perms(root, p, mode, is_config, out)

    # Windows: lstat mode bits are unreliable for ACLs. Surface an info-level
    # note for configs living in a world-writable parent (e.g. C:\Temp\...).
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
    # POSIX world-writable bit.
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
    # strip // line comments and /* */ block comments
    no_block = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    no_line = re.sub(r"(?m)^\s*//.*$", "", no_block)
    no_trailing = re.sub(r",(\s*[}\]])", r"\1", no_line)
    try:
        return json.loads(no_trailing)
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def scan(path: str) -> Dict[str, Any]:
    """Convenience wrapper returning a dict report (used by the MCP server)."""
    return scan_repo(path).to_dict()


def scan_repo(path: str) -> Report:
    """Scan a project directory and return a Report of trust/RCE risks."""
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
        if len(raw) > 2_000_000:  # skip absurdly large "config" files
            continue
        data = _load_jsonish(raw)
        _check_trust_config(root, p, raw, data, findings)
        _check_autorun(root, p, data, findings)

    _check_git_hooks(root, findings)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule,
                                 f.location))
    return Report(source=path, root=str(root), findings=findings,
                  files_scanned=files_scanned, symlinks_scanned=sym_count)


# --------------------------------------------------------------------------
# SARIF rendering
# --------------------------------------------------------------------------

_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}


def to_sarif(report: Report) -> Dict[str, Any]:
    rule_ids = sorted({f.rule for f in report.findings})
    rules = [{
        "id": rid,
        "name": rid,
        "shortDescription": {"text": rid},
    } for rid in rule_ids]

    results = []
    for f in report.findings:
        loc_uri = (f.location.split("::", 1)[0] or report.root)
        results.append({
            "ruleId": f.rule,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "properties": {"severity": f.severity, "domain": f.domain,
                           "remediation": f.remediation, "evidence": f.evidence},
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
