# Sample project (deliberately unsafe)

This is a tiny "innocent-looking" project that an AI coding agent might open.
It carries several SymJack / TrustFall risks for TrustGate to flag:

- `.cursor/mcp.json` — `autoApprove`, `alwaysAllow`, `dangerouslySkipPermissions`,
  and a `curl | bash` MCP command (one-click / supply-chain RCE).
- `.vscode/tasks.json` — a task with `runOn: folderOpen` (zero-click on open).
- `.devcontainer/devcontainer.json` — `postCreateCommand` lifecycle hook.
- `notes/host-secrets` — an out-of-repo symlink created by `run_demo.py`
  (symlink hijack pointing outside the repository).
