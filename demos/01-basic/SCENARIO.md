# Demo 01 — Scanning an unsafe AI-agent project

This scenario runs TrustGate against a deliberately under-hardened project
that an AI coding agent might open and auto-trust.

## Run it

```bash
python demos/01-basic/run_demo.py
# machine-readable:
python demos/01-basic/run_demo.py --format json
# SARIF for code-scanning dashboards:
python demos/01-basic/run_demo.py --format sarif
```

The runner copies `sample-project/` to a temp dir and plants an out-of-repo
symlink (`notes/host-secrets -> ../OUTSIDE_HOST_DIR`) at runtime, because
symlinks do not survive a git checkout reliably across platforms.

## What it should catch

| Domain   | Issue                                                                   | Severity |
|----------|-------------------------------------------------------------------------|----------|
| symlink  | `notes/host-secrets` resolves OUTSIDE the repo (symlink hijack)         | critical |
| symlink  | symlink target references a sensitive location (`id_rsa`)               | critical |
| trust    | `.cursor/mcp.json` sets `dangerouslySkipPermissions`/`autoApprove`/`alwaysAllow` | critical |
| trust    | `.cursor/mcp.json` runs `curl … \| bash` (supply-chain RCE)             | critical |
| autorun  | `.vscode/tasks.json` task runs on `folderOpen` (zero-click)             | critical |
| autorun  | `.devcontainer/devcontainer.json` `postCreateCommand` lifecycle hook    | medium   |

Because critical/high findings are present, the process exits non-zero
(`--fail-on high`), failing any CI gate that wraps it.

> On Windows, creating symlinks may require Developer Mode or elevation;
> if the symlink cannot be created the runner prints a warning and the
> non-symlink findings still demonstrate the tool.
