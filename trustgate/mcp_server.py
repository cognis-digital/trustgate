"""TrustGate MCP server — exposes the scanner as an MCP capability.

Two backends, tried in order:

  1. The Cognis Neural Suite's shared `cognis_core.mcp.build_mcp_server`
     helper, when running inside the suite.
  2. A self-contained, standard-library JSON-RPC-over-stdio MCP server
     (no third-party deps) so the tool also runs standalone.

The exposed tool is `trustgate_scan(path)` which returns the JSON report
produced by `trustgate.core.scan`.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

from trustgate.core import scan, TOOL_NAME, TOOL_VERSION

_DESCRIPTION = ("Detect symlink-hijack / one-click-RCE / unsafe-trust settings "
                "in AI coding-agent projects.")

_TOOL_SCHEMA = {
    "name": "trustgate_scan",
    "description": _DESCRIPTION,
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {"type": "string",
                     "description": "Project directory to scan."}
        },
        "required": ["path"],
        "additionalProperties": False,
    },
}


def _suite_server():
    """Use the shared suite helper if it is importable."""
    from cognis_core.mcp import build_mcp_server  # type: ignore
    return build_mcp_server(
        tool_name=TOOL_NAME,
        description=_DESCRIPTION,
        scan_fn=scan,
    )


# --------------------------------------------------------------------------
# Standalone stdlib JSON-RPC / MCP implementation
# --------------------------------------------------------------------------

def _send(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _result(req_id: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "result": result})


def _error(req_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": req_id,
           "error": {"code": code, "message": message}})


def _handle(msg: Dict[str, Any]) -> None:
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        _result(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
        })
    elif method in ("notifications/initialized", "initialized"):
        return  # notification, no response
    elif method == "tools/list":
        _result(req_id, {"tools": [_TOOL_SCHEMA]})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name != "trustgate_scan":
            _error(req_id, -32601, f"unknown tool: {name}")
            return
        path = args.get("path")
        if not path:
            _error(req_id, -32602, "missing required argument: path")
            return
        try:
            report = scan(path)
            _result(req_id, {
                "content": [{"type": "text",
                             "text": json.dumps(report, indent=2)}],
                "isError": False,
            })
        except Exception as exc:  # surface scan errors as tool errors
            _result(req_id, {
                "content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True,
            })
    elif method == "ping":
        _result(req_id, {})
    elif req_id is not None:
        _error(req_id, -32601, f"method not found: {method}")


def run_stdio_server() -> int:
    """Read newline-delimited JSON-RPC requests from stdin; reply on stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict):
            _handle(msg)
    return 0


def run_mcp_server() -> int:
    try:
        server = _suite_server()
    except Exception:
        return run_stdio_server()
    # Suite helper may return a callable to run, or run itself.
    if callable(server):
        server()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_mcp_server())
