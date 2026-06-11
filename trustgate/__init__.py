"""trustgate — part of the Cognis Neural Suite.

Detect symlink-hijack / one-click-RCE / unsafe-trust settings in
AI coding-agent projects.
"""
try:  # re-export the tool's public API + identity from core
    from trustgate.core import *  # noqa: F401,F403
except Exception:  # pragma: no cover
    pass
try:
    from trustgate.core import TOOL_NAME, TOOL_VERSION
except Exception:  # pragma: no cover
    TOOL_NAME = "trustgate"
    TOOL_VERSION = "0.1.0"
__version__ = TOOL_VERSION
