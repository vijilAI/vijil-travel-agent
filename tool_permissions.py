"""Tool permission enforcement via Strands hooks.

Reads tool_permissions from the genome (dict[str, str] mapping tool names
to "allow"|"confirm"|"deny") and intercepts tool calls before execution.

Permission levels:
- "allow": tool executes normally (default for unlisted tools)
- "confirm": tool is blocked with a message asking for confirmation
  (in non-interactive contexts like Darwin evaluation, this behaves like "deny")
- "deny": tool is blocked entirely

Wired into the Strands Agent via the hooks=[...] parameter, alongside
any existing Dome hooks.
"""

import logging
from typing import Any

from strands.hooks import BeforeToolCallEvent, HookRegistry
from strands.hooks.registry import HookProvider

logger = logging.getLogger(__name__)

# Valid permission levels
VALID_LEVELS = {"allow", "confirm", "deny"}


class ToolPermissionHook:
    """Strands HookProvider that enforces per-tool access control.

    Tools not listed in the permissions dict default to "allow".
    """

    def __init__(self, permissions: dict[str, str]) -> None:
        self._permissions = {
            k: v for k, v in permissions.items() if v in VALID_LEVELS
        }
        if self._permissions:
            logger.info(
                "ToolPermissionHook: enforcing permissions for %d tool(s): %s",
                len(self._permissions),
                {k: v for k, v in self._permissions.items() if v != "allow"},
            )

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        """Register the before-tool-call hook."""
        registry.add_callback(BeforeToolCallEvent, self._check_permission)

    def _check_permission(self, event: BeforeToolCallEvent, **kwargs: Any) -> None:
        """Check tool permission and cancel if denied."""
        tool_name = event.tool_use["name"]
        level = self._permissions.get(tool_name, "allow")

        if level == "deny":
            event.cancel_tool = (
                f"Tool '{tool_name}' is denied by policy. "
                f"This tool has been restricted by the agent's security configuration."
            )
            logger.info("ToolPermissionHook: DENIED tool call '%s'", tool_name)

        elif level == "confirm":
            # In non-interactive contexts (evaluation, API calls), confirm = deny.
            # In production with a human in the loop, this would pause for approval.
            event.cancel_tool = (
                f"Tool '{tool_name}' requires confirmation before execution. "
                f"Please confirm you want to proceed with this action."
            )
            logger.info("ToolPermissionHook: CONFIRM-BLOCKED tool call '%s'", tool_name)
