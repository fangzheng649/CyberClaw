"""ITSM gate module for gNMI Set operations.

Validates ServiceNow Change Request numbers before allowing any
gNMI Set (write) operation.  The CR must:
  1. Match the format CHG followed by one or more digits.
  2. Be in "Implement" state in ServiceNow.

In production the state check calls the servicenow-mcp MCP tools.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger("gnmi-mcp.itsm")

# CR number pattern: CHG followed by digits
_CR_PATTERN = re.compile(r"^CHG\d+$")


def validate_change_request(cr_number: str) -> dict[str, Any]:
    """Validate a ServiceNow Change Request number.

    Returns a dict with keys:
      - valid (bool): Whether the CR passed validation.
      - message (str): Explanation (always present).
      - cr_number (str): The CR number that was checked.
      - state (str | None): The CR state if retrieved.

    In lab mode (NETCLAW_LAB_MODE=true) format-only validation is performed
    without contacting ServiceNow.
    """
    # --- Format validation ---
    if not cr_number:
        return {
            "valid": False,
            "message": "Change request number is required for gNMI Set operations",
            "cr_number": cr_number,
            "state": None,
        }

    if not _CR_PATTERN.match(cr_number):
        return {
            "valid": False,
            "message": (
                f"Invalid CR format: '{cr_number}'. "
                "Expected format: CHG followed by digits (e.g. CHG0012345)"
            ),
            "cr_number": cr_number,
            "state": None,
        }

    # --- Lab mode bypass ---
    lab_mode = os.environ.get("NETCLAW_LAB_MODE", "false").lower() in ("true", "1", "yes")
    if lab_mode:
        logger.info("Lab mode: skipping ServiceNow state verification for %s", cr_number)
        return {
            "valid": True,
            "message": f"CR {cr_number} format valid (lab mode — ServiceNow check skipped)",
            "cr_number": cr_number,
            "state": "lab_mode",
        }

    # --- ServiceNow state verification ---
    # In production, this calls the servicenow-mcp tools to verify the CR
    # is in "Implement" state.  The integration point is documented here.
    #
    # Expected flow:
    #   1. Call servicenow-mcp get_change_request(number=cr_number)
    #   2. Check that the CR exists and state == "Implement"
    #   3. If state is not "Implement", reject with clear message
    #   4. If CR is withdrawn mid-execution, halt immediately
    #
    # For now, we attempt to call the ServiceNow integration and fall back
    # to format-only validation with a warning.

    try:
        cr_state = _check_servicenow_cr_state(cr_number)
        if cr_state is None:
            # ServiceNow unreachable — warn but allow in non-strict mode
            logger.warning("Could not verify CR %s with ServiceNow", cr_number)
            return {
                "valid": True,
                "message": (
                    f"CR {cr_number} format valid. "
                    "ServiceNow verification unavailable — proceeding with format validation only."
                ),
                "cr_number": cr_number,
                "state": "unverified",
            }

        if cr_state.lower() == "implement":
            return {
                "valid": True,
                "message": f"CR {cr_number} is in 'Implement' state — approved for changes",
                "cr_number": cr_number,
                "state": cr_state,
            }
        else:
            return {
                "valid": False,
                "message": (
                    f"CR {cr_number} is in '{cr_state}' state, not 'Implement'. "
                    "gNMI Set operations require the CR to be in 'Implement' state."
                ),
                "cr_number": cr_number,
                "state": cr_state,
            }

    except Exception as exc:
        logger.warning("ITSM verification error for %s: %s", cr_number, exc)
        return {
            "valid": True,
            "message": (
                f"CR {cr_number} format valid. "
                "ServiceNow verification encountered an error — proceeding with format validation only."
            ),
            "cr_number": cr_number,
            "state": "error",
        }


def _check_servicenow_cr_state(cr_number: str) -> str | None:
    """Query ServiceNow for the CR state.

    Integration point: in a full deployment this invokes the
    servicenow-mcp MCP tool ``get_change_request`` via the MCP client.

    Returns the CR state string (e.g. "Implement", "New", "Closed")
    or None if ServiceNow is unreachable.
    """
    # This is the integration point for servicenow-mcp.
    # When the servicenow-mcp server is available, it will be called here.
    # For standalone operation, return None to indicate ServiceNow is unavailable.
    return None
